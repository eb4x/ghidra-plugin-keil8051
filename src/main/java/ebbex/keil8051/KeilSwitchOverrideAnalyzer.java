package ebbex.keil8051;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Gives the decompiler the destinations of Keil's switches, through jump-table overrides.
 * <p>
 * <b>{@code ?C?xCASE} switches</b> always get one. {@link KeilSwitchTableAnalyzer} replaces each
 * call to a case helper with an injected indirect branch, but the value-to-target mapping lives
 * in a table the helper walks at run time, which no data-flow analysis can follow; the override at
 * the call site is the only way the decompiler learns the cases. Case labels come out as the
 * decompiler's unknown-label placeholder, {@code 0xbad1abe1bad1abe1}: a {@code basicoverride}
 * carries destinations and cannot carry values, and there is no arithmetic path from the switch
 * variable to the target for the decompiler to derive them from. See
 * {@link KeilCaseHelper#fixupBody()} for why that is preferred to address labels.
 * <p>
 * <b>{@code AJMP} jump tables</b> get one only where the decompiler cannot work them out itself.
 * <p>
 * {@link KeilJumpTableAnalyzer} repairs the <i>references</i>. It does not repair the decompiler,
 * which recovers jump tables from its own p-code and pays no attention to references already on a
 * branch. Where that recovery fails, a jump-table override fixes it: Ghidra stores one purely as
 * symbols in {@code <func>::override::jmp_<branchaddr>} (see {@link JumpTable#writeOverride}), and
 * the decompiler reads it back and emits "Switch is manually overridden" instead of guessing.
 * <p>
 * <b>An override is not free, which is why this analyzer stands aside when it can.</b> A
 * {@code basicoverride} carries destinations only — nothing about what the switch index means — so
 * the decompiler consumes it and stops deriving the switch variable itself, keeping whatever cruder
 * expression it had. Measured on the GL3523 L2 hub image under a Ghidra carrying the CJNE guard
 * fix, which recovers the plain {@code AJMP} shape natively:
 *
 * <pre>
 *   0xbd6a, no override:  switch(uVar1)            case 0: ... case 8:
 *   0xbd6a, override:     switch(bVar1 * '\x02')   case 0: case 2: ... case 0x10:
 * </pre>
 *
 * Same destinations, but the override rendering is plainly worse. So before writing one, this
 * analyzer clears any override it left on a previous run, decompiles the function, and writes an
 * override only if the decompiler did not recover this table on its own. The decision is made from
 * observed behaviour, never from a Ghidra version: stock Ghidra still needs the override on all
 * four dispatches in that image, and the page-carry shape at {@code 0xbcbf} needs it on every
 * Ghidra there is ("Could not recover jumptable ... Too many branches").
 * <p>
 * <b>Ordering.</b> {@link AnalysisPriority#FUNCTION_ANALYSIS}{@code .after()}, because
 * {@code grabOverrides()} ignores anything that is not a {@link FunctionDB} — the override symbols
 * have nowhere to live until the dispatch sits inside a defined function.
 */
public class KeilSwitchOverrideAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Keil C51 switch overrides";
	private static final String DESCRIPTION =
		"Writes decompiler jump-table overrides for Keil switches: always at ?C?CCASE/?C?ICASE/" +
			"?C?LCASE call sites, and at bounded AJMP switches only where the decompiler cannot " +
			"recover them itself, since an override renders those less clearly.";

	private static final int DECOMPILE_TIMEOUT_SECONDS = 30;

	/** {@code LCALL addr16}: the case table starts right after it. */
	private static final int LCALL_LENGTH = 3;

	private static final String OVERRIDE_NAMESPACE = "override";
	private static final String JUMP_NAMESPACE_PREFIX = "jmp_";

	public KeilSwitchOverrideAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return Keil8051.is8051(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		int caseTables = overrideCaseTables(program, monitor, log);
		int[] ajmp = overrideJumpTables(program, monitor, log);

		if (caseTables > 0 || ajmp[0] > 0 || ajmp[1] > 0) {
			// Msg.info only, never log.appendMsg: any content in the analysis MessageLog makes
			// AutoAnalysisPlugin pop a "warnings/errors issued during analysis" dialog.
			Msg.info(this, "Keil C51: wrote " + caseTables + " ?C?xCASE and " + ajmp[0] +
				" AJMP switch override(s); " + ajmp[1] +
				" AJMP table(s) recovered by the decompiler without one");
		}
		return caseTables > 0 || ajmp[0] > 0;
	}

	/**
	 * Overrides every {@code ?C?xCASE} call site that sits inside a function.
	 * <p>
	 * These always need one. The helper's call-fixup (installed by {@link KeilSwitchTableAnalyzer})
	 * turns the call into an indirect branch, but nothing tells the decompiler where it goes: the
	 * value-to-target mapping lives in a table the helper walks at run time, which no data-flow
	 * analysis can follow. So there is no stand-aside test here, unlike the AJMP tables.
	 * <p>
	 * The destinations are the cases and the default, deduplicated — several case values often
	 * share a body, and a jump table lists each destination once.
	 */
	private int overrideCaseTables(Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		int written = 0;
		for (Map.Entry<Address, KeilCaseHelper> helper : KeilSwitchTableAnalyzer
				.findHelpers(program, monitor).entrySet()) {
			for (Address site : KeilSwitchTableAnalyzer.findCallSites(program, helper.getKey(),
				monitor)) {
				monitor.checkCancelled();
				KeilCaseTable table = KeilCaseTable.parse(program.getMemory(), helper.getValue(),
					site.add(LCALL_LENGTH));
				if (table == null) {
					continue;
				}
				Function function = program.getFunctionManager().getFunctionContaining(site);
				if (!(function instanceof FunctionDB)) {
					// No defined function yet; a later pass will catch it.
					continue;
				}
				Set<Address> destinations = new LinkedHashSet<>();
				table.cases().forEach(entry -> destinations.add(entry.target()));
				destinations.add(table.defaultTarget());
				if (writeOverride(function, site, new ArrayList<>(destinations), log)) {
					written++;
				}
			}
		}
		return written;
	}

	/** The AJMP tables: override where the decompiler cannot recover them. Returns {written, stoodAside}. */
	private int[] overrideJumpTables(Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		List<KeilJumpTable> tables = KeilJumpTable.findAll(program, monitor);
		if (tables.isEmpty()) {
			return new int[] { 0, 0 };
		}

		DecompInterface decompiler = new DecompInterface();
		int written = 0;
		int stoodAside = 0;
		try {
			if (!decompiler.openProgram(program)) {
				// Without a decompiler we cannot tell, so fall back to the safe side: override.
				decompiler = null;
			}
			for (KeilJumpTable table : tables) {
				monitor.checkCancelled();
				Function function =
					program.getFunctionManager().getFunctionContaining(table.jump());
				if (!(function instanceof FunctionDB)) {
					continue;
				}

				// A stale override from a previous run would make the decompiler "recover" the
				// table from our own hint, so the test below has to run without it.
				removeOverride(program.getSymbolTable(), function, table.jump());

				if (decompiler != null &&
					decompilerRecovers(decompiler, function, table, monitor)) {
					stoodAside++;
					continue;
				}
				if (writeOverride(function, table.jump(), table.destinations(), log)) {
					written++;
				}
			}
		}
		finally {
			if (decompiler != null) {
				decompiler.dispose();
			}
		}
		return new int[] { written, stoodAside };
	}

	/** Decompiles {@code function} and reports whether it recovered {@code table} unaided. */
	private boolean decompilerRecovers(DecompInterface decompiler, Function function,
			KeilJumpTable table, TaskMonitor monitor) {

		DecompileResults results =
			decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
		if (results == null || !results.decompileCompleted()) {
			return false;
		}
		HighFunction high = results.getHighFunction();
		if (high == null || high.getJumpTables() == null) {
			return false;
		}
		for (JumpTable recovered : high.getJumpTables()) {
			if (table.jump().equals(recovered.getSwitchAddress())) {
				return matchesTable(List.of(recovered.getCases()), table.destinations());
			}
		}
		return false;
	}

	/**
	 * True when the decompiler's recovered cases are this table's entries, allowing for one extra
	 * target: the decompiler folds the switch's default into its case list, and this analyzer's
	 * table does not carry it.
	 * <p>
	 * The slack is exactly one, and that is what makes the test meaningful. An unguarded recovery
	 * — the failure this whole analyzer exists for — produces a case for every value the index can
	 * take, 128 of them against a real 9, which this rejects.
	 */
	static boolean matchesTable(Collection<Address> recoveredCases, List<Address> tableEntries) {
		Set<Address> recovered = new HashSet<>(recoveredCases);
		Set<Address> entries = new HashSet<>(tableEntries);
		if (!recovered.containsAll(entries)) {
			return false;
		}
		Set<Address> extra = new HashSet<>(recovered);
		extra.removeAll(entries);
		return extra.size() <= 1;
	}

	private boolean writeOverride(Function function, Address branch, List<Address> destinations,
			MessageLog log) {
		JumpTable override =
			new JumpTable(branch, new ArrayList<>(destinations), true, EquateSymbol.FORMAT_DEFAULT);
		try {
			override.writeOverride(function);
			return true;
		}
		catch (InvalidInputException e) {
			log.appendMsg(String.format("Keil C51: could not override switch at %s in %s: %s",
				branch, function.getName(), e.getMessage()));
			return false;
		}
	}

	/** Deletes {@code <func>::override::jmp_<jump>} if present, children first. */
	private void removeOverride(SymbolTable symbols, Function function, Address jump) {
		Namespace overrides = symbols.getNamespace(OVERRIDE_NAMESPACE, function);
		if (overrides == null) {
			return;
		}
		Namespace jumpTable = symbols.getNamespace(JUMP_NAMESPACE_PREFIX + jump, overrides);
		if (jumpTable == null) {
			return;
		}
		List<Symbol> children = new ArrayList<>();
		symbols.getChildren(jumpTable.getSymbol()).forEach(children::add);
		children.forEach(Symbol::delete);
		jumpTable.getSymbol().delete();
	}
}
