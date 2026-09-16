package ebbex.keil8051;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers Keil's bounded {@code AJMP}-table switches, which the stock decompiler-driven switch
 * analysis gets catastrophically wrong.
 * <p>
 * <b>The idiom.</b> When every case body is within reach, Keil compiles a dense {@code switch} into
 * a range check followed by a table of {@code AJMP} instructions:
 *
 * <pre>
 *   MOV  A,R6
 *   CJNE A,#0x09,$+0     ; the bound -- CJNE is used only for its carry
 *   JC   $+2
 *   AJMP default
 *   MOV  DPTR,#table
 *   ADD  A,ACC           ; index * 2, the AJMP entry size
 *   JMP  @A+DPTR
 *   table:
 *   AJMP case0           ; 2 bytes each, exactly <bound> of them
 *   AJMP case1
 *   ...
 * </pre>
 *
 * <b>Why the stock path fails.</b> Nothing marks the end of the table in the bytes, and Ghidra does
 * not read {@code CJNE #n / JC} as the bound, so {@link ghidra.app.plugin.core.analysis
 * .DecompilerSwitchAnalyzer} takes the index as unbounded and fabricates a case for every value the
 * doubled index can produce. On the GL3523 hub firmware's {@code vendor_req_A1_isp_mode_switch}
 * that turns a nine-entry table into <b>129</b> cases: everything after the real table is unrelated
 * code relabelled as case targets, some of it landing mid-instruction. The decompiler then follows
 * those targets and reports what it finds — {@code Unable to resolve constructor} where a target
 * hits the 8051's one undefined opcode ({@code 0xa5}), and {@code Could not follow disassembly flow
 * into non-existing memory} where flow leaves the loaded image.
 * <p>
 * <b>What this does.</b> It finds the dispatch by its fixed byte pattern, reads the bound out of
 * the compiler's own range check, verifies that exactly that many {@code AJMP} slots follow, and
 * lays down one {@code COMPUTED_JUMP} reference per case. That fixes the flow and — because
 * {@code DecompilerSwitchAnalyzer} skips any computed branch that already carries computed
 * references — stops the stock analyzer from ever fabricating the other 120.
 * <p>
 * <b>The bound is not optional.</b> A dispatch whose range check cannot be read is left alone. The
 * whole failure being repaired here is a table walked past its end, and guessing a length would be
 * the same mistake in a different hat.
 * <p>
 * <b>Ordering.</b> {@link AnalysisPriority#CODE_ANALYSIS}{@code .before()}, so the references exist
 * before the stock analyzer looks. On a program that was already analyzed without this extension
 * the damage is already in the database, so a one-shot re-run also removes the fabricated case
 * references and labels — see {@link #removeFabricatedCases}.
 */
public class KeilJumpTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Keil C51 AJMP jump tables";
	private static final String DESCRIPTION =
		"Recovers Keil's bounded 'CJNE #n / JC / MOV DPTR,#table / ADD A,ACC / JMP @A+DPTR' switches, " +
			"reading the case count from the compiler's own range check so the AJMP table is not " +
			"walked past its end. Also clears cases the stock switch analyzer fabricated past it.";

	private static final String TABLE_COMMENT_TAG = "Keil AJMP jump table";

	/** The namespace prefix Ghidra's own switch recovery puts its case labels in. */
	private static final String STOCK_SWITCH_NAMESPACE = "switchD_";

	public KeilJumpTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return Keil8051.is8051(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		AddressSet targets = new AddressSet();
		int tables = 0;
		int cases = 0;
		int removed = 0;
		for (KeilJumpTable table : KeilJumpTable.findAll(program, monitor)) {
			monitor.checkCancelled();
			removed += apply(program, table, targets, monitor);
			tables++;
			cases += table.entries().size();
		}

		if (!targets.isEmpty()) {
			new DisassembleCommand(targets, null, true).applyTo(program, monitor);
		}
		if (tables > 0) {
			Msg.info(this, "Keil C51: recovered " + tables + " AJMP jump table(s), " + cases +
				" case(s)" + (removed > 0 ? ", removed " + removed + " fabricated case(s)" : ""));
		}
		return tables > 0;
	}

	/** Applies one table and returns how many fabricated cases it cleaned up. */
	private int apply(Program program, KeilJumpTable table, AddressSet targets, TaskMonitor monitor) {
		Listing listing = program.getListing();
		ReferenceManager references = program.getReferenceManager();
		SymbolTable symbols = program.getSymbolTable();

		int removed = removeFabricatedCases(program, table);

		for (KeilJumpTable.Entry entry : table.entries()) {
			references.addMemoryReference(table.jump(), entry.address(), RefType.COMPUTED_JUMP,
				SourceType.ANALYSIS, 0);
			label(symbols, entry.address(), "caseD_" + Integer.toHexString(entry.caseValue()));
			targets.addRange(entry.address(), entry.address());
		}

		listing.setComment(table.address(), CommentType.PLATE, TABLE_COMMENT_TAG + ": " +
			table.entries().size() + " case(s), bound from CJNE #0x" +
			Integer.toHexString(table.bound()) + " at the dispatch");
		listing.setComment(table.jump(), CommentType.EOL,
			"Keil AJMP switch: " + table.entries().size() + " cases, table at " + table.address() +
				", ends " + table.end());
		return removed;
	}

	/**
	 * Removes what the stock switch analyzer left behind on a program analyzed before this extension
	 * was installed: the computed references from the dispatch to addresses beyond the real table,
	 * and the {@code switchD_*::caseD_*} labels on them.
	 * <p>
	 * Only references off the dispatch instruction and only labels in Ghidra's own switch namespace
	 * are touched — a name a human or another analyzer gave survives. Functions the stock analyzer
	 * created at fabricated targets are <i>not</i> deleted: some of them sit at addresses that are
	 * genuinely code, and deleting a function is not something to do on a guess.
	 */
	private int removeFabricatedCases(Program program, KeilJumpTable table) {
		ReferenceManager references = program.getReferenceManager();
		SymbolTable symbols = program.getSymbolTable();

		int removed = 0;
		for (Reference reference : references.getReferencesFrom(table.jump())) {
			Address to = reference.getToAddress();
			if (!reference.getReferenceType().isComputed()) {
				continue;
			}
			if (to.compareTo(table.address()) >= 0 && to.compareTo(table.end()) < 0) {
				continue;
			}
			references.delete(reference);
			removeStockCaseLabel(symbols, to);
			removed++;
		}
		return removed;
	}

	private void removeStockCaseLabel(SymbolTable symbols, Address at) {
		for (Symbol symbol : symbols.getSymbols(at)) {
			Namespace parent = symbol.getParentNamespace();
			if (parent == null || !parent.getName().startsWith(STOCK_SWITCH_NAMESPACE)) {
				continue;
			}
			if (symbol.isPrimary() && symbol.getSymbolType().isNamespace()) {
				continue;
			}
			symbol.delete();
		}
	}

	private void label(SymbolTable symbols, Address at, String name) {
		Symbol primary = symbols.getPrimarySymbol(at);
		if (primary != null && primary.getSource() != SourceType.DEFAULT) {
			return;
		}
		try {
			symbols.createLabel(at, name, SourceType.ANALYSIS);
		}
		catch (Exception e) {
			// A duplicate or unusable name costs nothing; the reference is what carries the flow.
		}
	}
}
