package ebbex.keil8051;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers the inline case tables Keil C51 emits for {@code switch} statements, which stock
 * disassembly cannot see past.
 * <p>
 * <b>Why the stock path fails.</b> Keil compiles a non-jump-table {@code switch} into
 * {@code LCALL ?C?CCASE} (or {@code ?C?ICASE} / {@code ?C?LCASE}) with the case table laid down
 * <i>immediately after the call</i>. The helper pops its own return address to find that table, so
 * it never returns to the call site. Ghidra sees an ordinary {@code LCALL}, assumes it returns, and
 * disassembles the table bytes as code — which both destroys the listing after every switch and
 * leaves the case targets unreachable, so whole tails of functions are never disassembled at all.
 * <p>
 * <b>What this does.</b> It finds the helpers by their library bodies (see {@link KeilCaseHelper} —
 * these images carry no symbols, so there is no name to match), finds the {@code LCALL} sites,
 * parses each table, and then: clears whatever the disassembler wrongly laid over the table,
 * defines the entries as data, drops a {@code COMPUTED_JUMP} reference from the {@code LCALL} to
 * every case target and to the default, clears the call's fall-through so flow stops running into
 * the table, and disassembles the targets.
 * <p>
 * Case targets are labelled but deliberately <i>not</i> turned into functions: they are blocks
 * inside the switch's own function, and splitting them out would fragment it and cost the
 * decompiler the switch.
 * <p>
 * <b>Ordering.</b> {@link AnalysisPriority#CODE_ANALYSIS}{@code .before()} — as early as an
 * instruction-driven analyzer can run, so the references and the cleared fall-through are in place
 * before the disassembler gets another chance to walk into a table. Anything it already laid down
 * on a previous pass is cleared here rather than worked around.
 */
public class KeilSwitchTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Keil C51 switch tables";
	private static final String DESCRIPTION =
		"Recovers the inline <target,value> case tables that follow LCALL ?C?CCASE/?C?ICASE/?C?LCASE " +
			"in Keil C51 code: defines the table as data, adds a computed jump reference per case, " +
			"and disassembles the case targets.";

	/** {@code LCALL addr16} — the only way Keil reaches a case helper. */
	private static final int LCALL_OPCODE = 0x12;
	private static final int LCALL_LENGTH = 3;

	private static final String TABLE_COMMENT_TAG = "Keil case table";

	public KeilSwitchTableAnalyzer() {
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

		Map<Address, KeilCaseHelper> helpers = findHelpers(program, monitor);
		if (helpers.isEmpty()) {
			return false;
		}

		AddressSet targets = new AddressSet();
		int tables = 0;
		int cases = 0;
		for (Map.Entry<Address, KeilCaseHelper> helper : helpers.entrySet()) {
			monitor.checkCancelled();
			prepareHelper(program, helper.getKey(), helper.getValue(), log);
			for (Address site : findCallSites(program, helper.getKey(), monitor)) {
				monitor.checkCancelled();
				KeilCaseTable table = applyTable(program, site, helper.getValue(), targets, monitor);
				if (table != null) {
					tables++;
					cases += table.cases().size();
				}
			}
		}

		if (!targets.isEmpty()) {
			new DisassembleCommand(targets, null, true).applyTo(program, monitor);
		}
		if (tables > 0) {
			Msg.info(this, "Keil C51: recovered " + tables + " switch table(s), " + cases + " case(s)");
		}
		return tables > 0;
	}

	/** Locates every copy of every case helper. Banked images carry one copy per bank. */
	static Map<Address, KeilCaseHelper> findHelpers(Program program, TaskMonitor monitor)
			throws CancelledException {

		Memory memory = program.getMemory();
		Map<Address, KeilCaseHelper> found = new LinkedHashMap<>();
		for (KeilCaseHelper helper : KeilCaseHelper.values()) {
			Address from = memory.getMinAddress();
			while (from != null) {
				monitor.checkCancelled();
				Address at = memory.findBytes(from, helper.signature(), null, true, monitor);
				if (at == null) {
					break;
				}
				found.put(at, helper);
				from = at.next();
			}
		}
		return found;
	}

	/** Every {@code LCALL <helper>} in the image, by byte pattern. */
	static List<Address> findCallSites(Program program, Address helper, TaskMonitor monitor)
			throws CancelledException {

		int target = (int) helper.getOffset();
		byte[] pattern = {
			(byte) LCALL_OPCODE, (byte) ((target >> 8) & 0xff), (byte) (target & 0xff)
		};

		Memory memory = program.getMemory();
		List<Address> sites = new ArrayList<>();
		Address from = memory.getMinAddress();
		while (from != null) {
			monitor.checkCancelled();
			Address at = memory.findBytes(from, pattern, null, true, monitor);
			if (at == null) {
				break;
			}
			sites.add(at);
			from = at.next();
		}
		return sites;
	}

	/**
	 * Applies one call site, or returns {@code null} when it is not really a switch.
	 * <p>
	 * A call site does <i>not</i> have to have been reached by flow yet. On these images it usually
	 * has not been: the GL3523 hub switch at {@code 0x8811} sits in a region auto-analysis never
	 * reaches from the interrupt vectors, and recovering its table is precisely what makes that
	 * region reachable. Waiting for the disassembler to arrive first would mean never recovering the
	 * tables that matter most.
	 * <p>
	 * What stands in for that evidence is the table itself. Every entry's target must land in loaded
	 * memory and the table must reach its zero terminator — for the ten-entry table at {@code 0x8814}
	 * that is ten independent constraints, which random data does not satisfy. Only once the table
	 * parses is the {@code LCALL} disassembled.
	 */
	private KeilCaseTable applyTable(Program program, Address site, KeilCaseHelper helper,
			AddressSet targets, TaskMonitor monitor) {

		Listing listing = program.getListing();
		Address tableAddress = site.add(LCALL_LENGTH);
		KeilCaseTable table = KeilCaseTable.parse(program.getMemory(), helper, tableAddress);
		if (table == null) {
			return null;
		}

		Instruction call = instructionAt(program, listing, site, monitor);
		if (call == null || call.getLength() != LCALL_LENGTH) {
			return null;
		}
		if (isAlreadyApplied(listing, tableAddress)) {
			return table;
		}

		listing.clearCodeUnits(tableAddress, table.end().subtract(1), false);
		defineTable(program, table);
		addReferences(program, call, table, targets);
		clearFallThrough(call);
		comment(listing, call, table);
		return table;
	}

	/**
	 * The {@code LCALL} at a verified site, disassembling it if nothing is defined there yet.
	 * Defined data is left alone: something else has claimed those bytes and is more likely right.
	 */
	private Instruction instructionAt(Program program, Listing listing, Address site,
			TaskMonitor monitor) {

		Instruction existing = listing.getInstructionAt(site);
		if (existing != null) {
			return existing;
		}
		if (listing.getDefinedDataContaining(site) != null) {
			return null;
		}
		new DisassembleCommand(site, null, false).applyTo(program, monitor);
		return listing.getInstructionAt(site);
	}

	private boolean isAlreadyApplied(Listing listing, Address tableAddress) {
		String comment = listing.getComment(CommentType.PLATE, tableAddress);
		return comment != null && comment.startsWith(TABLE_COMMENT_TAG);
	}

	/** Lays the entries out as {@code word} target + value, so the listing reads as a table. */
	private void defineTable(Program program, KeilCaseTable table) {
		Listing listing = program.getListing();
		DataType valueType = valueType(table.helper().valueSize());
		for (KeilCaseTable.KeilCase entry : table.cases()) {
			createData(listing, entry.address(), WordDataType.dataType);
			createData(listing, entry.address().add(2), valueType);
		}
		Address terminator = table.address().add(table.length() - KeilCaseHelper.TERMINATOR_SIZE);
		createData(listing, terminator, WordDataType.dataType);
		createData(listing, terminator.add(2), WordDataType.dataType);
	}

	private static DataType valueType(int size) {
		return switch (size) {
			case 1 -> ByteDataType.dataType;
			case 2 -> WordDataType.dataType;
			default -> DWordDataType.dataType;
		};
	}

	private void createData(Listing listing, Address at, DataType type) {
		try {
			Data existing = listing.getDefinedDataAt(at);
			if (existing == null) {
				listing.createData(at, type);
			}
		}
		catch (Exception e) {
			// A neighbouring code unit we could not clear; the references still carry the flow.
		}
	}

	/**
	 * References go on the {@code LCALL} itself: the helper's {@code JMP @A+DPTR} is where the
	 * branch physically happens, but the call site is where a reader — and the decompiler's flow —
	 * needs to see the switch.
	 */
	private void addReferences(Program program, Instruction call, KeilCaseTable table,
			AddressSet targets) {

		ReferenceManager references = program.getReferenceManager();
		SymbolTable symbols = program.getSymbolTable();

		references.addMemoryReference(call.getAddress(), table.address(), RefType.DATA,
			SourceType.ANALYSIS, CodeUnit.MNEMONIC);

		for (KeilCaseTable.KeilCase entry : table.cases()) {
			references.addMemoryReference(call.getAddress(), entry.target(), RefType.COMPUTED_JUMP,
				SourceType.ANALYSIS, CodeUnit.MNEMONIC);
			references.addMemoryReference(entry.address(), entry.target(), RefType.DATA,
				SourceType.ANALYSIS, 0);
			label(symbols, entry.target(), "caseD_" + Long.toHexString(entry.value()));
			targets.addRange(entry.target(), entry.target());
		}

		references.addMemoryReference(call.getAddress(), table.defaultTarget(), RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS, CodeUnit.MNEMONIC);
		label(symbols, table.defaultTarget(), "caseD_default");
		targets.addRange(table.defaultTarget(), table.defaultTarget());
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
			// A duplicate or otherwise unusable name costs nothing here; the reference is the point.
		}
	}

	/**
	 * The helper never returns to the call site, so the bytes after the {@code LCALL} are the table.
	 * Clearing the fall-through is what stops the disassembler walking into it again.
	 */
	private void clearFallThrough(Instruction call) {
		if (call.getFallThrough() != null) {
			call.setFallThrough(null);
		}
	}

	private void comment(Listing listing, Instruction call, KeilCaseTable table) {
		listing.setComment(table.address(), CommentType.PLATE,
			TABLE_COMMENT_TAG + " (" + table.helper().keilSymbol() + "): " + table.cases().size() +
				" case(s), default " + table.defaultTarget());
		listing.setComment(call.getAddress(), CommentType.EOL,
			table.helper().keilSymbol() + ": " + table.cases().size() + " cases, table at " +
				table.address() + ", does not return");
	}

	/**
	 * Makes the helper a function the decompiler can see a switch through, and names it if nobody
	 * has.
	 * <p>
	 * Clearing each call site's fall-through fixes the listing only. The decompiler ignores it,
	 * treats the call as returning, and decodes the case table after it as instructions — on the
	 * GL3523 L2 hub image at 0x8811, {@code keil_ccase_switch(...); nop(); SFR95 = Var2;
	 * SFR88 = Var1 + 1} is the table at 0x8814 read as code.
	 * <p>
	 * So the helper gets a call-fixup (see {@link KeilCaseHelper#fixupBody()}): every call to it is
	 * replaced by an indirect branch, which {@link KeilSwitchOverrideAnalyzer} then gives the case
	 * destinations through a jump-table override at the call site. With a lone branch injected the
	 * table bytes are no longer decoded, and the decompiler shows a real switch. If the fixup
	 * cannot be installed, the fallback is to mark the helper no-return: that shows no switch, but
	 * it does stop the table being read as code, and no-return is the truth about the helper.
	 * <p>
	 * All of that is applied whether or not the helper already has a name. A session that named it
	 * by hand still needs it; only the name and plate comment are left to them.
	 */
	private void prepareHelper(Program program, Address at, KeilCaseHelper helper,
			MessageLog log) {
		AddressSet body = new AddressSet(at, at.add(helper.signature().length - 1));
		new DisassembleCommand(body, null, true).applyTo(program, TaskMonitor.DUMMY);
		if (program.getFunctionManager().getFunctionAt(at) == null) {
			new CreateFunctionCmd(helper.label(), at, null, SourceType.ANALYSIS)
				.applyTo(program, TaskMonitor.DUMMY);
		}
		Function function = program.getFunctionManager().getFunctionAt(at);
		if (function != null) {
			bindFixup(program, function, helper, log);
		}

		SymbolTable symbols = program.getSymbolTable();
		Symbol primary = symbols.getPrimarySymbol(at);
		if (primary != null && primary.getSource() != SourceType.DEFAULT &&
			!primary.getName().equals(helper.label())) {
			// Someone named it; their name and plate comment stand.
			return;
		}
		label(symbols, at, helper.label());
		if (program.getListing().getComment(CommentType.PLATE, at) == null) {
			program.getListing().setComment(at, CommentType.PLATE,
				"Keil C51 library routine " + helper.keilSymbol() + "\n" +
					"Pops its return address to find the inline case table that follows each call " +
					"site, walks it, and jumps to the matching case. Never returns to the caller.");
		}
	}

	/** Installs the helper's call-fixup if the program lacks it, and binds it to the helper. */
	private void bindFixup(Program program, Function function, KeilCaseHelper helper,
			MessageLog log) {
		try {
			if (SpecExtension.getCompilerSpecExtension(program, SpecExtension.Type.CALL_FIXUP,
				helper.label()) == null) {
				new SpecExtension(program).addReplaceCompilerSpecExtension(
					helper.fixupExtension(), TaskMonitor.DUMMY);
			}
			if (!helper.label().equals(function.getCallFixup())) {
				function.setCallFixup(helper.label());
			}
			// The injected branch keeps the decompiler out of the table; no-return would now only
			// hide the switch the fixup exists to show.
			if (function.hasNoReturn()) {
				function.setNoReturn(false);
			}
		}
		catch (Exception e) {
			log.appendMsg("Keil C51: could not install the " + helper.keilSymbol() +
				" call-fixup, marking it no-return instead: " + e.getMessage());
			if (!function.hasNoReturn()) {
				function.setNoReturn(true);
			}
		}
	}
}
