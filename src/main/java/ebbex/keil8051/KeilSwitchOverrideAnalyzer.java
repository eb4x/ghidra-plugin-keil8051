package ebbex.keil8051;

import java.util.ArrayList;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Tells the decompiler how big Keil's {@code AJMP} jump tables really are.
 * <p>
 * {@link KeilJumpTableAnalyzer} repairs the <i>references</i>, which is what keeps the listing and
 * the function bodies sane and stops {@code DecompilerSwitchAnalyzer} creating case labels. It does
 * not repair the decompiler: the decompiler recovers jump tables itself, from its own p-code, and
 * pays no attention to the references already on the branch. Left to itself it still reads the
 * {@code CJNE A,#n} range check as an ordinary comparison rather than a bound, still treats the
 * index as unbounded, and still produces a case for every value it can take — 129 of them for the
 * nine-entry table at {@code 0xbd6a} in the GL3523 L2 hub firmware, with the
 * "Unable to resolve constructor" and "Could not follow disassembly flow into non-existing memory"
 * errors that come of following them.
 * <p>
 * A jump-table override fixes that, and Ghidra stores one purely as symbols: a namespace
 * {@code <func>::override::jmp_<branchaddr>} holding a {@code switch} label at the branch and a
 * {@code case_N} label at each destination (see {@link JumpTable#writeOverride}). The decompiler
 * reads them back through {@code HighFunction.grabOverrides()} and emits "Switch is manually
 * overridden" instead of guessing.
 * <p>
 * <b>Ordering.</b> {@link AnalysisPriority#FUNCTION_ANALYSIS}{@code .after()}, because
 * {@code grabOverrides()} ignores anything that is not a {@link FunctionDB} — the override symbols
 * have nowhere to live until the dispatch sits inside a defined function.
 */
public class KeilSwitchOverrideAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Keil C51 switch overrides";
	private static final String DESCRIPTION =
		"Writes decompiler jump-table overrides for the bounded AJMP switches recovered by the " +
			"Keil C51 AJMP jump tables analyzer, so the decompiler stops inventing a case for every " +
			"value the index could take.";

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

		int written = 0;
		for (KeilJumpTable table : KeilJumpTable.findAll(program, monitor)) {
			monitor.checkCancelled();
			Function function =
				program.getFunctionManager().getFunctionContaining(table.jump());
			if (!(function instanceof FunctionDB)) {
				// No defined function yet; a later pass over this dispatch will catch it.
				continue;
			}

			JumpTable override = new JumpTable(table.jump(),
				new ArrayList<>(table.destinations()), true, EquateSymbol.FORMAT_DEFAULT);
			try {
				// writeOverride() clears the jmp_<addr> namespace first, so re-running is safe.
				override.writeOverride(function);
				written++;
			}
			catch (InvalidInputException e) {
				log.appendMsg(String.format("Keil C51: could not override switch at %s in %s: %s",
					table.jump(), function.getName(), e.getMessage()));
			}
		}

		if (written > 0) {
			// Msg.info only, never log.appendMsg: any content in the analysis MessageLog makes
			// AutoAnalysisPlugin pop a "warnings/errors issued during analysis" dialog, so a
			// success count there would cry wolf on a clean run.
			Msg.info(this, "Keil C51: wrote " + written + " switch table override(s)");
		}
		return written > 0;
	}
}
