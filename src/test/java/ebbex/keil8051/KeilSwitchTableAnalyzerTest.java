package ebbex.keil8051;

import static org.junit.Assert.*;

import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * End-to-end test for {@link KeilSwitchTableAnalyzer} on the real GL3523 L2 hub switch.
 * <p>
 * Everything here is bytes copied out of that image: the {@code ?C?CCASE} body at {@code 0xc176},
 * the {@code LCALL} at {@code 0x8811} and the ten-case table that follows it. If Keil's library
 * body or table shape is ever something other than what was verified, this test is what says so.
 */
public class KeilSwitchTableAnalyzerTest extends AbstractGenericTest {

	private static final String CCASE_BODY =
		"d0 83 d0 82 f8 e4 93 70 12 74 01 93 70 0d a3 a3 93 f8 74 01 93 f5 82 88 83 e4 73 " +
			"74 02 93 68 60 ef a3 a3 a3 80 df";

	/** LCALL 0xc176, then the ten-case table; default 0x8b2b. */
	private static final String CALL_AND_TABLE =
		"12 c1 76 8b 29 00 8b 29 03 88 36 04 89 95 05 88 61 08 88 9c 17 88 f8 18 " +
			"8b 0e 1b 88 40 1c 8b 1d 1e 00 00 8b 2b";

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("hub", ProgramBuilder._8051);
		builder.createMemory("CODE", "0x8000", 0x6312);
		builder.setBytes("0xc176", CCASE_BODY);
		builder.setBytes("0x8811", CALL_AND_TABLE);
		// RET at every case target, so disassembling them has something to land on.
		for (String target : new String[] { "0x8b29", "0x8836", "0x8995", "0x8861", "0x889c",
			"0x88f8", "0x8b0e", "0x8840", "0x8b1d", "0x8b2b" }) {
			builder.setBytes(target, "22");
		}
		// Deliberately NOT disassembled: on the real image nothing reaches this call site, which is
		// exactly the case the analyzer has to handle.
		program = builder.getProgram();
	}

	private boolean analyze() throws Exception {
		int txId = program.startTransaction("keil switch tables");
		try {
			return new KeilSwitchTableAnalyzer().added(program, new AddressSet(),
				TaskMonitor.DUMMY, new MessageLog());
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void recoversEveryCaseTargetAndTheDefault() throws Exception {
		assertTrue("the hub switch must be recognised", analyze());

		Set<Address> jumps = new HashSet<>();
		for (Reference ref : program.getReferenceManager()
				.getReferencesFrom(builder.addr("0x8811"))) {
			if (ref.getReferenceType() == RefType.COMPUTED_JUMP) {
				jumps.add(ref.getToAddress());
			}
		}

		// ten cases, but 0x8b29 is the target of two of them, plus the default
		assertEquals(10, jumps.size());
		assertTrue("case 0x04 target", jumps.contains(builder.addr("0x8836")));
		assertTrue("case 0x1e target", jumps.contains(builder.addr("0x8b1d")));
		assertTrue("default target", jumps.contains(builder.addr("0x8b2b")));
	}

	@Test
	public void recoversASiteThatFlowNeverReached() throws Exception {
		assertNull("precondition: nothing has disassembled the call site",
			program.getListing().getInstructionAt(builder.addr("0x8811")));

		assertTrue(analyze());

		assertNotNull("the call site itself must end up disassembled",
			program.getListing().getInstructionAt(builder.addr("0x8811")));
		assertNotNull("and its case targets with it",
			program.getListing().getInstructionAt(builder.addr("0x8b1d")));
	}

	@Test
	public void recoversASiteFlowAlreadyReached() throws Exception {
		builder.disassemble("0x8811", 3);

		assertTrue(analyze());
		assertEquals(10, countJumpRefs());
	}

	@Test
	public void callDoesNotFallThroughIntoItsOwnTable() throws Exception {
		analyze();

		Instruction call = program.getListing().getInstructionAt(builder.addr("0x8811"));
		assertNotNull(call);
		assertNull("the helper never returns, so the table must not be reached by fall-through",
			call.getFallThrough());
	}

	@Test
	public void tableIsDefinedAsDataAndCommented() throws Exception {
		analyze();

		assertNotNull("table must be data, not stray instructions",
			program.getListing().getDefinedDataAt(builder.addr("0x8814")));
		assertNotNull("last of the ten entries",
			program.getListing().getDefinedDataAt(builder.addr("0x882f")));
		assertNotNull("zero terminator",
			program.getListing().getDefinedDataAt(builder.addr("0x8832")));
		assertNotNull("default target",
			program.getListing().getDefinedDataAt(builder.addr("0x8834")));

		String plate = program.getListing().getComment(CommentType.PLATE, builder.addr("0x8814"));
		assertNotNull(plate);
		assertTrue(plate.contains("?C?CCASE"));
		assertTrue(plate.contains("10 case"));
	}

	@Test
	public void helperIsNamedAsTheKeilLibraryRoutine() throws Exception {
		analyze();

		assertEquals(KeilCaseHelper.CCASE.label(),
			program.getSymbolTable().getPrimarySymbol(builder.addr("0xc176")).getName());
	}

	/**
	 * The decompiler must not read the inline case table as code.
	 * <p>
	 * Fixing the listing is not enough. On the real image, with the fall-through cleared and every
	 * case reference in place, the decompiler still treated {@code keil_ccase_switch} as a call
	 * that returns and decoded the table bytes at 0x8814 as instructions —
	 * {@code nop(); UNK_SFR_95 = uVar2; TCON = cVar1 + '\x01'; ...} — because it ignores the
	 * listing's fall-through and never reached a switch at all. That went unnoticed because no
	 * function contained 0x8811 to decompile: its entry, 0x8800, is reached only indirectly.
	 * <p>
	 * The check is on addresses rather than on which garbage appears: no p-code in the decompiled
	 * function may come from inside the table.
	 */
	@Test
	public void theDecompilerDoesNotReadTheCaseTableAsCode() throws Exception {
		// The real prologue at 0x8800: load the switch value and parameters from IDATA, then the
		// LCALL ?C?CCASE at 0x8811 that setUp already placed.
		builder.setBytes("0x8800", "ac 6e 85 6c 48 aa 6f e4 f9 ec 75 4a 00 f5 49 e5 48");
		assertTrue(analyze());
		builder.disassemble("0x8800", 0x14);

		int txId = program.startTransaction("function");
		try {
			new ghidra.app.cmd.function.CreateFunctionCmd("switch_function", builder.addr("0x8800"),
				null, SourceType.ANALYSIS).applyTo(program, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		Address tableStart = builder.addr("0x8814");
		Address tableEnd = builder.addr("0x8836");      // exclusive: 0x8836 is case 0x04's body
		ghidra.app.decompiler.DecompInterface decompiler =
			new ghidra.app.decompiler.DecompInterface();
		try {
			assertTrue(decompiler.openProgram(program));
			var results = decompiler.decompileFunction(
				program.getFunctionManager().getFunctionAt(builder.addr("0x8800")), 30,
				TaskMonitor.DUMMY);
			assertTrue(results.decompileCompleted());

			List<Address> fromTable = new ArrayList<>();
			var ops = results.getHighFunction().getPcodeOps();
			while (ops.hasNext()) {
				Address at = ops.next().getSeqnum().getTarget();
				if (at.compareTo(tableStart) >= 0 && at.compareTo(tableEnd) < 0) {
					fromTable.add(at);
				}
			}
			assertTrue("the case table was decompiled as code, at " + fromTable + ":\n" +
				results.getDecompiledFunction().getC(), fromTable.isEmpty());
		}
		finally {
			decompiler.dispose();
		}
	}

	@Test
	public void rerunIsIdempotent() throws Exception {
		analyze();
		int first = countJumpRefs();
		analyze();
		assertEquals("a one-shot re-run must not duplicate anything", first, countJumpRefs());
	}

	private int countJumpRefs() {
		int count = 0;
		for (Reference ref : program.getReferenceManager()
				.getReferencesFrom(builder.addr("0x8811"))) {
			if (ref.getReferenceType() == RefType.COMPUTED_JUMP) {
				count++;
			}
		}
		return count;
	}
}
