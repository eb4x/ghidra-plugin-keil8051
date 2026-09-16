package ebbex.keil8051;

import static org.junit.Assert.*;

import java.util.HashSet;
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
		builder.disassemble("0x8811", 3);
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
