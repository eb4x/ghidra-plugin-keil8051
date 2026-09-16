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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link KeilJumpTableAnalyzer} on the real dispatch in the GL3523 L2 hub firmware's
 * {@code vendor_req_A1_isp_mode_switch} at {@code 0xbd4f}.
 * <p>
 * This is the switch Ghidra's own analysis turns into 129 cases. Nine is the answer, and the bytes
 * say so: {@code CJNE A,#0x09} is the compiler's own range check.
 */
public class KeilJumpTableAnalyzerTest extends AbstractGenericTest {

	/**
	 * From CODE:bd5d — MOV A,R6 / CJNE A,#9 / JC / AJMP default / MOV DPTR,#0xbd6b / ADD A,ACC /
	 * JMP @A+DPTR, then the nine-entry AJMP table and the SJMP that follows it.
	 */
	private static final String DISPATCH_AND_TABLE =
		"ee b4 09 00 40 02 a1 ee 90 bd 6b 25 e0 73 " +
			"a1 7d a1 7f a1 ee a1 a2 a1 ee a1 aa a1 b2 a1 c6 a1 d3 80 60";

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("hub", ProgramBuilder._8051);
		builder.createMemory("CODE", "0x8000", 0x6312);
		builder.setBytes("0xbd5d", DISPATCH_AND_TABLE);
		program = builder.getProgram();
	}

	private boolean analyze() throws Exception {
		int txId = program.startTransaction("keil ajmp tables");
		try {
			return new KeilJumpTableAnalyzer().added(program, new AddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private Set<Address> computedJumps() {
		Set<Address> jumps = new HashSet<>();
		for (Reference ref : program.getReferenceManager().getReferencesFrom(builder.addr("0xbd6a"))) {
			if (ref.getReferenceType().isComputed()) {
				jumps.add(ref.getToAddress());
			}
		}
		return jumps;
	}

	@Test
	public void recoversExactlyTheNineCasesTheBoundAllows() throws Exception {
		assertTrue("the hub dispatch must be recognised", analyze());

		Set<Address> jumps = computedJumps();
		assertEquals("CJNE A,#0x09 bounds this table at nine entries", 9, jumps.size());
		assertTrue("first entry", jumps.contains(builder.addr("0xbd6b")));
		assertTrue("last entry", jumps.contains(builder.addr("0xbd7b")));
		assertFalse("0xbd7d is the SJMP after the table, not a case",
			jumps.contains(builder.addr("0xbd7d")));
	}

	@Test
	public void decodesAjmpTargetsWithinTheirOwnPage() throws Exception {
		analyze();

		KeilJumpTable table = KeilJumpTable.parse(program.getMemory(), builder.addr("0xbd65"),
			builder.addr("0xbd6a"), builder.addr("0xbd6b"), 9);

		assertNotNull(table);
		// AJMP takes address bits 10-8 from the opcode and the rest of the page from the next PC.
		assertEquals(builder.addr("0xbd7d"), table.entries().get(0).target());
		assertEquals(builder.addr("0xbdee"), table.entries().get(2).target());
		assertEquals(builder.addr("0xbdd3"), table.entries().get(8).target());
		assertEquals(18, table.length());
		assertEquals(builder.addr("0xbd7d"), table.end());
	}

	@Test
	public void casesAreNumberedByIndexNotByByteOffset() throws Exception {
		analyze();

		assertEquals("caseD_1", program.getSymbolTable()
			.getPrimarySymbol(builder.addr("0xbd6d")).getName());
	}

	@Test
	public void commentsTheTableWithTheBoundItUsed() throws Exception {
		analyze();

		String plate = program.getListing().getComment(CommentType.PLATE, builder.addr("0xbd6b"));
		assertNotNull(plate);
		assertTrue(plate, plate.contains("9 case(s)"));
		assertTrue(plate, plate.contains("0x9"));
	}

	@Test
	public void removesCasesTheStockAnalyzerFabricatedPastTheTable() throws Exception {
		// What Ghidra leaves behind: a computed jump to an address well past the real table.
		Address bogus = builder.addr("0xbe05");
		int txId = program.startTransaction("fabricate");
		try {
			program.getReferenceManager().addMemoryReference(builder.addr("0xbd6a"), bogus,
				RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		analyze();

		assertFalse("a target past the bound is not a case", computedJumps().contains(bogus));
		assertEquals(9, computedJumps().size());
	}

	@Test
	public void leavesADispatchWithNoReadableBoundAlone() throws Exception {
		ProgramBuilder other = new ProgramBuilder("nobound", ProgramBuilder._8051);
		other.createMemory("CODE", "0x8000", 0x1000);
		// The dispatch, but with no CJNE/JC range check in front of it.
		other.setBytes("0x8100", "00 00 00 00 00 00 00 90 81 10 25 e0 73 a1 20 a1 22");
		Program plain = other.getProgram();

		int txId = plain.startTransaction("keil ajmp tables");
		try {
			assertFalse("without the compiler's own bound there is nothing to trust",
				new KeilJumpTableAnalyzer().added(plain, new AddressSet(), TaskMonitor.DUMMY,
					new MessageLog()));
		}
		finally {
			plain.endTransaction(txId, true);
		}
	}

	/**
	 * The override is what actually silences the decompiler, so it is tested on a self-contained
	 * dispatch whose flow closes — the real hub bytes reach code this fixture does not contain, and
	 * without a function body around the branch there is nowhere for Ghidra to store an override.
	 */
	@Test
	public void writesADecompilerOverrideSoTheDecompilerStopsGuessing() throws Exception {
		ProgramBuilder self = new ProgramBuilder("selfcontained", ProgramBuilder._8051);
		self.createMemory("CODE", "0x9000", 0x100);
		//     CJNE A,#2 / JC / AJMP default / MOV DPTR,#0x900d / ADD A,ACC / JMP @A+DPTR
		//     then two AJMP entries, their RET bodies, and the default's RET.
		self.setBytes("0x9000", "b4 02 00 40 02 01 15 90 90 0d 25 e0 73 01 11 01 13 22 00 22 00 22");
		Program tiny = self.getProgram();

		int txId = tiny.startTransaction("recover and override");
		try {
			assertTrue(new KeilJumpTableAnalyzer().added(tiny, new AddressSet(), TaskMonitor.DUMMY,
				new MessageLog()));
		}
		finally {
			tiny.endTransaction(txId, true);
		}
		self.disassemble("0x9000", 13);
		txId = tiny.startTransaction("function and override");
		try {
			new ghidra.app.cmd.function.CreateFunctionCmd("dispatch", self.addr("0x9000"), null,
				SourceType.ANALYSIS).applyTo(tiny, TaskMonitor.DUMMY);
			assertNotNull("precondition: the branch must sit inside a function",
				tiny.getFunctionManager().getFunctionContaining(self.addr("0x900c")));

			assertTrue("an override must be written for the recovered table",
				new KeilSwitchOverrideAnalyzer().added(tiny, new AddressSet(), TaskMonitor.DUMMY,
					new MessageLog()));
		}
		finally {
			tiny.endTransaction(txId, true);
		}

		// Ghidra stores an override purely as symbols under <func>::override::jmp_<branch>.
		SymbolTable symbols = tiny.getSymbolTable();
		Namespace function = (Namespace) tiny.getFunctionManager()
			.getFunctionContaining(self.addr("0x900c"));
		Namespace overrides = symbols.getNamespace("override", function);
		assertNotNull("override namespace", overrides);
		assertNotNull("the decompiler reads the table back from jmp_<branch>",
			symbols.getNamespace("jmp_" + self.addr("0x900c"), overrides));
	}

	@Test
	public void rerunIsIdempotent() throws Exception {
		analyze();
		int first = computedJumps().size();
		analyze();
		assertEquals(first, computedJumps().size());
	}
}
