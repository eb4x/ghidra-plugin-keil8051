package ebbex.keil8051;

import static org.junit.Assert.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
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

	/** Recovers, disassembles, creates a function and runs the override pass on a program. */
	private static void recoverAndOverride(ProgramBuilder b, String entry, int length)
			throws Exception {
		Program p = b.getProgram();
		int txId = p.startTransaction("recover");
		try {
			new KeilJumpTableAnalyzer().added(p, new AddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			p.endTransaction(txId, true);
		}
		b.disassemble(entry, length);
		txId = p.startTransaction("function and override");
		try {
			new ghidra.app.cmd.function.CreateFunctionCmd("dispatch", b.addr(entry), null,
				SourceType.ANALYSIS).applyTo(p, TaskMonitor.DUMMY);
			// ProgramBuilder.disassemble runs auto-analysis: the override pass under test must not
			// already have run there.
			Function function = p.getFunctionManager().getFunctionAt(b.addr(entry));
			assertNull("precondition: no override before the pass runs",
				p.getSymbolTable().getNamespace("override", function));
			new KeilSwitchOverrideAnalyzer().added(p, new AddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			p.endTransaction(txId, true);
		}
	}

	private static boolean hasOverride(Program p, Address branch) {
		SymbolTable symbols = p.getSymbolTable();
		Namespace function = (Namespace) p.getFunctionManager().getFunctionContaining(branch);
		Namespace overrides = symbols.getNamespace("override", function);
		return overrides != null && symbols.getNamespace("jmp_" + branch, overrides) != null;
	}

	/**
	 * The override mechanics, on the one shape that always needs them.
	 * <p>
	 * The page-carry shape ({@code JNC $+2; INC DPH} between {@code ADD A,ACC} and
	 * {@code JMP @A+DPTR}) makes the table base a branch-dependent select, and no Ghidra — stock
	 * or carrying the CJNE guard fix — recovers it ("too many branches"). So an override is
	 * written whatever SDK this runs against, which is what makes this test deterministic.
	 */
	@Test
	public void writesAnOverrideWhereTheDecompilerCannotRecoverTheTable() throws Exception {
		ProgramBuilder self = new ProgramBuilder("pagecarry", ProgramBuilder._8051);
		self.createMemory("CODE", "0x9000", 0x100);
		// DEC A / CJNE A,#2 / JC / AJMP default / MOV DPTR,#0x9012 / ADD A,ACC / JNC $+2 /
		// INC DPH / JMP @A+DPTR / two AJMP slots / RET bodies for both cases and the default
		self.setBytes("0x9000",
			"14 b4 02 00 40 02 01 17 90 90 12 25 e0 50 02 05 83 73 01 16 01 18 22 22 22");
		recoverAndOverride(self, "0x9000", 18);

		assertTrue("nothing recovers the page-carry shape, so the override must be written",
			hasOverride(self.getProgram(), self.addr("0x9011")));
	}

	/**
	 * The plain shape, tested so it holds against any SDK.
	 * <p>
	 * Whether this table needs an override depends on the Ghidra underneath: stock Ghidra does
	 * not read {@code CJNE #n / JC} as a bound and fabricates cases, so an override is written;
	 * a Ghidra carrying the guard fix recovers it and the analyzer stands aside, because an
	 * override would render it worse. Which path is taken is not the point. The property is that
	 * afterwards the decompiler recovers exactly this table.
	 */
	@Test
	public void thePlainShapeEndsUpRecoveredExactlyWhicheverPathIsTaken() throws Exception {
		ProgramBuilder self = new ProgramBuilder("plain", ProgramBuilder._8051);
		self.createMemory("CODE", "0x9000", 0x100);
		//     CJNE A,#2 / JC / AJMP default / MOV DPTR,#0x900d / ADD A,ACC / JMP @A+DPTR
		//     then two AJMP entries, their RET bodies, and the default's RET.
		self.setBytes("0x9000", "b4 02 00 40 02 01 15 90 90 0d 25 e0 73 01 11 01 13 22 00 22 00 22");
		recoverAndOverride(self, "0x9000", 13);

		Program tiny = self.getProgram();
		Address branch = self.addr("0x900c");
		ghidra.app.decompiler.DecompInterface decompiler =
			new ghidra.app.decompiler.DecompInterface();
		try {
			assertTrue(decompiler.openProgram(tiny));
			var results = decompiler.decompileFunction(
				tiny.getFunctionManager().getFunctionContaining(branch), 30, TaskMonitor.DUMMY);
			assertTrue(results.decompileCompleted());

			ghidra.program.model.pcode.JumpTable recovered = null;
			for (var table : results.getHighFunction().getJumpTables()) {
				if (branch.equals(table.getSwitchAddress())) {
					recovered = table;
				}
			}
			assertNotNull("the decompiler must recover a table at the branch", recovered);
			assertTrue("and it must be exactly this table, plus at most the default",
				KeilSwitchOverrideAnalyzer.matchesTable(List.of(recovered.getCases()),
					List.of(self.addr("0x900d"), self.addr("0x900f"))));
		}
		finally {
			decompiler.dispose();
		}
	}

	/**
	 * The GL3523 L2 hub switch at {@code 0xbcbf}, reported by `hp-z27k-g3` as missed. Two things
	 * differ from the plain shape: {@code DEC A} before the bound, so slot 0 is case 1; and Keil's
	 * page-carry fix-up {@code JNC $+2; INC DPH} between {@code ADD A,ACC} and {@code JMP @A+DPTR},
	 * which broke a matcher that assumed those two were adjacent. The fix-up is dead here
	 * (2 * 27 = 54, no carry) but present in the bytes, which is exactly why matching on the bytes
	 * has to allow for it.
	 */
	@Test
	public void recoversTheVariantWithAPageCarryFixup() throws Exception {
		ProgramBuilder hub = new ProgramBuilder("hub2", ProgramBuilder._8051);
		hub.createMemory("CODE", "0x8000", 0x6312);
		// MOV A,R7 / DEC A / CJNE A,#0x1c / JC / AJMP default / MOV DPTR,#0xbcc0 / ADD A,ACC /
		// JNC $+2 / INC DPH / JMP @A+DPTR
		hub.setBytes("0xbcad", "ef 14 b4 1c 00 40 02 a1 4c 90 bc c0 25 e0 50 02 05 83 73");
		hub.setBytes("0xbcc0",
			"81 f8 81 fb a1 4c 81 fe a1 01 a1 04 a1 07 a1 0a a1 0d a1 10 a1 13 a1 16 " +
				"a1 1c a1 22 a1 25 a1 28 a1 2b a1 2e a1 33 a1 3a a1 3d a1 4c a1 1f a1 40 " +
				"a1 43 a1 19 a1 46 a1 49");
		Program hubProgram = hub.getProgram();

		int txId = hubProgram.startTransaction("keil ajmp tables");
		try {
			assertTrue("the page-carry variant must be recognised",
				new KeilJumpTableAnalyzer().added(hubProgram, new AddressSet(), TaskMonitor.DUMMY,
					new MessageLog()));
		}
		finally {
			hubProgram.endTransaction(txId, true);
		}

		int refs = 0;
		for (Reference ref : hubProgram.getReferenceManager()
				.getReferencesFrom(hub.addr("0xbcbf"))) {
			if (ref.getReferenceType().isComputed()) {
				refs++;
			}
		}
		assertEquals("CJNE A,#0x1c bounds this at 28 entries", 28, refs);

		KeilJumpTable table = KeilJumpTable.findAll(hubProgram, TaskMonitor.DUMMY).get(0);
		assertEquals(hub.addr("0xbcbf"), table.jump());
		assertEquals(hub.addr("0xbcc0"), table.address());
		assertEquals("table ends where the first case target begins",
			hub.addr("0xbcf8"), table.end());
		assertEquals("DEC A means slot 0 is case 1", 1, table.caseBias());
		assertEquals("0xbcb4: AJMP a1 4c -> 0xbd4c", hub.addr("0xbd4c"), table.defaultTarget());
		assertEquals(1, table.entries().get(0).caseValue());
		assertEquals(28, table.entries().get(27).caseValue());

		// Entries mix pages 0xbc and 0xbd; AJMP takes its page from the FOLLOWING instruction.
		assertEquals(hub.addr("0xbcf8"), table.entries().get(0).target());
		assertEquals("a case that jumps to the default target like any other",
			hub.addr("0xbd4c"), table.entries().get(2).target());
		assertEquals(hub.addr("0xbd49"), table.entries().get(27).target());
	}

	/**
	 * A branch the stock analyzer already processed correctly.
	 * <p>
	 * References are identified by (from, to, type, <b>operand index</b>), so adding one that
	 * differs only in operand index does not replace the existing reference — it adds a second to
	 * the same target. On the GL3523 L2 hub's 0xa81c, `hp-z27k-g3` found every one of the 8 slots
	 * listed twice for exactly that reason. Harmless to the decompiler, which reads the override,
	 * but it doubles xref and caller counts for anyone reading them.
	 */
	@Test
	public void doesNotDoubleReferencesTheBranchAlreadyHas() throws Exception {
		// The stock analyzer's refs: correct targets, but recorded against the mnemonic.
		int txId = program.startTransaction("stock refs");
		try {
			builder.disassemble("0xbd5d", 13);
			for (String slot : new String[] { "0xbd6b", "0xbd6d", "0xbd6f", "0xbd71", "0xbd73",
				"0xbd75", "0xbd77", "0xbd79", "0xbd7b" }) {
				program.getReferenceManager().addMemoryReference(builder.addr("0xbd6a"),
					builder.addr(slot), RefType.COMPUTED_JUMP, SourceType.ANALYSIS,
					ghidra.program.model.listing.CodeUnit.MNEMONIC);
			}
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertEquals("precondition", 9, countBd6aComputedRefs());

		analyze();

		assertEquals("each slot must still be referenced exactly once", 9, countBd6aComputedRefs());
	}

	private int countBd6aComputedRefs() {
		int count = 0;
		for (Reference ref : program.getReferenceManager()
				.getReferencesFrom(builder.addr("0xbd6a"))) {
			if (ref.getReferenceType().isComputed()) {
				count++;
			}
		}
		return count;
	}

	@Test
	public void recordsTheDefaultTargetFromTheJumpAfterTheRangeCheck() throws Exception {
		KeilJumpTable table = KeilJumpTable.findAll(program, TaskMonitor.DUMMY).get(0);

		// 0xbd63: AJMP a1 ee, next instruction 0xbd65, page 0xb800 -> 0xbdee
		assertEquals(builder.addr("0xbdee"), table.defaultTarget());

		analyze();
		String plate = program.getListing().getComment(CommentType.PLATE, builder.addr("0xbd6b"));
		assertTrue(plate, plate.contains("default CODE:bdee"));
	}

	/**
	 * GL3523 L2 hub, 0xa81c: the default's AJMP ({@code 21 04} at 0xa815) goes to 0xa904 — as
	 * Ghidra's own disassembly shows. By hand it is easy to get 0xa104 instead: the page is taken
	 * from the <i>following</i> instruction, and {@code 0xa817 & 0xf800} is {@code 0xa800}, not
	 * {@code 0xa000}. The decompiler, for its part, reports this default as 0xa815, the address of
	 * the jump rather than its destination, because the destination lies outside the function.
	 */
	@Test
	public void decodesTheDefaultWithTheFollowingInstructionsPage() throws Exception {
		ProgramBuilder hub = new ProgramBuilder("a81c", ProgramBuilder._8051);
		hub.createMemory("CODE", "0x8000", 0x6312);
		// MOV A,@R0 / CJNE A,#8 / JC / AJMP default / MOV DPTR,#0xa81d / ADD A,ACC / JMP @A+DPTR,
		// then the real eight-slot table
		hub.setBytes("0xa80f", "e6 b4 08 00 40 02 21 04 90 a8 1d 25 e0 73");
		hub.setBytes("0xa81d", "01 fe 01 2d 01 38 01 97 01 f6 01 73 01 81 01 8c");

		KeilJumpTable table = KeilJumpTable.findAll(hub.getProgram(), TaskMonitor.DUMMY).get(0);

		assertEquals(8, table.entries().size());
		assertEquals("the destination, not the jump at 0xa815, and not 0xa104",
			hub.addr("0xa904"), table.defaultTarget());
		assertEquals(hub.addr("0xa8fe"), table.entries().get(0).target());
	}

	@Test
	public void rerunIsIdempotent() throws Exception {
		analyze();
		int first = computedJumps().size();
		analyze();
		assertEquals(first, computedJumps().size());
	}
}
