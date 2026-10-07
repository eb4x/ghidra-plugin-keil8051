package ebbex.keil8051;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link KeilJumpTable} on its own: the dispatch scan, the range check, the default and
 * the {@code AJMP} decode, without the analyzer around them.
 * <p>
 * The bytes are the synthetic smoke sample's (src/test/smoke/smoke-m2.asm), not a vendor image.
 */
public class KeilJumpTableTest extends AbstractGenericTest {

	/**
	 * CODE:0080 — CJNE A,#3 / JC / LJMP 0x009d / MOV DPTR,#0x008e / ADD A,ACC / JMP @A+DPTR, then
	 * three AJMP slots to 0x94, 0x97 and 0x9a.
	 */
	private static final String LJMP_DEFAULT =
		"b4 03 00 40 03 02 00 9d 90 00 8e 25 e0 73 01 94 01 97 01 9a";

	/** The same switch guarded with JNC, which branches to the default itself (0x0091). */
	private static final String JNC_DEFAULT =
		"b4 03 00 50 0c 90 00 8b 25 e0 73 01 94 01 97 01 9a";

	private ProgramBuilder builder;

	private Program program(String at, String bytes) throws Exception {
		builder = new ProgramBuilder("smoke", ProgramBuilder._8051);
		builder.createMemory("CODE", "0x0000", 0x1000);
		builder.setBytes(at, bytes);
		return builder.getProgram();
	}

	private List<Address> addrs(long... offsets) {
		return java.util.Arrays.stream(offsets).mapToObj(builder::addr).toList();
	}

	@Test
	public void readsTheBoundTheTableAndAnLjmpDefault() throws Exception {
		List<KeilJumpTable> tables =
			KeilJumpTable.findAll(program("0x80", LJMP_DEFAULT), TaskMonitor.DUMMY);

		assertEquals(1, tables.size());
		KeilJumpTable table = tables.get(0);
		assertEquals(builder.addr(0x88), table.dispatch());
		assertEquals(builder.addr(0x8d), table.jump());
		assertEquals(builder.addr(0x8e), table.address());
		assertEquals(3, table.bound());
		assertEquals(0, table.caseBias());
		assertEquals(builder.addr(0x9d), table.defaultTarget());
		assertEquals(addrs(0x94, 0x97, 0x9a),
			table.entries().stream().map(KeilJumpTable.Entry::target).toList());
		assertEquals(builder.addr(0x94), table.end());
	}

	@Test
	public void aJncRangeCheckBranchesToTheDefault() throws Exception {
		List<KeilJumpTable> tables =
			KeilJumpTable.findAll(program("0x80", JNC_DEFAULT), TaskMonitor.DUMMY);

		assertEquals(1, tables.size());
		assertEquals(builder.addr(0x91), tables.get(0).defaultTarget());
	}

	@Test
	public void aSlotThatIsNotAnAjmpRejectsTheWholeTable() throws Exception {
		Program program = program("0x80", LJMP_DEFAULT);
		Address table = builder.addr(0x8e);

		assertNotNull(KeilJumpTable.parse(program.getMemory(), builder.addr(0x88),
			builder.addr(0x8d), table, 3));
		assertNull("slot 3 is MOV R2,#0x20, so a bound of 4 overreads the table",
			KeilJumpTable.parse(program.getMemory(), builder.addr(0x88), builder.addr(0x8d), table,
				4));
	}

	@Test
	public void anAjmpTakesItsPageFromTheFollowingInstruction() throws Exception {
		// AJMP at 0x07fe: the next instruction is at 0x0800, so 01 10 lands at 0x0810, not 0x0010.
		Program program = program("0x7fe", "01 10");

		KeilJumpTable table = KeilJumpTable.parse(program.getMemory(), builder.addr(0x7f0),
			builder.addr(0x7fd), builder.addr(0x7fe), 1);

		assertEquals(builder.addr(0x810), table.entries().get(0).target());
	}
}
