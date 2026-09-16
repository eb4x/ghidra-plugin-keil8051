package ebbex.keil8051;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;

/**
 * Tests for {@link KeilCaseTable}, the table shape all three Keil case helpers share.
 * <p>
 * The {@code char} case is the real table at {@code 0x8814} in the GL3523 L2 hub firmware — the
 * one the switch analyzer was written against — so the parser is measured against bytes a compiler
 * actually emitted, not against a hand-made ideal.
 */
public class KeilCaseTableTest extends AbstractGenericTest {

	/** The GL3523 L2 hub table at CODE:8814: ten cases, default 0x8b2b. */
	private static final String HUB_CCASE_TABLE =
		"8b 29 00 8b 29 03 88 36 04 89 95 05 88 61 08 88 9c 17 88 f8 18 8b 0e 1b " +
			"88 40 1c 8b 1d 1e 00 00 8b 2b";

	private ProgramBuilder builder(String at, String bytes) throws Exception {
		ProgramBuilder builder = new ProgramBuilder("keil", ProgramBuilder._8051);
		builder.createMemory("CODE", "0x8000", 0x6000);
		builder.setBytes(at, bytes);
		return builder;
	}

	@Test
	public void ccaseTableFromRealFirmwareParses() throws Exception {
		ProgramBuilder builder = builder("0x8814", HUB_CCASE_TABLE);
		Program program = builder.getProgram();

		KeilCaseTable table =
			KeilCaseTable.parse(program.getMemory(), KeilCaseHelper.CCASE, builder.addr("0x8814"));

		assertNotNull("real CCASE table must parse", table);
		assertEquals(10, table.cases().size());
		assertEquals(builder.addr("0x8b2b"), table.defaultTarget());
		assertEquals("10 entries of 3 bytes plus the 4-byte terminator", 34, table.length());
		assertEquals(builder.addr("0x8836"), table.end());

		// target first, value second -- the ordering that makes this format easy to get backwards
		assertEquals(0x00, table.cases().get(0).value());
		assertEquals(builder.addr("0x8b29"), table.cases().get(0).target());
		assertEquals(0x04, table.cases().get(2).value());
		assertEquals(builder.addr("0x8836"), table.cases().get(2).target());
		assertEquals(0x1e, table.cases().get(9).value());
		assertEquals(builder.addr("0x8b1d"), table.cases().get(9).target());
	}

	@Test
	public void icaseUsesTwoByteValuesAndFourByteEntries() throws Exception {
		ProgramBuilder builder =
			builder("0x9000", "90 10 01 00 90 20 12 34 00 00 90 30");
		Program program = builder.getProgram();

		KeilCaseTable table =
			KeilCaseTable.parse(program.getMemory(), KeilCaseHelper.ICASE, builder.addr("0x9000"));

		assertNotNull(table);
		assertEquals(2, table.cases().size());
		assertEquals(0x0100, table.cases().get(0).value());
		assertEquals(builder.addr("0x9010"), table.cases().get(0).target());
		assertEquals(0x1234, table.cases().get(1).value());
		assertEquals(builder.addr("0x9020"), table.cases().get(1).target());
		assertEquals(builder.addr("0x9030"), table.defaultTarget());
		assertEquals(12, table.length());
	}

	@Test
	public void lcaseUsesFourByteValuesAndSixByteEntries() throws Exception {
		ProgramBuilder builder =
			builder("0x9000", "90 10 00 00 01 00 00 00 90 20");
		Program program = builder.getProgram();

		KeilCaseTable table =
			KeilCaseTable.parse(program.getMemory(), KeilCaseHelper.LCASE, builder.addr("0x9000"));

		assertNotNull(table);
		assertEquals(1, table.cases().size());
		assertEquals(0x00000100L, table.cases().get(0).value());
		assertEquals(builder.addr("0x9020"), table.defaultTarget());
		assertEquals(10, table.length());
	}

	@Test
	public void targetOutsideLoadedCodeIsNotATable() throws Exception {
		// 0x2000 is below the block: bytes that merely look like an entry must be refused.
		ProgramBuilder builder = builder("0x9000", "20 00 01 00 00 90 20");
		Program program = builder.getProgram();

		assertNull(KeilCaseTable.parse(program.getMemory(), KeilCaseHelper.CCASE,
			builder.addr("0x9000")));
	}

	@Test
	public void terminatorWithNoCasesIsNotATable() throws Exception {
		ProgramBuilder builder = builder("0x9000", "00 00 90 20");
		Program program = builder.getProgram();

		assertNull(KeilCaseTable.parse(program.getMemory(), KeilCaseHelper.CCASE,
			builder.addr("0x9000")));
	}
}
