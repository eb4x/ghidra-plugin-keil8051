package ebbex.keil8051;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for {@link Keil8051VectorAnalyzer}.
 * <p>
 * The image is based at {@code 0x8000}, as the GL3523 hub firmware is, because the whole point of
 * the analyzer is that the vector offsets are relative to where the image was loaded — an analyzer
 * that hardcoded absolute {@code 0x0000} would pass a base-0 test and find nothing real.
 */
public class Keil8051VectorAnalyzerTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("fw", ProgramBuilder._8051);
		builder.createMemory("CODE", "0x8000", 0x1000);
		builder.setBytes("0x8000", "02 90 00");          // reset:      LJMP 0x9000
		builder.setBytes("0x8003", "02 90 10");          // ext0:       LJMP 0x9010
		builder.setBytes("0x800b", "00 00 00");          // timer0:     unused, zero fill
		builder.setBytes("0x8013", "ff ff ff");          // ext1:       unused, 0xff fill
		builder.setBytes("0x801b", "32");                // timer1:     RETI
		builder.setBytes("0x9000", "22");
		builder.setBytes("0x9010", "22");
		program = builder.getProgram();
	}

	private boolean analyze() throws Exception {
		int txId = program.startTransaction("8051 vectors");
		try {
			return new Keil8051VectorAnalyzer().added(program, new AddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void seedsResetAndUsedVectorsRelativeToTheImageBase() throws Exception {
		assertTrue(analyze());

		assertNotNull("reset at the image base",
			program.getFunctionManager().getFunctionAt(builder.addr("0x8000")));
		assertNotNull("first interrupt vector at base+3",
			program.getFunctionManager().getFunctionAt(builder.addr("0x8003")));
		assertNotNull("a RETI-only vector is still a real handler",
			program.getFunctionManager().getFunctionAt(builder.addr("0x801b")));
	}

	@Test
	public void namesTheClassicVectors() throws Exception {
		analyze();

		assertEquals("reset",
			program.getFunctionManager().getFunctionAt(builder.addr("0x8000")).getName());
		assertEquals("int_ext0",
			program.getFunctionManager().getFunctionAt(builder.addr("0x8003")).getName());
	}

	@Test
	public void skipsFilledVectorSlots() throws Exception {
		analyze();

		assertNull("0x00 fill is an unused slot",
			program.getFunctionManager().getFunctionAt(builder.addr("0x800b")));
		assertNull("0xff fill is an unused slot",
			program.getFunctionManager().getFunctionAt(builder.addr("0x8013")));
	}

	/**
	 * The USB-PD payload in the MStar image begins {@code MOV A,#5; MOVX @DPTR,A} — it is called,
	 * not reset into, and the bytes where its vectors would be are ordinary code. Seeding them
	 * would invent entry points and name them after interrupts they have nothing to do with.
	 */
	@Test
	public void doesNotInventVectorsInAModuleThatHasNone() throws Exception {
		ProgramBuilder payload = new ProgramBuilder("payload", ProgramBuilder._8051);
		payload.createMemory("CODE", "0x0000", 0x100);
		payload.setBytes("0x0000", "74 05 f0 e4 a3 f0 7f c0 12 d1 08 22");
		Program module = payload.getProgram();

		int txId = module.startTransaction("8051 vectors");
		try {
			new Keil8051VectorAnalyzer().added(module, new AddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			module.endTransaction(txId, true);
		}

		assertNotNull("code does start at the module base, so that much is seeded",
			module.getFunctionManager().getFunctionAt(payload.addr("0x0000")));
		assertEquals("and it is not called 'reset', which would assert a vector table",
			"entry", module.getFunctionManager().getFunctionAt(payload.addr("0x0000")).getName());
		assertNull("0x0003 is mid-instruction here, not a vector",
			module.getFunctionManager().getFunctionAt(payload.addr("0x0003")));
		assertNull("nor is 0x000b",
			module.getFunctionManager().getFunctionAt(payload.addr("0x000b")));
	}

	@Test
	public void theGuardIsAnOptionForWhenReachMattersMore() throws Exception {
		ProgramBuilder payload = new ProgramBuilder("payload", ProgramBuilder._8051);
		payload.createMemory("CODE", "0x0000", 0x100);
		payload.setBytes("0x0000", "74 05 f0 e4 a3 f0 7f c0 12 d1 08 22");
		Program module = payload.getProgram();

		Keil8051VectorAnalyzer analyzer = new Keil8051VectorAnalyzer();
		Options options = module.getOptions(Program.ANALYSIS_PROPERTIES);
		int txId = module.startTransaction("8051 vectors");
		try {
			analyzer.registerOptions(options, module);
			options.setBoolean("Seed vectors without a reset jump", true);
			analyzer.optionsChanged(options, module);
			analyzer.added(module, new AddressSet(), TaskMonitor.DUMMY, new MessageLog());
		}
		finally {
			module.endTransaction(txId, true);
		}

		assertNotNull("with the guard off, the interrupt slots are seeded again",
			module.getFunctionManager().getFunctionAt(payload.addr("0x0003")));
	}

	/**
	 * The GL3523 L2 hub's first 0x30 bytes, verbatim: LJMPs at +0, +3, +0xb and +0x1b, the "GLHUB"
	 * tag at +6, a routine the linker packed into +0x0e..+0x1a, and code from +0x1e on. The +0x13
	 * and +0x23 slots fall inside that code and are not vectors.
	 */
	private static final String L2_HUB_HEAD =
		"02 c0 8d 02 98 00 47 4c 48 55 42 02 d9 d0 90 00 00 e0 54 f7 f0 53 14 7f " +
			"c2 1c 22 02 d1 ea 75 5d 07 90 06 0f e0 44 01 f0 78 7d e6 30 e6 5c 30 12";

	@Test
	public void doesNotSeedSlotsThatFallInsideGapCode() throws Exception {
		ProgramBuilder hub = new ProgramBuilder("hub", ProgramBuilder._8051);
		hub.createMemory("CODE", "0x8000", 0x6312);
		hub.setBytes("0x8000", L2_HUB_HEAD);
		Program image = hub.getProgram();

		int txId = image.startTransaction("8051 vectors");
		try {
			new Keil8051VectorAnalyzer().added(image, new AddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			image.endTransaction(txId, true);
		}

		for (String vector : new String[] { "0x8000", "0x8003", "0x800b", "0x801b" }) {
			assertTrue(vector + " holds an LJMP and is a vector",
				image.getSymbolTable().isExternalEntryPoint(hub.addr(vector)));
		}
		for (String code : new String[] { "0x8013", "0x8023", "0x802b" }) {
			assertFalse(code + " is inside packed code, not a vector",
				image.getSymbolTable().isExternalEntryPoint(hub.addr(code)));
		}
	}

	/**
	 * The MStar scaler module's table, verbatim from {@code EIM152_020080}: vectors to +0x23, a
	 * routine at +0x26..+0x4a, then the core's extended vectors at +0x4b, +0x53 and +0x5b. A gap is
	 * not the end of the table.
	 */
	@Test
	public void keepsVectorsThatFollowAGap() throws Exception {
		ProgramBuilder scaler = new ProgramBuilder("scaler", ProgramBuilder._8051);
		scaler.createMemory("CODE", "0x0000", 0x10000);
		scaler.setBytes("0x0000",
			"02 0e aa 02 19 ac 32 32 00 22 ff 02 06 bd ff ff ff ff ff 02 05 14 ff ff " +
				"ff ff ff 02 17 95 ff ff ff ff ff 02 14 12 d3 ef 94 00 ee 94 00 40 1b ef " +
				"1f aa 06 70 01 1e 4a 60 11 7c 03 7d 6b ed 1d aa 04 70 01 1c 4a 60 e8 00 " +
				"80 f3 22 02 00 07 ff ff ff ff ff 02 00 06 ff ff ff ff ff 02 0b 93 e7 09");
		Program image = scaler.getProgram();

		int txId = image.startTransaction("8051 vectors");
		try {
			new Keil8051VectorAnalyzer().added(image, new AddressSet(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			image.endTransaction(txId, true);
		}

		for (String vector : new String[] { "0x0003", "0x000b", "0x0013", "0x001b", "0x0023",
			"0x004b", "0x0053", "0x005b" }) {
			assertTrue(vector + " is a vector",
				image.getSymbolTable().isExternalEntryPoint(scaler.addr(vector)));
		}
		for (String code : new String[] { "0x002b", "0x0033", "0x003b", "0x0043" }) {
			assertFalse(code + " is inside the packed routine",
				image.getSymbolTable().isExternalEntryPoint(scaler.addr(code)));
		}
	}

	@Test
	public void marksVectorsAsEntryPoints() throws Exception {
		analyze();

		assertTrue("analysis has to have somewhere to start from",
			program.getSymbolTable().isExternalEntryPoint(builder.addr("0x8000")));
	}
}
