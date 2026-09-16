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

	@Test
	public void marksVectorsAsEntryPoints() throws Exception {
		analyze();

		assertTrue("analysis has to have somewhere to start from",
			program.getSymbolTable().isExternalEntryPoint(builder.addr("0x8000")));
	}
}
