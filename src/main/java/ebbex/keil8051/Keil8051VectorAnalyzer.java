package ebbex.keil8051;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Seeds functions at the 8051 reset and interrupt vectors, so a raw firmware image has somewhere
 * for analysis to start.
 * <p>
 * <b>Why it is needed.</b> A raw-binary 8051 import has no entry points — nothing in the file says
 * where code begins — so auto-analysis reaches no code at all and the image comes up empty. The
 * hardware, however, fixes the answer: reset runs from offset 0 and every interrupt enters at
 * {@code 0x03 + 8n}. Those offsets are relative to where the image was loaded, not to absolute
 * zero, which is what makes this work for an image based somewhere other than 0 (the GL3523 hub
 * firmware loads at {@code 0x8000}).
 * <p>
 * <b>What it does.</b> For each vector, it disassembles, creates a function, names it, and marks it
 * an external entry point so later analysis follows it.
 * <p>
 * <b>Most probed slots are not vectors.</b> Keil's linker packs ordinary code into the gaps between
 * vectors and straight after the last used one, so a slot is seeded only if it holds a jump into
 * loaded code or a {@code RETI} and the code already reached from earlier entries does not run
 * through it (see {@link #vectorTableSeeds}). Seeding every slot that is not fill, as this once did,
 * splits real functions at invented entry points. In the smoke sample that put a fake
 * {@code int_vector_7} in the middle of a switch, so its jump-table override landed on the wrong
 * function.
 * <p>
 * <b>Not every 8051 image has a vector table.</b> A module that is called rather than reset into —
 * the USB-PD payload in the MStar scaler image begins {@code MOV A,#5; MOVX @DPTR,A}, mid-routine —
 * has ordinary code where its vectors would be, and seeding {@code base+0x03}, {@code +0x0b} and
 * the rest there invents entry points that do not exist and names them after interrupts they have
 * nothing to do with. So the interrupt vectors are seeded only when the reset slot actually holds a
 * jump, which is what a vector table always starts with. Without one, only the module's first byte
 * is seeded, as a plain {@code entry}: code does start there, and that much is true of any module.
 * <p>
 * <b>Ordering.</b> {@link AnalysisPriority#FORMAT_ANALYSIS}{@code .after()} — before any
 * code-driven analysis, since everything downstream depends on there being entry points at all.
 */
public class Keil8051VectorAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "8051 interrupt vectors";
	private static final String DESCRIPTION =
		"Seeds functions at the 8051 reset vector (image base) and the interrupt vectors at " +
			"base+0x03, +0x0b, +0x13, ... so raw firmware images have entry points to analyze from.";

	private static final String OPTION_VECTOR_COUNT = "Interrupt vector count";
	private static final String OPTION_VECTOR_COUNT_DESC =
		"How many interrupt vectors to probe past the reset vector. The classic 8051 has 5; " +
			"derivatives extend the table in the same 8-byte steps.";
	private static final int DEFAULT_VECTOR_COUNT = 32;

	private static final String OPTION_ASSUME_VECTORS = "Seed vectors without a reset jump";
	private static final String OPTION_ASSUME_VECTORS_DESC =
		"Seed the interrupt vectors even when the image does not begin with a jump, i.e. when it " +
			"has no vector table at all. Off by default, because on such an image those addresses " +
			"are ordinary code and naming them after interrupts asserts something untrue. Turning " +
			"it on trades that for reach: on the MStar USB-PD payload it finds about 5% more " +
			"functions, from entry points that are not really entry points.";
	private static final boolean DEFAULT_ASSUME_VECTORS = false;

	/** Offset of the first interrupt vector, and the stride between them. */
	private static final int FIRST_VECTOR = 0x03;
	private static final int VECTOR_STRIDE = 8;

	/** Bytes of a vector slot: an {@code LJMP} is 3, which is what a used slot almost always holds. */
	private static final int SLOT_SIZE = 3;

	/** The three jump opcodes a reset vector can hold. */
	private static final int LJMP = 0x02;
	private static final int SJMP = 0x80;
	private static final int AJMP_MASK = 0x1f;
	private static final int AJMP_OPCODE = 0x01;
	private static final int RETI = 0x32;

	/** The classic 8051 interrupt sources, in vector order, for naming. */
	private static final String[] VECTOR_NAMES = {
		"int_ext0", "int_timer0", "int_ext1", "int_timer1", "int_serial", "int_timer2"
	};

	private int vectorCount = DEFAULT_VECTOR_COUNT;
	private boolean assumeVectors = DEFAULT_ASSUME_VECTORS;

	public Keil8051VectorAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return Keil8051.is8051(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_VECTOR_COUNT, DEFAULT_VECTOR_COUNT, null,
			OPTION_VECTOR_COUNT_DESC);
		options.registerOption(OPTION_ASSUME_VECTORS, DEFAULT_ASSUME_VECTORS, null,
			OPTION_ASSUME_VECTORS_DESC);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		vectorCount = options.getInt(OPTION_VECTOR_COUNT, DEFAULT_VECTOR_COUNT);
		assumeVectors = options.getBoolean(OPTION_ASSUME_VECTORS, DEFAULT_ASSUME_VECTORS);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Address base = Keil8051.codeBase(program);
		if (base == null) {
			return false;
		}

		boolean vectorTable = hasVectorTable(program, base);
		List<Seed> seeded = vectorTable ? vectorTableSeeds(program, base, monitor)
				: assumeVectors ? assumedSeeds(program, base, monitor)
				: entrySeed(program, base, monitor);
		if (seeded.isEmpty()) {
			return false;
		}

		SymbolTable symbols = program.getSymbolTable();
		int created = 0;
		for (Seed seed : seeded) {
			monitor.checkCancelled();
			if (program.getListing().getInstructionAt(seed.address()) == null) {
				continue;
			}
			symbols.addExternalEntryPoint(seed.address());
			nameVector(program, seed.address(), vectorName(seed.index(), vectorTable), monitor);
			created++;
		}

		if (created > 0) {
			Msg.info(this, "8051: seeded " + created + " vector entry point(s) from " + base);
		}
		return created > 0;
	}

	/** A seeded entry point; {@code index} -1 is reset, 0 and up the interrupt vectors. */
	private record Seed(int index, Address address) {}

	/**
	 * The reset vector and every interrupt slot that really is a vector.
	 * <p>
	 * A slot is a vector only if it holds a jump into loaded code or a {@code RETI}, and no code
	 * already reached from an earlier entry runs through it. Both conditions are needed, measured
	 * on the real images. Keil's linker fills the gaps between vectors with ordinary code: in the
	 * GL3523 hubs a routine runs from {@code base+0x0e} to {@code +0x1a}, straight through the
	 * {@code +0x13} slot, and code follows the last used vector, so most of the 32 slots probed
	 * hold code. The gaps are not the end of the table either. The MStar scaler modules have code
	 * at {@code 0x26}-{@code 0x4a} and then real extended vectors at {@code 0x4b}, {@code 0x53}
	 * and {@code 0x5b}, so probing cannot stop at the first slot that is not a vector.
	 * <p>
	 * So each accepted entry is disassembled, following its flow, before the next slot is
	 * judged. A slot that flow has already covered is code, not a vector. A code byte that merely
	 * looks like a jump is caught that way, and the content test catches the rest. {@code SJMP}
	 * is accepted at reset only: Keil emits {@code LJMP} for an interrupt, and the L1 hub has an
	 * {@code SJMP} at {@code +0x3b} that is gap code.
	 */
	private List<Seed> vectorTableSeeds(Program program, Address base, TaskMonitor monitor)
			throws CancelledException {
		List<Seed> seeds = new ArrayList<>();
		seeds.add(new Seed(-1, base));
		disassemble(program, base, monitor);
		for (int index = 0; index < vectorCount; index++) {
			monitor.checkCancelled();
			Address vector = vectorAddress(base, index);
			if (vector == null || program.getListing().getInstructionContaining(vector) != null ||
				!isVectorEntry(program, vector)) {
				continue;
			}
			seeds.add(new Seed(index, vector));
			disassemble(program, vector, monitor);
		}
		return seeds;
	}

	/**
	 * With the guard off, every interrupt slot that is not fill, as before the vector-table rule:
	 * an image without a reset jump has no table to apply it to, and the option trades truth for
	 * reach on purpose.
	 */
	private List<Seed> assumedSeeds(Program program, Address base, TaskMonitor monitor)
			throws CancelledException {
		List<Seed> seeds = new ArrayList<>(entrySeed(program, base, monitor));
		AddressSet toDisassemble = new AddressSet();
		for (int index = 0; index < vectorCount; index++) {
			monitor.checkCancelled();
			Address vector = vectorAddress(base, index);
			if (vector != null && looksLikeCode(program, vector)) {
				seeds.add(new Seed(index, vector));
				toDisassemble.add(vector);
			}
		}
		new DisassembleCommand(toDisassemble, null, true).applyTo(program, monitor);
		return seeds;
	}

	/** Without a vector table, only the module's first byte: code does start there. */
	private List<Seed> entrySeed(Program program, Address base, TaskMonitor monitor) {
		if (!looksLikeCode(program, base)) {
			return List.of();
		}
		disassemble(program, base, monitor);
		return List.of(new Seed(-1, base));
	}

	private static void disassemble(Program program, Address at, TaskMonitor monitor) {
		new DisassembleCommand(at, null, true).applyTo(program, monitor);
	}

	/** {@code LJMP} or {@code AJMP} into loaded code, or a {@code RETI}. */
	private static boolean isVectorEntry(Program program, Address vector) {
		Memory memory = program.getMemory();
		try {
			int opcode = memory.getByte(vector) & 0xff;
			if (opcode == RETI) {
				return true;
			}
			if (opcode == LJMP) {
				long target = memory.getShort(vector.add(1)) & 0xffff;
				return Keil8051.isLoadedCode(program, vector.getNewAddress(target));
			}
			if ((opcode & AJMP_MASK) == AJMP_OPCODE) {
				long next = vector.getOffset() + 2;
				long target = (next & 0xf800) | ((opcode & 0xe0) << 3) |
					(memory.getByte(vector.add(1)) & 0xff);
				return Keil8051.isLoadedCode(program, vector.getNewAddress(target));
			}
			return false;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return false;
		}
	}

	/**
	 * Creates the vector's function and gives it the hardware's name for it.
	 * <p>
	 * A vector that is a bare {@code LJMP} — most of them — is a thunk, and Ghidra names a thunk
	 * after its destination. That name says nothing the destination does not already say, so it is
	 * replaced: what a reader needs at {@code base+0x03} is that this is the external-0 vector.
	 */
	private void nameVector(Program program, Address vector, String name, TaskMonitor monitor) {
		if (program.getFunctionManager().getFunctionAt(vector) == null) {
			new CreateFunctionCmd(name, vector, null, SourceType.ANALYSIS).applyTo(program, monitor);
		}
		Function function = program.getFunctionManager().getFunctionAt(vector);
		if (function == null || name.equals(function.getName())) {
			return;
		}
		try {
			function.setName(name, SourceType.ANALYSIS);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			// Some other analyzer got there with a better name; keep it.
		}
	}

	/** {@code index} of -1 is the reset vector at the image base; 0 and up are interrupt vectors. */
	private Address vectorAddress(Address base, int index) {
		try {
			int offset = index < 0 ? 0 : FIRST_VECTOR + index * VECTOR_STRIDE;
			return base.add(offset);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private String vectorName(int index, boolean vectorTable) {
		if (index < 0) {
			// Calling it "reset" would assert a vector table this image does not have.
			return vectorTable ? "reset" : "entry";
		}
		if (index < VECTOR_NAMES.length) {
			return VECTOR_NAMES[index];
		}
		return "int_vector_" + index;
	}

	/**
	 * True when the image really begins with a vector table, i.e. its first byte is a jump. Every
	 * 8051 reset vector is one — there are only three bytes before the first interrupt vector, so
	 * there is nothing else it could be.
	 */
	private boolean hasVectorTable(Program program, Address base) {
		if (!Keil8051.isLoadedCode(program, base)) {
			return false;
		}
		try {
			int opcode = program.getMemory().getByte(base) & 0xff;
			return opcode == LJMP || opcode == SJMP || (opcode & AJMP_MASK) == AJMP_OPCODE;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	/**
	 * A slot is worth seeding unless it is unreadable or holds one of the two fill patterns. The
	 * bytes themselves decide — an unused slot in a real image is {@code 00 00 00} or
	 * {@code ff ff ff}, and anything else is code the hardware would actually execute.
	 */
	private boolean looksLikeCode(Program program, Address vector) {
		if (!Keil8051.isLoadedCode(program, vector)) {
			return false;
		}
		Memory memory = program.getMemory();
		byte[] slot = new byte[SLOT_SIZE];
		try {
			if (memory.getBytes(vector, slot) != SLOT_SIZE) {
				return false;
			}
		}
		catch (MemoryAccessException e) {
			return false;
		}
		return !isFill(slot, (byte) 0x00) && !isFill(slot, (byte) 0xff);
	}

	private static boolean isFill(byte[] bytes, byte fill) {
		for (byte b : bytes) {
			if (b != fill) {
				return false;
			}
		}
		return true;
	}
}
