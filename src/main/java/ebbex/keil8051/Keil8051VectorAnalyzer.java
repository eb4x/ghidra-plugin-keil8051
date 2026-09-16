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
 * <b>What it does.</b> For each vector whose bytes look like code, it disassembles, creates a
 * function, names it, and marks it an external entry point so later analysis follows it.
 * <p>
 * A slot is skipped when its bytes are all {@code 0x00} or all {@code 0xff} — the two fill patterns
 * an unused vector carries — or when it will not disassemble. That is deliberately permissive:
 * seeding a vector that turns out to be padding costs a stray function, while missing one costs the
 * whole subtree of code it leads to.
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

	/** Offset of the first interrupt vector, and the stride between them. */
	private static final int FIRST_VECTOR = 0x03;
	private static final int VECTOR_STRIDE = 8;

	/** Bytes of a vector slot: an {@code LJMP} is 3, which is what a used slot almost always holds. */
	private static final int SLOT_SIZE = 3;

	/** The classic 8051 interrupt sources, in vector order, for naming. */
	private static final String[] VECTOR_NAMES = {
		"int_ext0", "int_timer0", "int_ext1", "int_timer1", "int_serial", "int_timer2"
	};

	private int vectorCount = DEFAULT_VECTOR_COUNT;

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
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		vectorCount = options.getInt(OPTION_VECTOR_COUNT, DEFAULT_VECTOR_COUNT);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Address base = Keil8051.codeBase(program);
		if (base == null) {
			return false;
		}

		List<Address> seeded = new ArrayList<>();
		AddressSet toDisassemble = new AddressSet();
		for (int index = -1; index < vectorCount; index++) {
			monitor.checkCancelled();
			Address vector = vectorAddress(base, index);
			if (vector == null || !looksLikeCode(program, vector)) {
				continue;
			}
			seeded.add(vector);
			toDisassemble.addRange(vector, vector);
		}

		if (seeded.isEmpty()) {
			return false;
		}

		new DisassembleCommand(toDisassemble, null, true).applyTo(program, monitor);

		SymbolTable symbols = program.getSymbolTable();
		int created = 0;
		for (int i = 0; i < seeded.size(); i++) {
			monitor.checkCancelled();
			Address vector = seeded.get(i);
			if (program.getListing().getInstructionAt(vector) == null) {
				continue;
			}
			symbols.addExternalEntryPoint(vector);
			nameVector(program, vector, vectorName(i - 1), monitor);
			created++;
		}

		if (created > 0) {
			Msg.info(this, "8051: seeded " + created + " vector entry point(s) from " + base);
		}
		return created > 0;
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

	private String vectorName(int index) {
		if (index < 0) {
			return "reset";
		}
		if (index < VECTOR_NAMES.length) {
			return VECTOR_NAMES[index];
		}
		return "int_vector_" + index;
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
