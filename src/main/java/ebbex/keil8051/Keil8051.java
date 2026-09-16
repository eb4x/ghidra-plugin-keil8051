package ebbex.keil8051;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Small shared helpers for the 8051 analyzers in this extension.
 */
final class Keil8051 {

	/** Ghidra's processor name for every 8051-family language variant. */
	private static final String PROCESSOR_8051 = "8051";

	private Keil8051() {
	}

	/** True for any 8051-family language (default, cip-51, mx51, ...). */
	static boolean is8051(Program program) {
		return PROCESSOR_8051.equals(program.getLanguage().getProcessor().toString());
	}

	/**
	 * The lowest initialized address in the program's default (code) space — the
	 * address an 8051 image's own offset 0 was loaded at, which is what the vector table and the
	 * reset entry are relative to. Returns {@code null} when the program has no such block.
	 */
	static Address codeBase(Program program) {
		Memory memory = program.getMemory();
		Address best = null;
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized()) {
				continue;
			}
			Address start = block.getStart();
			if (!start.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) {
				continue;
			}
			if (best == null || start.compareTo(best) < 0) {
				best = start;
			}
		}
		return best;
	}

	/**
	 * True when {@code address} holds bytes loaded from the image. Executability is deliberately not
	 * required: on 8051 the code space is a space of its own, so anything addressed there is code by
	 * construction, and raw imports do not always carry sensible block permissions.
	 */
	static boolean isLoadedCode(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		return block != null && block.isInitialized();
	}
}
