package ebbex.keil8051;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * One parsed Keil {@code AJMP}-table switch: the bounded {@code JMP @A+DPTR} dispatch and the table
 * of {@code AJMP} instructions it indexes.
 *
 * @param dispatch the {@code MOV DPTR,#table} that starts the idiom
 * @param jump the {@code JMP @A+DPTR} itself, where the case references belong
 * @param address the first table entry
 * @param entries the table entries in case order
 * @param bound the case count the compiler's own range check proves
 */
public record KeilJumpTable(Address dispatch, Address jump, Address address, List<Entry> entries,
		int bound) {

	/**
	 * One table slot: an {@code AJMP} instruction and where it goes.
	 *
	 * @param caseValue the switch value that selects this slot
	 * @param address the {@code AJMP} itself — what the dispatch branches to
	 * @param target where that {@code AJMP} lands
	 */
	public record Entry(int caseValue, Address address, Address target) {}

	/** {@code AJMP} is two bytes and its low five opcode bits are fixed. */
	private static final int AJMP_MASK = 0x1f;
	private static final int AJMP_OPCODE = 0x01;
	public static final int ENTRY_SIZE = 2;

	/**
	 * An {@code ADD A,ACC} index can reach at most 128 two-byte slots, and a real switch is far
	 * smaller. The cap only bounds the work done on a pattern that is not really a dispatch.
	 */
	private static final int MAX_ENTRIES = 128;

	/**
	 * Parses the {@code bound}-entry table at {@code address}, or returns {@code null} if the bytes
	 * there are not one.
	 * <p>
	 * Every slot must be an {@code AJMP} landing in loaded memory. That is what separates a real
	 * table from the run of unrelated code that follows it — and getting the end right is the whole
	 * point, since the stock analyzer's failure here is that it never finds one.
	 */
	public static KeilJumpTable parse(Memory memory, Address dispatch, Address jump, Address address,
			int bound) {

		if (bound < 1 || bound > MAX_ENTRIES) {
			return null;
		}
		List<Entry> entries = new ArrayList<>(bound);
		try {
			for (int index = 0; index < bound; index++) {
				Address at = address.add((long) index * ENTRY_SIZE);
				Address target = ajmpTarget(memory, at);
				if (target == null) {
					return null;
				}
				entries.add(new Entry(index, at, target));
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
		return new KeilJumpTable(dispatch, jump, address, List.copyOf(entries), bound);
	}

	/**
	 * Decodes an {@code AJMP}: the three high opcode bits carry address bits 10-8, and the
	 * destination shares the 2 KB page of the <i>following</i> instruction.
	 */
	private static Address ajmpTarget(Memory memory, Address at) throws MemoryAccessException {
		int opcode = memory.getByte(at) & 0xff;
		if ((opcode & AJMP_MASK) != AJMP_OPCODE) {
			return null;
		}
		long next = at.getOffset() + ENTRY_SIZE;
		long target = (next & 0xf800) | ((opcode & 0xe0) << 3) | (memory.getByte(at.add(1)) & 0xff);

		Address to = at.getNewAddress(target);
		MemoryBlock block = memory.getBlock(to);
		if (block == null || !block.isInitialized()) {
			return null;
		}
		return to;
	}

	/** Total size of the table in bytes. */
	public int length() {
		return entries.size() * ENTRY_SIZE;
	}

	/** The first address after the table. */
	public Address end() {
		return address.add(length());
	}
}
