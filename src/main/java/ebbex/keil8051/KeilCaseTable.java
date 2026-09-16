package ebbex.keil8051;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * One parsed Keil case table: the inline {@code <target, value>} entries that follow an
 * {@code LCALL ?C?xCASE}, plus the default target after the zero terminator.
 *
 * @param helper which helper's table this is, which fixes the entry stride
 * @param address the first entry, i.e. the byte after the 3-byte {@code LCALL}
 * @param cases the case entries in table order
 * @param defaultTarget where the helper jumps when no case matches
 * @param length total size of the table in bytes, terminator and default included
 */
public record KeilCaseTable(KeilCaseHelper helper, Address address, List<KeilCase> cases,
		Address defaultTarget, int length) {

	/**
	 * A single case: the value compared against the switch expression and where it jumps.
	 *
	 * @param value the case label, {@link KeilCaseHelper#valueSize()} bytes wide
	 * @param target the code this case branches to
	 * @param address where this entry sits in the table
	 */
	public record KeilCase(long value, Address target, Address address) {}

	/**
	 * A table longer than this is taken as a misparse rather than a real switch. Keil emits one
	 * entry per {@code case} label; real switches run to a few dozen, and the cap only has to keep
	 * a false-positive {@code LCALL} from walking the whole image.
	 */
	private static final int MAX_CASES = 512;

	/**
	 * Parses the table at {@code address}, or returns {@code null} if the bytes there are not one.
	 * <p>
	 * Every target — each case and the default — must land in initialized memory of the table's own
	 * (code) space, which is what rejects the byte sequences that merely look like an
	 * {@code LCALL} to a helper.
	 */
	public static KeilCaseTable parse(Memory memory, KeilCaseHelper helper, Address address) {
		List<KeilCase> cases = new ArrayList<>();
		int offset = 0;
		try {
			while (cases.size() <= MAX_CASES) {
				Address entry = address.add(offset);
				int target = memory.getShort(entry) & 0xffff;
				if (target == 0) {
					Address dflt = codeAddress(memory, address, entry.add(2));
					if (dflt == null || cases.isEmpty()) {
						return null;
					}
					int length = offset + KeilCaseHelper.TERMINATOR_SIZE;
					return new KeilCaseTable(helper, address, List.copyOf(cases), dflt, length);
				}
				Address to = codeAddress(memory, address, target);
				if (to == null) {
					return null;
				}
				cases.add(new KeilCase(readValue(memory, entry.add(2), helper.valueSize()), to, entry));
				offset += helper.entrySize();
			}
			return null;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			// Ran off the end of the block: not a table.
			return null;
		}
	}

	private static long readValue(Memory memory, Address at, int size) throws MemoryAccessException {
		return switch (size) {
			case 1 -> memory.getByte(at) & 0xffL;
			case 2 -> memory.getShort(at) & 0xffffL;
			default -> memory.getInt(at) & 0xffffffffL;
		};
	}

	/** Reads a big-endian target word and returns it as an address, or {@code null} if unusable. */
	private static Address codeAddress(Memory memory, Address inSpaceOf, Address wordAt)
			throws MemoryAccessException {
		return codeAddress(memory, inSpaceOf, memory.getShort(wordAt) & 0xffff);
	}

	private static Address codeAddress(Memory memory, Address inSpaceOf, int target) {
		Address to = inSpaceOf.getNewAddress(target);
		MemoryBlock block = memory.getBlock(to);
		if (block == null || !block.isInitialized()) {
			return null;
		}
		return to;
	}

	/** The first address after the table — where the enclosing function's code continues. */
	public Address end() {
		return address.add(length);
	}
}
