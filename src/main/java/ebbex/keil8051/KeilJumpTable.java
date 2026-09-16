package ebbex.keil8051;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

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

	/** {@code MOV DPTR,#imm16; ADD A,ACC; JMP @A+DPTR} — the dispatch, with the table address open. */
	private static final byte[] DISPATCH = {
		(byte) 0x90, 0, 0, (byte) 0x25, (byte) 0xe0, (byte) 0x73
	};
	private static final byte[] DISPATCH_MASK = {
		(byte) 0xff, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 0xff
	};

	/** Offset of {@code JMP @A+DPTR} within the dispatch pattern. */
	private static final int JUMP_OFFSET = 5;

	private static final int CJNE_A_IMM = 0xb4;
	private static final int JC = 0x40;
	private static final int JNC = 0x50;

	/**
	 * How far back to look for the range check. The shortest real gap is
	 * {@code CJNE}(3) + branch(2) + {@code AJMP default}(2) = 7 bytes, and an {@code LJMP} default
	 * or a register move makes it a little more.
	 */
	private static final int BOUND_SEARCH_MIN = 5;
	private static final int BOUND_SEARCH_MAX = 14;

	/**
	 * Every bounded {@code AJMP}-table dispatch in the program.
	 * <p>
	 * Discovery is by byte pattern rather than over disassembled instructions so that a dispatch in
	 * code nothing has reached yet is still found — the same reason {@link KeilSwitchTableAnalyzer}
	 * works from bytes.
	 */
	public static List<KeilJumpTable> findAll(Program program, TaskMonitor monitor)
			throws CancelledException {

		Memory memory = program.getMemory();
		List<KeilJumpTable> found = new ArrayList<>();
		Address from = memory.getMinAddress();
		while (from != null) {
			monitor.checkCancelled();
			Address at = memory.findBytes(from, DISPATCH, DISPATCH_MASK, true, monitor);
			if (at == null) {
				break;
			}
			KeilJumpTable table = parseDispatch(memory, at);
			if (table != null) {
				found.add(table);
			}
			from = at.next();
		}
		return found;
	}

	/** Reads the table address out of the dispatch and the case count out of the range check. */
	private static KeilJumpTable parseDispatch(Memory memory, Address dispatch) {
		try {
			Address table = dispatch.getNewAddress(memory.getShort(dispatch.add(1)) & 0xffff);
			int bound = readBound(memory, dispatch);
			if (bound < 1) {
				return null;
			}
			return parse(memory, dispatch, dispatch.add(JUMP_OFFSET), table, bound);
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	/**
	 * The case count, from the {@code CJNE A,#n} whose carry the following {@code JC}/{@code JNC}
	 * tests. Returns 0 when there is no such check, which means the dispatch is left alone: the
	 * failure being repaired is a table walked past its end, and guessing a length would be the
	 * same mistake again.
	 */
	private static int readBound(Memory memory, Address dispatch) throws MemoryAccessException {
		for (int back = BOUND_SEARCH_MIN; back <= BOUND_SEARCH_MAX; back++) {
			Address at;
			try {
				at = dispatch.subtract(back);
			}
			catch (RuntimeException e) {
				return 0;
			}
			if ((memory.getByte(at) & 0xff) != CJNE_A_IMM) {
				continue;
			}
			int branch = memory.getByte(at.add(3)) & 0xff;
			if (branch == JC || branch == JNC) {
				return memory.getByte(at.add(1)) & 0xff;
			}
		}
		return 0;
	}

	/** The addresses this switch can branch to, in case order. */
	public List<Address> destinations() {
		return entries.stream().map(Entry::address).toList();
	}

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
