package ebbex.keil8051;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

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
 * @param defaultTarget where an out-of-range switch value goes, or {@code null} when the jump after
 *     the range check is not one this can decode; it is not a table entry and gets no reference
 * @param caseBias what table slot 0 is the case label for — 1 when the switch value was
 *     decremented before the range check, which is how Keil compiles a switch not starting at zero
 */
public record KeilJumpTable(Address dispatch, Address jump, Address address, List<Entry> entries,
		int bound, int caseBias, Address defaultTarget) {

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
	 * The dispatch shapes, each {@code MOV DPTR,#table; ADD A,ACC; ...; JMP @A+DPTR} with the table
	 * address masked out.
	 *
	 * @param pattern bytes to match
	 * @param mask {@code 0xff} where {@code pattern} must match, {@code 0} where it is a wildcard
	 * @param jumpOffset where {@code JMP @A+DPTR} sits within the pattern
	 */
	private record Dispatch(byte[] pattern, byte[] mask, int jumpOffset) {}

	/**
	 * Two shapes, differing by Keil's page-carry fix-up.
	 * <p>
	 * {@code AJMP} entries are two bytes, so {@code ADD A,ACC} can carry out of the low byte of the
	 * table address whenever {@code 2 * bound} could exceed {@code 0xff} from the table base. Keil
	 * emits {@code JNC $+2; INC DPH} to cover that, and emits it on the evidence of the bound alone
	 * — at {@code 0xbcbb} in the GL3523 L2 hub image it is dead at run time ({@code 2 * 27 = 54})
	 * but present in the bytes. A matcher anchored on {@code ADD A,ACC} immediately followed by
	 * {@code JMP @A+DPTR} therefore skips a real switch, which is exactly what happened.
	 */
	private static final List<Dispatch> DISPATCHES = List.of(
		// MOV DPTR,#imm16; ADD A,ACC; JMP @A+DPTR
		new Dispatch(
			new byte[] { (byte) 0x90, 0, 0, (byte) 0x25, (byte) 0xe0, (byte) 0x73 },
			new byte[] { (byte) 0xff, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 0xff },
			5),
		// MOV DPTR,#imm16; ADD A,ACC; JNC $+2; INC DPH; JMP @A+DPTR
		new Dispatch(
			new byte[] { (byte) 0x90, 0, 0, (byte) 0x25, (byte) 0xe0, (byte) 0x50, (byte) 0x02,
				(byte) 0x05, (byte) 0x83, (byte) 0x73 },
			new byte[] { (byte) 0xff, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff },
			9));

	private static final int CJNE_A_IMM = 0xb4;
	private static final int JC = 0x40;
	private static final int JNC = 0x50;

	/**
	 * {@code DEC A} immediately before the bound is Keil's "cases do not start at zero" idiom: the
	 * switch value is decremented so slot {@code i} of the table is case {@code i + 1}.
	 */
	private static final int DEC_A = 0x14;

	private static final int LJMP = 0x02;
	private static final int SJMP = 0x80;
	private static final int CJNE_LENGTH = 3;
	private static final int BRANCH_LENGTH = 2;

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
		Map<Address, KeilJumpTable> found = new TreeMap<>();
		for (Dispatch dispatch : DISPATCHES) {
			Address from = memory.getMinAddress();
			while (from != null) {
				monitor.checkCancelled();
				Address at = memory.findBytes(from, dispatch.pattern(), dispatch.mask(), true,
					monitor);
				if (at == null) {
					break;
				}
				KeilJumpTable table = parseDispatch(memory, at, dispatch);
				if (table != null) {
					found.put(at, table);
				}
				from = at.next();
			}
		}
		return List.copyOf(found.values());
	}

	/** Reads the table address out of the dispatch and the case count out of the range check. */
	private static KeilJumpTable parseDispatch(Memory memory, Address dispatch, Dispatch shape) {
		try {
			Address table = dispatch.getNewAddress(memory.getShort(dispatch.add(1)) & 0xffff);
			Address check = boundCheck(memory, dispatch);
			if (check == null) {
				return null;
			}
			int bound = memory.getByte(check.add(1)) & 0xff;
			if (bound < 1) {
				return null;
			}
			return parse(memory, dispatch, dispatch.add(shape.jumpOffset()), table, bound,
				caseBias(memory, check), defaultTarget(memory, check));
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	/**
	 * Where an out-of-range switch value goes, read from the jump that follows the range check.
	 * <p>
	 * With {@code JC}, the in-range path branches away and the default is the jump that falls
	 * through after it — an {@code AJMP}, {@code LJMP} or {@code SJMP}. With {@code JNC}, the branch
	 * itself goes to the default. Returns {@code null} for anything else rather than guessing.
	 * <p>
	 * The default is the jump's <i>destination</i>, not the jump instruction. The decompiler reports
	 * it either way depending on whether the destination lies in the same function — for the
	 * GL3523 L2 hub it gives {@code 0xbdee} for {@code 0xbd6a} but {@code 0xa815}, the address of
	 * the {@code AJMP}, for {@code 0xa81c}, whose default really goes to {@code 0xa904}.
	 */
	private static Address defaultTarget(Memory memory, Address boundCheck) {
		try {
			Address branch = boundCheck.add(CJNE_LENGTH);
			Address afterBranch = branch.add(BRANCH_LENGTH);
			int branchOpcode = memory.getByte(branch) & 0xff;
			if (branchOpcode == JNC) {
				return inLoadedMemory(memory,
					afterBranch.add(memory.getByte(branch.add(1))));
			}
			if (branchOpcode != JC) {
				return null;
			}
			return decodeJump(memory, afterBranch);
		}
		catch (MemoryAccessException | RuntimeException e) {
			return null;
		}
	}

	/** Destination of an {@code AJMP}, {@code LJMP} or {@code SJMP} at {@code at}, else null. */
	private static Address decodeJump(Memory memory, Address at) throws MemoryAccessException {
		int opcode = memory.getByte(at) & 0xff;
		if (opcode == LJMP) {
			return inLoadedMemory(memory, at.getNewAddress(memory.getShort(at.add(1)) & 0xffff));
		}
		if (opcode == SJMP) {
			return inLoadedMemory(memory, at.add(2).add(memory.getByte(at.add(1))));
		}
		if ((opcode & AJMP_MASK) == AJMP_OPCODE) {
			return ajmpTarget(memory, at);
		}
		return null;
	}

	private static Address inLoadedMemory(Memory memory, Address address) {
		MemoryBlock block = memory.getBlock(address);
		return block != null && block.isInitialized() ? address : null;
	}

	/**
	 * Slot {@code 0} of the table is case {@code 1} when the switch value was decremented first,
	 * which is how Keil compiles a switch whose smallest label is not zero.
	 */
	private static int caseBias(Memory memory, Address boundCheck) {
		try {
			return (memory.getByte(boundCheck.subtract(1)) & 0xff) == DEC_A ? 1 : 0;
		}
		catch (MemoryAccessException | RuntimeException e) {
			return 0;
		}
	}

	/**
	 * The case count, from the {@code CJNE A,#n} whose carry the following {@code JC}/{@code JNC}
	 * tests. Returns 0 when there is no such check, which means the dispatch is left alone: the
	 * failure being repaired is a table walked past its end, and guessing a length would be the
	 * same mistake again.
	 */
	private static Address boundCheck(Memory memory, Address dispatch) throws MemoryAccessException {
		for (int back = BOUND_SEARCH_MIN; back <= BOUND_SEARCH_MAX; back++) {
			Address at;
			try {
				at = dispatch.subtract(back);
			}
			catch (RuntimeException e) {
				return null;
			}
			if ((memory.getByte(at) & 0xff) != CJNE_A_IMM) {
				continue;
			}
			int branch = memory.getByte(at.add(3)) & 0xff;
			if (branch == JC || branch == JNC) {
				return at;
			}
		}
		return null;
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
		return parse(memory, dispatch, jump, address, bound, 0, null);
	}

	/**
	 * As {@link #parse}, with the case-label bias the dispatch's {@code DEC A} implies and the
	 * default target read from its range check.
	 */
	public static KeilJumpTable parse(Memory memory, Address dispatch, Address jump, Address address,
			int bound, int caseBias, Address defaultTarget) {

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
				entries.add(new Entry(index + caseBias, at, target));
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
		return new KeilJumpTable(dispatch, jump, address, List.copyOf(entries), bound, caseBias,
			defaultTarget);
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
