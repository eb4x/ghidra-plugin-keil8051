// Smoke test for the Keil8051 extension, run headless on the committed samples in src/test/smoke/.
// Prints "SMOKE OK" when every check passes, and one "UNEXPECTED ..." line per failure.
//@category Keil8051

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ebbex.keil8051.KeilCaseHelper;
import ebbex.keil8051.MStarModule;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;

/**
 * Checks what the extension did to one sample program, in the decompiler rather than by counting
 * references: a switch counts as recovered only when the decompiler's own jump table at the branch
 * has exactly the expected destinations.
 * <p>
 * Headless analyzes only the primary program of a multi-program import (GP-2965), so each module of
 * the MStar-style image is checked by its own task, and the loader's module scan is checked here
 * against the file directly.
 */
public class Keil8051Smoke extends GhidraScript {

	private final List<String> failures = new ArrayList<>();

	@Override
	protected void run() throws Exception {
		switch (currentProgram.getName()) {
			case "SMOKE1_000100" -> {
				checkModuleScan();
				checkFileOffset(0x100);
				checkModule1(0x0000);
			}
			// Loaded by explicit offset, which names a module by its offset alone.
			case "module_010200" -> {
				checkFileOffset(0x10200);
				checkModule2();
			}
			case "keil8051-smoke-based.bin" -> checkModule1(0x8000);
			default -> fail("program " + currentProgram.getName() + " is not a smoke sample");
		}
		if (failures.isEmpty()) {
			println("SMOKE OK");
		}
	}

	/** The loader's scan finds both modules and names them from the sBoot info block. */
	private void checkModuleScan() throws Exception {
		try (ByteProvider provider =
			new FileByteProvider(new java.io.File(currentProgram.getExecutablePath()), null,
				java.nio.file.AccessMode.READ)) {
			List<String> names = MStarModule.findAll(provider).stream().map(MStarModule::name).toList();
			expect(names.equals(List.of("SMOKE1_000100", "SMOKE1_010200")), "module scan found " + names);
		}
	}

	/** CODE:0000 of a module is the byte at its file offset. */
	private void checkFileOffset(long offset) {
		MemoryBlock code = currentProgram.getMemory().getBlock("CODE");
		long actual = code == null || code.getSourceInfos().isEmpty() ? -1
				: code.getSourceInfos().get(0).getFileBytesOffset();
		expect(actual == offset, "CODE starts at file offset 0x%x, expected 0x%x".formatted(actual, offset));
	}

	private void checkModule1(long base) throws Exception {
		checkFunction(base + 0x00, "reset");
		checkFunction(base + 0x03, "int_ext0");
		checkFunction(base + 0x0b, "int_timer0");
		checkFunction(base + 0x23, "int_serial");

		Function helper = getFunctionAt(addr(base + 0x380));
		String label = KeilCaseHelper.CCASE.label();
		expect(helper != null && helper.getName().equals(label) && label.equals(helper.getCallFixup()),
			"?C?CCASE at 0x%x not recognised: %s".formatted(base + 0x380, helper));

		// Plain AJMP shape, cases 0..4: recovered by the decompiler itself or by the override.
		checkSwitch(base + 0x100, base + 0x10c, entries(base + 0x10d, 5), true);
		// Page-carry shape with DEC A, cases 1..12: only the override recovers it.
		checkSwitch(base + 0x1de, base + 0x1ef, entries(base + 0x1f0, 12), false);
		// ?C?CCASE: four cases and the default, keyed at the LCALL.
		checkSwitch(base + 0x300, base + 0x300,
			addrs(base + 0x313, base + 0x316, base + 0x319, base + 0x31c, base + 0x31f), false);
	}

	private void checkModule2() throws Exception {
		checkFunction(0x00, "reset");
		checkFunction(0x0b, "int_timer0");
		// Plain AJMP shape with an LJMP default, cases 0..2.
		checkSwitch(0x80, 0x8d, entries(0x8e, 3), true);
	}

	private void checkFunction(long offset, String name) {
		Function function = getFunctionAt(addr(offset));
		expect(function != null && function.getName().equals(name),
			"no function %s at 0x%x: %s".formatted(name, offset, function));
	}

	/**
	 * Decompiles the function at {@code entry} and checks the jump table at {@code branch}.
	 *
	 * @param plusDefault whether the decompiler may add the default to the cases, as it does when
	 *     it recovers a guarded table itself
	 */
	private void checkSwitch(long entry, long branch, Set<Address> expected, boolean plusDefault)
			throws Exception {
		Function function = getFunctionAt(addr(entry));
		if (function == null) {
			fail("no function at 0x%x".formatted(entry));
			return;
		}
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.openProgram(currentProgram);
			DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
			String where = "%s at 0x%x".formatted(function.getName(), entry);
			if (!results.decompileCompleted()) {
				fail(where + " did not decompile: " + results.getErrorMessage());
				return;
			}
			String errors = results.getErrorMessage();
			expect(errors == null || !errors.toLowerCase().contains("error"),
				where + " decompiled with errors: " + errors);
			String c = results.getDecompiledFunction().getC();
			expect(!c.contains("halt_baddata"), where + " decompiles to halt_baddata()");
			checkTable(results.getHighFunction(), where, addr(branch), expected, plusDefault);
		}
		finally {
			decompiler.dispose();
		}
	}

	private void checkTable(HighFunction high, String where, Address branch, Set<Address> expected,
			boolean plusDefault) {
		JumpTable[] tables = high == null ? null : high.getJumpTables();
		JumpTable table = tables == null ? null
				: Arrays.stream(tables)
						.filter(t -> t.getSwitchAddress().equals(branch))
						.findFirst()
						.orElse(null);
		if (table == null) {
			fail("%s: no jump table recovered at %s".formatted(where, branch));
			return;
		}
		Set<Address> cases = new TreeSet<>(Arrays.asList(table.getCases()));
		boolean exact = cases.equals(expected);
		boolean withDefault = plusDefault && cases.size() == expected.size() + 1 &&
			cases.containsAll(expected);
		expect(exact || withDefault,
			"%s: table at %s has %d targets %s, expected %s".formatted(where, branch, cases.size(),
				cases, expected));
	}

	private Set<Address> entries(long first, int count) {
		Set<Address> set = new TreeSet<>();
		for (int i = 0; i < count; i++) {
			set.add(addr(first + 2L * i));
		}
		return set;
	}

	private Set<Address> addrs(long... offsets) {
		Set<Address> set = new TreeSet<>();
		for (long offset : offsets) {
			set.add(addr(offset));
		}
		return set;
	}

	private Address addr(long offset) {
		return currentProgram.getAddressFactory().getAddressSpace("CODE").getAddress(offset);
	}

	private void expect(boolean ok, String message) {
		if (!ok) {
			fail(message);
		}
	}

	private void fail(String message) {
		failures.add(message);
		println("UNEXPECTED " + message);
	}
}
