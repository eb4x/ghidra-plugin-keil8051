package ebbex.keil8051;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;

/**
 * Tests for {@link KeilSwitchOverrideAnalyzer#matchesTable}, the test that decides whether the
 * decompiler already recovered a table and the override should stand aside.
 * <p>
 * The addresses are the GL3523 L2 hub dispatch at {@code 0xbd6a}: nine {@code AJMP} slots
 * {@code 0xbd6b..0xbd7b}, default {@code 0xbdee}. The stand-aside matters because an override,
 * though correct, renders that switch as {@code switch(bVar1 * 2)} with cases {@code 0, 2, 4, ...}
 * where the decompiler on its own gives {@code switch(uVar1)} with cases {@code 0..8}.
 */
public class KeilSwitchOverrideAnalyzerTest extends AbstractGenericTest {

	private final ProgramBuilder builder;

	public KeilSwitchOverrideAnalyzerTest() throws Exception {
		builder = new ProgramBuilder("hub", ProgramBuilder._8051);
		builder.createMemory("CODE", "0x8000", 0x6312);
	}

	private List<Address> addrs(long... offsets) {
		List<Address> list = new ArrayList<>();
		for (long offset : offsets) {
			list.add(builder.addr(offset));
		}
		return list;
	}

	private List<Address> table() {
		return addrs(0xbd6b, 0xbd6d, 0xbd6f, 0xbd71, 0xbd73, 0xbd75, 0xbd77, 0xbd79, 0xbd7b);
	}

	@Test
	public void decompilerRecoveringExactlyTheTableStandsAside() {
		assertTrue(KeilSwitchOverrideAnalyzer.matchesTable(table(), table()));
	}

	@Test
	public void theDecompilersDefaultCaseIsAllowed() {
		// dailydriver's no-extension arm: 9 entries plus the default at 0xbdee, 10 targets.
		List<Address> recovered = new ArrayList<>(table());
		recovered.add(builder.addr(0xbdee));

		assertTrue("the decompiler folds the default into its cases; that is still a match",
			KeilSwitchOverrideAnalyzer.matchesTable(recovered, table()));
	}

	@Test
	public void anUnguardedRecoveryIsNotAMatch() {
		// Stock Ghidra without the guard fix: a case for every value the doubled index can take.
		List<Address> fabricated = new ArrayList<>();
		for (int i = 0; i < 128; i++) {
			fabricated.add(builder.addr(0xbd6b + 2L * i));
		}
		fabricated.add(builder.addr(0xbdee));

		assertFalse("128 fabricated cases against a real 9 must still get the override",
			KeilSwitchOverrideAnalyzer.matchesTable(fabricated, table()));
	}

	@Test
	public void aRecoveryMissingAnEntryIsNotAMatch() {
		List<Address> short_ = new ArrayList<>(table());
		short_.remove(8);

		assertFalse(KeilSwitchOverrideAnalyzer.matchesTable(short_, table()));
	}

	@Test
	public void twoExtraTargetsIsNotAMatch() {
		List<Address> recovered = new ArrayList<>(table());
		recovered.add(builder.addr(0xbdee));
		recovered.add(builder.addr(0xbe05));

		assertFalse("only the default is allowed as slack",
			KeilSwitchOverrideAnalyzer.matchesTable(recovered, table()));
	}

	@Test
	public void nothingRecoveredIsNotAMatch() {
		// 0xbcbf on every Ghidra: "Could not recover jumptable ... Too many branches".
		assertFalse(KeilSwitchOverrideAnalyzer.matchesTable(List.of(), table()));
	}
}
