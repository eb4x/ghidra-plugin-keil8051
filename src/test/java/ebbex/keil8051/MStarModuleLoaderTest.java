package ebbex.keil8051;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.Option;

/**
 * Tests for {@link MStarModuleLoader}'s option surface.
 * <p>
 * Ghidra's {@code ProgramLoader} applies loader options by {@link Option#getArg()} alone — it is
 * the {@code analyzeHeadless} path, and the MCP import tool uses it too — so an option built
 * without an arg cannot be set from anywhere but the import dialog. The explicit-offsets option
 * exists precisely for the cases the vector-table scan gets wrong, so it being unreachable from a
 * script would defeat its purpose.
 */
public class MStarModuleLoaderTest extends AbstractGenericTest {

	private List<Option> options() {
		return new MStarModuleLoader().getDefaultOptions(null, null, null, false, false);
	}

	@Test
	public void everyOptionIsSettableFromAScript() {
		List<Option> options = options();

		assertFalse("the loader must expose its options", options.isEmpty());
		for (Option option : options) {
			assertNotNull("option '" + option.getName() + "' has no command-line arg, so " +
				"ProgramLoader cannot apply it", option.getArg());
			assertTrue("option '" + option.getName() + "' arg should look like a flag",
				option.getArg().startsWith("-"));
		}
	}

	@Test
	public void offsetsDefaultToTheScanAndSizeToAWholeCodeSpace() {
		List<Option> options = options();

		Option offsets = options.stream().filter(o -> o.getName().equals("Module offsets"))
			.findFirst().orElseThrow();
		assertEquals("empty means 'use what the scan found'", "", offsets.getValue());
		assertEquals(String.class, offsets.getValueClass());

		Option size = options.stream().filter(o -> o.getName().equals("Module size"))
			.findFirst().orElseThrow();
		assertEquals(MStarModule.MAX_MODULE_SIZE, size.getValue());
		assertEquals(Integer.class, size.getValueClass());
	}

	@Test
	public void rejectsAMalformedOffsetListRatherThanImportingNothing() {
		MStarModuleLoader loader = new MStarModuleLoader();
		List<Option> bad = List.of(new Option("Module offsets", "0x20080,banana", String.class,
			"-loader-moduleOffsets"));

		assertNotNull("a typo must be reported, not silently ignored",
			loader.validateOptions(null, null, bad, null));
	}

	@Test
	public void rejectsAModuleSizeLargerThanTheCodeSpace() {
		MStarModuleLoader loader = new MStarModuleLoader();
		List<Option> bad = List.of(new Option("Module size", 0x20000, Integer.class,
			"-loader-moduleSize"));

		assertNotNull(loader.validateOptions(null, null, bad, null));
	}
}
