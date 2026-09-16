package ebbex.keil8051;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Splits a flash image that holds several independent 8051 modules into one program per module.
 * <p>
 * <b>Why.</b> An MStar scaler image is a 1.26 MB flash dump, and the 8051 code in it is not one
 * program: it is several self-contained modules of at most 64 KB, each addressed from
 * {@code 0x0000}, at arbitrary offsets in the file, separated by compressed resources, {@code 0xff}
 * gaps and an ARM blob. Nothing links them — each has its own vector table and its own copy of the
 * Keil library. Imported flat the image cannot be loaded at all, since the modules would overlap in
 * the 8051's single 16-bit code space; imported as Raw Binary a module at a time, it takes a hand
 * calculation and a file split per module.
 * <p>
 * <b>What this does.</b> It finds the modules by their vector tables and creates one program for
 * each, named from the image's own sBoot firmware ID where there is one
 * ({@code EIM153_020080}). Each program holds a single initialized {@code CODE} block based at
 * {@code 0x0000}, which is where that module's code really runs, so
 * {@link Keil8051VectorAnalyzer} seeds its vectors and the rest of the extension applies unchanged.
 * <p>
 * <b>Detection is by vector table, not by header</b>, because these images have no header: a reset
 * {@code LJMP} at the module's first byte and at least three of the five interrupt vectors holding
 * a jump or a {@code RETI}. See {@link MStarModule}. The loader only offers itself when it finds
 * <i>two or more</i> modules — a file with one is an ordinary raw binary and Raw Binary should
 * handle it.
 * <p>
 * The offsets can be given explicitly when the scan is wrong; see the {@code Module offsets} option.
 * Detection is a heuristic over headerless data and is expected to be overridden sometimes — an
 * image region can hold 8051-looking bytes without being a module, and the ARM/8051 blob at
 * {@code 0x118000} in the known image is exactly the sort of thing that has to be excluded by hand.
 */
public class MStarModuleLoader extends AbstractProgramLoader {

	public static final String LOADER_NAME = "MStar 8051 multi-module flash image";

	/**
	 * Comma-separated file offsets to load as modules (e.g. {@code 0x20080,0x30080,0x108000}).
	 * Empty means "use whatever the vector-table scan found".
	 */
	private static final String OPTION_OFFSETS = "Module offsets";

	/** Bytes to load per module, at most {@code 0x10000} — the whole 8051 code space. */
	private static final String OPTION_SIZE = "Module size";

	/**
	 * Every option needs a command-line arg. Ghidra's {@code ProgramLoader} applies options by
	 * {@link Option#getArg()} alone — it is the {@code analyzeHeadless} path — so an option built
	 * without one cannot be set from anywhere but the import dialog.
	 */
	private static final String ARG_OFFSETS = "-loader-moduleOffsets";
	private static final String ARG_SIZE = "-loader-moduleSize";

	/** The language every module is loaded with; all of them are plain 8051. */
	private static final LanguageCompilerSpecPair LANGUAGE =
		new LanguageCompilerSpecPair("8051:BE:16:default", "default");

	/** A single module is Raw Binary's job; this loader is for images that hold several. */
	private static final int MIN_MODULES = 2;

	private static final String BLOCK_NAME = "CODE";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	/** Several programs come out of one file, so they belong in a folder of their own. */
	@Override
	public boolean loadsIntoNewFolder() {
		return true;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (provider.length() < MStarModule.MAX_MODULE_SIZE) {
			return List.of();
		}
		if (MStarModule.findAll(provider).size() < MIN_MODULES) {
			return List.of();
		}
		return List.of(new LoadSpec(this, 0, LANGUAGE, true));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean isFsrl) {

		return List.of(
			new Option(OPTION_OFFSETS, "", String.class, ARG_OFFSETS),
			new Option(OPTION_SIZE, MStarModule.MAX_MODULE_SIZE, Integer.class, ARG_SIZE));
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {

		for (Option option : options) {
			if (OPTION_SIZE.equals(option.getName())) {
				int size = (int) option.getValue();
				if (size < 1 || size > MStarModule.MAX_MODULE_SIZE) {
					return "Module size must be between 1 and 0x10000";
				}
			}
			if (OPTION_OFFSETS.equals(option.getName()) && parseOffsets(option) == null) {
				return "Module offsets must be a comma-separated list of numbers";
			}
		}
		return null;
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
			throws IOException, LoadException, CancelledException {

		ByteProvider provider = settings.provider();
		List<MStarModule> modules = modulesToLoad(provider, settings);
		if (modules.isEmpty()) {
			throw new LoadException("No 8051 modules found in " + settings.importName());
		}

		List<Loaded<Program>> loaded = new ArrayList<>();
		boolean complete = false;
		try {
			for (MStarModule module : modules) {
				settings.monitor().checkCancelled();
				Program program = createModuleProgram(module, settings);
				loaded.add(new Loaded<>(program, module.name(), provider.getFSRL(),
					settings.project(), settings.projectRootPath(), settings.mirrorFsLayout(),
					settings.consumer()));
			}
			complete = true;
		}
		finally {
			if (!complete) {
				loaded.forEach(Loaded::close);
			}
		}
		return loaded;
	}

	@Override
	protected void loadProgramInto(Program program, ImporterSettings settings) throws LoadException {
		throw new LoadException(LOADER_NAME + " creates one program per module and cannot add to " +
			"an existing program");
	}

	/**
	 * Builds one program: a single initialized {@code CODE} block holding the module's bytes at 0.
	 * <p>
	 * The block is backed by {@link FileBytes} covering the <i>whole</i> image, not just the
	 * module's slice, so that {@code Memory.locateAddressesForFileOffset} answers with true file
	 * offsets — asking where file offset {@code 0x108000} went gets {@code CODE:0000} of the module
	 * that came from there. Recording only the slice would make its offsets module-relative and the
	 * mapping useless, which is the whole reason for keeping them.
	 */
	private Program createModuleProgram(MStarModule module, ImporterSettings settings)
			throws IOException, CancelledException {

		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		Program program = createProgram(settings);
		Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);

		boolean success = false;
		int txId = program.startTransaction("load module");
		try {
			FileBytes fileBytes =
				MemoryBlockUtils.createFileBytes(program, settings.provider(), monitor);
			MemoryBlockUtils.createInitializedBlock(program, false, BLOCK_NAME, base, fileBytes,
				module.offset(), module.length(),
				"8051 module from file offset 0x%x".formatted(module.offset()), LOADER_NAME,
				true, true, true, log);
			// Without this every module reports the whole image's file name as its program name,
			// which makes several modules from one image indistinguishable in any listing of them.
			program.setName(module.name());
			log.appendMsg("%s: loaded 0x%x bytes from file offset 0x%x"
				.formatted(module.name(), module.length(), module.offset()));
			success = true;
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendException(e);
		}
		finally {
			program.endTransaction(txId, true);
		}

		if (!success) {
			program.release(settings.consumer());
			throw new IOException("could not create the CODE block for " + module.name());
		}
		return program;
	}

	/** The explicit offsets if the user gave any, otherwise whatever the scan found. */
	private List<MStarModule> modulesToLoad(ByteProvider provider, ImporterSettings settings)
			throws IOException {

		int size = MStarModule.MAX_MODULE_SIZE;
		List<Long> offsets = null;
		for (Option option : settings.options()) {
			if (OPTION_SIZE.equals(option.getName())) {
				size = (int) option.getValue();
			}
			if (OPTION_OFFSETS.equals(option.getName())) {
				offsets = parseOffsets(option);
			}
		}

		if (offsets == null || offsets.isEmpty()) {
			return MStarModule.findAll(provider);
		}

		List<MStarModule> modules = new ArrayList<>();
		for (long offset : offsets) {
			int length = (int) Math.min(size, provider.length() - offset);
			if (length > 0) {
				modules.add(new MStarModule(offset, length, "module_%06x".formatted(offset)));
			}
		}
		return modules;
	}

	/** Parses the offsets option, or returns {@code null} if it is malformed. */
	private static List<Long> parseOffsets(Option option) {
		Object value = option.getValue();
		if (value == null || value.toString().isBlank()) {
			return List.of();
		}
		List<Long> offsets = new ArrayList<>();
		for (String token : value.toString().split(",")) {
			String text = token.trim();
			try {
				offsets.add(text.toLowerCase().startsWith("0x")
					? Long.parseLong(text.substring(2), 16)
					: Long.parseLong(text));
			}
			catch (NumberFormatException e) {
				return null;
			}
		}
		return offsets;
	}
}
