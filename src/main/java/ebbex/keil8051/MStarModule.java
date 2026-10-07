package ebbex.keil8051;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;

/**
 * One self-contained 8051 module found inside a larger flash image.
 *
 * @param offset where the module starts in the file
 * @param length how many bytes it occupies, at most 64 KB
 * @param name a name for the program this module becomes
 */
public record MStarModule(long offset, int length, String name) {

	/**
	 * A module is at most a full 8051 code space. Nothing addresses past {@code 0xffff}, so a longer
	 * run of bytes is two modules or a module plus data, never one module.
	 */
	public static final int MAX_MODULE_SIZE = 0x10000;

	/** The reset vector, then the interrupt vectors, which is what identifies a module start. */
	private static final int[] VECTOR_OFFSETS = { 0x03, 0x0b, 0x13, 0x1b, 0x23 };

	private static final int LJMP = 0x02;
	private static final int RETI = 0x32;

	/**
	 * How many of the five interrupt vectors must hold a jump or a {@code RETI} before a candidate
	 * is believed. Three of five is deliberately loose: a module that services only a couple of
	 * interrupts is ordinary, and the reset {@code LJMP} at offset 0 is required on top of this.
	 */
	private static final int MIN_INTERRUPT_VECTORS = 3;

	/**
	 * Candidates are tested every 128 bytes. The modules in the MStar images sit at {@code 0x20080},
	 * {@code 0x30080} and {@code 0x108000} — aligned to 128 but emphatically not to 64 KB, so a
	 * coarser stride would miss them and a finer one only costs time.
	 */
	private static final int SCAN_STRIDE = 0x80;

	/** The sBoot marker that precedes the image's info block, used to name the modules. */
	private static final String SBOOT_MARKER = "MSVC0000S3";

	/** Distance from the marker to the info block, and from there to the firmware ID. */
	private static final int INFO_BLOCK_FROM_MARKER = 0x20;
	private static final int FIRMWARE_ID_IN_INFO_BLOCK = 0x78;
	private static final int FIRMWARE_ID_LENGTH = 6;

	/** How far into the file to look for the marker before giving up on naming. */
	private static final long MARKER_SEARCH_LIMIT = 0x40000;

	/**
	 * Every 8051 module in the image, in file order and non-overlapping.
	 * <p>
	 * A module is recognised by its vector table alone — a reset {@code LJMP} at its first byte and
	 * enough of the interrupt vectors behind it — because that is the only structure an 8051 image
	 * is guaranteed to have. There is no header to read: these images carry none.
	 */
	public static List<MStarModule> findAll(ByteProvider provider) throws IOException {
		String firmwareId = readFirmwareId(provider);
		long length = provider.length();

		List<MStarModule> modules = new ArrayList<>();
		long offset = 0;
		while (offset + VECTOR_OFFSETS[VECTOR_OFFSETS.length - 1] < length) {
			if (!isModuleStart(provider, offset)) {
				offset += SCAN_STRIDE;
				continue;
			}
			int size = (int) Math.min(MAX_MODULE_SIZE, length - offset);
			modules.add(new MStarModule(offset, size, name(firmwareId, offset)));
			// Skip the module's own body: a vector table inside it is not a second module.
			offset += size;
		}
		return List.copyOf(modules);
	}

	/**
	 * A module at an offset the caller chose rather than one the scan found, named the same way as
	 * a scanned one: from the image's sBoot firmware ID where there is one.
	 */
	public static MStarModule at(ByteProvider provider, long offset, int length) throws IOException {
		return new MStarModule(offset, length, name(readFirmwareId(provider), offset));
	}

	/** True when the bytes at {@code offset} look like the start of an 8051 image. */
	private static boolean isModuleStart(ByteProvider provider, long offset) throws IOException {
		if ((provider.readByte(offset) & 0xff) != LJMP) {
			return false;
		}
		int vectors = 0;
		for (int vector : VECTOR_OFFSETS) {
			if (offset + vector >= provider.length()) {
				return false;
			}
			int opcode = provider.readByte(offset + vector) & 0xff;
			if (opcode == LJMP || opcode == RETI) {
				vectors++;
			}
		}
		return vectors >= MIN_INTERRUPT_VECTORS;
	}

	/**
	 * The 6-character firmware ID from the image's info block, or {@code null} when the image has
	 * no sBoot marker. Only used for naming, so a miss costs nothing but a duller name.
	 */
	private static String readFirmwareId(ByteProvider provider) throws IOException {
		long marker = find(provider, SBOOT_MARKER.getBytes(StandardCharsets.US_ASCII));
		if (marker < 0) {
			return null;
		}
		long at = marker + INFO_BLOCK_FROM_MARKER + FIRMWARE_ID_IN_INFO_BLOCK;
		if (at + FIRMWARE_ID_LENGTH > provider.length()) {
			return null;
		}
		String id = new String(provider.readBytes(at, FIRMWARE_ID_LENGTH), StandardCharsets.US_ASCII);
		return id.chars().allMatch(c -> c > 0x20 && c < 0x7f) ? id : null;
	}

	private static long find(ByteProvider provider, byte[] needle) throws IOException {
		long limit = Math.min(provider.length(), MARKER_SEARCH_LIMIT) - needle.length;
		for (long at = 0; at <= limit; at++) {
			if (matches(provider, at, needle)) {
				return at;
			}
		}
		return -1;
	}

	private static boolean matches(ByteProvider provider, long at, byte[] needle) throws IOException {
		for (int i = 0; i < needle.length; i++) {
			if (provider.readByte(at + i) != needle[i]) {
				return false;
			}
		}
		return true;
	}

	private static String name(String firmwareId, long offset) {
		String where = "%06x".formatted(offset);
		return firmwareId == null ? "module_" + where : firmwareId + "_" + where;
	}
}
