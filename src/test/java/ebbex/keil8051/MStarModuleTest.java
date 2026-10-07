package ebbex.keil8051;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;

/**
 * Tests for {@link MStarModule}, the vector-table scan that finds independent 8051 modules inside a
 * flash image.
 * <p>
 * The layout mirrors the HP Z27k G3 scaler image: modules at offsets aligned to 128 but not to
 * 64 KB, an sBoot marker whose info block names them, and stretches of fill and non-8051 data in
 * between that must not be mistaken for modules.
 */
public class MStarModuleTest extends AbstractGenericTest {

	private static final int IMAGE_SIZE = 0x40000;

	/** Writes a plausible 8051 vector table: reset LJMP plus the five interrupt vectors. */
	private static void putVectorTable(byte[] image, int at) {
		image[at] = 0x02;
		image[at + 1] = (byte) 0x10;
		image[at + 2] = 0x00;
		for (int vector : new int[] { 0x03, 0x0b, 0x13, 0x1b, 0x23 }) {
			image[at + vector] = 0x02;
			image[at + vector + 1] = (byte) 0x20;
			image[at + vector + 2] = (byte) vector;
		}
	}

	private static ByteProvider image(byte[] bytes) {
		return new ByteArrayProvider(bytes);
	}

	@Test
	public void findsEveryModuleAndSkipsWhatIsBetweenThem() throws Exception {
		byte[] bytes = new byte[IMAGE_SIZE];
		java.util.Arrays.fill(bytes, (byte) 0xff);          // a gap, as the real image has
		putVectorTable(bytes, 0x00080);
		putVectorTable(bytes, 0x20080);

		List<MStarModule> modules = MStarModule.findAll(image(bytes));

		assertEquals(2, modules.size());
		assertEquals(0x00080, modules.get(0).offset());
		assertEquals(0x20080, modules.get(1).offset());
	}

	@Test
	public void aModuleIsAtMostTheWholeCodeSpace() throws Exception {
		byte[] bytes = new byte[IMAGE_SIZE];
		putVectorTable(bytes, 0);

		MStarModule module = MStarModule.findAll(image(bytes)).get(0);

		assertEquals("64 KB is the whole 8051 code space; nothing addresses past it",
			0x10000, module.length());
	}

	@Test
	public void aVectorTableInsideAModuleIsNotASecondModule() throws Exception {
		byte[] bytes = new byte[IMAGE_SIZE];
		putVectorTable(bytes, 0);
		// Data inside the first module that happens to look like a vector table.
		putVectorTable(bytes, 0x8000);

		List<MStarModule> modules = MStarModule.findAll(image(bytes));

		assertEquals(1, modules.size());
		assertEquals(0, modules.get(0).offset());
	}

	@Test
	public void fillAndRandomDataAreNotModules() throws Exception {
		byte[] zeros = new byte[IMAGE_SIZE];
		assertTrue("0x00 fill", MStarModule.findAll(image(zeros)).isEmpty());

		byte[] ones = new byte[IMAGE_SIZE];
		java.util.Arrays.fill(ones, (byte) 0xff);
		assertTrue("0xff fill", MStarModule.findAll(image(ones)).isEmpty());

		byte[] ljmpOnly = new byte[IMAGE_SIZE];
		ljmpOnly[0] = 0x02;      // a reset vector with nothing behind it
		assertTrue("a lone LJMP is not a vector table",
			MStarModule.findAll(image(ljmpOnly)).isEmpty());
	}

	@Test
	public void namesModulesFromTheSbootFirmwareId() throws Exception {
		byte[] bytes = new byte[IMAGE_SIZE];
		putVectorTable(bytes, 0x20080);
		// Marker at 0x1ffe0, so the info block is 0x20000 and the ID sits at 0x20078.
		byte[] marker = "MSVC0000S3".getBytes(StandardCharsets.US_ASCII);
		System.arraycopy(marker, 0, bytes, 0x1ffe0, marker.length);
		byte[] id = "EIM153".getBytes(StandardCharsets.US_ASCII);
		System.arraycopy(id, 0, bytes, 0x20078, id.length);

		assertEquals("EIM153_020080", MStarModule.findAll(image(bytes)).get(0).name());
	}

	@Test
	public void namesAModuleAtAnExplicitOffsetFromTheFirmwareIdToo() throws Exception {
		// The USB-PD payload at 0x108000 has no vector table, so it is only ever loaded this way.
		byte[] bytes = new byte[IMAGE_SIZE];
		byte[] marker = "MSVC0000S3".getBytes(StandardCharsets.US_ASCII);
		System.arraycopy(marker, 0, bytes, 0x1ffe0, marker.length);
		byte[] id = "EIM152".getBytes(StandardCharsets.US_ASCII);
		System.arraycopy(id, 0, bytes, 0x20078, id.length);

		MStarModule module = MStarModule.at(image(bytes), 0x30080, 0x100);
		assertEquals("EIM152_030080", module.name());
		assertEquals(0x30080, module.offset());
		assertEquals(0x100, module.length());
	}

	@Test
	public void namesAnExplicitModuleByOffsetWhenTheImageHasNoMarker() throws Exception {
		assertEquals("module_030080",
			MStarModule.at(image(new byte[IMAGE_SIZE]), 0x30080, 0x100).name());
	}

	@Test
	public void namesModulesByOffsetWhenTheImageHasNoMarker() throws Exception {
		byte[] bytes = new byte[IMAGE_SIZE];
		putVectorTable(bytes, 0x20080);

		assertEquals("module_020080", MStarModule.findAll(image(bytes)).get(0).name());
	}

	@Test
	public void threeOfFiveInterruptVectorsIsEnough() throws Exception {
		byte[] bytes = new byte[IMAGE_SIZE];
		bytes[0] = 0x02;
		bytes[0x03] = 0x02;
		bytes[0x0b] = 0x32;   // RETI is a real handler too
		bytes[0x13] = 0x02;
		// 0x1b and 0x23 left as 0x00: a module servicing only three interrupts

		assertEquals(1, MStarModule.findAll(image(bytes)).size());
	}

	@Test
	public void twoOfFiveIsNotEnough() throws Exception {
		byte[] bytes = new byte[IMAGE_SIZE];
		bytes[0] = 0x02;
		bytes[0x03] = 0x02;
		bytes[0x0b] = 0x02;

		assertTrue(MStarModule.findAll(image(bytes)).isEmpty());
	}
}
