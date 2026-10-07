package ebbex.keil8051;

import static org.junit.Assert.*;

import java.io.StringReader;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.Test;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

/**
 * Tests for {@link KeilCaseHelper}: the table geometry each helper implies and the call-fixup
 * document installed into the compiler spec.
 */
public class KeilCaseHelperTest {

	@Test
	public void entrySizeIsTheTargetWordPlusTheValueWidth() {
		assertEquals(3, KeilCaseHelper.CCASE.entrySize());
		assertEquals(4, KeilCaseHelper.ICASE.entrySize());
		assertEquals(6, KeilCaseHelper.LCASE.entrySize());
	}

	@Test
	public void theCcaseSignatureIsTheThirtyEightByteLibraryBody() {
		byte[] signature = KeilCaseHelper.CCASE.signature();
		assertEquals(38, signature.length);
		// POP DPH; POP DPL — the return address becomes the table pointer.
		assertArrayEquals(new byte[] { (byte) 0xd0, (byte) 0x83, (byte) 0xd0, (byte) 0x82 },
			java.util.Arrays.copyOf(signature, 4));
	}

	@Test
	public void signatureIsADefensiveCopy() {
		KeilCaseHelper.CCASE.signature()[0] = 0;
		assertEquals((byte) 0xd0, KeilCaseHelper.CCASE.signature()[0]);
	}

	@Test
	public void eachFixupIsAWellFormedCallfixupNamedAfterItsLabel() throws Exception {
		for (KeilCaseHelper helper : KeilCaseHelper.values()) {
			Element root = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder()
					.parse(new InputSource(new StringReader(helper.fixupExtension())))
					.getDocumentElement();

			assertEquals("callfixup", root.getTagName());
			assertEquals(helper.label(), root.getAttribute("name"));
			assertEquals(helper.fixupBody(), root.getElementsByTagName("body").item(0)
					.getTextContent().trim());
		}
	}
}
