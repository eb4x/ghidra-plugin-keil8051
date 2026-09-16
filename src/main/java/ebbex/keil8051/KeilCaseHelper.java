package ebbex.keil8051;


/**
 * The three Keil C51 library case helpers, identified by their (byte-identical) library bodies.
 * <p>
 * A {@code switch} that Keil does not turn into a jump table compiles to
 * {@code LCALL ?C?xCASE} followed <i>immediately</i> by the case table, inline in the instruction
 * stream. The helper pops its own return address off the stack — that address <i>is</i> the table
 * pointer — walks the table comparing the switch value, and jumps to the matching target. It never
 * returns to the call site, so the bytes after the {@code LCALL} are data, not code, and stock
 * disassembly runs straight into them.
 * <p>
 * All three share one table shape, verified against GL3523 hub firmware and the MStar scaler image:
 *
 * <pre>
 *   LCALL ?C?CCASE
 *   DW target0 (big-endian)   DB  value0      &lt;- entry, {@link #entrySize()} bytes
 *   DW target1                DB  value1
 *   ...
 *   DW 0x0000                                 &lt;- terminator
 *   DW default_target                         &lt;- taken when nothing matched
 * </pre>
 *
 * The target comes <i>first</i> and the value second; the value is {@link #valueSize()} bytes wide
 * (1 for {@code char}, 2 for {@code int}, 4 for {@code long}), which is the only thing that differs
 * between the three helpers. A table is therefore {@code entrySize * cases + 4} bytes long.
 * <p>
 * Matching is on the body bytes rather than on a symbol name because these images carry no symbols
 * at all. The bodies are stable Keil library code: the {@code CCASE} body found at {@code 0xc176} in
 * the GL3523 L2 hub image is byte-for-byte the one at {@code 0x25db} in the scaler image.
 */
public enum KeilCaseHelper {

	/** {@code ?C?CCASE} — {@code char}-sized cases; switch value in A, compared with {@code XRL A,R0}. */
	CCASE("keil_ccase_switch", "?C?CCASE", 1, "local t:2 = zext(ACC); goto [t];",
		"d0 83 d0 82 f8 e4 93 70 12 74 01 93 70 0d a3 a3 93 f8 74 01 93 f5 82 88 83 e4 73" +
		" 74 02 93 68 60 ef a3 a3 a3 80 df"),

	/** {@code ?C?ICASE} — {@code int}-sized cases; switch value in B:A, high byte compared with {@code CJNE A,B}. */
	ICASE("keil_icase_switch", "?C?ICASE", 2, "local t:2 = (zext(B) << 8) | zext(ACC); goto [t];",
		"d0 83 d0 82 f8 e4 93 70 12 74 01 93 70 0d a3 a3 93 f8 74 01 93 f5 82 88 83 e4 73" +
		" 74 02 93 b5 f0 06 74 03 93 68 60 e9 a3 a3 a3 a3 80 d8"),

	/** {@code ?C?LCASE} — {@code long}-sized cases; switch value in R4..R7, compared byte by byte. */
	LCASE("keil_lcase_switch", "?C?LCASE", 4, "local t:2 = (zext(R6) << 8) | zext(R7); goto [t];",
		"d0 83 d0 82 e4 93 70 12 74 01 93 70 0d a3 a3 93 f8 74 01 93 f5 82 88 83 e4 73" +
		" 74 02 93 6c 70 12 74 03 93 6d 70 0c 74 04 93 6e 70 06 74 05 93 6f 60 dd" +
		" a3 a3 a3 a3 a3 a3 80 ca");

	/** Bytes that terminate a table: a zero target word, followed by the default target word. */
	public static final int TERMINATOR_SIZE = 4;

	private final String label;
	private final String keilSymbol;
	private final int valueSize;
	private final String fixupBody;
	private final byte[] signature;

	KeilCaseHelper(String label, String keilSymbol, int valueSize, String fixupBody,
			String signatureHex) {
		this.label = label;
		this.keilSymbol = keilSymbol;
		this.valueSize = valueSize;
		this.fixupBody = fixupBody;
		this.signature = parseHex(signatureHex);
	}

	private static byte[] parseHex(String hex) {
		String[] tokens = hex.trim().split("\\s+");
		byte[] bytes = new byte[tokens.length];
		for (int i = 0; i < tokens.length; i++) {
			bytes[i] = (byte) Integer.parseInt(tokens[i], 16);
		}
		return bytes;
	}

	/** The name this analyzer gives the helper function. */
	public String label() {
		return label;
	}

	/** The name Keil's own linker map would use, recorded in the helper's plate comment. */
	public String keilSymbol() {
		return keilSymbol;
	}

	/** Width in bytes of a case value in this helper's tables. */
	public int valueSize() {
		return valueSize;
	}

	/** Size of one table entry: a 2-byte target plus the case value. */
	public int entrySize() {
		return 2 + valueSize;
	}

	/**
	 * The call-fixup injected in place of every call to this helper: a single indirect branch on
	 * the switch value.
	 * <p>
	 * The decompiler has no notion of a callee that consumes a table inline after its own call
	 * site. Replacing the call with an indirect branch gives it a switch to recover, and a
	 * jump-table override keyed at the call site then supplies the destinations. The branch
	 * target expression is there for the rendering only — the override decides where it goes —
	 * so it names the register the helper actually switches on: A for {@code char}, B:A for
	 * {@code int}. A {@code long} value is 32 bits and a code address 16, so {@code ?C?LCASE}
	 * can only show R6:R7, its low half.
	 */
	public String fixupBody() {
		return fixupBody;
	}

	/** The call-fixup as a compiler-spec extension document, named after {@link #label()}. */
	public String fixupExtension() {
		return "<callfixup name=\"" + label + "\"><pcode><body><![CDATA[ " + fixupBody +
			" ]]></body></pcode></callfixup>";
	}

	/** The library body used to recognise the helper in an image without symbols. */
	public byte[] signature() {
		return signature.clone();
	}
}
