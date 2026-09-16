# ghidra-plugin-keil8051

A Ghidra extension for 8051 firmware built with the **Keil C51** toolchain.

Raw 8051 images carry no headers, no symbols and no entry points, and Keil's code generator
puts data in the middle of the instruction stream. Stock auto-analysis therefore produces
almost nothing on them. This extension supplies the two pieces that get an image moving.

## Analyzers

| analyzer | slot | what it does |
| --- | --- | --- |
| `Keil8051VectorAnalyzer` | BYTE, `FORMAT_ANALYSIS.after()` | Seeds functions at the reset vector (image base) and the interrupt vectors at base+0x03, +0x0b, +0x13, … so analysis has entry points at all. |
| `KeilSwitchTableAnalyzer` | INSTRUCTION, `CODE_ANALYSIS.before()` | Recovers the inline case tables that follow `LCALL ?C?CCASE` / `?C?ICASE` / `?C?LCASE`. |

Both set `setSupportsOneTimeAnalysis()`, so they can be re-run from **Analysis → One Shot** on an
already-analyzed program, and both are idempotent.

### Keil case tables

A `switch` that Keil does not turn into a jump table compiles to a call to a library helper with
the case table laid down *immediately after the call*:

```
LCALL ?C?CCASE
DW target0   DB value0      <- entry
DW target1   DB value1
...
DW 0x0000                   <- terminator
DW default_target
```

The helper pops its own return address to find that table, so it never returns to the call site.
Ghidra sees an ordinary `LCALL`, assumes it returns, and disassembles the table as code — which
wrecks the listing after every switch and leaves the case targets unreachable.

The analyzer finds the helpers by their library bodies (these images have no symbols to match),
parses each table, defines it as data, adds a `COMPUTED_JUMP` reference from the `LCALL` to every
case target and to the default, clears the call's fall-through, and disassembles the targets.

Three helpers, differing only in how wide a case value is:

| helper | case value | entry stride |
| --- | --- | --- |
| `?C?CCASE` | 1 byte (`char`) | 3 |
| `?C?ICASE` | 2 bytes (`int`) | 4 |
| `?C?LCASE` | 4 bytes (`long`) | 6 |

**The target comes first and the value second** — the ordering that is easy to get backwards.

Case targets are labelled `caseD_<value>` but deliberately *not* turned into functions: they are
blocks inside the switch's own function, and splitting them out would fragment it and cost the
decompiler the switch.

See `docs/keil-c51-format.md` for the decoded helper bodies and the evidence behind all of this.

### Interrupt vectors

8051 hardware fixes the entry points: reset runs from offset 0 and every interrupt enters at
`0x03 + 8n`. Those offsets are relative to **where the image was loaded**, not to absolute zero,
which is what makes this work for an image based somewhere other than 0.

A slot is skipped when its three bytes are all `0x00` or all `0xff` — the two fill patterns an
unused vector carries. The vector count is an analyzer option (default 32); the classic 8051 has 5,
but derivatives extend the table in the same 8-byte steps.

## Build & install

Requires JDK 21+ and a gitignored, project-local `gradle.properties` holding `GHIDRA_INSTALL_DIR`
(an extracted Ghidra install, used at build time for `support/buildExtension.gradle` and the API
jars) and optionally `GHIDRA_USER_EXTENSIONS_DIR` (where `installExtension` extracts the build).

```bash
./gradlew buildExtension     # -> dist/ghidra_<ver>_<date>_Keil8051.zip
./gradlew installExtension   # copy the zip into the Ghidra install + extract into user Extensions
./gradlew uninstallExtension # remove both again
./gradlew test               # the JUnit suite
```

Restart Ghidra after installing for the new build to load.

## Status

**Banked-code support is not needed on the known targets, and is not implemented.** The premise —
that the 1.26 MB MStar scaler image uses software bank switching that an analyzer could resolve
into thunks — was investigated and disproved: there is no bank-switch trampoline and no bank latch
in that firmware. It is several independent, self-contained ≤64 KB 8051 images at arbitrary flash
offsets, and the window switching is done by the chip's flash-remap registers. See
`docs/keil-c51-format.md` for the evidence and the corrected module map.

What that target would actually benefit from is import-time support for splitting such a flash
image into its modules. That is not built yet.
