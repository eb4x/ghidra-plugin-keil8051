# ghidra-plugin-keil8051

A Ghidra extension for 8051 firmware built with the **Keil C51** toolchain.

Raw 8051 images carry no headers, no symbols and no entry points, and Keil's code generator
puts data in the middle of the instruction stream. Stock auto-analysis therefore produces
almost nothing on them. This extension supplies the two pieces that get an image moving.

## Loader

`MStarModuleLoader` — **MStar 8051 multi-module flash image**. An MStar scaler image is a 1.26 MB
flash dump, and the 8051 code in it is not one program: it is several self-contained modules of at
most 64 KB, each addressed from `0x0000`, at arbitrary file offsets, separated by compressed
resources, `0xff` gaps and an ARM blob. Flat it cannot be loaded at all — the modules would overlap
in the 8051's single 16-bit code space. A module at a time it takes a hand calculation and a file
split each.

The loader finds the modules and creates one program per module, each with a single `rwx` `CODE`
block based at `0x0000`, named from the image's own sBoot firmware ID (`EIM152_020080`). It offers
itself only when it finds **two or more** modules; one module is Raw Binary's job.

Detection is by **vector table**, because these images have no header: a reset `LJMP` at the
module's first byte, plus at least three of the five interrupt vectors holding a jump or a `RETI`.
That is a heuristic over headerless data and is meant to be overridden — the **Module offsets**
option (`-loader-moduleOffsets`) takes an explicit list (`0x20080,0x30080,0x108000`) and
**Module size** (`-loader-moduleSize`) the length. Both carry a command-line arg because Ghidra's
`ProgramLoader` applies loader options by `Option.getArg()` alone; an option without one is
reachable only from the import dialog.

**A module without a vector table will not be found**, and that is not hypothetical: in the known
image the USB-PD/DP-alt-mode payload at `0x108000` begins `MOV A,#5; MOVX @DPTR,A` and the one at
`0x100000` begins with a Keil register-init prologue. Neither is a reset vector, so both need
explicit offsets.

## Analyzers

| analyzer | slot | what it does |
| --- | --- | --- |
| `Keil8051VectorAnalyzer` | BYTE, `FORMAT_ANALYSIS.after()` | Seeds functions at the reset vector (image base) and the interrupt vectors at base+0x03, +0x0b, +0x13, … so analysis has entry points at all. |
| `KeilSwitchTableAnalyzer` | INSTRUCTION, `CODE_ANALYSIS.before()` | Recovers the inline case tables that follow `LCALL ?C?CCASE` / `?C?ICASE` / `?C?LCASE`. |
| `KeilJumpTableAnalyzer` | INSTRUCTION, `CODE_ANALYSIS.before()` | Recovers Keil's bounded `AJMP`-table switches, reading the case count from the compiler's own range check. |
| `KeilSwitchOverrideAnalyzer` | INSTRUCTION, `FUNCTION_ANALYSIS.after()` | Writes the decompiler jump-table override for those switches. Without it the decompiler re-invents the unbounded table on its own. |

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

### AJMP jump tables

Keil's other `switch` shape is an inline range check and a table of `AJMP` instructions:

```
CJNE A,#0x09,$+0     ; the bound -- CJNE is here only for its carry
JC   $+2
AJMP default
MOV  DPTR,#table
ADD  A,ACC           ; index * 2
JMP  @A+DPTR
table: AJMP case0 / AJMP case1 / ...   ; exactly <bound> two-byte entries
```

Nothing in the bytes marks the end of that table — only the `CJNE #n` does. Ghidra does not read it
as a bound, so its own switch recovery runs off the end: in the GL3523 L2 hub firmware it turns a
nine-entry table into **129 cases**, relabelling unrelated code as case targets and leaving the
decompiler to report `Unable to resolve constructor` and `Could not follow disassembly flow into
non-existing memory` as it follows them.

This analyzer reads the bound, verifies exactly that many `AJMP` slots, and lays down one
`COMPUTED_JUMP` per case — which also stops `DecompilerSwitchAnalyzer` creating its case labels,
since it skips any computed branch that already carries computed references. On a program analyzed
before the extension was installed,
a one-shot re-run additionally deletes the fabricated case references and their `switchD_*::caseD_*`
labels. It does **not** delete functions the stock analyzer created at fabricated targets: some of
those addresses are genuinely code, and that is not a call to make on a guess.

**Fixing the references is not enough on its own.** The decompiler recovers jump tables from its
own p-code and pays no attention to the references already on the branch, so left alone it still
reads `CJNE A,#n` as an ordinary comparison rather than a bound and still emits all 129 cases.
`KeilSwitchOverrideAnalyzer` writes a real jump-table override
(`<func>::override::jmp_<branch>`, read back by `HighFunction.grabOverrides()`), which is the part
that actually silences it. It runs after `FUNCTION_ANALYSIS` because an override has nowhere to
live until the branch sits inside a defined function.

**A dispatch whose bound cannot be read is left alone** — guessing a table length is the very
mistake being repaired.

### Interrupt vectors

8051 hardware fixes the entry points: reset runs from offset 0 and every interrupt enters at
`0x03 + 8n`. Those offsets are relative to **where the image was loaded**, not to absolute zero,
which is what makes this work for an image based somewhere other than 0.

A slot is skipped when its three bytes are all `0x00` or all `0xff` — the two fill patterns an
unused vector carries. The vector count is an analyzer option (default 32); the classic 8051 has 5,
but derivatives extend the table in the same 8-byte steps.

**Not every 8051 image has a vector table.** A module that is called rather than reset into — the
USB-PD payload in the MStar image begins `MOV A,#5; MOVX @DPTR,A`, mid-routine — has ordinary code
where its vectors would be. The interrupt vectors are therefore seeded only when the reset slot
actually holds a jump, which is what a vector table always starts with; without one, only the
module's first byte is seeded, as a plain `entry`. Measured on that payload: the guard drops 9
fabricated entry points named after interrupts the module does not have, at a cost of about 5% of
the functions (637 → 606). **Seed vectors without a reset jump** turns the guard off when reach
matters more than that.

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
