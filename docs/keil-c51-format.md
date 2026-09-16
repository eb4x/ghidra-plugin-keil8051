# Keil C51 code shapes, as verified

Everything here was read out of real images with the Ghidra MCP tools. Where something has not
been verified, it says so rather than guessing.

## Corpus

| image | loaded as | notes |
| --- | --- | --- |
| GL3523 L2 hub FW6964 | Raw Binary, `8051:BE:16:default`, base `0x8000`, 25362 bytes | the switch-table reference case |
| GL3523 L1 hub FW6952 | same | `?C?CCASE` at `0xbc89` |
| MStar scaler (HP Z27k G3) | Raw Binary, base 0, common `0x0000-0x7fff` + one bank at `0x8000-0xffff` | all three case helpers present |

## The case helpers

A `switch` Keil does not compile to a jump table becomes `LCALL ?C?xCASE` followed immediately by
an inline table. The helper pops its own return address — that address *is* the table pointer —
walks the table, and jumps to the match. **It never returns to the call site.**

Identification is by library body, because these images carry no symbols. The bodies are stable:
the `CCASE` body at `0xc176` in the L2 hub image is byte-for-byte the one at `0x25db` in the
scaler image.

### `?C?CCASE` — `char` cases

Found at hub `0xc176`, scaler `0x25db`. Switch value arrives in A.

```
d0 83     POP  DPH             ; return address = table pointer
d0 82     POP  DPL
f8        MOV  R0,A            ; R0 = switch value
e4        CLR  A
93        MOVC A,@A+DPTR       ; tbl[0] - target high
70 12     JNZ  compare
74 01     MOV  A,#1
93        MOVC A,@A+DPTR       ; tbl[1] - target low
70 0d     JNZ  compare
a3 a3     INC  DPTR x2         ; zero target = terminator; default follows
93        MOVC A,@A+DPTR       ; -- shared tail: load target into DPTR and jump
f8        MOV  R0,A
74 01     MOV  A,#1
93        MOVC A,@A+DPTR
f5 82     MOV  DPL,A
88 83     MOV  DPH,R0
e4        CLR  A
73        JMP  @A+DPTR
compare:
74 02     MOV  A,#2
93        MOVC A,@A+DPTR       ; tbl[2] - case value
68        XRL  A,R0
60 ef     JZ   tail            ; match -> jump to tbl[0..1]
a3 a3 a3  INC  DPTR x3         ; entry stride = 3
80 df     SJMP loop
```

### `?C?ICASE` — `int` cases

Found at scaler `0x2601`. Switch value arrives in B:A (high:low). Identical except the compare:

```
74 02 93  MOVC A,@A+DPTR       ; value high byte
b5 f0 06  CJNE A,B,next
74 03 93  MOVC A,@A+DPTR       ; value low byte
68        XRL  A,R0
60 e9     JZ   tail
a3 a3 a3 a3  INC DPTR x4       ; entry stride = 4
```

### `?C?LCASE` — `long` cases

Found at scaler `0x262e`. Value compared byte by byte against R4, R5, R6, R7
(`6c 6d 6e 6f` = `XRL A,Rn`); entry stride 6 (`a3` x6).

## The table

```
LCALL ?C?xCASE
DW target0 (big-endian)   <value0>      <- entry, 2 + valueSize bytes
DW target1                <value1>
...
DW 0x0000                               <- terminator
DW default_target
```

Target first, value second. Length = `entrySize * cases + 4`.

Verified whole, byte for byte, at both L2 hub call sites:

| call site | table | cases | default | table end |
| --- | --- | --- | --- | --- |
| `0x8811` | `0x8814` | 10 | `0x8b2b` | `0x8836` |
| `0xa3a5` | `0xa3a8` | 12 | `0xa43e` | `0xa3d0` |

Independently confirmed by the `hp-z27k-g3` session against its own copy of the L2 hub program:
same entry order, same ten targets and values, same default and same table end, and its
disassembly of the helper at `0xc176` matches the decode above. The entry order is not an
inference — the reverse reading ("value first") makes the first entry of both tables point at
`0x2900` / `0x3c00`, below the CODE block and unmapped, which is what the parser's
out-of-range check rejects.

In both, the byte after the table is itself a case target (`0x8836` is case `0x04`; `0xa3d0` is
case `0x08`), which is why flow resumes correctly once the targets are disassembled — there is no
need to "resume after the terminator" as a separate step.

## Decompiling a `?C?xCASE` switch

Recovering the table fixes the **listing**, not the decompiler. The decompiler ignores a call
site's cleared fall-through, treats the helper as a call that returns, and decodes the table bytes
after it as instructions. GL3523 L2 hub, function `0x8800` (whose entry is reached only indirectly,
which is why this went unnoticed — no function contained `0x8811` to decompile):

```
keil_ccase_switch(DAT_INTMEM_6c,0,DAT_INTMEM_6f);
nop(); INTMEM29 = param_2; SFR95 = Var2; SFR88 = Var1 + 1; ...     <- the table at 0x8814
```

The fix, settled with `dailydriver` as extension territory rather than core:

- Each helper gets a **call-fixup**, installed as a compiler-spec extension and bound with
  `Function.setCallFixup`. Its body is one indirect branch on the switch value —
  `local t:2 = zext(ACC); goto [t];` for `?C?CCASE` — so the decompiler sees a `BRANCHIND` at the
  call site instead of a returning call.
- A **jump-table override** keyed at the call site supplies the destinations: the cases plus the
  default, deduplicated. Injected ops carry the call site's address, which is how the override
  attaches to the injected branch.

Result, verified by a unit test running the real decompiler on these bytes:

```
switch(DAT_INTMEM_6c) {        <- the value the prologue loaded into A
case 0x8836: ...               <- ten destinations: nine case bodies and the default 0x8b2b
```

Two limits. Case labels are **addresses**, not the case values: a `basicoverride` carries
destinations only, and it can derive values only by emulating a data-flow path from the switch
variable to the branch — here the mapping is a table the helper walks, so there is none. And for
`?C?LCASE` the displayed switch value is `R6:R7` only, since a 32-bit value cannot fit a 16-bit code
address; its destinations are still exact.

If the extension cannot be installed, the helper is marked no-return instead, which stops the table
being read as code but shows no switch.

## Not case helpers

Two nearby routines also pop their return address to read inline data, and must not be confused
with the case helpers:

- scaler `0x271b` / `0x2734` — inline-constant loaders (read 5 bytes into `@R0`, then `JMP @A+DPTR`).
- hub `0xd19f`, L1 hub `0xc792` — `POP DPH; POP DPL; POP ACC; RET`.

## The other switch idiom: a bounded AJMP table

Keil has a second `switch` shape, used when the cases are dense and every body is in reach. It is
not a helper call at all — it is an inline range check and a table of `AJMP` instructions:

```
bd5d  ee           MOV  A,R6
bd5e  b4 09 00     CJNE A,#0x09,$+0   ; the bound; CJNE is here only for its carry
bd61  40 02        JC   $+2
bd63  a1 ee        AJMP default
bd65  90 bd 6b     MOV  DPTR,#0xbd6b  ; table base
bd68  25 e0        ADD  A,ACC         ; index * 2 = AJMP entry size
bd6a  73           JMP  @A+DPTR
bd6b  a1 7d        AJMP 0xbd7d        ; case 0   -- exactly <bound> entries
bd6d  a1 7f        AJMP 0xbd7f        ; case 1
...
bd7b  a1 d3        AJMP 0xbdd3        ; case 8
bd7d  80 60        SJMP ...           ; past the table
```

`AJMP` takes address bits 10-8 from the three high opcode bits and the rest of the page from the
address of the *following* instruction, so an entry can only reach within its own 2 KB page.

**Nothing in the bytes marks the end of the table.** The only thing that does is the compiler's own
`CJNE #n` / `JC`. Ghidra does not read it that way, so `DecompilerSwitchAnalyzer` treats the index
as unbounded and fabricates a case for every value the doubled index can take: at `0xbd4f` in the
L2 hub image that is **129 cases for a 9-entry table**, `caseD_0` through `caseD_fe`, all of it
unrelated code relabelled. Two of the resulting decompiler errors are visible in the log:

- `Unable to resolve constructor at CODE:be05` — the real instruction is `90 00 a5`
  (`MOV DPTR,#0x00a5`) at `0xbe03`, so `0xbe05` is the byte `a5`, the 8051's one undefined opcode.
- `Could not follow disassembly flow into non-existing memory at CODE:047f` — flow followed out of
  the fabricated cases and off the loaded image, which is based at `0x8000`.

### Two dispatch shapes

`AJMP` entries are two bytes, so `ADD A,ACC` can carry out of the low byte of the table address
whenever `2 * bound` could exceed `0xff` from the table base. Keil covers that with a fix-up, and
emits it on the evidence of the bound alone — so it appears even when it is dead at run time:

```
bcad  ef        MOV  A,R7
bcae  14        DEC  A             ; cases start at 1
bcaf  b4 1c 00  CJNE A,#0x1c,$+3   ; bound 28
bcb2  40 02     JC   bcb6
bcb4  a1 4c     AJMP bd4c          ; default
bcb6  90 bc c0  MOV  DPTR,#0xbcc0
bcb9  25 e0     ADD  A,ACC
bcbb  50 02     JNC  bcbf          ; page-carry fix-up: dead here (2 * 27 = 54), present anyway
bcbd  05 83     INC  DPH
bcbf  73        JMP  @A+DPTR
```

A matcher anchored on `ADD A,ACC` immediately followed by `JMP @A+DPTR` skips this entirely, which
is what happened to `0xbcbf` in the L2 hub image until `hp-z27k-g3` reported it. Both shapes are
now matched. Its 28-entry table at `0xbcc0` also mixes pages `0xbc` (`81 xx`) and `0xbd` (`a1 xx`),
which the per-entry `AJMP` decode already handled since each entry takes its page from its own
following instruction.

`DEC A` immediately before the bound is Keil's "cases do not start at zero" idiom: table slot `i`
is case `i + 1`, and the analyzer labels them accordingly.

`KeilJumpTableAnalyzer` reads the bound from the range check, verifies exactly that many `AJMP`
slots, and lays down one `COMPUTED_JUMP` per case. A dispatch whose bound cannot be read is left
alone: the failure being fixed is a table walked past its end, and guessing a length would be the
same mistake again.

**References alone do not fix the decompiler.** They stop `DecompilerSwitchAnalyzer` creating the
129 case labels — measurable, and confirmed on a fresh import: nine references off `0xbd6a` and no
`switchD_` symbol anywhere in the program. But the decompiler recovers jump tables itself, from its
own p-code, and ignores the references already on the branch; left at that it still produces all
129 cases and both warnings. `KeilSwitchOverrideAnalyzer` writes a real jump-table override
(`<func>::override::jmp_<branch>`, read back through `HighFunction.grabOverrides()`), which is what
actually silences it.

### Where the underlying fix belongs

Raised with the `dailydriver` session, which read the source rather than guessing. Their findings,
recorded here so nobody repeats the dead end:

- **It is not the 8051 Sleigh semantics.** `8051_main.sinc:745` gives `CJNE A,#data8,rel8` the
  semantics `compflags(ACC,Data); if (ACC!=Data) goto Rel8`, and `compflags` is
  `CY = (op1 < op2)` — a plain `INT_LESS` into the carry bit, which is exactly the shape
  `jumptable.cc`'s guard analysis wants. There is nothing to fix in the carry model. An earlier
  guess of mine that the Sleigh semantics might be at fault was wrong.
- **It is architecture-neutral.** `JumpBasic::analyzeGuards` is generic, and the idiom — compare,
  conditional branch, scale the index, jump into a table of jump instructions — is the classic
  branch-table form on 6502, Z80, 68k and Thumb `TBB` too, not a Keil quirk.
- **Root cause, found by `dailydriver` in stock headless Ghidra with no extension present.** The
  carry is not a varnode: `8051_main.sinc:213` defines it as `@define CY "PSW[7,1]"`, a bit-field of
  `PSW`, so every write is a read-modify-write of the whole register and every read is a
  shift-and-test. The raw p-code for `CJNE A,#0x9` / `JC` is:

  ```
  u700  = PSW & 0x7f
  u600  = ACC <u 9            <- the bound, exactly as compflags promises
  u800  = u600 << 7
  PSW   = u700 | u800
  ...
  ua900 = PSW >> 7
  uaa00 = ua900 != 0
  CBRANCH bd65, uaa00
  ```

  Getting from the `JC`'s branch condition back to `ACC <u 9` means pulling back through five ops
  (`INT_NOTEQUAL`, `INT_RIGHT`, `INT_OR`, `INT_LEFT`, `INT_LESS`). `JumpBasic::analyzeGuards` in
  `jumptable.cc` gives up at `maxpullback = 2`, so no guard range is ever recorded and
  `findSmallestNormal` falls through to the doubled value at its full 8-bit width with stride 2 —
  which is the 128-plus-default, and the `caseD_0`…`caseD_fe` stepping by 2, seen from the other
  end.

  Two things confirm it rather than merely fitting it. The full decompiler *does* simplify that
  chain — stock output prints the guard cleanly as `if (8 < puVar4) return puVar4;` — but jump-table
  recovery runs early, on a partially staged function, so the guard analysis only ever sees the raw
  bit-field form. And both warnings reproduce verbatim in stock headless Ghidra on a hand-created
  function at `0xbd4f` with no auto-analysis at all.

  **Nothing about this is 8051-specific.** Any processor whose flags are bit-fields of a status word
  rather than standalone registers hits it the moment a compiler guards a jump table with one. My
  earlier guess that the doubling was to blame was wrong; so was the guess before it that the guard
  *shape* went unrecognised.

**The override is not only a stopgap.** `dailydriver`'s fix (raised pullback budget plus an
`INT_LEFT` pullback in `CircleRange`) recovers `0x89b6`, `0xa81c` and `0xbd6a` exactly in stock
Ghidra — but **not** `0xbcbf`, and neither does stock. Both builds give up there with
*"Could not recover jumptable at 0xbcbf. Too many branches"* and render an indirect call:

```
sVar2 = -0x4340;
if (CARRY1(bVar1,bVar1)) sVar2 = -0x4240;
(*(code *)(sVar2 + (ushort)(bVar1 * '\x02')))();
```

The guard and the `DEC A` are both handled fine in their build; the blocker is the page-carry
fix-up. The table base is a select between two constants that depends on a branch, and the
jump-table model wants one data-flow path from a single switch variable to the jump. The only value
both inputs share is the final address, which ranges over 65536 values — hence "too many branches".
Fixing it needs either range-based dead-branch folding (proving `CARRY1(bVar1,bVar1)` is always
false once the guard holds) or a model that follows a select depending on the index; both are
larger changes, noted upstream as a follow-up rather than folded into that PR.

So for the page-carry shape this extension is the only thing that recovers the table at all, before
or after the core fix ships. For the other three the override will simply agree with what the
decompiler finds on its own.

## Verified on fresh imports

With the extension loaded, four raw imports (Raw Binary, `8051:BE:16:default`), each analysed once
with no manual work, and deleted afterwards:

| program | base | vectors seeded | case helpers | tables recovered | functions |
| --- | --- | --- | --- | --- | --- |
| GL3523 L2 hub | `0x8000` | 10 | `?C?CCASE` @ `0xc176` | `0x8814` (10 cases), `0xa3a8` (12) | 282 |
| GL3523 L1 hub | `0x8000` | 10 | `?C?CCASE` @ `0xbc89` | `0x8814` (10 cases), `0xa13c` (12) | 226 |
| USB-PD module (file `0x108000`, 64 KB) | 0 | 10 | all three | none — no call sites in this module | 637 |
| main scaler firmware (file `0x20080`, 64 KB) | 0 | 10 | none | none | 65 |

With the `AJMP` analyzers added, a re-import of the L2 hub image gives nine references off
`0xbd6a`, no `switchD_` symbol anywhere, an override reported `CONSUMED (9 cases -> 9 distinct
targets)`, and no `pcode error` in the application log at all. `vendor_req_A1_isp_mode_switch`
decompiles to a nine-case `switch` under `if (bVar1 < 9)` instead of the 129-case listing full of
`halt_baddata()`.

The L2 hub image has four `AJMP` dispatches: `0x89b6` (bound `0x0b`, 11 cases), `0xa81c`
(`0x08`, 8), `0xbd6a` (`0x09`, 9) and `0xbcbf` (`0x1c`, 28 — the page-carry shape, with `DEC A` so
its cases run 1 to 28). The overrides at `0xa81c` and `0xbd6a` both report `CONSUMED`; `0xa800`'s two log
warnings (`pcode error at CODE:f0d2` and `at CODE:2109`) come from `0xa81c` and are gone with it.

Independently confirmed by `hp-z27k-g3` on its hand-curated L2 program, running both one-shots in
order: nine cases under `if (bVar1 < 9)`, "Switch is manually overridden", no `halt_baddata()`,
override `CONSUMED (9 cases -> 9 distinct targets)`, and its own names and comments intact through
both passes. The recovered cases turned out to be readable semantics for the hub's ISP-mode vendor
request — wValue lo 0 leaves ISP, 1 enters it, 3/5/6 flip boot flags in XDATA `0x06ff`, 7/8 send a
DDC/CI write frame with op `0xf6` — which that session had previously only characterised from
observed USB traffic.

The main scaler module contains **no** `JMP @A+DPTR` at all, so this idiom is not what limits it to
65 functions in 64 KB. Whatever reaches the rest of that module, it is not a Keil `AJMP` switch.

Two results worth keeping:

- The L2 hub's hand-curated copy has 253 functions after manual work; the fresh import reaches 282
  with none. The switch at `0x8811` is in a region auto-analysis never reaches by flow, and it is
  recovered anyway.
- The main scaler firmware contains the inline-constant loaders, which also pop their return
  address. They were **not** matched as case helpers, which is the negative case that matters.
  Their addresses depend on what you anchor to: the first routine is `0x0465`, where the pop pair
  is also the entry; the second's entry is `0x047e` (`MOV R0,DPL; MOV B,DPH`) with its pop pair at
  `0x0483`. A caller lands on `0x047e`. Nothing in this extension names either — they are matched
  by nothing, which is the point.

## "Banked" code — there is no software bank switching

Investigated and **disproved**. The MStar (MST9U) scaler image is not banked in any sense an
extension can help with, and the overlay-block-per-bank plus bank-switch-stub model — the obvious
port of rtlink's DOS-overlay playbook — buys nothing here, because there are no stubs.

Established by `hp-z27k-g3` in Ghidra:

- An image-wide search for the Keil banked-call shape `d0 83 d0 82` finds **only** inline-constant
  loaders. In the main firmware at code `0x0465` and `0x047e`: both pop the return address, `MOVC`
  four bytes out of code space into IDATA/XDATA, and resume at return+4 via `MOV A,#4; JMP @A+DPTR`.
  Raw bytes at `0x0465`: `d0 83 d0 82 e4 93 f6 08 74 01 93 f6 08 74 02 93 f6 08 74 03 93 f6 74 04 73`.
  The `0x047e` variant swaps DPTR with B:R0 and calls a one-byte copy loop at `0x0495`. The same
  pair exists in the other module at `0x24b7`-`0x24cd`.
- Neither writes any SFR or XDATA bank latch; neither changes the code window. No bank number is
  passed anywhere, there is no inline `{bank, hi, lo}` descriptor, and no `?B_SWITCH`-style thunk.
- Each module is a self-contained ≤64 KB 8051 image (`0x0000`-`0xffff`) using plain `LCALL`/`LJMP`
  across the `0x8000` boundary.

The window switching is done **by the chip**, not by the code: the stub at file offset 0 programs
MStar flash-remap/MIU registers (XDATA `0x38a` bit 7, `0x393` = `0x5f`, `0x3a6` = `0x0e`,
`0xf80` = `0x1f`, `0xfb4` = 0) to select which 64 KB window the 8051 core sees.

### Module map of the 1.26 MB image

| file offset | what |
| --- | --- |
| `0x00000` | boot stub: programs the remap registers, then `SJMP $` |
| `0x1ffe0` | sBoot marker `MSVC0000S3\0SBT_YYMMDD...` |
| `0x20080-0x30080` | **main scaler firmware**, 64 KB; 8051 vector table right at `0x20080` (LJMPs at +0x00/+0x03/+0x0b/+0x13/+0x1b/+0x23) |
| `0x30080-0x40080` | EIM2xx panel variant, a second 64 KB copy |
| `0x100000`, `0x108000`, `0x110000` | a separate, self-contained USB-C Power Delivery / DisplayPort alt-mode module (VDM command-name string table at its code `0x4c7f`: `DiscoverID`, `DiscoverSVID`, `EnterMode`, `DPStatus`, `DPConfig`) |
| chunks 9-28, 36-39 | compressed resources |
| `0x118000` | mixed 8051 + ARM Thumb blob |

An earlier description of this image as "32 KiB common at `0x0000`-`0x7fff` plus a switched window
at `0x8000`-`0xffff`" was wrong and has been retracted by its author. Do not build on it.

### What was built instead: the module loader

`MStarModuleLoader` splits such an image into one program per module. Verified on
`HP_Z27kG3_EIM153_15100_20220322_Service.bin`: it auto-detects exactly the two modules at
`0x20080` and `0x30080`, names them `EIM152_020080` / `EIM152_030080` from the sBoot info block,
gives each an `rwx` `CODE` block at `0x0000`, and each then analyses to 10 seeded vectors and 65
functions — identical to a hand-split import, with no hand calculation.

Two findings from doing it:

- **The embedded firmware ID is `EIM152`, not `EIM153`.** The info block at `0x20000` holds the
  build date `20220322` at `+0x70` and the 6-character ID at `+0x78`, and that ID reads `EIM152`
  while the distributed file is named `..._EIM153_...`. The bytes are unambiguous.
- **Neither `0x100000` nor `0x108000` begins with a vector table.** `0x108000` is
  `74 05 f0` (`MOV A,#5; MOVX @DPTR,A`) and `0x100000` is `7b e1 7a 7a 79 94 78 3f`, a Keil
  register-init prologue. So the USB-PD/DP-alt-mode module is a payload that is called, not reset
  into, and the scan correctly refuses both. Loading it needs the explicit **Module offsets**
  option. It also means that importing that region as a raw 64 KB slice and letting
  `Keil8051VectorAnalyzer` seed "vectors" at `+0/+3/+0xb/...` seeds addresses that are not vectors
  at all — the code it reaches from them may still be real, but the entry points are not.

  Fixed: the analyzer now seeds the interrupt vectors only when the reset slot holds a jump, and
  names a vector-less module's first byte `entry` rather than `reset`. Measured on that payload,
  the guard drops 9 fabricated entry points at a cost of about 5% of the functions (637 → 606);
  the **Seed vectors without a reset jump** option restores the old behaviour for anyone who wants
  the reach. Suggested by `hp-z27k-g3` after the finding above.
