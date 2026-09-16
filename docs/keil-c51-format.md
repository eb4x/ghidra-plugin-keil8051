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

Whether the underlying gap belongs in core — the decompiler not reading `CJNE A,#n` + `JC`/`JNC` as
a range check, on an architecture whose only compare-and-set-carry *is* `CJNE` — has been raised
with the `dailydriver` session. The override stays regardless until something lands upstream.

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

### What would actually help

Import-time support for **one flash image containing several independent ≤64 KB 8051 images at
arbitrary offsets** — pick offset and length, optionally a second copy — plus vector seeding at
each module's own base. `Keil8051VectorAnalyzer` already handles the second half, because its
offsets are relative to the image base rather than to absolute zero.
