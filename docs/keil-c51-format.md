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

In both, the byte after the table is itself a case target (`0x8836` is case `0x04`; `0xa3d0` is
case `0x08`), which is why flow resumes correctly once the targets are disassembled — there is no
need to "resume after the terminator" as a separate step.

## Not case helpers

Two nearby routines also pop their return address to read inline data, and must not be confused
with the case helpers:

- scaler `0x271b` / `0x2734` — inline-constant loaders (read 5 bytes into `@R0`, then `JMP @A+DPTR`).
- hub `0xd19f`, L1 hub `0xc792` — `POP DPH; POP DPL; POP ACC; RET`.

## Banked code — NOT decoded

The MStar scaler image is banked: common code at `0x0000-0x7fff`, a switched 32 KiB window at
`0x8000-0xffff`, total bank count unknown. The bank-switch mechanism has **not** been decoded —
it is not known whether it is Keil `?B_SWITCH`/`?C?BANK` style or MStar-specific, which SFR or
XDATA latch selects a bank, or how the bank and target are passed. The boot stub writes XDATA
`0x38a`, `0x393`, `0x3a6`, `0xf80`, `0xfb4`, which look like MStar code-remap/MIU registers rather
than a Keil bank latch.

Nothing in this extension guesses at it. Ground truth first.
