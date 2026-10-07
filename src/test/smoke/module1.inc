; Module 1 of the smoke sample: a vector table, a plain AJMP switch, a page-carry AJMP switch and
; a ?C?CCASE switch, laid out the way Keil C51 emits them.
;
; Assembled at two bases: 0x0000 (smoke-m1.asm, module 1 of the MStar-style image) and 0x8000
; (smoke-based.asm, a raw image based where the GL3523 hub firmware is). The caller defines BASE.
; Every routine sits at a fixed .org so the smoke script can name its addresses.

	.area	CODE (ABS)

sp	= 0x81
dpl	= 0x82
dph	= 0x83
acc	= 0xe0

; ---- Vector table: reset, then five interrupts. Two RETI slots, as an unused vector carries.

	.org	BASE + 0x0000
	ljmp	main
	.org	BASE + 0x0003
	ljmp	isr_ext0
	.org	BASE + 0x000b
	ljmp	isr_timer0
	.org	BASE + 0x0013
	reti
	.org	BASE + 0x001b
	reti
	.org	BASE + 0x0023
	ljmp	isr_serial

	.org	BASE + 0x0040
main:
	mov	sp,#0x60
loop:
	mov	a,r7
	acall	plain_switch
	mov	a,r6
	acall	carry_switch
	mov	a,r5
	acall	char_switch
	sjmp	loop

isr_ext0:
	inc	0x30
	reti
isr_timer0:
	inc	0x31
	reti
isr_serial:
	inc	0x32
	reti

; ---- Plain shape: CJNE bound, JC, AJMP default, MOV DPTR, ADD A,ACC, JMP @A+DPTR. Cases 0..4.

	.org	BASE + 0x0100
plain_switch:
	cjne	a,#5,1$
1$:	jc	2$
	ajmp	plain_default
2$:	mov	dptr,#plain_table
	add	a,acc
	jmp	@a+dptr
plain_table:
	ajmp	plain_0
	ajmp	plain_1
	ajmp	plain_2
	ajmp	plain_3
	ajmp	plain_4
plain_0:
	mov	r2,#0x10
	ret
plain_1:
	mov	r2,#0x11
	ret
plain_2:
	mov	r2,#0x12
	ret
plain_3:
	mov	r2,#0x13
	ret
plain_4:
	mov	r2,#0x14
	ret
plain_default:
	mov	r2,#0xff
	ret

; ---- Page-carry shape with DEC A: cases 1..12, so table slot i is case i + 1. The JNC/INC DPH
; fix-up is dead at run time (2 * 11 never carries), as Keil emits it on the bound alone. The table
; straddles 0x0200, and four case bodies sit below it, so the AJMP entries mix opcodes 0x21 and 0x41.

	.org	BASE + 0x01a0
carry_1:
	mov	r3,#1
	ret
carry_2:
	mov	r3,#2
	ret
carry_3:
	mov	r3,#3
	ret
carry_4:
	mov	r3,#4
	ret

	.org	BASE + 0x01de
carry_switch:
	dec	a
	cjne	a,#12,1$
1$:	jc	2$
	ajmp	carry_default
2$:	mov	dptr,#carry_table
	add	a,acc
	jnc	3$
	inc	dph
3$:	jmp	@a+dptr
carry_table:
	ajmp	carry_1
	ajmp	carry_2
	ajmp	carry_3
	ajmp	carry_4
	ajmp	carry_5
	ajmp	carry_6
	ajmp	carry_7
	ajmp	carry_8
	ajmp	carry_9
	ajmp	carry_10
	ajmp	carry_11
	ajmp	carry_12
carry_5:
	mov	r3,#5
	ret
carry_6:
	mov	r3,#6
	ret
carry_7:
	mov	r3,#7
	ret
carry_8:
	mov	r3,#8
	ret
carry_9:
	mov	r3,#9
	ret
carry_10:
	mov	r3,#10
	ret
carry_11:
	mov	r3,#11
	ret
carry_12:
	mov	r3,#12
	ret
carry_default:
	mov	r3,#0xff
	ret

; ---- ?C?CCASE switch: LCALL the helper, then the inline table, target first, value second,
; terminated by a zero target and the default.

	.org	BASE + 0x0300
char_switch:
	lcall	ccase
	.dw	char_10
	.db	0x10
	.dw	char_20
	.db	0x20
	.dw	char_30
	.db	0x30
	.dw	char_40
	.db	0x40
	.dw	0
	.dw	char_default
char_10:
	mov	r4,#1
	ret
char_20:
	mov	r4,#2
	ret
char_30:
	mov	r4,#3
	ret
char_40:
	mov	r4,#4
	ret
char_default:
	mov	r4,#0xff
	ret

; ---- ?C?CCASE, Keil's library body. These 38 bytes are Keil's own code, kept byte-identical
; because the analyzer recognises the helper by its body (KeilCaseHelper.CCASE); everything else
; in this sample is original. build.sh checks the assembled bytes against that signature.

	.org	BASE + 0x0380
ccase:
	pop	dph
	pop	dpl
	mov	r0,a
1$:	clr	a
	movc	a,@a+dptr
	jnz	3$
	mov	a,#1
	movc	a,@a+dptr
	jnz	3$
	inc	dptr
	inc	dptr
2$:	movc	a,@a+dptr
	mov	r0,a
	mov	a,#1
	movc	a,@a+dptr
	mov	dpl,a
	mov	dph,r0
	clr	a
	jmp	@a+dptr
3$:	mov	a,#2
	movc	a,@a+dptr
	xrl	a,r0
	jz	2$
	inc	dptr
	inc	dptr
	inc	dptr
	sjmp	1$
