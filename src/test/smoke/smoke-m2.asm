; Module 2 of the MStar-style smoke image, linked at CODE:0000: its own vector table and one
; plain AJMP switch whose default is an LJMP rather than an AJMP.

	.area	CODE (ABS)

sp	= 0x81
acc	= 0xe0

	.org	0x0000
	ljmp	main
	.org	0x0003
	reti
	.org	0x000b
	ljmp	isr_timer0
	.org	0x0013
	reti
	.org	0x001b
	reti
	.org	0x0023
	reti

	.org	0x0040
main:
	mov	sp,#0x60
loop:
	mov	a,r7
	acall	switch3
	sjmp	loop

isr_timer0:
	inc	0x30
	reti

	.org	0x0080
switch3:
	cjne	a,#3,1$
1$:	jc	2$
	ljmp	switch3_default
2$:	mov	dptr,#switch3_table
	add	a,acc
	jmp	@a+dptr
switch3_table:
	ajmp	switch3_0
	ajmp	switch3_1
	ajmp	switch3_2
switch3_0:
	mov	r2,#0x20
	ret
switch3_1:
	mov	r2,#0x21
	ret
switch3_2:
	mov	r2,#0x22
	ret
switch3_default:
	mov	r2,#0xff
	ret
