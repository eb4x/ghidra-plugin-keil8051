; Module 1 linked at 0x8000, the raw-image case: the GL3523 hub firmware is based there, and the
; vector analyzer must seed base+0x03, +0x0b ... rather than absolute 0x03.
BASE	= 0x8000
	.include "module1.inc"
