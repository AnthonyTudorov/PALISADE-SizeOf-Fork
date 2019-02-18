



















































  
  
  
  
  
  





	.text
	.align	8
	.globl	__gmpn_add_nc 
	.type	__gmpn_add_nc,@function
__gmpn_add_nc:
	cmp	x4, #1
	b	.Lent
	.size	__gmpn_add_nc,.-__gmpn_add_nc
	.text
	.align	8
	.globl	__gmpn_add_n 
	.type	__gmpn_add_n,@function
__gmpn_add_n:
	cmn	xzr, xzr
.Lent:	tbz	x3, #0, .Lb0

	ldr	x4, [x1],#8
	ldr	x6, [x2],#8
	sub	x3, x3, #1
	adcs	x8, x4, x6
	str	x8, [x0],#8
	cbz	x3, .Lrt

.Lb0:	ldp	x4, x5, [x1],#16
	ldp	x6, x7, [x2],#16
	sub	x3, x3, #2
	adcs	x8, x4, x6
	adcs	x9, x5, x7
	cbz	x3, .Lend

.Ltop:	ldp	x4, x5, [x1],#16
	ldp	x6, x7, [x2],#16
	sub	x3, x3, #2
	stp	x8, x9, [x0],#16
	adcs	x8, x4, x6
	adcs	x9, x5, x7
	cbnz	x3, .Ltop

.Lend:	stp	x8, x9, [x0]
.Lrt:	adc	x0, xzr, xzr
	ret
	.size	__gmpn_add_n,.-__gmpn_add_n
