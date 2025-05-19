BITS 64
DEFAULT REL

STRUC Config
.pRopGadget: RESQ 1
.pTarget:	 RESQ 1
.dwArgCount: RESQ 1
.pRbx		 RESQ 1
.pArgs:		 RESQ 1
ENDSTRUC

GLOBAL Spoof
SECTION .text

Spoof:
	pop rdi													;pop the return Address and store in rdi register
	mov r10, rcx											;address of Config, which is passed as an argument in rcx
	mov r12d, [r10 + Config.dwArgCount]						;number of arguments are stored in r12
	sub r12d, 4												;no. of arguments on stack, as the first 4 are stored in registers
	mov r13, [r10 + Config.pArgs]							;args
	mov rcx, [r13]											;first arg
	mov rdx, [r13 + 8]										;second arg
	mov r8, [r13 + 16]										;third arg
	mov r9, [r13 + 24]										;fourth arg

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	; Loop To Move Arguments On The Stack
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		
	lea r12, [r12 * 8]										;calculating the size of additional arguments
	sub rsp, r12											;making space on the stack

loop_start:
	cmp r12, 0												;checking if the counter is zero
	jle loop_end							
	mov r15, rsp											;copying stack pointer into temp variable
	add r15, r12											;address where argument needs to be written
	sub r15, 8												
	mov rax, [r13 + 24 + r12]								;copying argument into temp variable
	mov [r15], rax											;writing argument on the stack
	sub r12, 8												;decrementing the counter
	jmp loop_start

loop_end:
	mov r13d, [r10 + Config.dwArgCount]						;storing the argument count a in non-volatile register	
	sub rsp, 32												;shadow space
	mov rax, [r10 + Config.pRopGadget]						;copying return address to temp variable (Gadget's address)
	push rax												;pushing the return address on the stack
	lea rbx, [cleanup]										;setting the value of rbx. Rop gadget will jump to this address
	mov [r10 + Config.pRbx], rbx
	lea rbx, [r10 + Config.pRbx]
	mov r12, [r10 + Config.pTarget]						
	jmp r12													;jumping to the target function

cleanup:
	
	lea r13, [r13 * 8]
	add rsp, r13											;reverting stack to its original state
	jmp rdi

		