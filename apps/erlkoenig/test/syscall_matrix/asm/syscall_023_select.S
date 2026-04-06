# syscall 23: select (timed)
.intel_syntax noprefix
.global _start
.text
_start:
    sub rsp, 16
    mov qword ptr [rsp], 0
    mov qword ptr [rsp+8], 0
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r9d, r9d
    mov edi, 0
    mov r8, rsp
    mov eax, 23
    syscall
    add rsp, 16
    mov eax, 60
    xor edi, edi
    syscall
