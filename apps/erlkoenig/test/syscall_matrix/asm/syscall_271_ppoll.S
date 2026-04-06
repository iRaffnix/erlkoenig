# syscall 271: ppoll (timed)
.intel_syntax noprefix
.global _start
.text
_start:
    sub rsp, 16
    mov qword ptr [rsp], 0
    mov qword ptr [rsp+8], 0
    xor edi, edi
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov esi, 0
    mov rdx, rsp
    mov eax, 271
    syscall
    add rsp, 16
    mov eax, 60
    xor edi, edi
    syscall
