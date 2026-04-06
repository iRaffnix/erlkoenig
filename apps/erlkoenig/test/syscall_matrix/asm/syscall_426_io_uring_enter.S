# syscall 426: io_uring_enter (normal)
.intel_syntax noprefix
.global _start
.text
_start:
    xor edi, edi
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 426
    syscall
    mov eax, 60
    xor edi, edi
    syscall
