# syscall 7: poll (normal)
.intel_syntax noprefix
.global _start
.text
_start:
    xor edi, edi
    xor esi, esi
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov edx, 0
    mov eax, 7
    syscall
    mov eax, 60
    xor edi, edi
    syscall
