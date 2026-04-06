package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Map memory (9)
	syscall.RawSyscall(9, 0, 0, 0) // mmap

	// Unmap memory (11)
	syscall.RawSyscall(11, 0, 0, 0) // munmap

	// Set memory protection (10)
	syscall.RawSyscall(10, 0, 0, 0) // mprotect

	// Change data segment size (12)
	syscall.RawSyscall(12, 0, 0, 0) // brk

	// Advise on memory usage (28)
	syscall.RawSyscall(28, 0, 0, 0) // madvise

	// Remap memory (25)
	syscall.RawSyscall(25, 0, 0, 0) // mremap

	// Lock memory (149)
	syscall.RawSyscall(149, 0, 0, 0) // mlock

	// Unlock memory (150)
	syscall.RawSyscall(150, 0, 0, 0) // munlock

	// Create anonymous file (319)
	syscall.RawSyscall(319, 0, 0, 0) // memfd_create

	// Pkey memory protect (329)
	syscall.RawSyscall(329, 0, 0, 0) // pkey_mprotect

}
