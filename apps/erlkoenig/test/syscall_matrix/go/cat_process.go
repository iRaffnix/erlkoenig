package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Get process ID (39)
	syscall.RawSyscall(39, 0, 0, 0) // getpid

	// Get parent PID (110)
	syscall.RawSyscall(110, 0, 0, 0) // getppid

	// Get user ID (102)
	syscall.RawSyscall(102, 0, 0, 0) // getuid

	// Get group ID (104)
	syscall.RawSyscall(104, 0, 0, 0) // getgid

	// Get thread ID (186)
	syscall.RawSyscall(186, 0, 0, 0) // gettid

	// Get system info (63)
	syscall.RawSyscall(63, 0, 0, 0) // uname

	// Process control (157)
	syscall.RawSyscall(157, 0, 0, 0) // prctl

	// Arch-specific prctl (158)
	syscall.RawSyscall(158, 0, 0, 0) // arch_prctl

	// Wait for process (61)
	syscall.RawSyscall(61, 0, 0, 0) // wait4

	// Wait for process (extended) (247)
	syscall.RawSyscall(247, 0, 0, 0) // waitid

	// Unshare namespaces (272)
	syscall.RawSyscall(272, 0, 0, 0) // unshare

	// Get/set resource limits (302)
	syscall.RawSyscall(302, 0, 0, 0) // prlimit64

	// Clone process (v3) (435)
	syscall.RawSyscall(435, 0, 0, 0) // clone3

}
