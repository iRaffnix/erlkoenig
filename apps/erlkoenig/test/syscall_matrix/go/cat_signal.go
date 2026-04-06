package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Set signal handler (13)
	syscall.RawSyscall(13, 0, 0, 0) // rt_sigaction

	// Block/unblock signals (14)
	syscall.RawSyscall(14, 0, 0, 0) // rt_sigprocmask

	// Send signal (62)
	syscall.RawSyscall(62, 0, 0, 0) // kill

	// Thread-directed signal (200)
	syscall.RawSyscall(200, 0, 0, 0) // tkill

	// Thread group signal (234)
	syscall.RawSyscall(234, 0, 0, 0) // tgkill

	// Set alternate signal stack (131)
	syscall.RawSyscall(131, 0, 0, 0) // sigaltstack

	// Set alarm timer (37)
	syscall.RawSyscall(37, 0, 0, 0) // alarm

}
