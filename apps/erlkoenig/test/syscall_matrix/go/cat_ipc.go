package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Create pipe (22)
	syscall.RawSyscall(22, 0, 0, 0) // pipe

	// Create pipe with flags (293)
	syscall.RawSyscall(293, 0, 0, 0) // pipe2

	// Fast userspace mutex (202)
	syscall.RawSyscall(202, 0, 0, 0) // futex

	// Create event fd (290)
	syscall.RawSyscall(290, 0, 0, 0) // eventfd2

	// Get shared memory (29)
	syscall.RawSyscall(29, 0, 0, 0) // shmget

	// Get semaphore (64)
	syscall.RawSyscall(64, 0, 0, 0) // semget

	// Get message queue (68)
	syscall.RawSyscall(68, 0, 0, 0) // msgget

	// Open message queue (240)
	syscall.RawSyscall(240, 0, 0, 0) // mq_open

}
