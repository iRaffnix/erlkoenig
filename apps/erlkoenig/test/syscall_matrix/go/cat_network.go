package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Create socket (41)
	syscall.RawSyscall(41, 0, 0, 0) // socket

	// Connect to address (42)
	syscall.RawSyscall(42, 0, 0, 0) // connect

	// Bind socket (49)
	syscall.RawSyscall(49, 0, 0, 0) // bind

	// Listen on socket (50)
	syscall.RawSyscall(50, 0, 0, 0) // listen

	// Accept connection (43)
	syscall.RawSyscall(43, 0, 0, 0) // accept

	// Send data (44)
	syscall.RawSyscall(44, 0, 0, 0) // sendto

	// Receive data (45)
	syscall.RawSyscall(45, 0, 0, 0) // recvfrom

	// Shutdown socket (48)
	syscall.RawSyscall(48, 0, 0, 0) // shutdown

	// Set socket option (54)
	syscall.RawSyscall(54, 0, 0, 0) // setsockopt

	// Get socket option (55)
	syscall.RawSyscall(55, 0, 0, 0) // getsockopt

	// Accept4 connection (288)
	syscall.RawSyscall(288, 0, 0, 0) // accept4

}
