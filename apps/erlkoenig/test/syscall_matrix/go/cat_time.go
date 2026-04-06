package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Get clock time (228)
	syscall.RawSyscall(228, 0, 0, 0) // clock_gettime

	// Get clock resolution (229)
	syscall.RawSyscall(229, 0, 0, 0) // clock_getres

	// High-res sleep (35)
	syscall.RawSyscall(35, 0, 0, 0) // nanosleep

	// Get time of day (96)
	syscall.RawSyscall(96, 0, 0, 0) // gettimeofday

	// Create POSIX timer (222)
	syscall.RawSyscall(222, 0, 0, 0) // timer_create

	// Create timer fd (283)
	syscall.RawSyscall(283, 0, 0, 0) // timerfd_create

	// Get time in seconds (201)
	syscall.RawSyscall(201, 0, 0, 0) // time

}
