package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Wait for epoll events (232)
	syscall.RawSyscall(232, 0, 0, 0) // epoll_wait

	// Control epoll (233)
	syscall.RawSyscall(233, 0, 0, 0) // epoll_ctl

	// Create epoll fd (291)
	syscall.RawSyscall(291, 0, 0, 0) // epoll_create1

	// Epoll wait with sigmask (281)
	syscall.RawSyscall(281, 0, 0, 0) // epoll_pwait

	// Init inotify (253)
	syscall.RawSyscall(253, 0, 0, 0) // inotify_init

	// Init inotify with flags (294)
	syscall.RawSyscall(294, 0, 0, 0) // inotify_init1

	// Setup io_uring (425)
	syscall.RawSyscall(425, 0, 0, 0) // io_uring_setup

	// Submit/wait io_uring (426)
	syscall.RawSyscall(426, 0, 0, 0) // io_uring_enter

}
