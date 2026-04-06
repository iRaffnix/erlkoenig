package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Open file relative to dirfd (257)
	syscall.RawSyscall(257, 0, 0, 0) // openat

	// Close file descriptor (3)
	syscall.RawSyscall(3, 0, 0, 0) // close

	// Read from fd (0)
	syscall.RawSyscall(0, 0, 0, 0) // read

	// Write to fd (1)
	syscall.RawSyscall(1, 0, 0, 0) // write

	// Stat file (262)
	syscall.RawSyscall(262, 0, 0, 0) // newfstatat

	// Read directory entries (217)
	syscall.RawSyscall(217, 0, 0, 0) // getdents64

	// Remove file (263)
	syscall.RawSyscall(263, 0, 0, 0) // unlinkat

	// Create directory (83)
	syscall.RawSyscall(83, 0, 0, 0) // mkdir

	// Remove directory (84)
	syscall.RawSyscall(84, 0, 0, 0) // rmdir

	// Rename file (82)
	syscall.RawSyscall(82, 0, 0, 0) // rename

	// Seek in file (8)
	syscall.RawSyscall(8, 0, 0, 0) // lseek

	// File control (72)
	syscall.RawSyscall(72, 0, 0, 0) // fcntl

	// Allocate file space (285)
	syscall.RawSyscall(285, 0, 0, 0) // fallocate

	// Extended stat (332)
	syscall.RawSyscall(332, 0, 0, 0) // statx

	// Check file access (439)
	syscall.RawSyscall(439, 0, 0, 0) // faccessat2

}
