package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Mount filesystem (165)
	syscall.RawSyscall(165, 0, 0, 0) // mount

	// Unmount filesystem (166)
	syscall.RawSyscall(166, 0, 0, 0) // umount2

	// Change root (161)
	syscall.RawSyscall(161, 0, 0, 0) // chroot

	// Pivot root (155)
	syscall.RawSyscall(155, 0, 0, 0) // pivot_root

	// Set namespace (308)
	syscall.RawSyscall(308, 0, 0, 0) // setns

	// Sync filesystems (162)
	syscall.RawSyscall(162, 0, 0, 0) // sync

	// Open process fd (434)
	syscall.RawSyscall(434, 0, 0, 0) // pidfd_open

	// Close fd range (436)
	syscall.RawSyscall(436, 0, 0, 0) // close_range

	// Memory seal (462)
	syscall.RawSyscall(462, 0, 0, 0) // mseal

}
