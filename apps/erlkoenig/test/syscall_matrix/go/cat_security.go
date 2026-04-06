package main

import (
	"syscall"
	"unsafe"
)

func main() {
	// Suppress unused import
	_ = unsafe.Pointer(nil)

	// Seccomp filter (317)
	syscall.RawSyscall(317, 0, 0, 0) // seccomp

	// BPF operations (321)
	syscall.RawSyscall(321, 0, 0, 0) // bpf

	// Get capabilities (125)
	syscall.RawSyscall(125, 0, 0, 0) // capget

	// Set capabilities (126)
	syscall.RawSyscall(126, 0, 0, 0) // capset

	// Landlock create (444)
	syscall.RawSyscall(444, 0, 0, 0) // landlock_create_ruleset

	// Landlock add rule (445)
	syscall.RawSyscall(445, 0, 0, 0) // landlock_add_rule

	// Landlock restrict (446)
	syscall.RawSyscall(446, 0, 0, 0) // landlock_restrict_self

	// Get random bytes (318)
	syscall.RawSyscall(318, 0, 0, 0) // getrandom

}
