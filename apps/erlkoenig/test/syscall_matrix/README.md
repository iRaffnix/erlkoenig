# Syscall Matrix Tests

End-to-end validation that erlkoenig\_elf's x86\_64 syscall extraction works
correctly against real compiled binaries, not just synthetic in-memory ELF blobs.

## What It Tests

The static syscall decoder in `elf_syscall` scans the `.text` section of an ELF
binary for `SYSCALL` instructions (`0F 05`), walks backward through the
preceding instructions, and resolves the value loaded into `EAX`/`RAX` to
determine which Linux syscall is being invoked.  For binaries that dispatch
syscalls through shared stubs (like Go's `syscall.RawSyscall`), a second pass
performs **callsite analysis**: it locates stub functions via the symbol table,
finds all `CALL` instructions targeting them, and resolves the syscall number
from the caller's register setup.

This test suite verifies both resolution strategies against every defined
x86\_64 syscall number (0--462) and compares the results to `strace` ground
truth.

The suite is split into two tiers.

### Tier A -- Assembly Binaries (precise decoder validation)

For each of the ~356 non-skipped x86\_64 syscalls a minimal assembly program is
generated.  Every program has the same shape:

```asm
.intel_syntax noprefix
.global _start
.text
_start:
    xor edi, edi          # zero all arg registers
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, <NR>         # target syscall number
    syscall
    mov eax, 60           # exit(0)
    xor edi, edi
    syscall
```

Because the syscall number is loaded with a plain `MOV EAX, imm32` immediately
before the `SYSCALL` instruction, the static decoder has an unambiguous pattern
to match.  The test asserts:

1. The target syscall number **must** appear in the `resolved` map returned by
   `elf_syscall:extract/1`.
2. `exit` (60) **must** also appear (except for exit-like syscalls 60 and 231
   where the target _is_ the exit).
3. If strace data is available: every syscall name reported by strace must be
   present in the statically resolved set (`strace ⊆ static`).  False positives
   (static finding more than strace) are acceptable -- false negatives are not.

Special cases handled by the generator:

| Tier | Syscalls | Handling |
|------|----------|----------|
| `normal` (~320) | Most syscalls | Zeroed args cause EFAULT/EBADF/EINVAL, returns immediately |
| `timed` (~3) | `select`, `pselect6`, `ppoll` | Allocates a zero-valued timeout struct on the stack so the call returns immediately instead of blocking |
| `exit_like` (2) | `exit` (60), `exit_group` (231) | The target syscall _is_ the exit; no trailing `exit` is emitted |
| `blocking` (2) | `pause`, `rt_sigsuspend` | Skipped -- would hang indefinitely |
| `skip` (~20) | Historic stubs, reserved 336--423, `rt_sigreturn`, `vfork`, etc. | Skipped -- not safely testable in isolation |

### Tier B -- Go Binaries (callsite analysis validation)

Ten Go programs grouped by category (network, filesystem, process, memory, ipc,
signal, time, io\_multiplex, security, system) each invoke several related
syscalls via `syscall.RawSyscall(SYS_XXX, 0, 0, 0)`.

Go's `syscall.RawSyscall` is an assembly stub in the runtime where a single
shared `SYSCALL` instruction serves all call sites.  The syscall number is
passed as the first argument via RAX (Go's register-based calling convention
since Go 1.17).  The backward scan from the `SYSCALL` instruction alone cannot
resolve this because the value is set by the *caller*, not locally.

The callsite analysis in `elf_syscall.erl` resolves these by:

1. Finding stub symbols (`syscall.RawSyscall`, `syscall.Syscall`, etc.) via
   `elf_parse_symtab`.
2. Locating all direct `CALL rel32` instructions targeting those stubs.
3. Scanning backward from each `CALL` site for `MOV EAX/RAX, imm32` -- the
   same pattern the direct resolver uses, but applied at the caller instead of
   at the `SYSCALL` instruction.

This achieves **100% strace coverage** across all ten Go test categories:
every syscall observed by strace at runtime is also found by static analysis.

Assertions:

1. The binary **must** parse without error.
2. At least some syscalls **must** be detected (resolved + unresolved > 0).
3. If strace data is available: coverage percentage is reported.  Low coverage
   triggers a warning but does not fail the test.

## How It Works

### Data flow

```
syscall_defs.erl          # [{Nr, Name, Tier, AsmArgs}] for all x86_64 syscalls
       |
       v
gen_asm.escript ---------> asm/syscall_NNN_name.S     (356 files, checked in)
gen_go.escript ----------> go/cat_category.go          (10 files, checked in)
       |
       v
build_asm.sh ------------> bin/asm/syscall_NNN_name    (as + ld, gitignored)
build_go.sh -------------> bin/go/cat_category         (go build, gitignored)
       |
       v
run_strace.sh -----------> strace/asm/*.strace         (strace -c, gitignored)
                            strace/go/*.strace
       |
       v
elf_syscall_matrix_test    EUnit: parse binary -> extract -> assert
```

### Syscall resolution pipeline

```
         .text binary data
               |
               v
   elf_decode_x86_64:decode_all/1     decode all instructions
               |
       +-------+--------+
       |                 |
       v                 v
  find SYSCALL      find CALL rel32
  instructions      instructions
       |                 |
       v                 v
  scan backward     match target addr
  for MOV RAX       against stub symbols
  (direct resolve)  (from elf_parse_symtab)
       |                 |
       |                 v
       |            scan backward from
       |            CALL for MOV RAX
       |            (callsite resolve)
       |                 |
       +--------+--------+
                |
                v
         resolved syscall
         number -> name via
         elf_syscall_db
```

### Source generation (checked in)

**`syscall_defs.erl`** is the single source of truth.  It exports `x86_64/0`
which returns a list of `{Nr, Name, Tier, AsmArgs}` tuples covering every
defined x86\_64 syscall number.  `Tier` controls whether and how the assembly
is generated; `AsmArgs` specifies non-default register values (e.g. a stack
pointer for timed syscalls).

**`gen_asm.escript`** reads `syscall_defs:x86_64()`, skips `blocking` and `skip`
entries, and writes one `.S` file per remaining syscall into `asm/`.  The
generated assembly sources are checked into git so reviewers can inspect them
and the build step only requires `binutils`, not Erlang.

**`gen_go.escript`** writes ten `cat_*.go` files into `go/`, each containing
`syscall.RawSyscall` calls for a group of related syscalls.

### Compilation (gitignored)

**`build_asm.sh`** assembles and links each `.S` file with GNU as/ld into a
tiny static ELF binary (~700 bytes each).  Incremental: skips if the binary is
newer than the source.

**`build_go.sh`** compiles each `.go` file with `CGO_ENABLED=0 GOARCH=amd64`.
Incremental.  Allowed to fail (the `-` prefix in the Makefile) so the suite
works without a Go toolchain.

### Strace ground truth (gitignored)

**`run_strace.sh`** runs `strace -f -c -S name` on each binary, capturing the
summary table (which syscalls were actually invoked at runtime).  The test
module parses this table and checks that every strace-observed syscall was also
found by static analysis.

### Test execution

**`elf_syscall_matrix_test.erl`** is an EUnit module with two test generators:

- `asm_matrix_test_/0` scans `bin/asm/` for binaries and emits one test per
  file.  Each test calls `elf_parse:from_binary/1` followed by
  `elf_syscall:extract/1` and asserts on the resolved map.

- `go_matrix_test_/0` does the same for `bin/go/` with coverage reporting.

Both generators return an empty list when binaries are absent, so `rebar3 eunit`
never fails on a fresh checkout -- the matrix tests simply do not run.

## Directory Layout

```
test/syscall_matrix/
    syscall_defs.erl        Data module (source of truth)
    gen_asm.escript          Generates asm/*.S
    gen_go.escript           Generates go/*.go
    build_asm.sh             Compiles asm -> bin/asm
    build_go.sh              Compiles go  -> bin/go
    run_strace.sh            Runs strace  -> strace/
    asm/                     Generated .S files  (checked in)
    go/                      Generated .go files (checked in)
    bin/                     Compiled binaries   (gitignored)
    strace/                  Strace outputs      (gitignored)
test/elf_syscall_matrix_test.erl   EUnit test module
```

## Usage

```bash
# Full pipeline: generate sources, build, strace, test
make test-matrix-build      # compile asm + go binaries
make test-matrix-strace     # run strace on all binaries
make test-matrix            # run EUnit matrix tests

# Or all at once alongside the regular test suite
make test-all

# Regenerate sources after editing syscall_defs.erl
make test-matrix-gen
```

### Prerequisites

| Tool | Package | Required for |
|------|---------|--------------|
| `as`, `ld` | `binutils` | Tier A (assembly binaries) |
| `strace` | `strace` | Strace ground truth (optional) |
| `go` | `golang` | Tier B (Go binaries, optional) |

Tests skip gracefully when prerequisites are absent.

## Adding a New Syscall

1. Add the entry to `syscall_defs.erl` with the appropriate tier.
2. Add the name/number mapping to `src/elf_syscall_db.erl`.
3. Add a `category_lookup` clause in `elf_syscall_db.erl`.
4. Run `make test-matrix-gen` to regenerate the `.S` file.
5. Run `make test-matrix-build test-matrix` to verify.

## Design Rationale

**Why assembly and not C?**  A C compiler may reorder instructions, inline
functions, or use different register allocation strategies that obscure the
`MOV EAX, imm32 ; SYSCALL` pattern the decoder looks for.  Hand-written
assembly guarantees exactly the instruction sequence we want to test, making
failures unambiguous: if the decoder cannot find `MOV EAX, 41` followed by
`SYSCALL` in a 17-byte binary, the bug is in the decoder.

**Why Go as a second tier?**  Go produces large, statically linked binaries
with a realistic instruction mix.  Its syscall dispatch goes through shared
runtime stubs (`syscall.RawSyscall`), which exercises the callsite analysis
path -- a fundamentally different resolution strategy from the direct backward
scan.  The Go tests validate that the full pipeline (symbol table lookup, call
target resolution, cross-function backward scan) works correctly on real
compiler output.

**Why strace as ground truth?**  strace captures the actual syscalls made at
runtime by intercepting them in the kernel.  It is the most authoritative
answer to "what syscalls does this binary use."  The assertion
`strace ⊆ static` encodes the invariant that static analysis must be a
superset of dynamic behaviour -- it may over-approximate (dead code) but must
never miss a syscall that actually executes.

**Why two resolution strategies?**  Most statically linked C/Zig/Rust binaries
inline their syscall wrappers, producing a `MOV EAX, <nr> ; SYSCALL` pattern
that the direct backward scan handles.  Go (and potentially other runtimes)
centralise syscall dispatch into shared stubs, requiring callsite analysis to
trace the syscall number from the caller through the `CALL` instruction.
Together, the two strategies cover the vast majority of statically linked
Linux binaries.
