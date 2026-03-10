# Static Binaries

Erlkoenig runs static binaries — single executables that carry everything
they need. No shared libraries, no linker, no filesystem layout required.
Drop a file into a container and it runs.

## Why static?

Each Erlkoenig container gets a minimal tmpfs as its root filesystem.
There is no `/lib`, no `/usr`, no package manager. A dynamically linked
binary would fail immediately:

```
/opt/bin/server: error while loading shared libraries:
    libc.so.6: cannot open shared object file
```

A static binary has no such dependency. It contains all code — including
libc — in a single file. The kernel loads it, maps it into memory, and
jumps to `_start`. Nothing else needed.

This is also why containers start in 67ms. There is no image to unpack,
no layers to mount, no library resolution. Just `exec()` on a file.

## What is musl?

**musl** is a lightweight C standard library designed for static linking.
The standard glibc is optimized for dynamic linking and produces large,
complex static binaries (often with subtle runtime issues around DNS,
locale, and threading). musl produces small, clean, fully self-contained
executables.

| | glibc (dynamic) | glibc (static) | musl (static) |
|---|---|---|---|
| Hello World | 16 KB + libc.so | ~900 KB | ~26 KB |
| Dependencies | libc, ld-linux | none (but NSS issues) | none |
| DNS resolution | works | may break (NSS plugins) | works |
| Erlkoenig compatible | no | fragile | yes |

## Installing musl-gcc

On Debian/Ubuntu:

```bash
apt-get install musl-tools
```

This gives you `musl-gcc` — a wrapper around your system GCC that links
against musl instead of glibc. Your compiler, your flags, your Makefile.
Just swap `gcc` for `musl-gcc` and add `-static`.

## Practical example: Echo server

A minimal TCP echo server that listens on port 8080 and echoes back
whatever it receives. Small enough to read in one sitting, useful
enough to demonstrate a real container workload.

### The code

```c
/* echo.c — a static TCP echo server for Erlkoenig */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

int main(int argc, char *argv[]) {
    int port = 8080;
    if (argc > 1) port = atoi(argv[1]);

    /* Ignore SIGPIPE — we handle write errors via return codes */
    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };
    bind(srv, (struct sockaddr *)&addr, sizeof(addr));
    listen(srv, 16);

    printf("echo: listening on :%d\n", port);
    fflush(stdout);

    for (;;) {
        int client = accept(srv, NULL, NULL);
        if (client < 0) continue;

        char buf[4096];
        ssize_t n;
        while ((n = read(client, buf, sizeof(buf))) > 0)
            write(client, buf, n);

        close(client);
    }
}
```

### Build it

```bash
musl-gcc -static -O2 -o echo echo.c
```

Verify it's static:

```bash
$ file echo
echo: ELF 64-bit LSB executable, x86-64, statically linked

$ ldd echo
    not a dynamic executable

$ ls -lh echo
-rwxr-xr-x 1 user user 26K Mar 10 12:00 echo
```

26 KB. No dependencies. Runs on any Linux kernel.

### Run it in Erlkoenig

Copy the binary to the server and spawn a container:

```erlang
{ok, Pid} = erlkoenig_core:spawn(<<"/opt/bin/echo">>, #{
    name => <<"echo">>,
    ip   => {10, 0, 0, 10},
    args => [<<"8080">>]
}).
```

Test from the host:

```bash
$ echo "hello" | nc 10.0.0.10 8080
hello
```

The container has its own IP, its own PID namespace, its own mount
namespace. The echo server sees only itself. 26 KB of binary, 67ms
to start, ~1 MB of RAM.

## Go binaries

Go produces static binaries by default (when not using cgo):

```bash
CGO_ENABLED=0 go build -o server main.go
```

The output is a static binary that runs in Erlkoenig without changes.
Go's built-in net package handles DNS resolution without glibc, so
networking works in the minimal container environment.

For cgo-enabled builds (e.g., when using SQLite):

```bash
CGO_ENABLED=1 CC=musl-gcc go build -ldflags '-linkmode external -extldflags "-static"' -o server main.go
```

## Rust binaries

Rust can target musl directly:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The output in `target/x86_64-unknown-linux-musl/release/` is a static
binary ready for Erlkoenig.

## C++ binaries

Same as C — use musl-gcc and link statically:

```bash
musl-gcc -static -O2 -lstdc++ -o server server.cpp
```

For larger C++ projects, set the toolchain in CMake:

```cmake
set(CMAKE_C_COMPILER musl-gcc)
set(CMAKE_CXX_COMPILER musl-gcc)
set(CMAKE_EXE_LINKER_FLAGS "-static")
```

## What does NOT work

- **Dynamically linked binaries** — no shared libraries in the container
- **Shell scripts** — no `/bin/sh` in the container (unless you provide one as a static binary like BusyBox)
- **Python/Ruby/Node.js** — interpreters need their runtime; consider compiling to a static binary with tools like PyInstaller, or run them outside Erlkoenig
- **Binaries that dlopen() plugins at runtime** — static linking eliminates the dynamic linker

## Quick reference

| Language | Command | Notes |
|----------|---------|-------|
| C | `musl-gcc -static -o bin src.c` | `apt-get install musl-tools` |
| Go | `CGO_ENABLED=0 go build -o bin` | Static by default |
| Rust | `cargo build --target x86_64-unknown-linux-musl` | `rustup target add ...` |
| C++ | `musl-gcc -static -lstdc++ -o bin src.cpp` | Same musl-tools package |
| Zig | `zig build -Dtarget=x86_64-linux-musl` | Built-in musl support |
