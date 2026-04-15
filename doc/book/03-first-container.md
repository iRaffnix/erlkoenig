# Chapter 3 — Your First Container

Ten minutes, five steps, a running container with a persistent volume.
Prerequisite: erlkoenig is installed and the systemd service is up
(→ Chapter 2), and the volume backing is in place (XFS loop with
`prjquota`, see the last section of Chapter 2).

## Step 1: Write an `.exs` file

The minimal example ships with the repo at
`examples/minimal_volume_opts.exs`. Copy it or use it directly:

```elixir
defmodule MyFirst do
  use Erlkoenig.Stack

  host do
    ipvlan "app-net",
      parent: {:dummy, "ek_app"},
      subnet: {10, 0, 0, 0, 24}
  end

  pod "app", strategy: :one_for_one do
    container "svc",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper",
      args: ["600"],
      zone: "app-net",
      replicas: 1,
      restart: :permanent do

      volume "/uploads", persist: "uploads",
                         opts: "rw,nosuid,nodev,noexec,relatime"
    end
  end
end
```

The sleeper binary sits at `/opt/erlkoenig/rt/demo/test-erlkoenig-sleeper`
after a release install — a static musl binary (≈ 19 KB) that sleeps for
the given number of seconds. Ideal for exploration: it behaves
deterministically and doesn't need a listening port.

## Step 2: Compile to a `.term` file

erlkoenig consumes Erlang terms, not Elixir source. The DSL is compiled
once and serialised:

```bash
cd /home/dev/code/erlkoenig/dsl
MIX_ENV=test mix run --no-deps-check --no-compile -e '
  [{mod, _} | _] = Code.compile_file("../examples/minimal_volume_opts.exs")
  mod.write!("/tmp/my_first.term")
'
```

`mod.write!/1` writes the compiled term as an Erlang text file. It's
worth a `cat` — you'll see a map with `pods`, `zones`, `host`.

## Step 3: Load

Loading the config starts every declared container. The loader runs inside
the node's BEAM:

```bash
sudo erlkoenig eval 'erlkoenig_config:load(<<"/tmp/my_first.term">>).'
# → {ok, [<0.423.0>]}
```

The return value is the list of pids of the started container state
machines. One here, because `replicas: 1`.

## Step 4: Inspect

Every container state machine answers `inspect/1` with a status map:

```bash
sudo erlkoenig eval '
  [Pid | _] = pg:get_members(erlkoenig_pg, erlkoenig_cts),
  erlkoenig:inspect(Pid).
'
```

The interesting fields: `state` (should be `running`), `os_pid` (the
kernel pid of the container process), `netns_path`
(`/proc/<pid>/ns/net` — the container's own network namespace), `volumes`
(host and container paths with their mount options).

From the host you can peek into the container's rootfs:

```bash
sudo ls /proc/<os_pid>/root/uploads
```

The same directory is on the host under
`/var/lib/erlkoenig/volumes/<uuid>/`, where `<uuid>` is a generated
`ek_vol_<16hex>` identifier. For easier navigation there's a symlink:
`/var/lib/erlkoenig/volumes/by-name/svc/uploads → ../../<uuid>`
(→ Chapter 8).

## Step 5: Stop

```bash
sudo erlkoenig eval '
  [Pid | _] = pg:get_members(erlkoenig_pg, erlkoenig_cts),
  erlkoenig:stop(Pid).
'
```

The container receives SIGTERM; after five seconds, erlkoenig escalates to
SIGKILL. Because the DSL declares `restart: :permanent`, a container that
dies on its own would be restarted automatically — `stop/1` is the
explicit "stay down" signal.

## Common pitfalls

**`invalid_persist_name`.** The `persist:` name contains uppercase letters
or punctuation. The regex is `[a-z0-9][a-z0-9_-]*` — the parser rejects
anything else with a clear message.

**`parent device not found`.** The `ipvlan` block references
`{:device, "eth0"}`, which doesn't exist on this host. On laptops and
isolated VMs, prefer `{:dummy, "ek_<name>"}` — erlkoenig then creates the
dummy interface itself.

**Write failure inside `/uploads`.** Either the volume was mounted with
`opts: "ro,..."`, or the container runs as UID 65534 but the host
directory is owned by root. The volume store chowns new directories to
the container UID automatically; that only works if erlkoenig runs with
CAP_CHOWN (the default under the systemd path).

**Typo in `opts:`.** Strings like `"nosudi"` in place of `"nosuid"` are
rejected on load with `{error, {unknown_flag, <<"nosudi">>}}`. The
mount-opts parser is strict on bare tokens (→ Chapter 8).

## Where to go next

The minimal example is intentionally thin. For more:

- **Multiple volume classes, harder mount options** → `examples/hardened_volumes.exs` and Chapter 8
- **Container options in depth** (restart policies, limits, caps) → Chapter 4
- **IPVLAN L3S, zones, DNS** → Chapter 5
- **Firewall rules in the DSL** → Chapter 6
