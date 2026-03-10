# Install from Release

No build tools required. The release tarball includes its own Erlang
runtime (ERTS) and the C runtime is a static binary. Both run on any
Linux x86_64 system with kernel >= 5.2.

## What you need

- A Linux server (x86_64, kernel >= 5.2)
- Root access (for capabilities and systemd)
- Two files from a [GitHub Release](https://github.com/erlkoenig/erlkoenig/releases) or a build machine:
  - `erlkoenig-0.1.0.tar.gz` — OTP release (~16 MB, includes ERTS)
  - `erlkoenig_rt-linux-amd64` — C runtime (92 KB, static binary)
- Optional:
  - `erlkoenig-dsl-linux-amd64` — DSL compiler escript (~1.4 MB)
  - `static-demo-binaries-linux-amd64.tar.gz` — 14 static demo binaries for testing

If you have access to a build machine, generate these with:

```bash
make release    # → dist/erlkoenig-0.1.0.tar.gz + dist/erlkoenig-dsl
make rt         # → build/release/erlkoenig_rt + build/release/demo/*
make go-demos   # → build/release/{echo-server,reverse-proxy,api-server}
```

## Step 1: Create the erlkoenig user

```bash
sudo useradd -r -m -d /opt/erlkoenig -s /bin/bash erlkoenig
sudo mkdir -p /etc/erlkoenig /usr/lib/erlkoenig
sudo chown erlkoenig:erlkoenig /opt/erlkoenig /etc/erlkoenig
```

## Step 2: Install the C runtime

```bash
sudo cp erlkoenig_rt /usr/lib/erlkoenig/erlkoenig_rt
sudo chown root:root /usr/lib/erlkoenig/erlkoenig_rt
sudo chmod 755 /usr/lib/erlkoenig/erlkoenig_rt

sudo setcap \
  cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,\
cap_setpcap,cap_setuid,cap_setgid,cap_dac_override,\
cap_bpf,cap_sys_resource+ep \
  /usr/lib/erlkoenig/erlkoenig_rt
```

Verify:

```bash
$ getcap /usr/lib/erlkoenig/erlkoenig_rt
/usr/lib/erlkoenig/erlkoenig_rt cap_dac_override,cap_setgid,cap_setuid,... = ep

$ file /usr/lib/erlkoenig/erlkoenig_rt
... ELF 64-bit LSB executable, x86-64, statically linked ...
```

## Step 3: Install the OTP release

```bash
sudo -u erlkoenig tar xzf erlkoenig-0.1.0.tar.gz -C /opt/erlkoenig
```

The release includes everything:

```
/opt/erlkoenig/
├── bin/erlkoenig         Start/stop script
├── erts-15.2/            Bundled Erlang runtime
├── lib/                  OTP applications
├── releases/             Release config
├── activate              Shell environment (source this)
├── doc/                  Documentation
└── examples/             DSL example configs
```

## Step 4: Generate the cookie

```bash
sudo -u erlkoenig bash -c '
  COOKIE=$(openssl rand -base64 32 | tr -d "/+=" | head -c 32)
  sed "s/erlkoenig_dev/$COOKIE/" \
    /opt/erlkoenig/releases/0.1.0/vm.args \
    > /etc/erlkoenig/vm.args
  chmod 600 /etc/erlkoenig/vm.args
'
```

## Step 5: Install the systemd service

```bash
sudo cp /opt/erlkoenig/erlkoenig.service /usr/lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable erlkoenig
sudo systemctl start erlkoenig
```

Check it's running:

```bash
$ sudo systemctl status erlkoenig
● erlkoenig.service - Erlkoenig Container Runtime
     Active: active (running)

$ sudo journalctl -u erlkoenig -n 5
... erlkoenig: Application erlkoenig_core started
... erlkoenig: Application erlkoenig_nft started
```

## Step 6: Activate the shell environment

```bash
source /opt/erlkoenig/activate
```

This gives you a `(erlkoenig)` prompt with shell shortcuts:

```
(erlkoenig) $ ek-ps
  NAME       STATE    IP            PIDS  RESTARTS
  --------------------------------------------------------
  (no containers running)

(erlkoenig) $ ek-spawn hello /usr/lib/erlkoenig/demo/test-erlkoenig-echo_server 10.0.0.5 7777
```

Run `deactivate` to leave the environment.

## Step 7 (optional): Install the DSL compiler

If you have the `erlkoenig-dsl` escript:

```bash
sudo -u erlkoenig cp erlkoenig-dsl /opt/erlkoenig/bin/erlkoenig-dsl
sudo -u erlkoenig chmod 755 /opt/erlkoenig/bin/erlkoenig-dsl

# Fix the shebang to use the bundled ERTS
ERTS_BIN=$(ls -d /opt/erlkoenig/erts-*/bin | head -1)
sudo -u erlkoenig sed -i "1s|.*|#!${ERTS_BIN}/escript|" \
  /opt/erlkoenig/bin/erlkoenig-dsl
```

Now you can compile `.exs` config files:

```bash
(erlkoenig) $ ek-load examples/simple_echo.exs
```

## Step 8 (optional): Install demo binaries

The demo archive contains 11 static C binaries and 3 static Go binaries
for testing containers. None of them require any libraries on the host.

```bash
tar xzf static-demo-binaries-linux-amd64.tar.gz

# C test binaries (sleeper, echo_server, crasher, mem_eater, ...)
sudo mkdir -p /usr/lib/erlkoenig/demo
sudo cp static-demo-binaries/test-erlkoenig-* /usr/lib/erlkoenig/demo/
sudo chown -R root:root /usr/lib/erlkoenig/demo
sudo chmod 700 /usr/lib/erlkoenig/demo/*

# Go demo binaries (echo-server, reverse-proxy, api-server)
sudo cp static-demo-binaries/{echo-server,reverse-proxy,api-server} /usr/lib/erlkoenig/
sudo chmod 755 /usr/lib/erlkoenig/{echo-server,reverse-proxy,api-server}
```

Try it out:

```bash
(erlkoenig) $ ek-spawn hello /usr/lib/erlkoenig/demo/test-erlkoenig-echo_server 10.0.0.5 7777
(erlkoenig) $ ek-spawn web /usr/lib/erlkoenig/echo-server 10.0.0.6 8080
```

## Uninstall

```bash
sudo systemctl stop erlkoenig
sudo systemctl disable erlkoenig
sudo rm /usr/lib/systemd/system/erlkoenig.service
sudo systemctl daemon-reload
sudo rm -rf /opt/erlkoenig /usr/lib/erlkoenig /etc/erlkoenig
sudo userdel -r erlkoenig
```

## Troubleshooting

**"Operation not permitted" on container start:**
Check that `erlkoenig_rt` has capabilities: `getcap /usr/lib/erlkoenig/erlkoenig_rt`.
If empty, re-run the `setcap` command from step 2.

**"Cannot bind to port 53":**
The BEAM needs `CAP_NET_BIND_SERVICE`. Check the systemd unit has
`AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE`.

**Cookie mismatch on remote_console:**
Ensure `VMARGS_PATH=/etc/erlkoenig/vm.args` is set. The `activate`
script does this automatically.

**Release doesn't start:**
Check the journal: `journalctl -u erlkoenig -e`. Common issue:
the bundled ERTS architecture doesn't match (the release is x86_64 only).
