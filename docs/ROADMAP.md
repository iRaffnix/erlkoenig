# Roadmap

Erlkoenig runs on a single node today. This document outlines what's
next — and why the architecture makes these features natural extensions
rather than rewrites.

## Why clustering is within reach

Every design decision in Erlkoenig was made with distribution in mind:

- **Containers are Erlang processes.** Erlang processes can be
  supervised, monitored, and messaged across nodes transparently.
- **Discovery uses `pg`.** Process groups work across connected
  nodes out of the box. `erlkoenig_core:list()` already returns
  all containers in the `pg` group — on a cluster, it returns
  containers from every node.
- **The control plane is a standard OTP release.** Erlang
  distribution (TLS-encrypted, cookie-authenticated) connects
  nodes with one config change.
- **State is per-process, not global.** No shared database, no
  coordination service, no consensus protocol needed for basic
  operations.

## Planned features

### Multi-node scheduling

Spawn containers on any node in the cluster:

```erlang
erlkoenig_core:spawn(<<"/opt/bin/server">>, #{
    name => <<"web">>,
    node => 'erlkoenig@node2',
    restart => on_failure
}).
```

The supervisor on the target node owns the container. If the node
goes down, OTP detects it (heartbeat) and the container can be
restarted on a surviving node.

### Live migration

Move a running container between nodes without downtime:

1. Snapshot cgroup state + open file descriptors
2. Transfer via Erlang distribution protocol
3. Recreate namespaces on target node
4. Redirect network (update DNS, re-attach firewall chain)
5. Resume execution

The hard part is filesystem state — tmpfs contents need to be
serialized. For stateless containers (the common case), migration
is fast.

### Distributed firewall

Ban an IP on one node, block it everywhere:

```erlang
erlkoenig_nft:ban("203.0.113.42").
%% → pg:broadcast → all nodes add to local blocklist set
```

`pg` delivers the message to every connected node. Each node's
`erlkoenig_nft_firewall` adds the IP to its local nf_tables set independently.
Latency is one Erlang message hop — microseconds on a local network.

Conntrack events can be shared the same way. A port scan detected
on node 1 triggers a ban on all nodes before the scanner reaches
node 2.

### Federated DNS

Container names resolve across the cluster:

```
web.node1.erlkoenig → 10.0.0.2   (on node1)
api.node2.erlkoenig → 10.0.1.3   (on node2)
```

Each node's DNS server knows its local containers. Cross-node queries
are forwarded to the owning node via Erlang distribution — no
external DNS infrastructure, no etcd, no gossip protocol.

### Zone spanning

Zones can span multiple nodes. A bridge on node 1 and a bridge on
node 2 are connected via a VXLAN or WireGuard tunnel. Containers in
the same zone communicate as if they were local, regardless of which
node they run on.

## What this is not

Erlkoenig is not trying to be a generic orchestrator. There is no
intent to replicate job scheduling, service meshes, or ingress
controllers. The goal is a small, fast, correct runtime that
leverages OTP's distribution for the hard problems (failure detection,
state transfer, group membership) instead of reimplementing them.
