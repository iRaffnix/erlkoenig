# AMQP Event Bridge

erlkoenig publishes container lifecycle events to RabbitMQ via AMQP 0-9-1.
Events flow from Worker-Nodes to a central Broker on the infrastructure host.

See [ADR-0014](../../erlkoenigin/decisions/0014-amqp-integration-backbone.md) for the architecture decision.

## Architecture

```
┌──────────────────────┐
│  Infrastructure Host │
│                      │
│  RabbitMQ 4.x        │  ← Broker (single instance)
│  :5672               │
│                      │
│  Python consumers    │  ← Monitoring, alerting, dashboards
└──────────┬───────────┘
           │ AMQP (tcp:5672)
┌──────────┴───────────┐
│  erlkoenig Node      │
│                      │
│  erlkoenig_amqp_sup  │  ← Supervisierter Subtree
│    ├ amqp_conn       │     Connection + Reconnect
│    └ amqp_publisher  │     JSON publish
│                      │
│  (kein RabbitMQ)     │
└──────────────────────┘
```

Multiple erlkoenig Nodes connect to the same Broker.

## Broker Setup (Infrastructure Host)

### Install RabbitMQ 4.x (Generic Unix)

```bash
# Download and extract
wget https://github.com/rabbitmq/rabbitmq-server/releases/download/v4.1.0/rabbitmq-server-generic-unix-4.1.0.tar.xz -O /tmp/rabbitmq.tar.xz
mkdir -p /opt/rabbitmq
tar xf /tmp/rabbitmq.tar.xz -C /opt/rabbitmq --strip-components=1

# Create system user
useradd --system --no-create-home --shell /usr/sbin/nologin rabbitmq
mkdir -p /var/lib/rabbitmq /var/log/rabbitmq /etc/rabbitmq
chown -R rabbitmq:rabbitmq /var/lib/rabbitmq /var/log/rabbitmq /etc/rabbitmq /opt/rabbitmq
```

### Configure

```bash
cat > /etc/rabbitmq/rabbitmq.conf << 'EOF'
# Listen on all interfaces
listeners.tcp.default = 5672

# Default user for erlkoenig nodes
default_user = erlkoenig
default_pass = erlkoenig
default_vhost = /

log.console = true
log.console.level = info
EOF
```

### Systemd Service

```bash
cat > /etc/systemd/system/rabbitmq.service << 'EOF'
[Unit]
Description=RabbitMQ 4.x Message Broker
After=network.target

[Service]
Type=simple
User=rabbitmq
Group=rabbitmq

Environment=RABBITMQ_MNESIA_DIR=/var/lib/rabbitmq/mnesia
Environment=RABBITMQ_LOG_BASE=/var/log/rabbitmq
Environment=RABBITMQ_NODENAME=rabbit@HOSTNAME
Environment=HOME=/var/lib/rabbitmq

ExecStart=/opt/rabbitmq/sbin/rabbitmq-server
ExecStop=/opt/rabbitmq/sbin/rabbitmqctl shutdown

Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Replace HOSTNAME
sed -i "s/HOSTNAME/$(hostname)/" /etc/systemd/system/rabbitmq.service

systemctl daemon-reload
systemctl enable rabbitmq
systemctl start rabbitmq
```

### Verify

```bash
# Copy cookie for CLI access
cp /var/lib/rabbitmq/.erlang.cookie ~/.erlang.cookie
chmod 400 ~/.erlang.cookie

# Check status
/opt/rabbitmq/sbin/rabbitmqctl status | head -10

# Create user (if not using default_user)
/opt/rabbitmq/sbin/rabbitmqctl add_user erlkoenig erlkoenig
/opt/rabbitmq/sbin/rabbitmqctl set_permissions -p / erlkoenig ".*" ".*" ".*"
```

## erlkoenig Node Configuration

In `sys.config` on each erlkoenig node:

```erlang
{erlkoenig, [
    %% ... other config ...

    {amqp, #{
        enabled  => true,
        host     => "192.168.1.10",      %% Broker IP
        port     => 5672,
        user     => <<"erlkoenig">>,
        password => <<"erlkoenig">>,
        vhost    => <<"/">>,
        exchange => <<"erlkoenig.events">>
    }}
]}
```

Set `enabled => false` (default) to disable AMQP entirely. erlkoenig runs normally without a broker.

## Events

All internal erlkoenig events are forwarded as JSON to the `erlkoenig.events` topic exchange.

### Exchange

| Property | Value |
|----------|-------|
| Name | `erlkoenig.events` |
| Type | `topic` |
| Durable | `true` |
| Auto-delete | `false` |

### Routing Keys

| Routing Key | When |
|---|---|
| `container.started` | Container enters running state |
| `container.stopped` | Container exited |
| `container.failed` | Container hit a fatal error |
| `container.restarting` | Restart backoff started |
| `container.oom` | OOM kill detected |
| `container.unhealthy` | Health check failed |
| `metrics.fork` | Fork syscall traced |
| `metrics.exec` | Exec syscall traced |
| `metrics.exit` | Process exit traced |
| `metrics.oom` | OOM event traced |
| `policy.violation` | Policy engine triggered |

### JSON Envelope

```json
{
  "v": 1,
  "ts": "2026-04-04T12:34:56.789Z",
  "node": "erlkoenig@worker-1",
  "routing_key": "container.stopped",
  "payload": {
    "id": "a1b2c3d4-...",
    "exit_code": -1,
    "signal": 9
  }
}
```

## Python Consumer (Demo Tool)

```bash
pip install pika
python3 tools/event_consumer.py <broker-host> [pattern]
```

Examples:

```bash
# All container lifecycle events
python3 tools/event_consumer.py 192.168.1.10

# All events (including metrics, policy)
python3 tools/event_consumer.py 192.168.1.10 "#"

# Only policy violations
python3 tools/event_consumer.py 192.168.1.10 "policy.*"
```

Output:

```
Listening on 192.168.1.10 exchange=erlkoenig.events pattern=container.*
────────────────────────────────────────────────────────────
10:31:31.843 container.stopped         36b4342a-7f0 exit=-1 sig=9
10:31:31.857 container.restarting      36b4342a-7f0 attempt #1
10:31:32.965 container.started         36b4342a-7f0
```

## Failure Behavior

| Situation | Behavior |
|---|---|
| Broker unreachable at startup | erlkoenig starts normally, AMQP reconnects with backoff (5s..60s) |
| Broker goes down | Connection lost, events dropped, auto-reconnect |
| Broker comes back | Reconnect automatic, events flow again |
| `enabled => false` | No AMQP processes started, zero overhead |

erlkoenig never depends on broker availability. Container operations, firewall, health checks — everything works without AMQP.

## OTP Supervision

```
erlkoenig_sup
├── ... (core services)
├── erlkoenig_amqp_sup (rest_for_one)    ← isolated subtree
│   ├── erlkoenig_amqp_conn                 connection owner
│   └── erlkoenig_amqp_publisher            event publisher
└── erlkoenig_pod_sup_sup
```

If the AMQP subtree crashes, only event forwarding stops. The rest of erlkoenig is unaffected.

## Modules

| Module | Type | Purpose |
|---|---|---|
| `erlkoenig_amqp_sup` | supervisor | rest_for_one subtree |
| `erlkoenig_amqp_conn` | gen_server | AMQP connection, reconnect, channel management |
| `erlkoenig_amqp_publisher` | gen_server | JSON publish via amqp_channel:cast |
| `erlkoenig_amqp_forwarder` | gen_event handler | Thin adapter on erlkoenig_events bus |
| `erlkoenig_amqp_codec` | module (no process) | Event → {RoutingKey, JSON} mapping |

## Future Phases

The AMQP subtree is designed for extension without restructuring:

| Phase | Exchange | Direction | Purpose |
|---|---|---|---|
| v1 (current) | `erlkoenig.events` | out | Lifecycle events |
| v2 | `erlkoenig.commands` | in | Deploy, stop, scale |
| v3 | `erlkoenig.audit` | out | Security audit copy |
| v4 | `erlkoenig.cluster` | both | Multi-node coordination |
