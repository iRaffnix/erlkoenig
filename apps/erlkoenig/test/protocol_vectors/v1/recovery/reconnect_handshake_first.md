# recovery: reconnect_handshake_first

Textual sequence vector. Not consumed by the binary golden runner — it
documents the ORDER in which frames must travel on a reconnect, so a
future implementer can build a sequence-driver or a manual reproducer
without re-deriving the contract.

## Sequence

```
BEAM                                C runtime
  |                                    |
  |  gen_tcp:connect (Unix, packet,4)  |
  |----------------------------------> | accept4(), enter do_handshake()
  |                                    |
  |  <<0x01>>            (handshake)   |
  |----------------------------------> | read version = 1, equal OK
  |                                    |
  |               <<0x01>> (reply)     |
  | <----------------------------------|
  |                                    |
  |  <<0x14, 0x01>>  (CMD_QUERY_STATUS)|
  |----------------------------------> | dispatch_command(QUERY_STATUS)
  |                                    |
  |           REPLY_STATUS (TLV)       |
  | <----------------------------------|
  |                                    |
```

## Invariant

The first frame on every fresh connection (every accept4) MUST be the
single version byte. Sending CMD_QUERY_STATUS (or any other tagged
command) first gets read as `peer_version = 0x14`, rejected at
`do_handshake()`, socket closed. This is how BEAM-crash recovery was
silently 100% broken before the fix in erlkoenig_ct_rt commit e2de0ee.

## Regression coverage

- Erlang side: `erlkoenig_ct_rt_tests:connect_to_runtime_sends_handshake_first_test`
  drives `connect_to_runtime/1` against a fake Unix server that
  records frame order. Asserts handshake bytes arrive BEFORE
  CMD_QUERY_STATUS.
- Binary vector for the REPLY_STATUS after handshake lives in
  `../replies/reply_status_alive.bin` + `.expected.term`.

## Why no .bin for the sequence

A full sequence vector would require a runnable driver (fake server or
embedded BEAM fixture) that both repos can execute. That belongs to
SPEC-RT-006 (`ek_test_client`) when it lands. For the spike: the
Erlang ct_rt unit test carries the wire-order invariant; the binary
vectors carry the payload invariants. Good enough to catch the two
concrete drifts that motivated this spec.
