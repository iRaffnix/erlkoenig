#!/usr/bin/env python3
"""Run Erlkoenig live labs against a real host.

This is intentionally an operator-contract test, not a unit test. It checks
that the same DSL claim is visible across the layers an operator actually uses:
compiled config, live kernel state through ek, canonical firewall events, and
AMQP when broker credentials are available.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
import socket
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LabError(RuntimeError):
    pass


def log(msg: str) -> None:
    print(f"[live-lab] {msg}", flush=True)


def run(
    cmd: list[str],
    *,
    timeout: int = 30,
    check: bool = True,
    echo_output: bool = True,
    cwd: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    log("$ " + " ".join(cmd))
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if echo_output and proc.stdout:
        print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
    if check and proc.returncode != 0:
        if not echo_output and proc.stdout:
            print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
        raise LabError(f"command failed rc={proc.returncode}: {' '.join(cmd)}")
    return proc


def ssh(
    host: str,
    command: str,
    *,
    timeout: int = 30,
    check: bool = True,
    echo_output: bool = True,
) -> str:
    proc = run(["ssh", host, command], timeout=timeout, check=check, echo_output=echo_output)
    return proc.stdout


def scp(local: Path, host: str, remote: str) -> None:
    run(["scp", str(local), f"{host}:{remote}"], timeout=30)


def remote_ek(args: argparse.Namespace, ek_args: str, *, timeout: int = 30) -> str:
    return ssh(args.host, f"{args.prefix}/bin/ek {ek_args}", timeout=timeout)


def remote_ek_json(args: argparse.Namespace, ek_args: str, *, timeout: int = 30):
    out = ssh(args.host, f"{args.prefix}/bin/ek --format json {ek_args}",
              timeout=timeout, echo_output=False)
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise LabError(f"ek JSON output did not decode for `{ek_args}`: {exc}\n{out}") from exc


def require_counter(counters: list[dict], name: str) -> dict:
    for row in counters:
        if row.get("name") == name:
            return row
    names = [row.get("name") for row in counters]
    raise LabError(f"missing counter {name!r}; visible counters: {names}")


def require_event(events: list[dict], counter: str) -> dict:
    for event in events:
        if event.get("counter") == counter:
            return event
    seen = [event.get("counter") for event in events if event.get("kind") == "counter_rate"]
    raise LabError(f"missing firewall event for counter {counter!r}; seen counters: {seen}")


def generate_ssh_counter_traffic(args: argparse.Namespace, count: int = 4) -> None:
    command = " ".join(
        [
            "for i in",
            " ".join(str(i) for i in range(1, count + 1)),
            f"; do {args.prefix}/bin/ek node ping >/dev/null; sleep 1; done",
        ]
    )
    ssh(args.host, command, timeout=count + 10)


def ssh_hostname(host: str) -> str:
    result = run(["ssh", "-G", host], timeout=10, echo_output=False)
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key == "hostname" and value.strip():
            return value.strip()
    return host


def generate_drop_counter_traffic(args: argparse.Namespace, count: int = 4) -> None:
    hostname = ssh_hostname(args.host)
    for _ in range(count):
        try:
            with socket.create_connection((hostname, 1), timeout=1):
                pass
        except OSError:
            pass
        time.sleep(0.25)


def collect_amqp_during(
    args: argparse.Namespace,
    pattern: str,
    action,
    *,
    seconds: int = 8,
    expected_keys: set[str] | None = None,
) -> list[dict]:
    try:
        import pika
    except ImportError as exc:
        raise LabError("pika is required for AMQP checks; install it or pass --skip-amqp") from exc

    user = os.environ.get("AMQP_USER")
    passwd = os.environ.get("AMQP_PASS")
    host = args.amqp_host or os.environ.get("AMQP_HOST")
    if not user or not passwd or not host:
        raise LabError("set AMQP_HOST, AMQP_USER and AMQP_PASS or pass --skip-amqp")

    events: list[dict] = []
    errors: queue.Queue[BaseException] = queue.Queue()
    ready = threading.Event()
    action_done = threading.Event()
    expected_keys = expected_keys or set()

    def consume() -> None:
        try:
            conn = pika.BlockingConnection(
                pika.ConnectionParameters(host, credentials=pika.PlainCredentials(user, passwd))
            )
            ch = conn.channel()
            ch.exchange_declare("erlkoenig.events", "topic", durable=True)
            q = ch.queue_declare("", exclusive=True)
            ch.queue_bind(q.method.queue, "erlkoenig.events", pattern)

            deadline = time.time() + seconds
            ready.set()
            while time.time() < deadline:
                method, _props, body = ch.basic_get(q.method.queue, auto_ack=True)
                if method is None:
                    time.sleep(0.2)
                    continue
                events.append(json.loads(body))
                if action_done.is_set() and expected_keys.issubset(
                    {event.get("key") for event in events}
                ):
                    break
            conn.close()
        except BaseException as exc:  # noqa: BLE001 - surface thread failures to caller
            errors.put(exc)
            ready.set()

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    if not ready.wait(timeout=5):
        raise LabError("AMQP consumer did not become ready")

    action()
    action_done.set()
    thread.join(timeout=seconds + 3)
    if not errors.empty():
        raise LabError(f"AMQP check failed: {errors.get()!r}")
    return events


def collect_amqp(args: argparse.Namespace, pattern: str, seconds: int = 8) -> list[dict]:
    return collect_amqp_during(
        args,
        pattern,
        lambda: generate_ssh_counter_traffic(args, count=4),
        seconds=seconds,
    )


def binary_hash(args: argparse.Namespace, path: str) -> str:
    out = ssh(args.host, f"sha256sum {path}", timeout=30, echo_output=False)
    fields = out.strip().split()
    if not fields:
        raise LabError(f"sha256sum returned no hash for {path!r}: {out!r}")
    hash_value = fields[0]
    if len(hash_value) != 64:
        raise LabError(f"unexpected sha256 shape for {path!r}: {hash_value!r}")
    return hash_value


def remote_ek_checked(args: argparse.Namespace, ek_args: str, *, timeout: int = 30) -> str:
    return ssh(args.host, f"{args.prefix}/bin/ek {ek_args}", timeout=timeout)


def remote_ek_unchecked(
    args: argparse.Namespace,
    ek_args: str,
    *,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return run(
        ["ssh", args.host, f"{args.prefix}/bin/ek {ek_args}"],
        timeout=timeout,
        check=False,
    )


def remote_journal_since(args: argparse.Namespace, since: str) -> str:
    return ssh(
        args.host,
        f"journalctl -u erlkoenig --since '{since}' --no-pager -o cat",
        timeout=30,
        echo_output=False,
    )


def remote_now(args: argparse.Namespace) -> str:
    return ssh(args.host, "date --iso-8601=seconds", timeout=10, echo_output=False).strip()


def require_journal_lifecycle(
    journal: str,
    name: str,
    *,
    exit_code: int | None = 0,
    term_signal: int | None = 0,
) -> None:
    started = f"event: container {name} started"
    stopped = f"event: container {name} stopped"
    if started not in journal:
        raise LabError(f"journalctl missing lifecycle start {started!r}:\n{journal}")
    if stopped not in journal:
        raise LabError(f"journalctl missing lifecycle stop {stopped!r}:\n{journal}")
    if exit_code is not None and f"exit_code => {exit_code}" not in journal:
        raise LabError(f"journalctl missing exit_code => {exit_code} for {name!r}:\n{journal}")
    if term_signal is not None and f"term_signal => {term_signal}" not in journal:
        raise LabError(f"journalctl missing term_signal => {term_signal} for {name!r}:\n{journal}")


def collect_stream_during(
    args: argparse.Namespace,
    stream_name: str,
    action,
    *,
    seconds: int = 8,
    retention: str = "1D",
) -> list[dict]:
    try:
        import pika
    except ImportError as exc:
        raise LabError("pika is required for stream checks; install it or pass --skip-amqp") from exc

    user = os.environ.get("AMQP_USER")
    passwd = os.environ.get("AMQP_PASS")
    host = args.amqp_host or os.environ.get("AMQP_HOST")
    if not user or not passwd or not host:
        raise LabError("set AMQP_HOST, AMQP_USER and AMQP_PASS or pass --skip-amqp")

    messages: list[dict] = []
    errors: queue.Queue[BaseException] = queue.Queue()
    ready = threading.Event()

    def consume() -> None:
        try:
            conn = pika.BlockingConnection(
                pika.ConnectionParameters(host, credentials=pika.PlainCredentials(user, passwd))
            )
            ch = conn.channel()
            ch.queue_declare(
                queue=stream_name,
                durable=True,
                arguments={"x-queue-type": "stream", "x-max-age": retention},
            )

            def on_message(ch_, method, properties, body):
                headers = properties.headers or {}
                messages.append({
                    "headers": headers,
                    "body": body.decode("utf-8", errors="replace"),
                })
                ch_.basic_ack(method.delivery_tag)

            ch.basic_qos(prefetch_count=100)
            ch.basic_consume(
                queue=stream_name,
                on_message_callback=on_message,
                arguments={"x-stream-offset": "next"},
            )
            deadline = time.time() + seconds
            ready.set()
            while time.time() < deadline:
                ch.connection.process_data_events(time_limit=0.25)
            conn.close()
        except BaseException as exc:  # noqa: BLE001 - surface thread failures to caller
            errors.put(exc)
            ready.set()

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    if not ready.wait(timeout=5):
        raise LabError("stream consumer did not become ready")

    action()
    thread.join(timeout=seconds + 3)
    if not errors.empty():
        raise LabError(f"stream check failed: {errors.get()!r}")
    return messages


def lab_firewall_host_counters(args: argparse.Namespace) -> None:
    lab = ROOT / "examples/live_labs/10_firewall_host_counters.exs"
    remote_exs = "/tmp/ek_live_lab_10_firewall_host_counters.exs"
    remote_term = "/tmp/ek_live_lab_10.term"

    log("copy DSL lab to host")
    scp(lab, args.host, remote_exs)

    log("compile and validate DSL on host")
    remote_ek(args, f"dsl compile {remote_exs} -o {remote_term}", timeout=60)
    remote_ek(args, f"config validate {remote_term}", timeout=30)

    log("apply host firewall lab with explicit lockout bypass")
    journal_since = remote_now(args)
    apply_output = remote_ek(args, f"--allow-lockout up {remote_term}", timeout=60)
    remote_ek(args, "node ping", timeout=15)

    log("assert host nft apply is visible in ek output and journalctl")
    summary = "erlkoenig_config: nft_table erlkoenig_host:"
    applied = "erlkoenig_config: nft_table erlkoenig_host applied ok"
    if summary not in apply_output:
        raise LabError(f"ek up output missing nft table summary {summary!r}:\n{apply_output}")
    if applied not in apply_output:
        raise LabError(f"ek up output missing nft apply-ok line {applied!r}:\n{apply_output}")
    journal = remote_journal_since(args, journal_since)
    adopted = "[erlkoenig_nft] Runtime config adopted: table=erlkoenig_host"
    if adopted not in journal:
        raise LabError(f"journalctl missing runtime adoption line {adopted!r}:\n{journal}")
    log("operator output ok: nft summary/apply-ok; journalctl ok: runtime adopted")

    log("assert named counters are visible through ek nft counters")
    counters = remote_ek_json(args, "nft counters", timeout=30)
    ssh_counter = require_counter(counters, "live_ssh_accept")
    drop_counter = require_counter(counters, "live_input_drop")
    log(f"counter ok: live_ssh_accept total={ssh_counter.get('total_packets')}")
    log(f"counter ok: live_input_drop total={drop_counter.get('total_packets')}")

    log("generate accept/drop traffic and assert canonical firewall events")
    generate_ssh_counter_traffic(args, count=4)
    generate_drop_counter_traffic(args, count=4)
    events = remote_ek_json(args, "firewall events --limit 50", timeout=30)
    ssh_event = require_event(events, "live_ssh_accept")
    drop_event = require_event(events, "live_input_drop")
    log(f"event ok: live_ssh_accept chain={ssh_event.get('chain')} kind={ssh_event.get('kind')}")
    log(f"event ok: live_input_drop chain={drop_event.get('chain')} kind={drop_event.get('kind')}")

    if args.skip_amqp:
        log("AMQP check skipped")
        return

    log("assert AMQP routing distinguishes accept counters from drop counters")
    def generate_counter_traffic() -> None:
        generate_ssh_counter_traffic(args, count=4)
        generate_drop_counter_traffic(args, count=4)

    amqp_events = collect_amqp_during(
        args,
        "firewall.#",
        generate_counter_traffic,
        seconds=24,
        expected_keys={
            "firewall.live_ssh_accept.counter",
            "firewall.live_input.drop",
        },
    )
    keys = [event.get("key") for event in amqp_events]
    if "firewall.live_ssh_accept.counter" not in keys:
        raise LabError(f"missing AMQP key firewall.live_ssh_accept.counter; keys={keys}")
    if "firewall.live_input.drop" not in keys:
        raise LabError(f"missing AMQP key firewall.live_input.drop; keys={keys}")
    if "firewall.live_ssh_accept.drop" in keys:
        raise LabError("accept counter was routed as drop: firewall.live_ssh_accept.drop")
    log("AMQP ok: live_ssh_accept.counter and live_input.drop observed")


def lab_admission_denial(args: argparse.Namespace) -> None:
    lab = ROOT / "examples/showcase/resource_admission_denial_lab.exs"
    remote_exs = "/tmp/ek_live_lab_11_admission_denial.exs"
    remote_term = "/tmp/ek_live_lab_11.term"

    log("copy DSL lab to host")
    scp(lab, args.host, remote_exs)

    log("compile denial DSL on host")
    remote_ek(args, f"dsl compile {remote_exs} -o {remote_term}", timeout=60)

    log("assert static resource validation rejects the overcommit")
    validate = run(
        ["ssh", args.host, f"{args.prefix}/bin/ek config validate {remote_term}"],
        timeout=30,
        check=False,
    )
    if validate.returncode == 0:
        raise LabError("admission-denial config unexpectedly validated")
    for expected in ("validation failed", "container_limit_exceeds_ceiling", "memory"):
        if expected not in validate.stdout:
            raise LabError(
                f"validation output missing {expected!r}:\n{validate.stdout}"
            )
    log("static rejection ok: container_limit_exceeds_ceiling")

    log("assert ek up fails before creating containers")
    up = run(
        ["ssh", args.host, f"{args.prefix}/bin/ek up {remote_term}"],
        timeout=60,
        check=False,
    )
    if up.returncode == 0:
        raise LabError("admission-denial up unexpectedly succeeded")
    if "container_limit_exceeds_ceiling" not in up.stdout:
        raise LabError(f"ek up did not surface resource ceiling failure:\n{up.stdout}")

    rows = remote_ek_json(args, "ct list", timeout=30)
    leaked = [
        row.get("name") for row in rows
        if row.get("name") in ("worker-0", "worker-1")
    ]
    if leaked:
        raise LabError(f"denial lab created containers despite rejection: {leaked}")
    log("ct list ok: worker-0/worker-1 absent after rejection")

    log("assert workstation explainer renders the denial causal graph")
    rendered = run(
        [
            "mix",
            "erlkoenig.showcase",
            "resource_admission_denial",
            "--explain",
            "--format",
            "mermaid",
        ],
        cwd=ROOT / "dsl",
        timeout=60,
        echo_output=False,
    ).stdout
    for expected in (
        "graph TD",
        "admission_denial__worker_1",
        "capacity_snapshot__worker_1",
        "capacity_held_by",
        "8.0G",
    ):
        if expected not in rendered:
            raise LabError(f"explainer output missing {expected!r}:\n{rendered}")
    log("explainer ok: worker-1 denial Mermaid graph rendered")


def lab_quarantine_crashloop(args: argparse.Namespace) -> None:
    lab = ROOT / "examples/live_labs/04_controlled_crash.exs"
    remote_exs = "/tmp/ek_live_lab_12_quarantine_crashloop.exs"
    remote_term = "/tmp/ek_live_lab_12.term"
    binary_path = f"{args.prefix}/rt/demo/test-erlkoenig-crasher"
    expected_hash = binary_hash(args, binary_path)

    log("copy DSL lab to host")
    scp(lab, args.host, remote_exs)

    log("compile and validate crashloop DSL on host")
    remote_ek(args, f"dsl compile {remote_exs} -o {remote_term}", timeout=60)
    remote_ek(args, f"config validate {remote_term}", timeout=30)

    def unquarantine() -> None:
        remote_ek_unchecked(args, f"quarantine remove {expected_hash}", timeout=30)

    def crash_once(index: int) -> bool:
        log(f"crash iteration {index}/5")
        up = remote_ek_unchecked(args, f"up {remote_term}", timeout=60)
        if up.returncode != 0:
            if index == 5 and "binary_quarantined" in up.stdout:
                log("quarantine gate refused the fifth crashloop start")
                return True
            raise LabError(
                f"crash iteration {index} failed before expected quarantine:\n"
                f"{up.stdout}"
            )
        ssh(args.host, "sleep 6", timeout=10, echo_output=False)
        info = remote_ek_json(args, "ct inspect fail-0-crasher", timeout=30)
        if info.get("state") != "failed":
            raise LabError(f"fail-0-crasher expected failed, got {info.get('state')!r}")
        exit_info = info.get("exit_info", {})
        if exit_info.get("term_signal") != 11:
            raise LabError(f"expected SIGSEGV term_signal=11, got {exit_info}")
        return False

    try:
        log("clear any previous quarantine for the crasher binary")
        unquarantine()

        def run_crashes() -> None:
            for i in range(1, 6):
                if crash_once(i):
                    break

        if args.skip_amqp:
            run_crashes()
            security_events: list[dict] = []
            log("AMQP check skipped")
        else:
            log("capture security AMQP event while driving crashloop")
            security_events = collect_amqp_during(
                args,
                "security.#",
                run_crashes,
                seconds=45,
            )

        log("assert quarantine list contains crashloop entry")
        entries = remote_ek_json(args, "quarantine list", timeout=30)
        match = None
        for entry in entries:
            if entry.get("hash") == expected_hash:
                match = entry
                break
        if not match:
            raise LabError(f"missing crasher hash in quarantine list: {entries}")
        reason = match.get("reason")
        if not isinstance(reason, dict) or reason.get("kind") != "crashloop":
            raise LabError(f"quarantine reason is not crashloop: {match}")
        if reason.get("count") != 5:
            raise LabError(f"quarantine crash count expected 5, got {reason}")
        log(f"quarantine ok: hash={expected_hash[:8]} count=5")

        if security_events:
            expected_key = f"security.{expected_hash[:8]}.quarantined"
            keys = [event.get("key") for event in security_events]
            if expected_key not in keys:
                raise LabError(f"missing AMQP key {expected_key}; keys={keys}")
            log(f"AMQP security ok: {expected_key}")

        log("assert next spawn is refused by quarantine")
        refused = remote_ek_unchecked(args, f"up {remote_term}", timeout=60)
        if refused.returncode == 0:
            raise LabError("quarantined binary unexpectedly spawned")
        if "binary_quarantined" not in refused.stdout and "quarantine" not in refused.stdout:
            raise LabError(f"spawn refusal did not mention quarantine:\n{refused.stdout}")

        rows = remote_ek_json(args, "ct list", timeout=30)
        if any(row.get("name") == "fail-0-crasher" for row in rows):
            raise LabError("fail-0-crasher appears in ct list after quarantine refusal")
        log("ct list ok: fail-0-crasher absent after quarantine refusal")
    finally:
        try:
            remote_ek_unchecked(args, f"down {remote_term}", timeout=90)
        finally:
            unquarantine()


def require_container_row(rows: list[dict], name: str) -> dict:
    for row in rows:
        if row.get("name") == name:
            return row
    names = [row.get("name") for row in rows]
    raise LabError(f"missing container {name!r}; visible containers: {names}")


def require_amqp_key(events: list[dict], key: str) -> dict:
    for event in events:
        if event.get("key") == key:
            return event
    keys = [event.get("key") for event in events]
    raise LabError(f"missing AMQP key {key!r}; keys={keys}")


def require_stats(info: dict, required: list[str]) -> dict:
    stats = info.get("stats")
    if not isinstance(stats, dict):
        raise LabError(f"inspect output has no stats map: keys={sorted(info)}")
    missing = [key for key in required if key not in stats]
    if missing:
        raise LabError(f"inspect stats missing keys {missing}; present={sorted(stats)}")
    return stats


def require_volume(volumes: list[dict], persist: str) -> dict:
    for volume in volumes:
        if volume.get("persist") == persist:
            return volume
    names = [volume.get("persist") for volume in volumes]
    raise LabError(f"missing volume persist={persist!r}; visible persists={names}")


def require_inspect_volume(info: dict, container_path: str) -> dict:
    volumes = info.get("volumes")
    if not isinstance(volumes, list):
        raise LabError(f"inspect output has no volumes list: keys={sorted(info)}")
    for volume in volumes:
        if volume.get("container") == container_path:
            return volume
    paths = [volume.get("container") for volume in volumes if isinstance(volume, dict)]
    raise LabError(f"missing inspect volume mounted at {container_path!r}; paths={paths}")


def destroy_volumes(args: argparse.Namespace, volumes: list[dict]) -> None:
    for volume in volumes:
        uuid = volume.get("uuid")
        if uuid:
            remote_ek(args, f"vol destroy {uuid} --yes", timeout=30)


def run_stack_lab_setup(
    args: argparse.Namespace,
    *,
    lab: Path,
    remote_exs: str,
    remote_term: str,
) -> None:
    log("copy DSL lab to host")
    scp(lab, args.host, remote_exs)

    log("compile and validate DSL on host")
    remote_ek(args, f"dsl compile {remote_exs} -o {remote_term}", timeout=60)
    remote_ek(args, f"config validate {remote_term}", timeout=30)


def assert_runtime_timeline(
    info: dict,
    name: str,
    expected_events: list[str],
    *,
    exit_signal: int | None = None,
    kill_signal: int | None = None,
) -> None:
    timeline = info.get("runtime_timeline") or []
    events = [row.get("event") for row in timeline]
    missing = [event for event in expected_events if event not in events]
    if missing:
        raise LabError(
            f"{name} runtime_timeline missing {missing}; events={events!r} timeline={timeline!r}"
        )

    positions = [events.index(event) for event in expected_events]
    if positions != sorted(positions):
        raise LabError(
            f"{name} runtime_timeline order mismatch; expected={expected_events!r} timeline={timeline!r}"
        )

    if kill_signal is not None:
        kill_event = next(row for row in timeline if row.get("event") == "kill_received")
        if kill_event.get("term_signal") != kill_signal:
            raise LabError(
                f"{name} runtime_timeline expected kill signal={kill_signal}, got {kill_event!r}"
            )

    if exit_signal is not None:
        exit_event = next(row for row in timeline if row.get("event") == "process_exited")
        if exit_event.get("term_signal") != exit_signal:
            raise LabError(
                f"{name} runtime_timeline expected exit signal={exit_signal}, got {exit_event!r}"
            )


def run_lifecycle_lab(
    args: argparse.Namespace,
    *,
    lab: Path,
    remote_exs: str,
    remote_term: str,
    names: list[str],
) -> None:
    run_stack_lab_setup(args, lab=lab, remote_exs=remote_exs, remote_term=remote_term)
    journal_since = remote_now(args)

    try:
        log("assert lifecycle starts are visible in AMQP")
        if args.skip_amqp:
            remote_ek(args, f"up {remote_term}", timeout=60)
        else:
            start_events = collect_amqp_during(
                args,
                "container.#",
                lambda: remote_ek(args, f"up {remote_term}", timeout=60),
                seconds=8,
            )
            for name in names:
                started = require_amqp_key(start_events, f"container.{name}.started")
                payload = started.get("payload", {})
                log(f"AMQP start ok: {payload.get('name')} pid={payload.get('os_pid')}")

        log("assert containers are visible through ek ct list and inspect")
        rows = remote_ek_json(args, "ct list", timeout=30)
        for name in names:
            row = require_container_row(rows, name)
            log(f"ct list ok: {name} state={row.get('state')} ip={row.get('ip')}")
            info = remote_ek_json(args, f"ct inspect {name}", timeout=30)
            if info.get("name") != name:
                raise LabError(f"inspect returned wrong container: {info.get('name')!r}")
            log(f"inspect ok: {name} state={info.get('state')}")

        log("assert lifecycle stops are visible in AMQP and ek state")
        if args.skip_amqp:
            remote_ek(args, f"down {remote_term}", timeout=90)
        else:
            stop_events = collect_amqp_during(
                args,
                "container.#",
                lambda: remote_ek(args, f"down {remote_term}", timeout=90),
                seconds=10,
            )
            for name in names:
                stopped = require_amqp_key(stop_events, f"container.{name}.stopped")
                payload = stopped.get("payload", {})
                log(f"AMQP stop ok: {name} exit={payload.get('exit_code')} signal={payload.get('signal')}")

        log("assert runtime stop timeline shows kill and cleanup")
        for name in names:
            info = remote_ek_json(args, f"ct inspect {name}", timeout=30)
            assert_runtime_timeline(
                info,
                name,
                [
                    "spawn_accepted",
                    "go_accepted",
                    "kill_received",
                    "process_exited",
                    "cleanup_started",
                    "cleanup_done",
                    "runtime_reset_idle",
                ],
                kill_signal=15,
            )
            log(f"runtime timeline ok: {name} stop -> cleanup -> idle")

        rows_after = remote_ek_json(args, "ct list", timeout=30)
        for name in names:
            if any(row.get("name") == name for row in rows_after):
                raise LabError(f"{name} still appears in ct list after down")
            log(f"ct list ok: {name} absent after down")

        log("assert lifecycle is visible in journalctl")
        journal = remote_journal_since(args, journal_since)
        for name in names:
            require_journal_lifecycle(journal, name)
            log(f"journalctl ok: {name} start and clean stop observed")
    except Exception:
        remote_ek(args, f"down {remote_term}", timeout=90)
        raise


def lab_lifecycle_minimal(args: argparse.Namespace) -> None:
    run_lifecycle_lab(
        args,
        lab=ROOT / "examples/live_labs/01_lifecycle_minimal.exs",
        remote_exs="/tmp/ek_live_lab_01_lifecycle_minimal.exs",
        remote_term="/tmp/ek_live_lab_01.term",
        names=["life-0-echo"],
    )


def lab_lifecycle_two_containers(args: argparse.Namespace) -> None:
    run_lifecycle_lab(
        args,
        lab=ROOT / "examples/live_labs/02_lifecycle_two_containers.exs",
        remote_exs="/tmp/ek_live_lab_02_lifecycle_two_containers.exs",
        remote_term="/tmp/ek_live_lab_02.term",
        names=["duo-0-echo", "duo-0-worker"],
    )


def lab_observability_stats(args: argparse.Namespace) -> None:
    remote_term = "/tmp/ek_live_lab_03.term"
    name = "obs-0-echo"
    run_stack_lab_setup(
        args,
        lab=ROOT / "examples/live_labs/03_observability_stats.exs",
        remote_exs="/tmp/ek_live_lab_03_observability_stats.exs",
        remote_term=remote_term,
    )
    journal_since = remote_now(args)

    try:
        log("start observability container and wait for stats timers")
        remote_ek(args, f"up {remote_term}", timeout=60)
        ssh(args.host, "sleep 4", timeout=8)

        log("assert inspect exposes live cgroup stats")
        info = remote_ek_json(args, f"ct inspect {name}", timeout=30)
        if info.get("state") != "running":
            raise LabError(f"{name} expected running, got {info.get('state')!r}")
        stats = require_stats(info, ["memory_bytes", "memory_peak", "cpu_usec", "pids_current"])
        log(
            "inspect stats ok: "
            f"mem={stats.get('memory_bytes')} peak={stats.get('memory_peak')} "
            f"cpu_usec={stats.get('cpu_usec')} pids={stats.get('pids_current')}"
        )

        if args.skip_amqp:
            log("AMQP check skipped")
        else:
            log("assert AMQP emits memory/cpu/pids/pressure/oom stats")
            events = collect_amqp_during(
                args,
                f"stats.{name}.*",
                lambda: ssh(args.host, "sleep 5", timeout=10),
                seconds=6,
            )
            for metric in ("memory", "cpu", "pids", "pressure", "oom"):
                event = require_amqp_key(events, f"stats.{name}.{metric}")
                payload = event.get("payload", {})
                log(f"AMQP stats ok: {metric} keys={sorted(payload)}")

        log("stop observability container")
        remote_ek(args, f"down {remote_term}", timeout=90)
        rows_after = remote_ek_json(args, "ct list", timeout=30)
        if any(row.get("name") == name for row in rows_after):
            raise LabError(f"{name} still appears in ct list after down")
        log(f"ct list ok: {name} absent after down")

        log("assert lifecycle is visible in journalctl")
        journal = remote_journal_since(args, journal_since)
        require_journal_lifecycle(journal, name)
        log("journalctl ok: observability container start and clean stop observed")
    except Exception:
        remote_ek(args, f"down {remote_term}", timeout=90)
        raise


def lab_controlled_crash(args: argparse.Namespace) -> None:
    remote_term = "/tmp/ek_live_lab_04.term"
    name = "fail-0-crasher"
    run_stack_lab_setup(
        args,
        lab=ROOT / "examples/live_labs/04_controlled_crash.exs",
        remote_exs="/tmp/ek_live_lab_04_controlled_crash.exs",
        remote_term=remote_term,
    )
    journal_since = remote_now(args)

    log("start crashing container and capture lifecycle AMQP")
    if args.skip_amqp:
        remote_ek(args, f"up {remote_term}", timeout=60)
        ssh(args.host, "sleep 4", timeout=8)
    else:
        events = collect_amqp_during(
            args,
            f"container.{name}.#",
            lambda: remote_ek(args, f"up {remote_term}", timeout=60),
            seconds=8,
        )
        started = require_amqp_key(events, f"container.{name}.started")
        stopped = require_amqp_key(events, f"container.{name}.stopped")
        log(f"AMQP start ok: {started.get('payload', {}).get('name')}")
        stop_payload = stopped.get("payload", {})
        if stop_payload.get("signal") != 11:
            raise LabError(f"expected SIGSEGV signal=11, got {stop_payload}")
        log(f"AMQP stop ok: exit={stop_payload.get('exit_code')} signal={stop_payload.get('signal')}")

    log("assert post-mortem inspect shows failed crash state")
    info = remote_ek_json(args, f"ct inspect {name}", timeout=30)
    if info.get("state") != "failed":
        raise LabError(f"{name} expected failed, got {info.get('state')!r}")
    exit_info = info.get("exit_info", {})
    if exit_info.get("term_signal") != 11:
        raise LabError(f"{name} expected term_signal=11, got {exit_info}")
    log(f"inspect crash ok: state=failed exit={exit_info.get('exit_code')} signal=11")

    log("assert runtime timeline matches the natural crash path")
    expected_events = [
        "spawn_accepted",
        "go_accepted",
        "process_exited",
        "cleanup_started",
        "cleanup_done",
        "runtime_reset_idle",
    ]
    assert_runtime_timeline(info, name, expected_events, exit_signal=11)
    log(f"runtime timeline ok: {' -> '.join(expected_events)}")

    rows_after = remote_ek_json(args, "ct list", timeout=30)
    if any(row.get("name") == name for row in rows_after):
        raise LabError(f"{name} appears in running ct list after crash")
    log(f"ct list ok: {name} absent after crash")

    log("assert crash lifecycle is visible in journalctl")
    journal = remote_journal_since(args, journal_since)
    require_journal_lifecycle(journal, name, exit_code=-1, term_signal=11)
    log("journalctl ok: crash start and SIGSEGV stop observed")

    log("tear down crash lab stack and assert no active container remains")
    remote_ek(args, f"down {remote_term}", timeout=90)
    rows_after_down = remote_ek_json(args, "ct list", timeout=30)
    if any(row.get("name") == name for row in rows_after_down):
        raise LabError(f"{name} appears in ct list after crash lab down")
    log(f"ct list ok: {name} absent after crash lab down")


def lab_log_stream(args: argparse.Namespace) -> None:
    remote_term = "/tmp/ek_live_lab_07.term"
    name = "log-0-speaker"
    stream_name = f"erlkoenig.log.{name}"
    run_stack_lab_setup(
        args,
        lab=ROOT / "examples/live_labs/07_log_stream.exs",
        remote_exs="/tmp/ek_live_lab_07_log_stream.exs",
        remote_term=remote_term,
    )

    log("start transient log container and capture RabbitMQ stream")
    up_output: dict[str, str] = {}
    journal_since = remote_now(args)

    def start_log_container() -> None:
        up_output["text"] = remote_ek(args, f"up {remote_term}", timeout=60)

    if args.skip_amqp:
        start_log_container()
        ssh(args.host, "sleep 3", timeout=8)
    else:
        messages = collect_stream_during(
            args,
            stream_name,
            start_log_container,
            seconds=8,
            retention="1D",
        )
        bodies = "\n".join(message["body"] for message in messages)
        for expected in ("stdout: Zeile 1", "stdout: Zeile 2", "stdout: Zeile 3"):
            if expected not in bodies:
                raise LabError(f"missing stream line {expected!r}; bodies={bodies!r}")
        stdout_msgs = [
            message for message in messages
            if message["headers"].get("fd") in ("stdout", b"stdout")
        ]
        if not stdout_msgs:
            raise LabError(f"stream {stream_name} had no stdout messages: {messages}")
        log(f"stream ok: {stream_name} messages={len(messages)} stdout={len(stdout_msgs)}")

    if "no net_info" in up_output.get("text", ""):
        raise LabError(f"ek up emitted noisy net_info warning:\n{up_output['text']}")

    log("assert lifecycle is visible in journalctl")
    journal = remote_journal_since(args, journal_since)
    require_journal_lifecycle(journal, name)
    log("journalctl ok: lifecycle start and clean stop observed")

    log("assert post-mortem inspect shows clean stopped state")
    info = remote_ek_json(args, f"ct inspect {name}", timeout=30)
    if info.get("state") != "stopped":
        raise LabError(f"{name} expected stopped, got {info.get('state')!r}")
    exit_info = info.get("exit_info", {})
    if exit_info.get("exit_code") != 0 or exit_info.get("term_signal") != 0:
        raise LabError(f"{name} expected clean exit, got {exit_info}")
    log("inspect ok: state=stopped exit=0 signal=0")

    rows_after = remote_ek_json(args, "ct list", timeout=30)
    if any(row.get("name") == name for row in rows_after):
        raise LabError(f"{name} appears in running ct list after transient exit")
    log(f"ct list ok: {name} absent after transient exit")

    log("tear down log lab stack and assert no active container remains")
    remote_ek(args, f"down {remote_term}", timeout=90)
    rows_after_down = remote_ek_json(args, "ct list", timeout=30)
    if any(row.get("name") == name for row in rows_after_down):
        raise LabError(f"{name} appears in ct list after log lab down")
    log(f"ct list ok: {name} absent after log lab down")


def lab_volumes_persistent(args: argparse.Namespace) -> None:
    remote_term = "/tmp/ek_live_lab_08.term"
    name = "vol-lab-0-svc"
    expected = ["primary-data", "readonly-config", "upload-cache"]
    run_stack_lab_setup(
        args,
        lab=ROOT / "examples/live_labs/08_volumes_persistent.exs",
        remote_exs="/tmp/ek_live_lab_08_volumes_persistent.exs",
        remote_term=remote_term,
    )

    created: list[dict] = []
    try:
        log("start persistent-volume container")
        remote_ek(args, f"up {remote_term}", timeout=60)

        log("assert inspect exposes resolved mount declarations")
        info = remote_ek_json(args, f"ct inspect {name}", timeout=30)
        if info.get("state") != "running":
            raise LabError(f"{name} expected running, got {info.get('state')!r}")
        for path in ("/data", "/etc/app", "/uploads"):
            require_inspect_volume(info, path)
        log("inspect volumes ok: /data /etc/app /uploads")

        log("assert volume metadata is visible through ek vol list")
        volumes = remote_ek_json(args, f"vol list --container {name}", timeout=30)
        for persist in expected:
            row = require_volume(volumes, persist)
            created.append(row)
            log(f"vol list ok: {persist} uuid={row.get('uuid')} lifecycle={row.get('lifecycle')}")

        primary = remote_ek_json(args, "vol inspect primary-data", timeout=30)
        if primary.get("persist") != "primary-data" or not primary.get("host_path"):
            raise LabError(f"vol inspect primary-data returned unexpected payload: {primary}")
        log(f"vol inspect ok: primary-data host_path={primary.get('host_path')}")

        log("stop container and assert persistent metadata remains")
        remote_ek(args, f"down {remote_term}", timeout=90)
        after = remote_ek_json(args, f"vol list --container {name}", timeout=30)
        for persist in expected:
            require_volume(after, persist)
        log("persistent metadata ok after down")
    finally:
        try:
            remote_ek(args, f"down {remote_term}", timeout=90)
        except LabError:
            pass
        if created:
            log("cleanup lab-created persistent volumes")
            destroy_volumes(args, created)


def lab_volumes_ephemeral(args: argparse.Namespace) -> None:
    remote_term = "/tmp/ek_live_lab_09.term"
    name = "eph-lab-0-worker"
    run_stack_lab_setup(
        args,
        lab=ROOT / "examples/live_labs/09_volumes_ephemeral.exs",
        remote_exs="/tmp/ek_live_lab_09_volumes_ephemeral.exs",
        remote_term=remote_term,
    )

    scratch_uuid = None
    try:
        log("start ephemeral-volume container")
        remote_ek(args, f"up {remote_term}", timeout=60)

        volumes = remote_ek_json(args, f"vol list --container {name}", timeout=30)
        scratch = require_volume(volumes, "scratch-run")
        scratch_uuid = scratch.get("uuid")
        log(f"ephemeral volume visible: scratch-run uuid={scratch_uuid}")

        log("stop container and assert ephemeral metadata is removed")
        remote_ek(args, f"down {remote_term}", timeout=90)
        after = remote_ek_json(args, f"vol list --container {name}", timeout=30)
        if after:
            raise LabError(f"ephemeral volumes still listed after down: {after}")
        log("vol list ok: ephemeral container has no volumes after down")

        if scratch_uuid:
            orphans = remote_ek_json(args, "vol orphans", timeout=30)
            orphan_ids = [row.get("uuid") for row in orphans]
            if scratch_uuid in orphan_ids:
                raise LabError(f"ephemeral volume directory became orphan: {scratch_uuid}")
            log("vol orphans ok: scratch-run uuid absent")
    finally:
        try:
            remote_ek(args, f"down {remote_term}", timeout=90)
        except LabError:
            pass


LABS = {
    "admission-denial": lab_admission_denial,
    "controlled-crash": lab_controlled_crash,
    "firewall-host-counters": lab_firewall_host_counters,
    "lifecycle-minimal": lab_lifecycle_minimal,
    "lifecycle-two-containers": lab_lifecycle_two_containers,
    "log-stream": lab_log_stream,
    "observability-stats": lab_observability_stats,
    "quarantine-crashloop": lab_quarantine_crashloop,
    "volumes-ephemeral": lab_volumes_ephemeral,
    "volumes-persistent": lab_volumes_persistent,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Erlkoenig live operator-contract labs")
    parser.add_argument("lab", choices=sorted(LABS))
    parser.add_argument("--host", default=os.environ.get("ERLKOENIG_LAB_HOST", "erlkoenig-2__root"))
    parser.add_argument("--prefix", default=os.environ.get("ERLKOENIG_PREFIX", "/opt/erlkoenig"))
    parser.add_argument("--amqp-host", default=os.environ.get("AMQP_HOST"))
    parser.add_argument("--skip-amqp", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        LABS[args.lab](args)
    except LabError as exc:
        print(f"[live-lab] FAIL: {exc}", file=sys.stderr)
        return 1
    log(f"PASS: {args.lab}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
