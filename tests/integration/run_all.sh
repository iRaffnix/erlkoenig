#!/bin/bash
# Run all Erlkoenig integration tests
# Usage: sudo -E ./tests/integration/run_all.sh
set -e

# Go to project root (two levels up from this script)
cd "$(dirname "$0")/../.."

# Compile test helper
erlc -o tests/integration tests/integration/test_helper.erl

GREEN='\033[32m'
RED='\033[31m'
BOLD='\033[1m'
RESET='\033[0m'

TESTS=(
    "01_lifecycle.escript        Spawn, Inspect, Stop, Exit"
    "04_memory_limit.escript     OOM-Kill bei Memory-Limit"
    "05_pid_limit.escript        PID-Limit (Fork-Schutz)"
    "06_restart.escript          Auto-Restart mit Backoff"
    "07_seccomp.escript          Seccomp Syscall-Filter"
    "08_file_injection.escript   File Injection"
    "09_dns.escript              DNS Service Discovery"
    "10_firewall.escript         Firewall Isolation"
    "11_output.escript           Output Capture"
    "12_protocol.escript         Low-Level Protokoll (SPAWN/GO/EXITED)"
    "14_pty.escript              PTY + Stdin Integration"
    "15_dsl_config.escript       DSL Config Pipeline (escript → term → load)"
    "16_proc_masking.escript     Process Masking"
    "17_signature.escript        Binary Signature Verification"
    "18_bind_mount_volume.escript Persistent Volumes (Bind Mount)"
    "19_cgroup_topology.escript  cgroup Topology (beam/ + containers/)"
    "20_beam_survives_oom.escript BEAM überlebt Container OOM-Kill"
    "21_e2e_full_stack.escript   E2E: Full Stack Compile/Load/Verify"
    "22_pki_container.escript    PKI: Signed Container Startup"
    "23_ipvlan.escript           IPVLAN L3S Networking"
    "24_container_nft.escript    Per-Container nft Firewall (CMD_NFT_SETUP)"
    "25_volume_mount_opts.escript Volume Mount Options (ro, nosuid, opts: string)"
    "26_dsl_volume_opts.escript  DSL → .term → load → verify kernel mount flags"
    "27_ephemeral_volume_cleanup.escript Ephemeral volumes + UUID store + cleanup"
)

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   Erlkoenig Integration Test Suite        ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo ""

PASSED=0
FAILED=0
FAILED_NAMES=""

for entry in "${TESTS[@]}"; do
    SCRIPT=$(echo "$entry" | awk '{print $1}')
    DESC=$(echo "$entry" | cut -d' ' -f2-)

    echo -e "${BOLD}>>> ${DESC} (${SCRIPT})${RESET}"

    if escript "tests/integration/${SCRIPT}" 2>&1; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        FAILED_NAMES="${FAILED_NAMES}  - ${SCRIPT}: ${DESC}\n"
    fi

    # Clean up any leftover nft table between tests
    nft delete table inet erlkoenig 2>/dev/null || true
    sleep 1
done

echo ""
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo -e "  Passed: ${GREEN}${PASSED}${RESET}"
echo -e "  Failed: ${RED}${FAILED}${RESET}"

if [ "$FAILED" -gt 0 ]; then
    echo -e "\n  Failed tests:"
    echo -e "${RED}${FAILED_NAMES}${RESET}"
    exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}  All ${PASSED} tests passed!${RESET}"
echo ""
