#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGGER_BIN="$ROOT_DIR/build/logger"

BUILD_FIRST=1
KEEP_ARTIFACTS=0
VERBOSE=0
SCENARIO="all"
WORK_DIR=""

PIDS=()
STARTED_PID=""

usage() {
    cat <<'EOF'
Usage:
  scripts/cluster_integration_tests.sh [options]

Options:
  --no-build            Skip `make -j4`
  --keep-artifacts      Keep temp logs/keys/node stdout files
  --work-dir PATH       Use a specific working directory
  --scenario NAME       One of: all, happy, quorum, repair (default: all)
  --scenario=NAME       Same as --scenario NAME
  --work-dir=PATH       Same as --work-dir PATH
  --verbose             Print node stdout logs at the end
  -h, --help            Show this help
EOF
}

log() {
    printf '[cluster-test] %s\n' "$*"
}

die() {
    printf '[cluster-test] ERROR: %s\n' "$*" >&2
    exit 1
}

remove_pid() {
    local target="$1"
    local next=()
    local p
    for p in "${PIDS[@]:-}"; do
        if [[ "$p" != "$target" ]]; then
            next+=("$p")
        fi
    done
    if [[ ${#next[@]} -gt 0 ]]; then
        PIDS=("${next[@]}")
    else
        PIDS=()
    fi
}

stop_node() {
    local pid="$1"
    if [[ -z "$pid" ]]; then
        return
    fi
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    remove_pid "$pid"
}

cleanup() {
    local p
    for p in "${PIDS[@]:-}"; do
        stop_node "$p"
    done

    if [[ "${WORK_DIR:-}" != "" ]]; then
        if [[ "$KEEP_ARTIFACTS" -eq 1 ]]; then
            log "artifacts kept at: $WORK_DIR"
        else
            rm -rf "$WORK_DIR"
        fi
    fi
}

trap cleanup EXIT INT TERM

hash_file() {
    local f="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$f" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$f" | awk '{print $1}'
    else
        openssl dgst -sha256 "$f" | awk '{print $NF}'
    fi
}

pick_unique_ports() {
    local count="$1"
    local ports=()
    local min_port=20000
    local max_port=59999

    while [[ "${#ports[@]}" -lt "$count" ]]; do
        local cand
        cand=$(( min_port + (RANDOM % (max_port - min_port + 1)) ))

        if command -v lsof >/dev/null 2>&1; then
            if lsof -nP -iTCP:"$cand" -sTCP:LISTEN >/dev/null 2>&1; then
                continue
            fi
        fi

        local seen=0
        local p
        for p in "${ports[@]:-}"; do
            if [[ "$p" == "$cand" ]]; then
                seen=1
                break
            fi
        done
        if [[ "$seen" -eq 0 ]]; then
            ports+=("$cand")
        fi
    done

    echo "${ports[*]}"
}

ensure_keys() {
    local pub="$1"
    local priv="$2"
    local bootstrap_log="$WORK_DIR/_keygen.log"

    if [[ ! -f "$pub" || ! -f "$priv" ]]; then
        "$LOGGER_BIN" add score 0 "bootstrap" \
            --author 0 \
            --nonce 1 \
            --log "$bootstrap_log" \
            --pub "$pub" \
            --priv "$priv" >/dev/null 2>&1 || true
        rm -f "$bootstrap_log"
    fi

    [[ -f "$pub" ]] || die "failed to create pub key: $pub"
    [[ -f "$priv" ]] || die "failed to create priv key: $priv"
}

pub_hex() {
    local pub="$1"
    "$LOGGER_BIN" show-pub --pub "$pub" | tr -d '[:space:]'
}

wait_for_node_ready() {
    local pid="$1"
    local logfile="$2"
    local port="$3"

    local i
    for i in $(seq 1 200); do
        if ! kill -0 "$pid" 2>/dev/null; then
            if [[ -f "$logfile" ]]; then
                printf '[cluster-test] node log (%s):\n' "$logfile" >&2
                tail -n 50 "$logfile" >&2 || true
            fi
            die "node process died early (pid=$pid), see: $logfile"
        fi

        # Use non-blocking port checks only; protocol probes can block indefinitely.
        if command -v lsof >/dev/null 2>&1; then
            if lsof -nP -a -p "$pid" -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
                return 0
            fi
        elif command -v nc >/dev/null 2>&1; then
            if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
                return 0
            fi
        else
            # Fallback: if still alive for >2 seconds, assume node reached listen loop.
            if [[ "$i" -gt 20 ]]; then
                return 0
            fi
        fi

        # Keep old log-based readiness as a fallback (can be delayed by buffering).
        if grep -q "listening on" "$logfile" 2>/dev/null; then
            return 0
        fi

        sleep 0.1
    done

    if [[ -f "$logfile" ]]; then
        printf '[cluster-test] node log (%s):\n' "$logfile" >&2
        tail -n 50 "$logfile" >&2 || true
    fi
    die "node did not report ready in time: $logfile"
}

start_node() {
    local node_id="$1"
    local leader_id="$2"
    local port="$3"
    local log_path="$4"
    local pub_path="$5"
    local priv_path="$6"
    local peers_path="$7"
    local out_log="$8"

    "$LOGGER_BIN" node \
        --node-id "$node_id" \
        --leader-id "$leader_id" \
        --listen "127.0.0.1:${port}" \
        --log "$log_path" \
        --pub "$pub_path" \
        --priv "$priv_path" \
        --peers "$peers_path" \
        >"$out_log" 2>&1 &
    local pid=$!
    PIDS+=("$pid")
    wait_for_node_ready "$pid" "$out_log" "$port"
    STARTED_PID="$pid"
}

submit_ok() {
    local port="$1"
    local event="$2"
    local player="$3"
    local desc="$4"
    local nonce="$5"

    local out
    if ! out=$("$LOGGER_BIN" submit \
        --host 127.0.0.1 \
        --port "$port" \
        --event "$event" \
        --player "$player" \
        --desc "$desc" \
        --nonce "$nonce" 2>&1); then
        printf '%s\n' "$out" >&2
        die "submit failed unexpectedly (nonce=$nonce)"
    fi

    if [[ "$out" != *"OK nonce="* ]]; then
        printf '%s\n' "$out" >&2
        die "submit output did not include ACK marker (nonce=$nonce)"
    fi
}

submit_expect_nack() {
    local port="$1"
    local event="$2"
    local player="$3"
    local desc="$4"
    local nonce="$5"
    local nack_code="$6"

    local out
    if out=$("$LOGGER_BIN" submit \
        --host 127.0.0.1 \
        --port "$port" \
        --event "$event" \
        --player "$player" \
        --desc "$desc" \
        --nonce "$nonce" 2>&1); then
        printf '%s\n' "$out" >&2
        die "submit unexpectedly succeeded; expected nack=$nack_code"
    fi

    if [[ "$out" != *"nack=${nack_code}"* ]]; then
        printf '%s\n' "$out" >&2
        die "submit failed, but not with expected nack=$nack_code"
    fi
}

wait_for_convergence() {
    local peers_path="$1"
    shift
    local logs=("$@")

    local attempts=150
    local i
    for i in $(seq 1 "$attempts"); do
        local all_ok=1
        local ref_hash=""
        local lp

        for lp in "${logs[@]}"; do
            if ! "$LOGGER_BIN" verify-peers --log "$lp" --peers "$peers_path" >/dev/null 2>&1; then
                all_ok=0
                break
            fi

            local cur_hash
            cur_hash="$(hash_file "$lp")"
            if [[ -z "$ref_hash" ]]; then
                ref_hash="$cur_hash"
            elif [[ "$cur_hash" != "$ref_hash" ]]; then
                all_ok=0
                break
            fi
        done

        if [[ "$all_ok" -eq 1 ]]; then
            return 0
        fi

        sleep 0.1
    done

    local lp
    for lp in "${logs[@]}"; do
        "$LOGGER_BIN" verify-peers --log "$lp" --peers "$peers_path" || true
    done
    die "logs did not converge in time"
}

scenario_happy_3node() {
    log "scenario happy: 3-node quorum replication"

    local d="$WORK_DIR/happy3"
    mkdir -p "$d"

    local l1="$d/n1.log" l2="$d/n2.log" l3="$d/n3.log"
    local p1="$d/n1.pub" p2="$d/n2.pub" p3="$d/n3.pub"
    local s1="$d/n1.priv" s2="$d/n2.priv" s3="$d/n3.priv"
    local peers="$d/peers.conf"

    ensure_keys "$p1" "$s1"
    ensure_keys "$p2" "$s2"
    ensure_keys "$p3" "$s3"

    local port1 port2 port3
    read -r port1 port2 port3 <<<"$(pick_unique_ports 3)"

    cat >"$peers" <<EOF
1 127.0.0.1 ${port1} $(pub_hex "$p1")
2 127.0.0.1 ${port2} $(pub_hex "$p2")
3 127.0.0.1 ${port3} $(pub_hex "$p3")
EOF

    local pid1 pid2 pid3
    start_node 1 1 "$port1" "$l1" "$p1" "$s1" "$peers" "$d/node1.out"; pid1="$STARTED_PID"
    start_node 2 1 "$port2" "$l2" "$p2" "$s2" "$peers" "$d/node2.out"; pid2="$STARTED_PID"
    start_node 3 1 "$port3" "$l3" "$p3" "$s3" "$peers" "$d/node3.out"; pid3="$STARTED_PID"

    submit_ok "$port1" score 23 "happy-a1" 10101
    submit_ok "$port1" foul  23 "happy-a2" 10102

    wait_for_convergence "$peers" "$l1" "$l2" "$l3"

    stop_node "$pid1"
    stop_node "$pid2"
    stop_node "$pid3"

    log "scenario happy: PASS"
}

scenario_quorum_retry_2node() {
    log "scenario quorum: fail-then-duplicate-retry"

    local d="$WORK_DIR/quorum2"
    mkdir -p "$d"

    local l1="$d/n1.log" l2="$d/n2.log"
    local p1="$d/n1.pub" p2="$d/n2.pub"
    local s1="$d/n1.priv" s2="$d/n2.priv"
    local peers="$d/peers.conf"

    ensure_keys "$p1" "$s1"
    ensure_keys "$p2" "$s2"

    local port1 port2
    read -r port1 port2 <<<"$(pick_unique_ports 2)"

    cat >"$peers" <<EOF
1 127.0.0.1 ${port1} $(pub_hex "$p1")
2 127.0.0.1 ${port2} $(pub_hex "$p2")
EOF

    local pid1 pid2
    start_node 1 1 "$port1" "$l1" "$p1" "$s1" "$peers" "$d/node1.out"; pid1="$STARTED_PID"

    submit_expect_nack "$port1" score 9 "qfail" 22001 9

    start_node 2 1 "$port2" "$l2" "$p2" "$s2" "$peers" "$d/node2.out"; pid2="$STARTED_PID"

    submit_ok "$port1" score 9 "qfail" 22001

    wait_for_convergence "$peers" "$l1" "$l2"

    stop_node "$pid1"
    stop_node "$pid2"

    log "scenario quorum: PASS"
}

scenario_repair_2node() {
    log "scenario repair: follower divergence truncate+replay"

    local d="$WORK_DIR/repair2"
    mkdir -p "$d"

    local l1="$d/n1.log" l2="$d/n2.log"
    local p1="$d/n1.pub" p2="$d/n2.pub"
    local s1="$d/n1.priv" s2="$d/n2.priv"
    local peers="$d/peers.conf"

    ensure_keys "$p1" "$s1"
    ensure_keys "$p2" "$s2"

    local port1 port2
    read -r port1 port2 <<<"$(pick_unique_ports 2)"

    cat >"$peers" <<EOF
1 127.0.0.1 ${port1} $(pub_hex "$p1")
2 127.0.0.1 ${port2} $(pub_hex "$p2")
EOF

    local pid1 pid2
    start_node 1 1 "$port1" "$l1" "$p1" "$s1" "$peers" "$d/node1.out"; pid1="$STARTED_PID"
    start_node 2 1 "$port2" "$l2" "$p2" "$s2" "$peers" "$d/node2.out"; pid2="$STARTED_PID"

    submit_ok "$port1" score 1 "base" 33001

    stop_node "$pid2"

    "$LOGGER_BIN" add score 99 "rogue" \
        --author 2 \
        --nonce 99001 \
        --log "$l2" \
        --pub "$p2" \
        --priv "$s2" >/dev/null

    start_node 2 1 "$port2" "$l2" "$p2" "$s2" "$peers" "$d/node2b.out"; pid2="$STARTED_PID"

    submit_ok "$port1" foul 1 "after-repair" 33002

    wait_for_convergence "$peers" "$l1" "$l2"

    local printed
    printed="$("$LOGGER_BIN" print "$l2")"
    if grep -q "rogue" <<<"$printed"; then
        printf '%s\n' "$printed" >&2
        die "follower still contains rogue entry after repair"
    fi

    stop_node "$pid1"
    stop_node "$pid2"

    log "scenario repair: PASS"
}

validate_scenario() {
    case "$1" in
        all|happy|quorum|repair) return 0 ;;
        *) return 1 ;;
    esac
}

run_scenario() {
    local name="$1"
    log "scenario $name: START"
    case "$name" in
        happy)
            scenario_happy_3node
            ;;
        quorum)
            scenario_quorum_retry_2node
            ;;
        repair)
            scenario_repair_2node
            ;;
        *)
            die "internal error: unknown scenario '$name'"
            ;;
    esac
    log "scenario $name: DONE"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-build)
                BUILD_FIRST=0
                ;;
            --keep-artifacts)
                KEEP_ARTIFACTS=1
                ;;
            --work-dir)
                shift
                [[ $# -gt 0 ]] || die "--work-dir requires a value"
                WORK_DIR="$1"
                ;;
            --work-dir=*)
                WORK_DIR="${1#*=}"
                [[ -n "$WORK_DIR" ]] || die "--work-dir requires a value"
                ;;
            --scenario)
                shift
                [[ $# -gt 0 ]] || die "--scenario requires a value"
                SCENARIO="$1"
                ;;
            --scenario=*)
                SCENARIO="${1#*=}"
                [[ -n "$SCENARIO" ]] || die "--scenario requires a value"
                ;;
            --verbose)
                VERBOSE=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
        shift
    done
}

main() {
    parse_args "$@"

    if ! validate_scenario "$SCENARIO"; then
        die "--scenario must be one of: all, happy, quorum, repair"
    fi

    if [[ "$BUILD_FIRST" -eq 1 ]]; then
        log "building project"
        make -C "$ROOT_DIR" -j4 >/dev/null
    fi

    [[ -x "$LOGGER_BIN" ]] || die "logger binary not found: $LOGGER_BIN"

    if [[ -z "$WORK_DIR" ]]; then
        WORK_DIR="$(mktemp -d /tmp/tp-cluster-tests.XXXXXX)"
    else
        mkdir -p "$WORK_DIR"
    fi
    log "work dir: $WORK_DIR"

    if [[ "$SCENARIO" == "all" ]]; then
        run_scenario happy
        run_scenario quorum
        run_scenario repair
    else
        run_scenario "$SCENARIO"
    fi

    if [[ "$VERBOSE" -eq 1 ]]; then
        log "node stdout logs:"
        find "$WORK_DIR" -name "*.out" -type f -print | while read -r f; do
            printf '\n===== %s =====\n' "$f"
            cat "$f"
        done
    fi

    log "ALL REQUESTED SCENARIOS PASSED"
}

main "$@"
