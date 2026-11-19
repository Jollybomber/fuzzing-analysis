#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Override for a fresh campaign, e.g. BIN_DIR=bin_v2 OUT_ROOT=fuzz_out_v2 $0 --all
BIN_DIR="${BIN_DIR:-${ROOT_DIR}/bin}"
SEED_DIR="${SEED_DIR:-${ROOT_DIR}/fuzz_seeds}"
OUT_ROOT="${OUT_ROOT:-${ROOT_DIR}/fuzz_out}"

DURATION_SEC=1800   # 30 minutes per run (-V 1800)
TIMEOUT_MS=1000     # 1000 ms per execution (-t 1000)
MEM_LIMIT="none"    # Consistent across normal, ASan, and ASan+UBSan (-m none)
REPEATS="${REPEATS:-5}"   # Runs per parser/config for --all

usage() {
    cat <<EOF
Usage:
  Single run:
    $0 <cjson|jsonc> <normal|asan|asan_ubsan> <runN> [core_id]

  Full campaign: 2 parsers x 3 configs x REPEATS runs (default 5), N pinned cores:
    $0 --all [max_parallel]
EOF
    exit 1
}

run_single() {
    local parser="$1"
    local config="$2"
    local run_id="$3"
    local core_id="${4:-}"

    local target_bin="${BIN_DIR}/${parser}_afl_${config}"
    local campaign_dir="${OUT_ROOT}/${parser}_${config}_${run_id}"

    if [[ ! -x "${target_bin}" ]]; then
        echo "Error: target binary not found or not executable: ${target_bin}" >&2
        exit 1
    fi

    if [[ ! -d "${SEED_DIR}" ]] || [[ -z "$(ls -A "${SEED_DIR}")" ]]; then
        echo "Error: seed directory is missing or empty: ${SEED_DIR}" >&2
        exit 1
    fi

    if [[ -e "${campaign_dir}" ]]; then
        echo "Error: ${campaign_dir} already exists; set OUT_ROOT to a fresh directory." >&2
        exit 1
    fi
    mkdir -p "${campaign_dir}"

    # Ensure UBSan aborts so AFL++ records UB findings in crashes/
    export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=0"
    export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:symbolize=0"
    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

    local core_flag=()
    if [[ -n "${core_id}" ]]; then
        core_flag=(-b "${core_id}")
    fi

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting ${parser}_${config}_${run_id} (core=${core_id:-auto}, duration=${DURATION_SEC}s)"

    afl-fuzz \
        -i "${SEED_DIR}" \
        -o "${campaign_dir}" \
        -V "${DURATION_SEC}" \
        -t "${TIMEOUT_MS}" \
        -m "${MEM_LIMIT}" \
        "${core_flag[@]}" \
        -- "${target_bin}" @@ > "${campaign_dir}/afl.log" 2>&1

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Finished ${parser}_${config}_${run_id}"
}

run_all_parallel() {
    local max_parallel="${1:-3}"
    local jobs=()

    for (( r = 1; r <= REPEATS; r++ )); do
        local run_id="run${r}"
        for parser in cjson jsonc; do
            for config in normal asan asan_ubsan; do
                jobs+=("${parser}:${config}:${run_id}")
            done
        done
    done

    echo "Scheduling ${#jobs[@]} campaigns (${max_parallel} concurrent workers, ~$(( ${#jobs[@]} * DURATION_SEC / max_parallel / 3600 ))h+ wall-clock)..."

    local active_pids=()
    local slot=0

    for job in "${jobs[@]}"; do
        IFS=':' read -r parser config run_id <<< "${job}"
        local core_id=$(( slot % max_parallel ))

        AFL_NO_UI=1 run_single "${parser}" "${config}" "${run_id}" "${core_id}" &
        active_pids+=($!)
        slot=$(( slot + 1 ))

        if (( ${#active_pids[@]} >= max_parallel )); then
            wait "${active_pids[0]}"
            active_pids=("${active_pids[@]:1}")
        fi
    done

    wait
    echo "All ${#jobs[@]} fuzzing runs completed."
}

if [[ $# -lt 1 ]]; then
    usage
fi

# Only fuzz binaries produced (and verified) by the current setup_and_build.sh.
if [[ ! -f "${BIN_DIR}/build_manifest.json" ]]; then
    echo "Error: ${BIN_DIR}/build_manifest.json missing; rebuild with scripts/setup_and_build.sh." >&2
    exit 1
fi
mkdir -p "${OUT_ROOT}"
cp "${BIN_DIR}/build_manifest.json" "${OUT_ROOT}/build_manifest.json"

[[ "$REPEATS" =~ ^[1-9][0-9]*$ ]] || { echo "Error: REPEATS must be a positive integer" >&2; exit 1; }

if [[ "$1" == "--all" ]]; then
    run_all_parallel "${2:-3}"
elif [[ $# -ge 3 && $# -le 4 ]]; then
    run_single "$1" "$2" "$3" "${4:-}"
else
    usage
fi