#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Override for a fresh campaign, e.g. BIN_DIR=bin_v2 OUT_ROOT=fuzz_out_v2 $0 --all
BIN_DIR="${BIN_DIR:-${ROOT_DIR}/bin}"
SEED_DIR="${SEED_DIR:-${ROOT_DIR}/fuzz_seeds}"
OUT_ROOT="${OUT_ROOT:-${ROOT_DIR}/fuzz_out}"
# AFL writes every test case to .cur_input before running the target with @@. Keeping that
# file on a container-local path (not a macOS/Windows bind mount such as /work) avoids
# milliseconds of file I/O per execution, which otherwise dominates exec time and hides
# sanitizer overhead. Set CUR_INPUT_ROOT= (empty) to keep it inside the output directory.
CUR_INPUT_ROOT="${CUR_INPUT_ROOT-/tmp/afl_cur_input}"

DURATION_SEC=1800   # 30 minutes per run (-V 1800)
TIMEOUT_MS=1000     # 1000 ms per execution (-t 1000)
MEM_LIMIT="none"    # Consistent across normal, ASan, and ASan+UBSan (-m none)
REPEATS="${REPEATS:-5}"   # Runs per parser/config for --all
CONFIGS=(normal asan asan_ubsan)

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

# Write the campaign's provenance record and refuse targets that differ from the build manifest.
write_run_manifest() {
    local parser="$1" config="$2" run_id="$3" core_id="$4" target_bin="$5" campaign_dir="$6"
    python3 - "$parser" "$config" "$run_id" "$core_id" "$target_bin" "$campaign_dir" \
        "$SEED_DIR" "${BIN_DIR}/build_manifest.json" "$DURATION_SEC" "$TIMEOUT_MS" "$MEM_LIMIT" <<'PY'
import hashlib, json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
parser, config, run_id, core, target, campaign, seeds, manifest_path, duration, timeout, mem = sys.argv[1:]
digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
target_sha = digest(target)
manifest = json.loads(Path(manifest_path).read_text())
expected = manifest.get("binaries_sha256", {}).get(Path(target).name)
if expected != target_sha:
    sys.exit(f"Error: {target} does not match {manifest_path} (expected {expected}, got {target_sha})")
version = subprocess.run(["afl-fuzz", "--version"], capture_output=True, text=True)
record = {
    "campaign": Path(campaign).name, "parser": parser, "config": config, "run_id": run_id,
    "core": int(core) if core else None, "started_utc": datetime.now(timezone.utc).isoformat(),
    "target": target, "target_sha256": target_sha, "build_manifest_sha256": digest(manifest_path),
    "duration_sec": int(duration), "timeout_ms": int(timeout), "mem_limit": mem,
    "seeds_sha256": {p.name: digest(p) for p in sorted(Path(seeds).iterdir()) if p.is_file()},
    "env": {k: os.environ.get(k) for k in ("ASAN_OPTIONS", "UBSAN_OPTIONS", "AFL_TMPDIR", "AFL_NO_UI",
                                           "AFL_SKIP_CPUFREQ", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES")},
    "afl_fuzz_version": (version.stdout or version.stderr).strip().splitlines()[0] if (version.stdout or version.stderr) else None,
    "cpu_count": os.cpu_count(),
}
(Path(campaign) / "run_manifest.json").write_text(json.dumps(record, indent=2) + "\n")
PY
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
        return 1
    fi

    if [[ ! -d "${SEED_DIR}" ]] || [[ -z "$(ls -A "${SEED_DIR}")" ]]; then
        echo "Error: seed directory is missing or empty: ${SEED_DIR}" >&2
        return 1
    fi

    if [[ -e "${campaign_dir}" ]]; then
        echo "Error: ${campaign_dir} already exists; set OUT_ROOT to a fresh directory." >&2
        return 1
    fi
    mkdir -p "${campaign_dir}"

    # Ensure UBSan aborts so AFL++ records UB findings in crashes/
    export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=0"
    export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:symbolize=0"
    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    if [[ -n "${CUR_INPUT_ROOT}" ]]; then
        local root_id
        root_id="$(cd "${OUT_ROOT}" && pwd | cksum | cut -d' ' -f1)"
        export AFL_TMPDIR="${CUR_INPUT_ROOT}/$(basename "${OUT_ROOT}")_${root_id}_${parser}_${config}_${run_id}"
        mkdir -p "${AFL_TMPDIR}"
    else
        unset AFL_TMPDIR
    fi

    local core_flag=()
    if [[ -n "${core_id}" ]]; then
        core_flag=(-b "${core_id}")
    fi

    if ! write_run_manifest "${parser}" "${config}" "${run_id}" "${core_id}" "${target_bin}" "${campaign_dir}"; then
        rmdir "${campaign_dir}" 2>/dev/null || true   # leave no empty folder behind, so a retry is possible
        return 1
    fi

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting ${parser}_${config}_${run_id} (core=${core_id:-auto}, duration=${DURATION_SEC}s, cur_input=${AFL_TMPDIR:-output dir})"

    local status=0
    afl-fuzz \
        -i "${SEED_DIR}" \
        -o "${campaign_dir}" \
        -V "${DURATION_SEC}" \
        -t "${TIMEOUT_MS}" \
        -m "${MEM_LIMIT}" \
        "${core_flag[@]}" \
        -- "${target_bin}" @@ > "${campaign_dir}/afl.log" 2>&1 || status=$?

    if (( status != 0 )); then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] FAILED ${parser}_${config}_${run_id} (afl-fuzz exit ${status}; see ${campaign_dir}/afl.log)" >&2
        return "${status}"
    fi
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Finished ${parser}_${config}_${run_id}"
}

run_all_parallel() {
    local max_parallel="${1:-3}"
    [[ "${max_parallel}" =~ ^[1-9][0-9]*$ ]] || { echo "Error: max_parallel must be a positive integer" >&2; exit 1; }
    local jobs=()
    local p_index=0

    # Each group of three consecutive jobs is one parser's three builds for one repeat, so
    # the builds being compared run side by side under the same machine conditions. The
    # build order is rotated every group, so each build runs on every core across repeats
    # (with max_parallel=3, job N is pinned to core N % 3).
    for (( r = 1; r <= REPEATS; r++ )); do
        local run_id="run${r}"
        p_index=0
        for parser in cjson jsonc; do
            local shift_by=$(( (r - 1 + p_index) % ${#CONFIGS[@]} ))
            local i
            for (( i = 0; i < ${#CONFIGS[@]}; i++ )); do
                local config="${CONFIGS[$(( (i + shift_by) % ${#CONFIGS[@]} ))]}"
                jobs+=("${parser}:${config}:${run_id}")
            done
            p_index=$(( p_index + 1 ))
        done
    done

    echo "Scheduling ${#jobs[@]} campaigns (${max_parallel} concurrent workers, ~$(( ${#jobs[@]} * DURATION_SEC / max_parallel / 3600 ))h+ wall-clock)..."

    local active_pids=() active_names=() failed=()
    local slot=0

    for job in "${jobs[@]}"; do
        IFS=':' read -r parser config run_id <<< "${job}"
        # The job started max_parallel slots earlier owned this core and has been waited for.
        local core_id=$(( slot % max_parallel ))

        AFL_NO_UI=1 run_single "${parser}" "${config}" "${run_id}" "${core_id}" &
        active_pids+=($!)
        active_names+=("${parser}_${config}_${run_id}")
        slot=$(( slot + 1 ))

        if (( ${#active_pids[@]} >= max_parallel )); then
            wait "${active_pids[0]}" || failed+=("${active_names[0]}")
            active_pids=("${active_pids[@]:1}")
            active_names=("${active_names[@]:1}")
        fi
    done

    local i
    for i in "${!active_pids[@]}"; do
        wait "${active_pids[$i]}" || failed+=("${active_names[$i]}")
    done

    if (( ${#failed[@]} > 0 )); then
        echo "ERROR: ${#failed[@]} of ${#jobs[@]} campaigns failed: ${failed[*]}" >&2
        return 1
    fi
    echo "All ${#jobs[@]} fuzzing runs completed."
}

if [[ $# -lt 1 ]]; then
    usage
fi

# Validate the arguments before creating anything.
if [[ "$1" == "--all" ]]; then
    [[ $# -le 2 ]] || usage
elif [[ $# -ge 3 && $# -le 4 ]]; then
    [[ "$1" =~ ^(cjson|jsonc)$ && "$2" =~ ^(normal|asan|asan_ubsan)$ && "$3" =~ ^run[0-9]+$ ]] || usage
    [[ -z "${4:-}" || "${4}" =~ ^[0-9]+$ ]] || usage
else
    usage
fi
[[ "$REPEATS" =~ ^[1-9][0-9]*$ ]] || { echo "Error: REPEATS must be a positive integer" >&2; exit 1; }

# Only fuzz binaries produced (and verified) by the current setup_and_build.sh.
if [[ ! -f "${BIN_DIR}/build_manifest.json" ]]; then
    echo "Error: ${BIN_DIR}/build_manifest.json missing; rebuild with scripts/setup_and_build.sh." >&2
    exit 1
fi
# OUT_ROOT/build_manifest.json is what the analyzer checks binaries against, so never replace it
# with a different build's manifest.
mkdir -p "${OUT_ROOT}"
if [[ -e "${OUT_ROOT}/build_manifest.json" ]]; then
    if ! cmp -s "${BIN_DIR}/build_manifest.json" "${OUT_ROOT}/build_manifest.json"; then
        echo "Error: ${OUT_ROOT} already holds campaigns from a different build (build_manifest.json differs)." >&2
        exit 1
    fi
else
    cp "${BIN_DIR}/build_manifest.json" "${OUT_ROOT}/build_manifest.json"
fi

if [[ "$1" == "--all" ]]; then
    run_all_parallel "${2:-3}"
else
    run_single "$1" "$2" "$3" "${4:-}"
fi
