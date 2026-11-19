#!/usr/bin/env bash
# Show progress of a run_fuzzing.sh campaign.
# Usage: scripts/fuzz_progress.sh [out_root] [master_log]
set -uo pipefail

OUT_ROOT="${1:-/work/fuzz_out_v2}"
LOG="${2:-/work/fuzz_master_v2.log}"

[[ -d "$OUT_ROOT" ]] || { echo "No output directory yet: $OUT_ROOT" >&2; exit 1; }

total="$(grep -o 'Scheduling [0-9]*' "$LOG" 2>/dev/null | grep -o '[0-9]*' || true)"
finished="$(grep -c 'Finished ' "$LOG" 2>/dev/null || true)"
failed="$(grep -c 'FAILED ' "$LOG" 2>/dev/null || true)"
started="$(grep -c 'Starting ' "$LOG" 2>/dev/null || true)"
echo "Campaigns: ${finished:-0} finished, ${failed:-0} failed, $(( ${started:-0} - ${finished:-0} - ${failed:-0} )) running, ${total:-?} total"
grep -q 'campaigns failed' "$LOG" 2>/dev/null && echo "DONE WITH FAILURES (see FAILED lines in $LOG)"
grep -q 'fuzzing runs completed' "$LOG" 2>/dev/null && echo "ALL DONE"
echo

printf '%-24s %-8s %8s %10s %8s %7s %5s\n' campaign status run_time execs/sec coverage crashes hangs
for dir in "$OUT_ROOT"/*/; do
    name="$(basename "$dir")"
    stats="$dir/default/fuzzer_stats"
    if [[ ! -f "$stats" ]]; then
        printf '%-24s %-8s\n' "$name" starting
        continue
    fi
    if grep -q "Finished ${name}\$" "$LOG" 2>/dev/null; then status=done
    elif grep -q "FAILED ${name} " "$LOG" 2>/dev/null; then status=failed
    else status=running; fi
    awk -v n="$name" -v st="$status" -F' *: ' '{s[$1]=$2}
        END {printf "%-24s %-8s %7ss %10s %8s %7s %5s\n", n, st, s["run_time"], s["execs_per_sec"],
             s["bitmap_cvg"], s["saved_crashes"], s["saved_hangs"]}' "$stats"
done
# fuzzer_stats is refreshed about once a minute, so running values lag slightly.
