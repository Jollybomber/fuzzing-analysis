#!/bin/bash
set -e

echo "[+] Starting differential testing campaign..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RESULTS_DIR="${RESULTS_DIR:-$PROJECT_ROOT/results}"
mkdir -p "$RESULTS_DIR"

# Override for a new build, e.g. BIN_DIR=bin_v2 ./scripts/run_baseline_comparison.sh
BIN_DIR="${BIN_DIR:-$PROJECT_ROOT/bin}"
CJSON_BIN="$BIN_DIR/cjson_parse"
JSONC_BIN="$BIN_DIR/jsonc_parse"

if [ ! -x "$CJSON_BIN" ] || [ ! -x "$JSONC_BIN" ]; then
    echo "[-] Error: Normal parser binaries not found. Run ./scripts/setup_and_build.sh first."
    exit 1
fi

# Archive previous baseline logs if they exist so old data is never lost
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
if ls "$RESULTS_DIR"/test_results_*.log "$RESULTS_DIR"/test_results_*.jsonl >/dev/null 2>&1; then
    ARCHIVE_DIR="$RESULTS_DIR/archive_$TIMESTAMP"
    mkdir -p "$ARCHIVE_DIR"
    mv "$RESULTS_DIR"/test_results_*.log "$RESULTS_DIR"/test_results_*.jsonl "$ARCHIVE_DIR"/ 2>/dev/null || true
    echo "[*] Archived previous baseline logs to $ARCHIVE_DIR"
fi

run_suite() {
    local suite_name="$1"
    local suite_dir="$2"
    local log_file="$RESULTS_DIR/test_results_${suite_name}.log"
    local jsonl_file="$RESULTS_DIR/test_results_${suite_name}.jsonl"

    shopt -s nullglob
    local files=("$suite_dir"/*.json)
    shopt -u nullglob

    if [ ${#files[@]} -eq 0 ]; then
        echo "[-] Error: No .json files found in $suite_dir"
        exit 1
    fi

    echo "[*] Processing $suite_name (${#files[@]} files)..."
    : > "$log_file"
    : > "$jsonl_file"

    for testfile in "${files[@]}"; do
        # Allow diff_driver.py exit code 1 (discrepancy found) without aborting set -e
        python3 "$SCRIPT_DIR/diff_driver.py" "$CJSON_BIN" "$JSONC_BIN" "$testfile" --jsonl "$jsonl_file" >> "$log_file" 2>&1 || [ $? -eq 1 ]
    done
}

run_suite "handwritten" "$PROJECT_ROOT/tests/handwritten_test_cases"
run_suite "JSONTestSuite" "$PROJECT_ROOT/tests/JSONTestSuite/test_parsing"

echo "[+] Baseline differential tests completed!"
python3 - "$RESULTS_DIR/test_results_handwritten.jsonl" "$RESULTS_DIR/test_results_JSONTestSuite.jsonl" <<'PY'
import json, sys
from collections import Counter

for path in sys.argv[1:]:
    total = 0
    agreed = 0
    tag_counts = Counter()
    with open(path, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            total += 1
            if row["agreed"]:
                agreed += 1
            for t in row["tags"]:
                tag_counts[t] += 1
    print(f"Summary for {path.split('/')[-1]}: total={total}, agreed={agreed}, discrepant={total - agreed}, tags={dict(tag_counts)}")
PY