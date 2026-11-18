#!/bin/bash
set -e

echo "[+] Starting differential testing campaign..."

# Get the absolute path of the directory where the script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

RESULTS_DIR="$PROJECT_ROOT/results"
mkdir -p "$RESULTS_DIR"

CJSON_BIN="$PROJECT_ROOT/builds/cjson_normal/cjson_parse"
JSONC_BIN="$PROJECT_ROOT/builds/jsonc_normal/build_internal/apps/json_parse"

# 1. Run Handwritten Test Cases
echo "[*] Processing handwritten test cases..."
> "$RESULTS_DIR/test_results_handwritten.log"
for testfile in "$PROJECT_ROOT"/tests/handwritten_test_cases/*.json; do
    [ -e "$testfile" ] || continue
    python3 "$SCRIPT_DIR/diff_driver.py" "$CJSON_BIN" "$JSONC_BIN" "$testfile"
done > "$RESULTS_DIR/test_results_handwritten.log" 2>&1

# 2. Run JSONTestSuite
echo "[*] Processing JSONTestSuite parsing tests..."
> "$RESULTS_DIR/test_results_JSONTestSuite.log"
for testfile in "$PROJECT_ROOT"/tests/JSONTestSuite/test_parsing/*.json; do
    [ -e "$testfile" ] || continue
    python3 "$SCRIPT_DIR/diff_driver.py" "$CJSON_BIN" "$JSONC_BIN" "$testfile"
done > "$RESULTS_DIR/test_results_JSONTestSuite.log" 2>&1

echo "[+] All differential tests completed successfully!"