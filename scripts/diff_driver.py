#!/usr/bin/env python3
import argparse
import base64
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

# Reuse analyze_fuzzing.py's exact value comparison so baseline and fuzzing results are
# scored by the same rules: exact decimal numbers (1E2 == 100, long decimals not rounded),
# object-key order ignored, duplicate keys preserved, non-RFC number spellings compared by value.
_spec = importlib.util.spec_from_file_location("analyze_fuzzing", Path(__file__).with_name("analyze_fuzzing.py"))
analyzer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(analyzer)

# Tags that make a row a disagreement. The others only describe output validity.
DISCREPANCY_TAGS = {"ABNORMAL_EXECUTION", "ACCEPTANCE_DISCREPANCY", "SEMANTIC_DISCREPANCY", "COMPARISON_LIMIT",
                    "UNCOMPARABLE_OUTPUT"}
TAG_NAMES = {"ACCEPTANCE_DIFFERENCE": "ACCEPTANCE_DISCREPANCY", "VALUE_DIFFERENCE": "SEMANTIC_DISCREPANCY"}

SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "LeakSanitizer",
    "MemorySanitizer",
    "runtime error:",
)


def decode_bytes(raw: bytes):
    """Decodes bytes as strict UTF-8, flagging invalid sequences instead of dropping them."""
    try:
        return raw.decode("utf-8"), True
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="backslashreplace"), False


def run_parser(binary_path: str, file_path: str, timeout_sec: float = 5.0):
    """Runs a parser binary and classifies its execution outcome."""
    try:
        result = subprocess.run(
            [binary_path, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired as exc:
        out_str, out_utf8 = decode_bytes(exc.stdout or b"")
        err_str, err_utf8 = decode_bytes(exc.stderr or b"")
        return {
            "returncode": -999,
            "status": "timeout",
            "sanitizer_hit": False,
            "stdout": out_str,
            "stderr": err_str,
            "stdout_b64": base64.b64encode(exc.stdout or b"").decode(),
            "stdout_valid_utf8": out_utf8,
            "stderr_valid_utf8": err_utf8,
        }

    out_str, out_utf8 = decode_bytes(result.stdout)
    err_str, err_utf8 = decode_bytes(result.stderr)
    code = result.returncode
    sanitizer_hit = any(marker in err_str for marker in SANITIZER_MARKERS)

    if code < 0 or code >= 128:
        status = "crash"
    elif sanitizer_hit:
        status = "sanitizer"
    elif code == 0:
        status = "accepted"
    elif code == 1:
        status = "rejected"
    else:
        status = "harness_error"

    return {
        "returncode": code,
        "status": status,
        "sanitizer_hit": sanitizer_hit,
        "stdout": out_str,
        "stderr": err_str,
        "stdout_b64": base64.b64encode(result.stdout).decode(),
        "stdout_valid_utf8": out_utf8,
        "stderr_valid_utf8": err_utf8,
    }


def differential_test(bin1: str, bin2: str, test_file: str, jsonl_path: str = None) -> bool:
    if not os.path.isfile(bin1) or not os.path.isfile(bin2):
        print(f"[-] Missing parser binary: {bin1} or {bin2}", file=sys.stderr)
        sys.exit(2)
    if not os.path.isfile(test_file):
        print(f"[-] Missing test input: {test_file}", file=sys.stderr)
        sys.exit(2)

    print(f"[*] Testing file: {test_file}")
    r1 = run_parser(bin1, test_file)
    r2 = run_parser(bin2, test_file)

    raw_tags = analyzer.compare({**r1, "output_truncated": False}, {**r2, "output_truncated": False})
    tags = [TAG_NAMES.get(t, t) for t in raw_tags]
    discrepancies = []
    if "ABNORMAL_EXECUTION" in tags:
        discrepancies.append(f"EXECUTION STATUS: Parser 1={r1['status']} (code={r1['returncode']}), "
                             f"Parser 2={r2['status']} (code={r2['returncode']})")
    if "ACCEPTANCE_DISCREPANCY" in tags:
        discrepancies.append(f"ACCEPTANCE DISCREPANCY: Parser 1 {r1['status']}, Parser 2 {r2['status']}")
    if "SEMANTIC_DISCREPANCY" in tags:
        discrepancies.append("SEMANTIC DISCREPANCY:\n"
                             f"  Parser 1 raw: {r1['stdout'].strip()}\n"
                             f"  Parser 2 raw: {r2['stdout'].strip()}")
    if "COMPARISON_LIMIT" in tags:
        discrepancies.append("COMPARISON LIMIT: outputs could not be compared exactly")
    if "UNCOMPARABLE_OUTPUT" in tags:
        discrepancies.append("UNCOMPARABLE OUTPUT: an output is not parseable JSON and the outputs differ")
    notes = []
    if "INVALID_UTF8_OUTPUT" in tags:
        notes.append(f"Output is not valid UTF-8 (parser 1 valid={r1['stdout_valid_utf8']}, "
                     f"parser 2 valid={r2['stdout_valid_utf8']}); compared by value with the raw bytes preserved")
    if "INVALID_JSON_OUTPUT" in tags:
        notes.append("An output is not strict RFC 8259 JSON (e.g. json-c echoing `1.`); compared by value")

    if jsonl_path:
        record = {
            "file": test_file,
            "basename": os.path.basename(test_file),
            "agreed": not DISCREPANCY_TAGS.intersection(tags),
            "tags": tags,
            "parser1": r1,
            "parser2": r2,
        }
        with open(jsonl_path, "a", encoding="utf-8") as jf:
            jf.write(json.dumps(record) + "\n")

    if discrepancies:
        print(f"[!] DISCREPANCY FOUND in {test_file}:")
        for d in discrepancies:
            print(f"    - {d}")
        if r1["stderr"].strip():
            print(f"    [Stderr Parser 1]: {r1['stderr'].strip()}")
        if r2["stderr"].strip():
            print(f"    [Stderr Parser 2]: {r2['stderr'].strip()}")
        return False

    for note in notes:
        print(f"    [note] {note}")
    print(f"[+] Parsers agree ({r1['status']}).")
    return True


def main():
    parser = argparse.ArgumentParser(description="Differential JSON parser test driver")
    parser.add_argument("parser1_bin", help="Path to first parser binary (e.g., cjson_parse)")
    parser.add_argument("parser2_bin", help="Path to second parser binary (e.g., jsonc_parse)")
    parser.add_argument("json_file", help="Path to input JSON file")
    parser.add_argument("--jsonl", default=None, help="Optional path to append JSONL results")
    args = parser.parse_args()

    agreed = differential_test(args.parser1_bin, args.parser2_bin, args.json_file, args.jsonl)
    sys.exit(0 if agreed else 1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # A harness failure must not be mistaken for a parser discrepancy (exit 1).
        print(f"[-] Harness error: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)