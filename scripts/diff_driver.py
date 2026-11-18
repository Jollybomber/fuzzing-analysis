#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys

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
        "stdout_valid_utf8": out_utf8,
        "stderr_valid_utf8": err_utf8,
    }


def canonicalize_json(raw_stdout: str):
    """
    Parses JSON while preserving:
      1. Exact object key order and duplicate keys (via object_pairs_hook)
      2. Explicit JSON types so `true` != `1` and `int` != `float`
    """
    def tag_value(val):
        if val is None:
            return ("null", None)
        if isinstance(val, bool):
            return ("bool", val)
        if isinstance(val, int):
            return ("int", val)
        if isinstance(val, float):
            return ("float", val)
        if isinstance(val, str):
            return ("str", val)
        if isinstance(val, list):
            return ("array", [tag_value(item) for item in val])
        if isinstance(val, tuple) and len(val) == 2 and val[0] == "__object__":
            return ("object", [(k, tag_value(v)) for k, v in val[1]])
        return ("unknown", repr(val))

    parsed = json.loads(
        raw_stdout,
        object_pairs_hook=lambda pairs: ("__object__", pairs),
    )
    return tag_value(parsed)


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

    discrepancies = []
    tags = []

    # 1. Abnormal execution (crashes, timeouts, sanitizer hits, harness errors)
    abnormal = {"crash", "timeout", "sanitizer", "harness_error"}
    if r1["status"] in abnormal or r2["status"] in abnormal:
        tags.append("ABNORMAL_EXECUTION")
        discrepancies.append(
            f"EXECUTION STATUS: Parser 1={r1['status']} (code={r1['returncode']}), "
            f"Parser 2={r2['status']} (code={r2['returncode']})"
        )

    # 2. Invalid UTF-8 on stdout
    if not r1["stdout_valid_utf8"] or not r2["stdout_valid_utf8"]:
        tags.append("INVALID_UTF8_OUTPUT")
        discrepancies.append(
            f"UTF-8 OUTPUT ERROR: Parser 1 valid={r1['stdout_valid_utf8']}, "
            f"Parser 2 valid={r2['stdout_valid_utf8']}"
        )

    # 3. Acceptance vs. Rejection discrepancy
    if (r1["status"] in {"accepted", "rejected"}) and (r2["status"] in {"accepted", "rejected"}):
        if r1["status"] != r2["status"]:
            tags.append("ACCEPTANCE_DISCREPANCY")
            discrepancies.append(
                f"ACCEPTANCE DISCREPANCY: Parser 1 {r1['status']}, Parser 2 {r2['status']}"
            )

    # 4. Semantic / AST discrepancy when both accepted
    if r1["status"] == "accepted" and r2["status"] == "accepted":
        try:
            canon1 = canonicalize_json(r1["stdout"])
        except Exception as exc:
            canon1 = None
            tags.append("HARNESS_OUTPUT_ERROR")
            discrepancies.append(f"Parser 1 exited 0 with invalid JSON stdout: {exc}")

        try:
            canon2 = canonicalize_json(r2["stdout"])
        except Exception as exc:
            canon2 = None
            tags.append("HARNESS_OUTPUT_ERROR")
            discrepancies.append(f"Parser 2 exited 0 with invalid JSON stdout: {exc}")

        if canon1 is not None and canon2 is not None and canon1 != canon2:
            tags.append("SEMANTIC_DISCREPANCY")
            discrepancies.append(
                f"SEMANTIC DISCREPANCY:\n"
                f"  Parser 1 raw: {r1['stdout'].strip()}\n"
                f"  Parser 2 raw: {r2['stdout'].strip()}"
            )

    if jsonl_path:
        record = {
            "file": test_file,
            "basename": os.path.basename(test_file),
            "agreed": len(discrepancies) == 0,
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
    main()