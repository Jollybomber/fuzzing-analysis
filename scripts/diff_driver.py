#!/usr/bin/env python3
import subprocess
import sys
import os
import json

def run_parser(binary_path, file_path):
    """Runs a parser binary against a JSON file and returns exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            [binary_path, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5 # Prevent hangs/infinite loops on malformed inputs
        )
        return result.returncode, result.stdout.decode('utf-8', errors='ignore'), result.stderr.decode('utf-8', errors='ignore')
    except subprocess.TimeoutExpired:
        return -999, "", "TIMEOUT"

def normalize_output(stdout_data):
    """Normalizes output/AST representation to catch semantic discrepancies."""
    # Depending on how your parser wrappers print output, you can parse 
    # the textual AST or JSON representation into a standard Python dict 
    # to compare semantic equivalence (e.g., duplicate keys).
    try:
        return json.loads(stdout_data)
    except:
        return stdout_data.strip()

def differential_test(bin1, bin2, test_file):
    print(f"[*] Testing file: {test_file}")
    
    # Run Parser 1 (e.g., cJSON wrapper)
    code1, out1, err1 = run_parser(bin1, test_file)
    
    # Run Parser 2 (e.g., json-c wrapper)
    code2, out2, err2 = run_parser(bin2, test_file)
    
    # Check for crashes (non-zero or negative exit codes, or sanitizer hits in stderr)
    parser1_crashed = code1 != 0 or "AddressSanitizer" in err1 or "UndefinedBehavior" in err1
    parser2_crashed = code2 != 0 or "AddressSanitizer" in err2 or "UndefinedBehavior" in err2
    
    discrepancies = []
    
    # 1. Crash Discrepancy
    if parser1_crashed != parser2_crashed:
        discrepancies.append(f"CRASH DISCREPANCY: Parser 1 crashed={parser1_crashed}, Parser 2 crashed={parser2_crashed}")
    
    # 2. Acceptance/Rejection Discrepancy (Exit status agreement)
    parser1_accepted = (code1 == 0)
    parser2_accepted = (code2 == 0)
    if parser1_accepted != parser2_accepted:
        discrepancies.append(f"ACCEPTANCE DISCREPANCY: Parser 1 accepted={parser1_accepted}, Parser 2 accepted={parser2_accepted}")
    
    # 3. Semantic / Normalized Output Discrepancy (if both accepted)
    if parser1_accepted and parser2_accepted:
        norm1 = normalize_output(out1)
        norm2 = normalize_output(out2)
        if norm1 != norm2:
            discrepancies.append(f"SEMANTIC DISCREPANCY:\n  Parser 1: {norm1}\n  Parser 2: {norm2}")

    if discrepancies:
        print(f"[!] DISCREPANCY FOUND in {test_file}:")
        for d in discrepancies:
            print(f"    - {d}")
        if err1: print(f"    [Stderr Parser 1]: {err1.strip()}")
        if err2: print(f"    [Stderr Parser 2]: {err2.strip()}")
        return False
    else:
        print("[+] Parsers agree.")
        return True

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 diff_driver.py <parser1_bin> <parser2_bin> [json_file]")
        sys.exit(1)
        
    bin_a = sys.argv[1]
    bin_b = sys.argv[2]
    target = sys.argv[3] if len(sys.argv) > 3 else "test.json"
    
    differential_test(bin_a, bin_b, target)