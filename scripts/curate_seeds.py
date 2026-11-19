#!/usr/bin/env python3
"""Curate ~75 diverse valid JSON seeds for AFL++ fuzzing."""

import json
import shutil
import tempfile
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JTS_DIR = ROOT / "tests" / "JSONTestSuite" / "test_parsing"
SEED_DIR = ROOT / "fuzz_seeds"
CJSON_BIN = ROOT / "bin" / "cjson_parse"
JSONC_BIN = ROOT / "bin" / "jsonc_parse"

TARGET_JTS_COUNT = 67  # + 8 synthetic valid seeds = 75 total

SYNTHETIC_VALID_SEEDS = {
    "valid_empty_obj.json": b"{}",
    "valid_empty_arr.json": b"[]",
    "valid_primitives.json": b'{"bool_t":true,"bool_f":false,"nil":null,"int":-42,"float":3.14159e-10}',
    "valid_nested_mixed.json": b'{"users":[{"id":1,"tags":["admin","ops"]},{"id":2,"tags":[]}],"meta":{"count":2}}',
    "valid_escapes.json": b'{"escapes":"\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\\u03B1\\uD83D\\uDE00"}',
    "valid_int64_bounds.json": b'{"max":9223372036854775807,"min":-9223372036854775808,"zero":0}',
    "valid_duplicate_keys.json": b'{"role":"user","role":"admin","nested":{"k":1,"k":2}}',
    "valid_whitespace.json": b' \n\t\r { \n "a" \t : \r [ 1 , 2 , 3 ] \n } \r\n ',
}


def both_parsers_accept(data: bytes) -> bool:
    if not CJSON_BIN.exists() or not JSONC_BIN.exists():
        return True
    with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
        tmp.write(data)
        tmp.flush()
        for binary in (CJSON_BIN, JSONC_BIN):
            res = subprocess.run([str(binary), tmp.name], capture_output=True)
            if res.returncode != 0:
                return False
    return True


def categorize(name: str) -> str:
    for prefix in ("y_array", "y_number", "y_object", "y_string", "y_structure"):
        if name.startswith(prefix):
            return prefix
    return "other"


def main() -> None:
    if not JTS_DIR.is_dir():
        raise FileNotFoundError(f"JSONTestSuite directory not found: {JTS_DIR}")

    if SEED_DIR.exists():
        shutil.rmtree(SEED_DIR)
    SEED_DIR.mkdir(parents=True)

    # Group valid y_*.json files by syntactic category
    buckets: dict[str, list[Path]] = {}
    for path in sorted(JTS_DIR.glob("y_*.json")):
        raw = path.read_bytes()
        try:
            json.loads(raw.decode("utf-8"))
        except Exception:
            continue
        if not both_parsers_accept(raw):
            continue
        buckets.setdefault(categorize(path.name), []).append(path)

    # Round-robin selection across categories for balanced feature coverage
    selected: list[Path] = []
    keys = sorted(buckets.keys())
    idx = 0
    while len(selected) < TARGET_JTS_COUNT and any(buckets.values()):
        key = keys[idx % len(keys)]
        if buckets[key]:
            # Evenly stride through each bucket
            step = max(1, len(buckets[key]) // max(1, (TARGET_JTS_COUNT - len(selected)) // len(keys)))
            selected.append(buckets[key].pop(0 if step == 1 else min(1, len(buckets[key]) - 1)))
        idx += 1

    for src in selected:
        shutil.copy2(src, SEED_DIR / src.name)

    for name, content in SYNTHETIC_VALID_SEEDS.items():
        assert both_parsers_accept(content), f"Parser rejected synthetic seed: {name}"
        (SEED_DIR / name).write_bytes(content)

    total = len(list(SEED_DIR.glob("*.json")))
    print(f"Curated {total} valid seeds into {SEED_DIR} ({len(selected)} from JSONTestSuite + {len(SYNTHETIC_VALID_SEEDS)} synthetic).")


if __name__ == "__main__":
    main()