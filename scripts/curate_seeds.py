#!/usr/bin/env python3
"""Curate ~75 diverse valid JSON seeds for AFL++ fuzzing.

Seeds are valid JSONTestSuite `y_*` files that both parsers accept, chosen evenly across
syntactic categories (array, number, object, string, structure), plus 8 synthetic seeds.

    python3 scripts/curate_seeds.py --bin-dir bin_v2 --output fuzz_seeds_new

--legacy reproduces the selection used for the committed fuzz_seeds/ (and therefore for the
fuzz_out_v2 campaigns). That older loop only ever picked the first or second file of each
category instead of spreading picks across it; the default selection fixes this.
The output directory must not already contain files, so existing seeds are never deleted.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JTS_DIR = ROOT / "tests" / "JSONTestSuite" / "test_parsing"

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


def both_parsers_accept(data: bytes, binaries) -> bool:
    with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
        tmp.write(data)
        tmp.flush()
        return all(subprocess.run([str(b), tmp.name], capture_output=True).returncode == 0 for b in binaries)


def categorize(name: str) -> str:
    for prefix in ("y_array", "y_number", "y_object", "y_string", "y_structure"):
        if name.startswith(prefix):
            return prefix
    return "other"


def select_legacy(buckets):
    """The original selection loop, kept verbatim to reproduce the committed seed set."""
    buckets = {k: list(v) for k, v in buckets.items()}
    selected, keys, idx = [], sorted(buckets), 0
    while len(selected) < TARGET_JTS_COUNT and any(buckets.values()):
        key = keys[idx % len(keys)]
        if buckets[key]:
            step = max(1, len(buckets[key]) // max(1, (TARGET_JTS_COUNT - len(selected)) // len(keys)))
            selected.append(buckets[key].pop(0 if step == 1 else min(1, len(buckets[key]) - 1)))
        idx += 1
    return selected


def select_even(buckets):
    """Give each category a round-robin share of the target, then pick evenly spaced files."""
    keys = sorted(buckets)
    quota = dict.fromkeys(keys, 0)
    remaining = min(TARGET_JTS_COUNT, sum(len(v) for v in buckets.values()))
    while remaining:
        for key in keys:
            if remaining and quota[key] < len(buckets[key]):
                quota[key] += 1
                remaining -= 1
    selected = []
    for key in keys:
        files, q = buckets[key], quota[key]
        if q == 0:
            continue
        positions = [len(files) // 2] if q == 1 else [round(i * (len(files) - 1) / (q - 1)) for i in range(q)]
        selected += [files[p] for p in positions]
    return selected


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin-dir", type=Path, default=ROOT / "bin_v2",
                    help="Directory with cjson_parse and jsonc_parse (default: bin_v2)")
    ap.add_argument("--output", type=Path, default=ROOT / "fuzz_seeds")
    ap.add_argument("--legacy", action="store_true", help="Reproduce the selection of the committed fuzz_seeds/")
    args = ap.parse_args()

    binaries = [args.bin_dir / "cjson_parse", args.bin_dir / "jsonc_parse"]
    missing = [str(b) for b in binaries if not b.is_file()]
    if missing:
        sys.exit("Error: parser binaries not found (needed to check every seed): " + ", ".join(missing))
    if not JTS_DIR.is_dir():
        sys.exit(f"Error: JSONTestSuite directory not found: {JTS_DIR}")
    if args.output.exists() and any(args.output.iterdir()):
        sys.exit(f"Error: {args.output} already contains files; choose a new --output directory")
    args.output.mkdir(parents=True, exist_ok=True)

    # Group valid y_*.json files by syntactic category
    buckets: dict[str, list[Path]] = {}
    for path in sorted(JTS_DIR.glob("y_*.json")):
        raw = path.read_bytes()
        try:
            json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if both_parsers_accept(raw, binaries):
            buckets.setdefault(categorize(path.name), []).append(path)

    selected = select_legacy(buckets) if args.legacy else select_even(buckets)
    for src in selected:
        (args.output / src.name).write_bytes(src.read_bytes())
    for name, content in SYNTHETIC_VALID_SEEDS.items():
        if not both_parsers_accept(content, binaries):
            sys.exit(f"Error: a parser rejected synthetic seed {name}")
        (args.output / name).write_bytes(content)

    total = len(list(args.output.glob("*.json")))
    mode = "legacy" if args.legacy else "even"
    print(f"Curated {total} valid seeds into {args.output} ({len(selected)} from JSONTestSuite + "
          f"{len(SYNTHETIC_VALID_SEEDS)} synthetic; {mode} selection).")


if __name__ == "__main__":
    main()
