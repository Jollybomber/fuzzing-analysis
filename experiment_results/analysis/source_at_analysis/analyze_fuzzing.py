#!/usr/bin/env python3
"""Read AFL++ campaigns, audit targets, and optionally replay their saved inputs.

Standard-library only. Never modifies fuzz_out or rebuilds a target. Run --help.
"""

import argparse
import base64
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import csv
import ctypes
import ctypes.util
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
KINDS = ("queue", "crashes", "hangs")
SANITIZERS = ("AddressSanitizer", "UndefinedBehaviorSanitizer", "LeakSanitizer",
              "MemorySanitizer", "runtime error:")
METRICS = ("run_time", "execs_done", "execs_per_sec", "corpus_count", "corpus_found",
           "saved_crashes", "saved_hangs", "edges_found", "total_edges", "bitmap_cvg",
           "stability", "exec_timeout", "peak_rss_mb", "cycles_done", "cpu_affinity")
ALIASES = {"corpus_count": "paths_total", "corpus_found": "paths_found",
           "saved_crashes": "unique_crashes", "saved_hangs": "unique_hangs"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def number(value):
    if value is None:
        return None
    try:
        value = str(value).strip().rstrip("%")
        return float(value) if "." in value else int(value)
    except ValueError:
        return None


def read_stats(path):
    return {k.strip(): v.strip() for k, v in
            (line.split(":", 1) for line in path.read_text(errors="replace").splitlines()
             if ":" in line)}


def file_time_ms(name):
    match = re.search(r"(?:^|,)time:(\d+)(?:,|$)", name)
    return int(match[1]) if match else None


def xxh3(data):
    """AFL++ 5.04a get_binary_hash uses XXH3_64bits, not SHA-256."""
    try:
        library = ctypes.util.find_library("xxhash")
        if not library:
            return None
        function = ctypes.CDLL(library).XXH3_64bits
        function.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        function.restype = ctypes.c_uint64
        return hex(function(data, len(data)))
    except (OSError, AttributeError):
        return None


def inspect_binary(path):
    if not path.is_file():
        return {"path": str(path), "exists": False}
    data = path.read_bytes()
    return {"path": str(path), "exists": True, "bytes": len(data),
            "sha256": sha256(data), "xxh3_64": xxh3(data),
            "asan_runtime_marker": b"__asan_init" in data,
            # UBSan runtime symbols alone do NOT prove checks instrument the target.
            "ubsan_runtime_marker": b"__ubsan_handle_" in data}


def read_plot(path, campaign, instance):
    if not path.is_file():
        return []
    lines = path.read_text(errors="replace").splitlines()
    if not lines:
        return []
    headers = [x.strip() for x in lines[0].lstrip("# ").split(",")]
    rows = []
    for fields in csv.reader(lines[1:], skipinitialspace=True):
        if len(fields) != len(headers):
            continue  # An active AFL process may be partway through a final line.
        row = {k: number(v) if number(v) is not None else v.strip()
               for k, v in zip(headers, fields)}
        row.update(campaign=campaign, instance=instance)
        rows.append(row)
    return rows


def load_build_manifest(fuzz_root):
    path = fuzz_root / "build_manifest.json"
    try:
        return json.loads(path.read_text()) if path.is_file() else None
    except (OSError, ValueError):
        return None


def collect(fuzz_root, bin_dir, expected_seconds, expected_repeats):
    runs, timeline, inputs, binary_cache = [], [], {}, {}
    stats_paths = sorted(fuzz_root.rglob("fuzzer_stats"))
    if not stats_paths:
        raise ValueError(f"No fuzzer_stats files found under {fuzz_root}")
    for path in stats_paths:
        stats = read_stats(path)
        instance = path.parent
        # Support modern campaign/default and older campaign/fuzzer_stats layouts.
        match = re.fullmatch(r"(.+)_(asan_ubsan|asan|normal)_(run\d+)", instance.name)
        campaign_dir = instance if match else instance.parent
        match = match or re.fullmatch(r"(.+)_(asan_ubsan|asan|normal)_(run\d+)", campaign_dir.name)
        parser, config, repeat = match.groups() if match else ("unknown", "unknown", "unknown")
        campaign = str(campaign_dir.relative_to(fuzz_root)) if campaign_dir != fuzz_root else fuzz_root.name
        row = {"campaign": campaign, "instance": instance.name, "parser": parser,
               "config": config, "repeat": repeat, "stats_path": str(path),
               "warnings": [], "command_line": stats.get("command_line", ""),
               "afl_version": stats.get("afl_version"), "target_mode": stats.get("target_mode"),
               "start_time": number(stats.get("start_time")),
               "last_update": number(stats.get("last_update")),
               "stats_sha256": sha256(path.read_bytes()), "raw_stats": stats}
        for key in METRICS:
            row[key] = number(stats.get(key, stats.get(ALIASES.get(key))))
        if row["run_time"] is None and row["start_time"] is not None and row["last_update"] is not None:
            row["run_time"] = row["last_update"] - row["start_time"]
        if row["execs_done"] is not None and row["run_time"]:
            row["execs_per_sec"] = row["execs_done"] / row["run_time"]
        log_path = campaign_dir / "afl.log"
        log = log_path.read_text(errors="replace") if log_path.is_file() else ""
        row["time_limit_reached"] = "Time limit was reached" in log
        row["log_sha256"] = sha256(log_path.read_bytes()) if log_path.is_file() else None
        if not row["time_limit_reached"]:
            row["warnings"].append("No time-limit completion marker; check interrupted/active runs.")
        if row["run_time"] is None or row["run_time"] < expected_seconds * 0.98:
            row["warnings"].append("Missing duration or shorter than requested analysis duration.")
        for key in ("execs_done", "saved_crashes", "saved_hangs", "edges_found", "total_edges"):
            if row[key] is None:
                row["warnings"].append(f"Missing statistic: {key}; do not interpret it as zero.")
        if row["stability"] is not None and row["stability"] < 100:
            row["warnings"].append("Coverage stability below 100%; path observations have variability.")
        original_seeds, original_seed_names = [], []
        for kind in KINDS:
            files = sorted(f for f in (instance / kind).glob("*")
                           if f.is_file() and f.name.startswith(("id:", "id_")))
            row[kind + "_files"] = len(files)
            times = []
            for file in files:
                data = file.read_bytes()
                digest = sha256(data)
                timestamp = file_time_ms(file.name)
                if timestamp is not None:
                    times.append(timestamp / 1000)
                if kind == "queue" and ",orig:" in file.name:
                    original_seeds.append(digest)
                    original_seed_names.append(file.name.split(",orig:", 1)[1])
                origin = {"campaign": campaign, "instance": instance.name,
                          "parser": parser, "config": config, "kind": kind,
                          "path": str(file.relative_to(fuzz_root)),
                          "time_seconds": timestamp / 1000 if timestamp is not None else None,
                          "is_seed": kind == "queue" and ",orig:" in file.name}
                item = inputs.setdefault(digest, {"sha256": digest, "bytes": len(data),
                                                 "origins": []})
                item["origins"].append(origin)
            if kind != "queue":
                row["first_" + kind + "_seconds"] = min(times) if times else None
                expected = row["saved_" + kind]
                if expected is not None and expected != len(files):
                    row["warnings"].append(f"Saved {kind} statistic does not match files on disk.")
        row["seed_derived_queue_files"] = len(original_seeds)
        row["retained_seed_multiset_sha256"] = sha256("\n".join(sorted(original_seeds)).encode())
        row["seed_name_multiset_sha256"] = sha256("\n".join(sorted(original_seed_names)).encode())
        binary = bin_dir / f"{parser}_afl_{config}"
        key = str(binary)
        if key not in binary_cache:
            binary_cache[key] = inspect_binary(binary)
        row["binary"] = binary_cache[key]
        if not row["binary"]["exists"]:
            row["warnings"].append("Target binary unavailable; instrumentation and target provenance cannot be checked.")
        saved_hash = instance / "target_hash"
        row["saved_target_hash"] = saved_hash.read_text().strip() if saved_hash.is_file() else None
        row["target_hash_match"] = None
        if row["saved_target_hash"] and row["binary"].get("xxh3_64"):
            try:
                row["target_hash_match"] = int(row["saved_target_hash"], 16) == int(row["binary"]["xxh3_64"], 16)
            except ValueError:
                pass
        if row["target_hash_match"] is False:
            row["warnings"].append("Current target differs from saved AFL fingerprint, or uses another hash algorithm.")
        if config == "normal" and row["binary"].get("asan_runtime_marker"):
            row["warnings"].append("NORMAL LABEL INVALID: current target contains the ASan runtime marker.")
        if config in ("asan", "asan_ubsan") and row["binary"].get("exists") and not row["binary"].get("asan_runtime_marker"):
            row["warnings"].append("ASan-labelled target has no ASan marker; instrumentation needs verification.")
        # Provenance: run_fuzzing.sh writes a per-campaign run_manifest.json and copies the
        # build's build_manifest.json (flags, toolchain, source commits, binary hashes) into
        # the campaign root. Older campaigns may only have the latter.
        manifest = campaign_dir / "run_manifest.json"
        row["run_manifest"] = json.loads(manifest.read_text()) if manifest.is_file() else None
        build_manifest = load_build_manifest(fuzz_root)
        row["build_manifest_found"] = build_manifest is not None
        expected_sha = (build_manifest or {}).get("binaries_sha256", {}).get(binary.name)
        row["build_manifest_sha_match"] = (None if expected_sha is None or not row["binary"].get("sha256")
                                           else expected_sha == row["binary"]["sha256"])
        if row["run_manifest"] is None and build_manifest is None:
            row["warnings"].append("No run or build manifest: compiler flags, environment and source snapshot not recorded.")
        elif row["run_manifest"] is None:
            row["warnings"].append("No per-campaign run_manifest.json: the campaign predates run_fuzzing.sh's run records "
                                   "(and its container-local .cur_input), so core, environment and seed hashes are not "
                                   "recorded and exec/s may be limited by file I/O.")
        if row["build_manifest_sha_match"] is False:
            row["warnings"].append("Current target binary differs from the build_manifest.json used for this campaign.")
        if row["run_manifest"] and row["binary"].get("sha256") and \
                row["run_manifest"].get("target_sha256") not in (None, row["binary"]["sha256"]):
            row["warnings"].append("Current target binary differs from the one recorded when the campaign started.")
        timeline.extend(read_plot(instance / "plot_data", campaign, instance.name))
        runs.append(row)
    warnings = []
    campaigns = Counter(r["campaign"] for r in runs)
    groups = defaultdict(list)
    for row in runs:
        if campaigns[row["campaign"]] > 1:
            row["warnings"].append("Multiple workers in this campaign; excluded from independent-repeat aggregates.")
        else:
            groups[(row["parser"], row["config"])].append(row)
    aggregates = []
    for (parser, config), rows in sorted(groups.items()):
        aggregate = {"parser": parser, "config": config, "runs": len(rows)}
        if len(rows) != expected_repeats:
            warnings.append(f"{parser}/{config}: {len(rows)} runs, expected {expected_repeats}.")
        if len({r["binary"].get("sha256") for r in rows}) > 1:
            warnings.append(f"{parser}/{config}: multiple current target hashes.")
        for key in METRICS:
            values = [r[key] for r in rows if r[key] is not None]
            aggregate[key + "_mean"] = statistics.mean(values) if values else None
            aggregate[key + "_sd"] = statistics.stdev(values) if len(values) > 1 else None
            aggregate[key + "_min"] = min(values) if values else None
            aggregate[key + "_max"] = max(values) if values else None
        for key in ("execs_done", "saved_crashes", "saved_hangs"):
            aggregate[key + "_sum"] = sum(r[key] for r in rows) if all(r[key] is not None for r in rows) else None
        aggregates.append(aggregate)
    seed_hashes = {r["retained_seed_multiset_sha256"] for r in runs}
    if len(seed_hashes) > 1:
        warnings.append("Retained seed-derived queue bytes differ. AFL may trim these files; this does NOT "
                        "prove the initial seeds differed. Preserve a pre-run seed manifest.")
    if len({r["seed_name_multiset_sha256"] for r in runs}) > 1:
        warnings.append("Original seed names differ between runs; check pre-run seed manifests.")
    hashes = defaultdict(list)
    for key, binary in binary_cache.items():
        if binary.get("sha256"):
            hashes[binary["sha256"]].append(Path(key).name)
    for names in hashes.values():
        if len(names) > 1:
            warnings.append("IDENTICAL TARGET BINARIES across labels: " + ", ".join(names))
    if any(r["config"] == "normal" and r["binary"].get("asan_runtime_marker") for r in runs):
        warnings.append("Do not calculate sanitizer overhead: at least one normal-labelled target contains ASan.")
    known = {(r["parser"], r["config"]) for r in runs}
    for parser in ("cjson", "jsonc"):
        for config in ("normal", "asan", "asan_ubsan"):
            if (parser, config) not in known:
                warnings.append(f"Missing experiment cell: {parser}/{config}.")
    return {"runs": runs, "groups": aggregates, "warnings": warnings,
            "inputs": sorted(inputs.values(), key=lambda x: x["sha256"]), "timeline": timeline}


class ObjectPairs(list):
    pass


class ComparisonLimit(ValueError):
    pass


class JSONNumber:
    """Exact finite decimal value, without binary-float or Decimal exponent bounds."""
    def __init__(self, token):
        negative = token.startswith("-")
        parts = re.split("[eE]", token.lstrip("-"))
        mantissa, exponent = parts[0], parts[1] if len(parts) == 2 else "0"
        integer, dot, fraction = mantissa.partition(".")
        digits = (integer + fraction).lstrip("0")
        if not digits:
            self.value = (False, "0", 0)
            return
        exponent_digits = exponent.lstrip("+-").lstrip("0") or "0"
        if len(exponent_digits) > 4000:
            raise ComparisonLimit("Exponent exceeds the analyzer's 4000-digit limit")
        exponent_value = int(("-" if exponent.startswith("-") else "") + exponent_digits)
        significant = digits.rstrip("0")
        self.value = (negative, significant, exponent_value - len(fraction) + len(digits) - len(significant))


LENIENT_NUMBER = re.compile(r"-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")
STRICT_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")


def normalize_lenient_numbers(text):
    """Rewrite non-RFC number spellings outside strings into equivalent RFC 8259 numbers.

    json-c re-emits a double's original token, so it can print `1.`, `-.5`, `0.e1` or `068e1`.
    The value is unchanged (`1.` -> `1`, `-.5` -> `-0.5`, `068e1` -> `68e1`), which lets such
    outputs still be compared by value. Returns (text, changed).
    """
    out, i, changed, in_string = [], 0, False, False
    while i < len(text):
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\":
                out.append(text[i + 1:i + 2])
                i += 2
                continue
            in_string = ch != '"'
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        match = LENIENT_NUMBER.match(text, i) if (ch.isdigit() or ch in "-.") else None
        if match:
            token = match.group()
            if not STRICT_NUMBER.fullmatch(token):
                sign = "-" if token.startswith("-") else ""
                mantissa, _, exponent = token.lstrip("-").replace("E", "e").partition("e")
                integer, _, fraction = mantissa.partition(".")
                token = sign + (integer.lstrip("0") or "0") + ("." + fraction if fraction else "") + \
                    ("e" + exponent if exponent else "")
                changed = True
            out.append(token)
            i = match.end()
            continue
        out.append(ch)
        i += 1
    return "".join(out), changed


def canonicalize(raw, lenient=False):
    """JSON value comparison: exact decimal numbers, unordered object keys,
    ordered arrays and ordered duplicate values per key. Does not erase duplicates.
    This compares serialized values, not the libraries' internal numeric storage.
    lenient=True first rewrites non-RFC number spellings (see normalize_lenient_numbers).
    """
    def invalid_constant(value):
        raise ValueError("Non-JSON constant: " + value)

    def canonical(value):
        if isinstance(value, ObjectPairs):
            groups = defaultdict(list)
            for key, item in value:
                groups[key].append(canonical(item))
            return ("object", tuple((k, tuple(v)) for k, v in sorted(groups.items())))
        if isinstance(value, list):
            return ("array", tuple(canonical(item) for item in value))
        if isinstance(value, JSONNumber):
            return ("number", value.value)
        if isinstance(value, bool):
            return ("boolean", value)
        if value is None:
            return ("null",)
        return ("string", value)

    # surrogateescape keeps invalid UTF-8 bytes distinguishable (equal bytes compare equal),
    # so outputs containing raw non-UTF-8 bytes can still be compared by value.
    text = raw.decode("utf-8", errors="surrogateescape")
    if lenient:
        text = normalize_lenient_numbers(text)[0]
    return canonical(json.loads(text, object_pairs_hook=ObjectPairs,
                                parse_int=JSONNumber, parse_float=JSONNumber,
                                parse_constant=invalid_constant))


def execute(binary, input_path, timeout, output_limit=1048576):
    env = dict(os.environ)
    env.update(ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1",
               UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:symbolize=1:print_stacktrace=1")
    start = time.perf_counter()
    code, status, error = None, None, None
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            result = subprocess.run([str(binary), str(input_path)], stdout=out, stderr=err,
                                    timeout=timeout, env=env)
            code = result.returncode
        except subprocess.TimeoutExpired:
            status = "timeout"
        except OSError as exc:
            status, error = "harness_error", str(exc)
        elapsed = time.perf_counter() - start
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(output_limit + 1), err.read(output_limit + 1)
    stdout_truncated, stderr_truncated = len(stdout) > output_limit, len(stderr) > output_limit
    truncated = stdout_truncated or stderr_truncated
    stdout, stderr = stdout[:output_limit], stderr[:output_limit]
    diagnostic = stderr.decode("utf-8", errors="backslashreplace")
    sanitizer = [marker for marker in SANITIZERS if marker in diagnostic]
    if status is None:
        status = "crash" if code < 0 else "sanitizer" if sanitizer else (
            "accepted" if code == 0 else "rejected" if code == 1 else "harness_error")
    signature = None
    if sanitizer or status == "crash":
        lines = [l.strip() for l in diagnostic.splitlines()
                 if "ERROR:" in l or "runtime error:" in l or re.match(r"\s*#\d+", l)]
        normalized = re.sub(r"0x[0-9a-fA-F]+|==\d+==", "<address>", "\n".join(lines[:6]))
        signature = sha256((status + str(code) + normalized).encode())
    return {"status": status, "returncode": code, "seconds": elapsed,
            "sanitizer_markers": sanitizer, "failure_signature": signature,
            "stdout_b64": base64.b64encode(stdout).decode(),
            "stderr_b64": base64.b64encode(stderr).decode(),
            "stdout": stdout.decode("utf-8", errors="backslashreplace"),
            "stderr": diagnostic, "output_truncated": truncated,
            "stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated, "error": error}


def compare(left, right):
    tags = []
    abnormal = {"crash", "sanitizer", "timeout", "harness_error"}
    if left["status"] in abnormal or right["status"] in abnormal:
        tags.append("ABNORMAL_EXECUTION")
    elif left["status"] != right["status"]:
        tags.append("ACCEPTANCE_DIFFERENCE")
    if left.get("stdout_truncated", left["output_truncated"]) or right.get("stdout_truncated", right["output_truncated"]):
        tags.append("OUTPUT_LIMIT")
        return tags
    if left["status"] == right["status"] == "accepted":
        values = []
        for result in (left, right):
            raw = base64.b64decode(result["stdout_b64"])
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError:
                # Reported, but the value comparison below still runs on the raw bytes.
                tags.append("INVALID_UTF8_OUTPUT")
            try:
                values.append(canonicalize(raw))
            except (ComparisonLimit, RecursionError):
                tags.append("COMPARISON_LIMIT")
            except (ValueError, ArithmeticError):
                # Not strict JSON (e.g. json-c echoing `1.`): report it, but still compare the
                # value if the only problem is a non-RFC number spelling.
                tags.append("INVALID_JSON_OUTPUT")
                try:
                    values.append(canonicalize(raw, lenient=True))
                except (ComparisonLimit, RecursionError):
                    tags.append("COMPARISON_LIMIT")
                except (ValueError, ArithmeticError):
                    pass
        if len(values) == 2 and values[0] != values[1]:
            tags.append("VALUE_DIFFERENCE")
        elif len(values) < 2 and left["stdout_b64"] != right["stdout_b64"] and "COMPARISON_LIMIT" not in tags:
            # At least one output could not be parsed even leniently and the outputs differ:
            # never treat that as agreement.
            tags.append("UNCOMPARABLE_OUTPUT")
    return sorted(set(tags))


def replay(data, fuzz_root, bin_dir, output, timeout, repeats, workers, limit, output_limit=1048576):
    left_bin, right_bin = bin_dir / "cjson_parse", bin_dir / "jsonc_parse"
    for binary in (left_bin, right_bin):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError(f"Missing executable {binary}; replay inside the Linux build environment.")
    selected = data["inputs"][:limit] if limit else data["inputs"]
    tag_counts, pairs, candidates = Counter(), Counter(), []
    equal_output_tags, seed_tags = Counter(), Counter()
    confirmation_failed = 0

    def one(item):
        path = fuzz_root / item["origins"][0]["path"]
        r1, r2 = execute(left_bin, path, timeout, output_limit), execute(right_bin, path, timeout, output_limit)
        if r1["error"] or r2["error"]:
            raise ValueError(r1["error"] or r2["error"])
        tags = compare(r1, r2)
        stable = True
        checks = []
        if tags:
            fingerprint = (tags, r1["status"], r2["status"], r1["stdout_b64"], r2["stdout_b64"],
                           r1["failure_signature"], r2["failure_signature"])
            for _ in range(repeats - 1):
                a, b = execute(left_bin, path, timeout, output_limit), execute(right_bin, path, timeout, output_limit)
                check = (compare(a, b), a["status"], b["status"], a["stdout_b64"], b["stdout_b64"],
                         a["failure_signature"], b["failure_signature"])
                checks.append({"tags": check[0], "parser1": a, "parser2": b})
                stable = stable and check == fingerprint
        return {"sha256": item["sha256"], "bytes": item["bytes"], "origins": item["origins"],
                "tags": tags, "repeatable": stable if tags else None,
                "confirmation_attempts": repeats if tags else 1, "confirmations": checks,
                "representation_only": not tags and r1["status"] == r2["status"] == "accepted"
                    and r1["stdout_b64"] != r2["stdout_b64"], "parser1": r1, "parser2": r2}

    representation_only = 0
    with (output / "replay.jsonl").open("w") as handle, ThreadPoolExecutor(max_workers=workers) as pool:
        for count, record in enumerate(pool.map(one, selected), 1):
            handle.write(json.dumps(record) + "\n")
            tag_counts.update(record["tags"])
            pairs[(record["parser1"]["status"], record["parser2"]["status"])] += 1
            representation_only += record["representation_only"]
            if record["tags"]:
                candidates.append(record)
                confirmation_failed += not record["repeatable"]
                if record["parser1"]["stdout_b64"] == record["parser2"]["stdout_b64"]:
                    equal_output_tags.update(record["tags"])
                if any(o["is_seed"] for o in record["origins"]):
                    seed_tags.update(record["tags"])
            if count % 500 == 0:
                print(f"Replayed {count}/{len(selected)} distinct inputs", flush=True)
    write_csv(output / "findings.csv", [
        {"sha256": r["sha256"], "bytes": r["bytes"], "tags": r["tags"],
         "repeatable": r["repeatable"], "cjson_status": r["parser1"]["status"],
         "jsonc_status": r["parser2"]["status"],
         "identical_stdout": r["parser1"]["stdout_b64"] == r["parser2"]["stdout_b64"],
         "has_seed_origin": any(o["is_seed"] for o in r["origins"]),
         "input_path": str(fuzz_root / r["origins"][0]["path"])} for r in candidates])
    example_counts = Counter()
    for record in sorted(candidates, key=lambda r: (r["bytes"], r["sha256"])):
        for tag in record["tags"]:
            if example_counts[tag] >= 10:
                continue
            folder = output / "examples" / tag
            folder.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fuzz_root / record["origins"][0]["path"], folder / (record["sha256"] + ".bin"))
            example_counts[tag] += 1
    # Reproduce saved fault artifacts with their originating instrumented target.
    triage, processed = [], set()
    run_lookup = {(r["campaign"], r["instance"]): r for r in data["runs"]}
    for item in data["inputs"]:
        for origin in item["origins"]:
            if origin["kind"] not in ("crashes", "hangs"):
                continue
            run = run_lookup[(origin["campaign"], origin["instance"])]
            binary = Path(run["binary"]["path"])
            key = (item["sha256"], str(binary), origin["kind"])
            if key in processed:
                continue
            processed.add(key)
            attempts = [execute(binary, fuzz_root / origin["path"], timeout, output_limit) for _ in range(repeats)]
            reproduced = sum(a["status"] == "timeout" if origin["kind"] == "hangs" else
                             a["status"] in ("crash", "sanitizer") for a in attempts)
            triage.append({"sha256": item["sha256"], "origin": origin,
                           "binary": run["binary"], "target_hash_match": run["target_hash_match"],
                           "timeout_seconds": timeout, "attempts": attempts,
                           "reproduced_attempts": reproduced})
    write_json(output / "triage.json", triage)
    return {"inputs_replayed": len(selected), "total_distinct_inputs": len(data["inputs"]),
            "partial": len(selected) != len(data["inputs"]), "candidate_inputs": len(candidates),
            "tag_counts": dict(tag_counts), "nonrepeatable_candidates": confirmation_failed,
            "tag_counts_identical_stdout": dict(equal_output_tags),
            "tag_counts_with_seed_origin": dict(seed_tags),
            "representation_only": representation_only,
            "status_pairs": {" / ".join(k): v for k, v in pairs.items()},
            "saved_faults_replayed": len(triage),
            "saved_faults_reproduced": sum(r["reproduced_attempts"] > 0 for r in triage),
            "settings": {"timeout_seconds": timeout, "confirmation_repeats": repeats,
                         "workers": workers, "output_limit_bytes": output_limit,
                         "sanitizer_options": "abort on error; leak detection off; symbolization on"},
            "baseline_binaries": [inspect_binary(left_bin), inspect_binary(right_bin)]}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def write_csv(path, rows):
    if not rows:
        path.write_text("")
        return
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})


def render_report(data, replay_summary):
    runs = data["runs"]
    executions = sum(r["execs_done"] or 0 for r in runs)
    occurrences = sum(len(i["origins"]) for i in data["inputs"])
    lines = ["# AFL++ run analysis", "", f"Generated: {datetime.now(timezone.utc).isoformat()}", "",
             f"{len(runs)} fuzzer instances; {executions:,} recorded executions; "
             f"{occurrences:,} saved input occurrences; {len(data['inputs']):,} distinct byte sequences.", "",
             "## Per-configuration results", "",
             "These are directory labels, not independently proven sanitizer configurations. "
             "SD is sample standard deviation across separate runs. Different binaries have different edge spaces.", "",
             "| Parser | Label | Runs | Executions | Exec/s mean ± SD | Edges mean | Saved crashes | Saved hangs |",
             "|---|---|---:|---:|---:|---:|---:|---:|"]
    def fmt(value, places=2):
        return "unknown" if value is None else f"{value:,.{places}f}"
    for group in data["groups"]:
        lines.append(f"| {group['parser']} | {group['config']} | {group['runs']} | "
                     f"{fmt(group['execs_done_sum'], 0)} | {fmt(group['execs_per_sec_mean'])} ± "
                     f"{fmt(group['execs_per_sec_sd'])} | {fmt(group['edges_found_mean'], 1)} | "
                     f"{fmt(group['saved_crashes_sum'], 0)} | {fmt(group['saved_hangs_sum'], 0)} |")
    lines += ["", "## Validity checks", ""]
    lines += ["- " + warning for warning in data["warnings"]]
    issues = defaultdict(list)
    for run in runs:
        for warning in run["warnings"]:
            issues[warning].append(run["campaign"] + "/" + run["instance"])
    for warning, names in issues.items():
        lines.append(f"- {warning} ({len(names)} instances)")
    matches = Counter(str(r["target_hash_match"]) for r in runs)
    lines += [f"- Current target/AFL XXH3 fingerprint checks: {dict(matches)}. None means unavailable; "
              "False means mismatch or unsupported algorithm. SHA-256 is recorded separately.", "",
              "## Interpretation", "",
              "- AFL saved crashes/hangs are candidate artifacts, not counts of independent bugs. "
              "Deduplicate bytes, replay, inspect diagnostics, and group root causes.",
              "- Zero saved crashes means no crashes were saved under this campaign's configuration and budget; "
              "it does not establish safety or absence of semantic disagreements.",
              "- Queue counts include original seeds and retained coverage-increasing inputs, not every mutation executed.",
              "- bitmap_cvg is an AFL instrumentation metric, not source-line coverage. Do not compare raw edge counts "
              "between different parsers or differently instrumented binaries as a security ranking.",
              "- Configuration throughput differences are descriptive only. Optimization level, CPU/core assignment, "
              "concurrent workload, input mix, and sanitizer configuration confound overhead claims.",
              "- A missing first-crash/first-hang time is not zero. It means no such saved artifact was found; "
              "use the run budget as a right-censoring bound, not an observed time to finding.", ""]
    if replay_summary:
        r = replay_summary
        lines += ["## Differential replay", "",
                  f"Replayed {r['inputs_replayed']:,}/{r['total_distinct_inputs']:,} distinct inputs "
                  f"through both normal parser wrappers. Candidate inputs: {r['candidate_inputs']:,}. "
                  f"Nonrepeatable candidates: {r['nonrepeatable_candidates']:,}.", "",
                  f"Status pairs: {r['status_pairs']}", "", f"Candidate tags: {r['tag_counts']}", "",
                  f"Representation-only differences with equal compared values: {r['representation_only']}.", "",
                  f"Saved fault/input-target combinations replayed: {r['saved_faults_replayed']}; "
                  f"reproduced at least once: {r['saved_faults_reproduced']}.", "",
                  "Replay settings: " + json.dumps(r["settings"]), "",
                  "Replay compares serialized JSON values using exact decimal arithmetic, preserves duplicate values "
                  "per key, ignores unrelated object-key ordering, and retains array order and JSON types. "
                  "A number printed differently can still expose serialization/rounding differences rather than "
                  "different internal values. Each candidate needs interpretation against the input and library APIs.", "",
                  "INVALID_UTF8_OUTPUT and INVALID_JSON_OUTPUT describe accepted output that cannot be decoded as "
                  "strict UTF-8 JSON; they are not automatically disagreements between parsers. "
                  f"Identical-output candidate counts by tag: {r['tag_counts_identical_stdout']}. "
                  f"Candidates also seen in seed-derived queue entries: {r['tag_counts_with_seed_origin']}. "
                  "COMPARISON_LIMIT and OUTPUT_LIMIT are analyzer limitations, not parser defects.", "",
                  "The replay corpus is AFL's retained corpus, not every input generated. Finding counts are neither "
                  "independent bugs nor an unbiased disagreement rate. Small examples are copied into examples/; "
                  "these are selected representatives, not minimized test cases.", ""]
    else:
        lines += ["## Replay not performed", "",
                  "Run again inside the Linux container with --replay to analyze retained semantic differences "
                  "and reproduce saved crashes/hangs. Current statistics alone do not provide that evidence.", ""]
    lines += ["## Files", "", "- summary.json: complete metrics, warnings and current target fingerprints.",
              "- runs.csv / groups.csv: per-instance measurements and independent-repeat summaries.",
              "- timeline.csv: AFL plot_data rows, with campaign and instance provenance.",
              "- corpus.jsonl: SHA-256 deduplication and every saved input's origins.",
              "- replay.jsonl / replay_summary.json / triage.json: generated only with --replay.", "",
              "- findings.csv: compact candidate index, including the original file path and repeatability.",
              "- source_at_analysis/: snapshots of scripts/wrappers at analysis time, not proof of build-time source.", "",
              "## References", "",
              "- AFL++ status fields: https://aflplus.plus/docs/status_screen/",
              "- AFL++ methodology and triage: https://aflplus.plus/docs/fuzzing_in_depth/", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "fuzz_out")
    parser.add_argument("--output", type=Path, help="New/empty output directory; existing results are never overwritten")
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "bin")
    parser.add_argument("--expected-seconds", type=float, default=1800)
    parser.add_argument("--expected-repeats", type=int, default=5,
                        help="Runs expected per parser/config (run_fuzzing.sh REPEATS; default 5)")
    parser.add_argument("--replay", action="store_true", help="Execute saved inputs; requires Linux target binaries")
    parser.add_argument("--timeout", type=float, default=1.0, help="Replay timeout per process in seconds")
    parser.add_argument("--confirm", type=int, default=3, help="Attempts per candidate and saved fault")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent differential replay workers; triage is serial")
    parser.add_argument("--limit", type=int, default=0, help="Limit differential replay to N SHA-sorted inputs; 0=all. Triage stays complete.")
    parser.add_argument("--output-limit", type=int, default=1048576, help="Maximum bytes retained per stdout/stderr stream")
    args = parser.parse_args()
    if min(args.timeout, args.confirm, args.workers, args.expected_seconds, args.expected_repeats, args.output_limit) <= 0 or args.limit < 0:
        parser.error("Durations/counts must be positive; limit must be nonnegative")
    fuzz_root, bin_dir = args.input.resolve(), args.bin_dir.resolve()
    output = (args.output or ROOT / "results" / ("fuzz_analysis_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))).resolve()
    if output == fuzz_root or fuzz_root in output.parents:
        parser.error("Place analysis output outside the input artifact directory")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        parser.error(f"Output directory is not empty: {output}")
    try:
        data = collect(fuzz_root, bin_dir, args.expected_seconds, args.expected_repeats)
        output.mkdir(parents=True, exist_ok=True)
        write_csv(output / "runs.csv", [{k: v for k, v in r.items() if k != "raw_stats"} for r in data["runs"]])
        write_csv(output / "groups.csv", data["groups"])
        write_csv(output / "timeline.csv", data["timeline"])
        with (output / "corpus.jsonl").open("w") as handle:
            for item in data["inputs"]:
                handle.write(json.dumps(item) + "\n")
        summary = {k: v for k, v in data.items() if k not in ("inputs", "timeline")}
        summary.update(generated_utc=datetime.now(timezone.utc).isoformat(), input_root=str(fuzz_root),
                       distinct_inputs=len(data["inputs"]),
                       input_occurrences=sum(len(i["origins"]) for i in data["inputs"]),
                       analysis_script_sha256=sha256(Path(__file__).read_bytes()))
        # These snapshots describe analysis-time source, not necessarily build-time source.
        evidence = output / "source_at_analysis"
        evidence.mkdir()
        for name in ("setup_and_build.sh", "run_fuzzing.sh", "cjson_parse.c", "jsonc_parse.c",
                     "analyze_fuzzing.py"):
            source = ROOT / "scripts" / name
            if source.is_file():
                shutil.copyfile(source, evidence / name)
        summary["analysis_time_source_sha256"] = {
            p.name: sha256(p.read_bytes()) for p in sorted(evidence.iterdir())}
        write_json(output / "summary.json", summary)
        (output / "report.md").write_text(render_report(data, None))
        replay_summary = replay(data, fuzz_root, bin_dir, output, args.timeout, args.confirm,
                                args.workers, args.limit, args.output_limit) if args.replay else None
        if replay_summary:
            write_json(output / "replay_summary.json", replay_summary)
            (output / "report.md").write_text(render_report(data, replay_summary))
        print(f"Analysis written to {output}")
        print(f"Instances: {len(data['runs'])}; distinct inputs: {len(data['inputs'])}")
        return 0
    except (ValueError, OSError) as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
