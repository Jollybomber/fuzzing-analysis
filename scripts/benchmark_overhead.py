#!/usr/bin/env python3
"""Measure sanitizer runtime overhead on a fixed set of inputs.

Fuzzing throughput (execs/sec) is confounded: every campaign executes a different
mix of inputs. This benchmark instead parses the *same* inputs with every build.

For each parser it links scripts/bench_harness.c against the exact library objects
that setup_and_build.sh produced for each variant (BUILD_DIR/<parser>_<variant>/), so
the parser code being timed is the code that was fuzzed:

  baseline    plain clang, no AFL instrumentation, no sanitizers
  normal      AFL instrumentation only
  asan        AFL + AddressSanitizer
  asan_ubsan  AFL + AddressSanitizer + UndefinedBehaviorSanitizer

The harness loads all inputs into memory and times parse + serialize only, so process
start-up and file I/O are excluded. Repetitions run the four variants in a shuffled
order on one pinned core, and slowdowns are computed per repetition (paired).

Run inside the AFL++ container, after setup_and_build.sh, on an otherwise idle machine:
    python3 scripts/benchmark_overhead.py --build-dir build_v2 --fuzz-dir fuzz_out_v2
"""
import argparse
import csv
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARSERS = ("cjson", "jsonc")
VARIANTS = ("baseline", "normal", "asan", "asan_ubsan")
SANITIZER_ENV = {"baseline": {}, "normal": {}, "asan": {"AFL_USE_ASAN": "1"},
                 "asan_ubsan": {"AFL_USE_ASAN": "1", "AFL_USE_UBSAN": "1"}}
CLEARED_ENV = ("AFL_USE_ASAN", "AFL_USE_UBSAN", "AFL_USE_MSAN", "AFL_USE_LSAN", "AFL_USE_TSAN",
               "AFL_USE_CFISAN", "AFL_USE_RTSAN", "AFL_USE_TYSAN", "AFL_HARDEN")
RUN_ENV = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=0",
           "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:symbolize=0",
           "AFL_QUIET": "1"}


def die(message):
    sys.exit(f"Error: {message}")


def variant_env(variant):
    env = {k: v for k, v in os.environ.items() if k not in CLEARED_ENV}
    env.update(SANITIZER_ENV[variant])
    return env


def build_harness(parser, variant, build_dir, out_dir, flags):
    compiler = "clang" if variant == "baseline" else "afl-clang-fast"
    lib_dir = build_dir / f"{parser}_{variant}"
    if parser == "cjson":
        includes = [f"-I{ROOT / 'src' / 'cjson_src'}"]
        libs = [str(lib_dir / "cJSON.o"), "-lm"]
        define = "-DBENCH_CJSON"
    else:
        includes = [f"-I{ROOT / 'src' / 'jsonc_src'}", f"-I{lib_dir}"]
        libs = [str(lib_dir / "libjson-c.a")]
        define = "-DBENCH_JSONC"
    for lib in libs:
        if lib != "-lm" and not Path(lib).is_file():
            die(f"Missing {lib}; run setup_and_build.sh with BUILD_DIR={build_dir}")
    obj = out_dir / f"bench_{parser}_{variant}.o"
    exe = out_dir / f"bench_{parser}_{variant}"
    env = variant_env(variant)
    subprocess.run([compiler, *flags, define, *includes, "-c", str(ROOT / "scripts" / "bench_harness.c"),
                    "-o", str(obj)], check=True, env=env)
    subprocess.run([compiler, *flags, str(obj), *libs, "-o", str(exe)], check=True, env=env)
    data = exe.read_bytes()
    has_asan, has_afl = b"__asan_init" in data, b"__afl_area_ptr" in data
    if has_asan != (variant in ("asan", "asan_ubsan")) or has_afl != (variant != "baseline"):
        die(f"{exe.name}: unexpected instrumentation (asan={has_asan}, afl={has_afl})")
    return exe


def corpus_inputs(name, fuzz_dir):
    if name == "conformance":
        files = sorted((ROOT / "tests" / "JSONTestSuite" / "test_parsing").glob("*.json"))
        files += sorted((ROOT / "tests" / "handwritten_test_cases").glob("*.json"))
        files += sorted(p for p in (ROOT / "fuzz_seeds").iterdir() if p.is_file())
        return files
    by_hash = {}
    for kind in ("queue", "crashes", "hangs"):
        for path in sorted(fuzz_dir.glob(f"*/*/{kind}/id:*")):
            if path.is_file():
                by_hash.setdefault(hashlib.sha256(path.read_bytes()).hexdigest(), path)
    return [by_hash[h] for h in sorted(by_hash)]


def run(exe, list_file, loops, core):
    cmd = [str(exe), str(list_file), str(loops)]
    if core is not None and shutil.which("taskset"):
        cmd = ["taskset", "-c", str(core), *cmd]
    result = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, **RUN_ENV}, timeout=3600)
    if result.returncode != 0:
        die(f"{exe.name} failed (exit {result.returncode}): {result.stderr[-2000:]}")
    fields = dict(item.split("=", 1) for item in result.stdout.split())
    return {k: int(v) for k, v in fields.items()}


def quantile(values, q):
    values = sorted(values)
    pos = (len(values) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (pos - lo)


def bootstrap_ci(values, rng, draws=10000):
    medians = sorted(statistics.median(rng.choices(values, k=len(values))) for _ in range(draws))
    return medians[int(0.025 * draws)], medians[int(0.975 * draws) - 1]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", type=Path, default=ROOT / "build_v2")
    ap.add_argument("--bin-dir", type=Path, default=ROOT / "bin_v2", help="Read build flags from its build_manifest.json")
    ap.add_argument("--fuzz-dir", type=Path, default=ROOT / "fuzz_out_v2",
                    help="Campaign root whose distinct saved inputs form the 'fuzz' corpus")
    ap.add_argument("--corpora", default="conformance,fuzz", help="Comma-separated: conformance, fuzz")
    ap.add_argument("--reps", type=int, default=10, help="Repetitions per variant (default 10)")
    ap.add_argument("--target-seconds", type=float, default=1.0,
                    help="Calibrate loops so one normal-build run takes about this long")
    ap.add_argument("--core", type=int, default=0, help="CPU core to pin to (-1 disables pinning)")
    ap.add_argument("--seed", type=int, default=4239)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    build_dir, bin_dir = args.build_dir.resolve(), args.bin_dir.resolve()
    corpora = [c.strip() for c in args.corpora.split(",") if c.strip()]
    if any(c not in ("conformance", "fuzz") for c in corpora) or args.reps < 2 or args.target_seconds <= 0:
        die("invalid --corpora, --reps (>= 2) or --target-seconds")
    manifest_path = bin_dir / "build_manifest.json"
    if not manifest_path.is_file():
        die(f"{manifest_path} missing; build with setup_and_build.sh first")
    manifest = json.loads(manifest_path.read_text())
    flags = manifest["common_flags"].split()
    for tool in ("clang", "afl-clang-fast"):
        if not shutil.which(tool):
            die(f"{tool} not found; run inside the AFL++ container")
    out = (args.output or ROOT / "results" / ("overhead_" + datetime.now().strftime("%Y%m%d_%H%M%S"))).resolve()
    if out.exists():
        die(f"{out} already exists")
    (out / "bin").mkdir(parents=True)
    core = None if args.core < 0 else args.core
    rng = random.Random(args.seed)

    print(f"Building harnesses with flags: {' '.join(flags)}")
    exes = {(p, v): build_harness(p, v, build_dir, out / "bin", flags) for p in PARSERS for v in VARIANTS}

    lists, corpus_meta = {}, {}
    for name in corpora:
        files = corpus_inputs(name, args.fuzz_dir.resolve())
        if not files:
            die(f"corpus '{name}' is empty")
        lists[name] = out / f"inputs_{name}.txt"
        lists[name].write_text("".join(f"{p.resolve()}\n" for p in files))
        corpus_meta[name] = {"inputs": len(files), "bytes": sum(p.stat().st_size for p in files)}
        print(f"Corpus {name}: {len(files)} inputs, {corpus_meta[name]['bytes']} bytes")

    rows, warnings = [], []
    for parser in PARSERS:
        for name in corpora:
            probe = run(exes[(parser, "normal")], lists[name], 1, core)
            loops = max(1, round(args.target_seconds * 1e9 / max(probe["ns"], 1)))
            accepted = {}
            print(f"{parser}/{name}: {loops} loops per run, {args.reps} reps x {len(VARIANTS)} variants")
            for rep in range(1, args.reps + 1):
                order = list(VARIANTS)
                rng.shuffle(order)
                for variant in order:
                    r = run(exes[(parser, variant)], lists[name], loops, core)
                    accepted.setdefault(variant, r["accepted"])
                    rows.append({"parser": parser, "corpus": name, "variant": variant, "rep": rep,
                                 "order": order.index(variant), "ns": r["ns"], "inputs": r["inputs"],
                                 "loops": r["loops"], "accepted": r["accepted"],
                                 "ns_per_input": r["ns"] / (r["inputs"] * r["loops"])})
            if len(set(accepted.values())) != 1:
                warnings.append(f"{parser}/{name}: accepted counts differ across variants: {accepted}")

    with (out / "raw.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    summary = []
    for parser in PARSERS:
        for name in corpora:
            per = {v: {r["rep"]: r["ns_per_input"] for r in rows
                       if (r["parser"], r["corpus"], r["variant"]) == (parser, name, v)} for v in VARIANTS}
            for variant in VARIANTS:
                times = list(per[variant].values())
                entry = {"parser": parser, "corpus": name, "variant": variant, "reps": len(times),
                         "median_us_per_input": statistics.median(times) / 1000,
                         "q1_us": quantile(times, 0.25) / 1000, "q3_us": quantile(times, 0.75) / 1000,
                         "cv_percent": 100 * statistics.stdev(times) / statistics.mean(times)}
                for ref in ("baseline", "normal"):
                    ratios = [per[variant][k] / per[ref][k] for k in per[variant]]
                    lo, hi = bootstrap_ci(ratios, rng)
                    entry[f"slowdown_vs_{ref}"] = statistics.median(ratios)
                    entry[f"slowdown_vs_{ref}_ci95"] = [lo, hi]
                summary.append(entry)

    with (out / "summary.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["parser", "corpus", "variant", "reps", "median_us_per_input", "q1_us", "q3_us",
                         "cv_percent", "slowdown_vs_normal", "ci95_low", "ci95_high",
                         "slowdown_vs_baseline", "base_ci95_low", "base_ci95_high"])
        for s in summary:
            writer.writerow([s["parser"], s["corpus"], s["variant"], s["reps"], f"{s['median_us_per_input']:.4f}",
                             f"{s['q1_us']:.4f}", f"{s['q3_us']:.4f}", f"{s['cv_percent']:.2f}",
                             f"{s['slowdown_vs_normal']:.4f}", *(f"{x:.4f}" for x in s["slowdown_vs_normal_ci95"]),
                             f"{s['slowdown_vs_baseline']:.4f}", *(f"{x:.4f}" for x in s["slowdown_vs_baseline_ci95"])])

    meta = {"generated_utc": datetime.now(timezone.utc).isoformat(), "build_dir": str(build_dir),
            "build_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "flags": flags, "reps": args.reps, "target_seconds": args.target_seconds, "core": core,
            "seed": args.seed, "corpora": corpus_meta, "run_env": RUN_ENV, "cpu_count": os.cpu_count(),
            "platform": platform.platform(), "warnings": warnings,
            "clang": subprocess.run(["clang", "--version"], capture_output=True, text=True).stdout.splitlines()[0]}
    (out / "summary.json").write_text(json.dumps({"meta": meta, "results": summary}, indent=2) + "\n")

    lines = ["# Sanitizer overhead benchmark", "",
             f"Generated {meta['generated_utc']}. Same inputs for every build; parse + serialize only, in-process; "
             f"{args.reps} paired repetitions per build, shuffled order, pinned to core {core}.", "",
             "Slowdown = median over repetitions of (variant time / reference time) in the same repetition; "
             "brackets are bootstrap 95% confidence intervals.", ""]
    for name in corpora:
        lines += [f"## Corpus: {name} ({corpus_meta[name]['inputs']} inputs)", "",
                  "| Parser | Build | Median µs/input | IQR (µs) | CV % | Slowdown vs normal | Slowdown vs plain clang |",
                  "|---|---|---:|---:|---:|---:|---:|"]
        for s in (s for s in summary if s["corpus"] == name):
            lo, hi = s["slowdown_vs_normal_ci95"]
            blo, bhi = s["slowdown_vs_baseline_ci95"]
            lines.append(f"| {s['parser']} | {s['variant']} | {s['median_us_per_input']:.3f} | "
                         f"{s['q1_us']:.3f}–{s['q3_us']:.3f} | {s['cv_percent']:.1f} | "
                         f"{s['slowdown_vs_normal']:.2f}× [{lo:.2f}, {hi:.2f}] | "
                         f"{s['slowdown_vs_baseline']:.2f}× [{blo:.2f}, {bhi:.2f}] |")
        lines.append("")
    lines += ["## Warnings", ""] + ([f"- {w}" for w in warnings] or ["- None"]) + [""]
    (out / "report.md").write_text("\n".join(lines))
    print(f"Results written to {out}")
    if warnings:
        print("Warnings:\n  " + "\n  ".join(warnings))


if __name__ == "__main__":
    main()
