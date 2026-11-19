# cJSON vs. json-c: Security & Differential Analysis

A security-focused comparative analysis framework evaluating **cJSON (v1.7.19)** and **json-c (v0.16)**. This project implements an automated pipeline covering environment setup, symmetric parser wrappers, multi-variant compilation (Normal, AFL++ ASan, AFL++ ASan + UBSan), differential testing across compliance suites and handwritten cases, and AFL++ fuzzing campaigns.

---

## Repository Structure

```text
fuzzing-analysis/
├── fuzz_seeds/             # 75-file seed corpus for AFL++ (selected by scripts/curate_seeds.py)
├── scripts/
│   ├── cjson_parse.c, jsonc_parse.c   # Parser wrappers: read a file, print normalized JSON
│   ├── setup_and_build.sh             # Builds and verifies all parser/sanitizer variants
│   ├── diff_driver.py                 # Compares both parsers on one input
│   ├── run_baseline_comparison.sh     # Differential testing on JSONTestSuite + handwritten cases
│   ├── run_fuzzing.sh                 # AFL++ campaigns (single run or full matrix)
│   ├── fuzz_progress.sh               # Progress table for running campaigns
│   ├── analyze_fuzzing.py             # Statistics, differential replay, and crash/hang triage
│   ├── classify_findings.py           # Root cause for every parser disagreement
│   ├── bench_harness.c, benchmark_overhead.py  # Fixed-input sanitizer overhead benchmark
│   ├── make_charts.py                 # Report figures and tables
│   └── curate_seeds.py                # Regenerates fuzz_seeds/ from JSONTestSuite
├── src/                    # Library source trees (cjson_src/, jsonc_src/; not in git)
├── tests/
│   ├── handwritten_test_cases/        # Security and edge-case inputs
│   ├── JSONTestSuite/                 # Compliance suite (git submodule)
│   └── test_analyze_fuzzing.py        # Unit tests for the analyzer
└── README.md
```

Generated output is not committed: `bin*/` and `build*/` (binaries and build logs),
`fuzz_out*/` (AFL++ campaigns), `results/` (test logs and analysis reports), and
`fuzz_master*.log`. The exception is `experiment_results/`, the committed copy of the results
the findings are based on.

---

## Getting Started & Workflow

### Step 1: Populate Source Code

Clone the target libraries into `src/` at the pinned versions and fetch JSONTestSuite:

```bash
mkdir -p src
git clone --branch v1.7.19 --depth 1 https://github.com/DaveGamble/cJSON.git src/cjson_src
git clone --branch json-c-0.16-20220414 --depth 1 https://github.com/json-c/json-c.git src/jsonc_src
git submodule update --init tests/JSONTestSuite
```

### Step 2: Start the AFL++ Container

`afl-clang-fast` and `afl-fuzz` need Linux, so every later step runs inside the official
AFL++ container with the repository mounted at `/work`. Start it in the background so a
multi-hour campaign keeps running after you close your terminal:

```bash
# Run once, from the repository root on your host
docker run -d --name json-fuzz \
  --mount "type=bind,source=$PWD,target=/work" \
  --workdir /work \
  aflplusplus/aflplusplus:latest sleep infinity

# Open a shell in it (repeat whenever you need one)
docker exec -it json-fuzz bash
```

All commands below are run inside the container from `/work`.

### Step 3: Build Binaries

```bash
BUILD_DIR=build_v2 BIN_DIR=bin_v2 ./scripts/setup_and_build.sh
```

The script refuses to overwrite an existing `BUILD_DIR` or `BIN_DIR`, so use new names for
each rebuild. It builds every variant with Clang and the same flags
(`-O1 -g -fno-omit-frame-pointer`):

| Binary | Compiler | Sanitizers | Used for |
|---|---|---|---|
| `cjson_parse`, `jsonc_parse` | `clang` | none | Differential testing |
| `*_afl_normal` | `afl-clang-fast` | none | Fuzzing baseline |
| `*_afl_asan` | `afl-clang-fast` | ASan | Fuzzing |
| `*_afl_asan_ubsan` | `afl-clang-fast` | ASan + UBSan | Fuzzing |

> **Sanitizer variables:** AFL++ enables a sanitizer whenever `AFL_USE_ASAN` or
> `AFL_USE_UBSAN` is *set*, even to `0`. The build script unsets them for the normal build
> rather than setting them to `0`.

After building, the script checks each object file for the expected ASan, UBSan, and AFL
instrumentation, then smoke-tests every binary. A successful build ends with eight `PASS`
lines and `Build verified`, and writes `bin_v2/build_manifest.json` (flags, toolchain
versions, source commits, and binary checksums).

Optional manual check that both wrappers accept, print, and reject input correctly:

```bash
# Valid empty object -> prints {} and exits 0
./bin_v2/cjson_parse tests/handwritten_test_cases/empty_structure.json
./bin_v2/jsonc_parse tests/handwritten_test_cases/empty_structure.json

# Malformed input -> error on stderr, exit 1
./bin_v2/cjson_parse tests/handwritten_test_cases/unterminated_string.json; echo "cJSON exit=$?"
./bin_v2/jsonc_parse tests/handwritten_test_cases/unterminated_string.json; echo "json-c exit=$?"
```

### Step 4: Run Differential Testing (Baseline)

Run both parsers on the handwritten cases and JSONTestSuite and record every disagreement:

```bash
BIN_DIR=bin_v2 RESULTS_DIR=results/baseline_v2_fixed ./scripts/run_baseline_comparison.sh
```

Output in `RESULTS_DIR` (existing logs there are moved to an `archive_<timestamp>/`
folder first):

* `test_results_handwritten.log` / `.jsonl`
* `test_results_JSONTestSuite.log` / `.jsonl`

### Step 5: Run the Main Fuzzing Campaign

The full matrix is **2 parsers × 3 builds × 5 repeats × 30 minutes = 30 campaigns**. All
campaigns use the same seeds (`fuzz_seeds/`), a 1000 ms timeout, and no memory limit.
They run three at a time, about 5 hours in total. Each group of three is one parser's
normal, ASan, and ASan+UBSan builds running together, so the builds being compared share
the same machine conditions.

```bash
BIN_DIR=/work/bin_v2 OUT_ROOT=/work/fuzz_out_v2 \
  nohup ./scripts/run_fuzzing.sh --all 3 > fuzz_master_v2.log 2>&1 &
```

* `--all 3` runs three campaigns at a time, each pinned to its own CPU core. Each group of
  three is one parser's three builds. The build order rotates between groups, so every build
  runs on every core across the repeats (with `REPEATS` ≥ 3). Running more at once finishes sooner, but contention
  makes the speed comparison less reliable.
* AFL writes each test case to `.cur_input` in a container-local folder
  (`CUR_INPUT_ROOT`, default `/tmp/afl_cur_input`), not on the `/work` bind mount. On
  Docker Desktop that bind-mount I/O otherwise costs milliseconds per execution: a 20 s
  test ran 886 exec/s on the bind mount against 5,339 exec/s locally. Set `CUR_INPUT_ROOT=` to
  get the old behaviour.
* `REPEATS=3` (or any number) changes the repeat count; the default is 5.
* The script only runs binaries whose folder contains `build_manifest.json` and whose SHA-256
  matches it. It refuses to reuse an existing campaign folder, copies the manifest into
  `OUT_ROOT`, and writes a `run_manifest.json` into each campaign folder. That file records the
  core, settings, environment, seed hashes, and target hash.
* If any campaign fails, the script lists it and exits non-zero.
* Keep the host awake for the whole run (on macOS, run `caffeinate -i` in another
  terminal). Sleep pauses Docker and cuts campaigns short.

About a minute after starting, confirm the campaigns use the new binaries:

```bash
cat fuzz_out_v2/*/default/cmdline     # paths should start with /work/bin_v2/
```

**Check progress** at any time (read-only; safe while fuzzing):

```bash
./scripts/fuzz_progress.sh                       # defaults: fuzz_out_v2, fuzz_master_v2.log
watch -n 60 ./scripts/fuzz_progress.sh           # refresh every minute
./scripts/fuzz_progress.sh fuzz_out other.log    # a different campaign
```

It shows how many campaigns are finished, failed, and running, out of the total scheduled.
For each campaign it shows status, run time, executions per second, coverage, crashes, and
hangs. When the run ends it prints `ALL DONE`, or `DONE WITH FAILURES` if any campaign failed.

**Single campaign** (for testing or rerunning one configuration):

```bash
BIN_DIR=/work/bin_v2 OUT_ROOT=/work/fuzz_out_v2 \
  ./scripts/run_fuzzing.sh <cjson|jsonc> <normal|asan|asan_ubsan> <runN> [core_id]

# Example
BIN_DIR=/work/bin_v2 OUT_ROOT=/work/fuzz_out_v2 ./scripts/run_fuzzing.sh cjson asan run1 0
```

Each campaign writes AFL++'s standard output to `OUT_ROOT/<parser>_<build>_<runN>/`,
including `default/fuzzer_stats`, `default/plot_data`, `default/queue/`,
`default/crashes/`, `default/hangs/`, and `afl.log`.

### Step 6: Analyze the Results

After the campaign finishes:

```bash
python3 scripts/analyze_fuzzing.py --input fuzz_out_v2 --bin-dir bin_v2 \
  --expected-repeats 5 --replay --timeout 1 --confirm 3
```

* `--bin-dir` must point to the binaries the campaigns used.
* `--expected-repeats` (default 5) and `--expected-seconds` (default 1800) are what the
  analyzer checks each campaign against; it warns about missing or short runs. It also
  checks every target binary against `OUT_ROOT/build_manifest.json`.
* `--replay` runs every saved input through both parsers and replays each saved crash and
  hang `--confirm` times; it needs the Linux container.

The analyzer writes a new folder each time, `results/fuzz_analysis_<timestamp>/` (or
`--output <dir>`). Start with `report.md`; the other files are:

| File | Contents |
|---|---|
| `runs.csv`, `groups.csv` | Per-campaign statistics and per-build mean/spread (speed, coverage, edges, findings) |
| `timeline.csv` | AFL++ `plot_data` over time for every campaign |
| `findings.csv` | Parser disagreements with paths to the original inputs |
| `triage.json` | Replay results for saved crashes and hangs, including sanitizer output |
| `summary.json`, `replay_summary.json` | Totals, validity warnings, and the exact settings used |
| `corpus.jsonl`, `replay.jsonl`, `examples/` | Every distinct saved input with its origins, both parsers' replay output, and small example inputs per tag |
| `source_at_analysis/` | Snapshot of the scripts and wrappers used for the analysis |

Run the analyzer's unit tests with:

```bash
python3 -m unittest discover -s tests -p 'test_analyze_fuzzing.py'
```

### Step 7: Classify Disagreements by Root Cause

Assigns each disagreement found by the replay a single primary root cause (e.g.
duplicate keys, a lone surrogate, a control byte used as whitespace) and confirms it by
repairing that feature and re-running both binaries:

```bash
python3 scripts/classify_findings.py --analysis results/fuzz_analysis_<timestamp> \
  --fuzz-dir fuzz_out_v2 --bin-dir bin_v2
```

This writes `root_causes.csv` and `classified.json` into the analysis folder.

### Step 8: Measure Sanitizer Overhead on Fixed Inputs

Fuzzing exec/s depends on which inputs each campaign happens to run and on file I/O, so the
overhead is also measured in-process on identical inputs. The benchmark links
`scripts/bench_harness.c` against the exact library objects in `BUILD_DIR` and times only
parse + serialize (10 paired repetitions, shuffled order, pinned core). Run it with nothing
else using the machine (about 10 minutes):

```bash
python3 scripts/benchmark_overhead.py --build-dir build_v2 --bin-dir bin_v2 \
  --fuzz-dir fuzz_out_v2 --reps 10 --output results/overhead_v2
```

`results/overhead_v2/report.md` reports per-input time and slowdown, with 95% confidence
intervals, for plain clang, normal, ASan, and ASan+UBSan builds.

### Step 9: Generate Figures and Tables

Needs `matplotlib`, which the container lacks, so run it on the host:

```bash
python3 scripts/make_charts.py --analysis results/fuzz_analysis_<timestamp> \
  --baseline results/baseline_v2_fixed --overhead results/overhead_v2 \
  --causes results/fuzz_analysis_<timestamp>/root_causes.csv --output results/charts_v2
```

Produces five PNG figures (fuzzing throughput, coverage over time, overhead benchmark,
baseline outcomes, root causes) and `tables.md`. That file has the same numbers as the
figures, plus exact Mann-Whitney tests and per-build discovery statistics.

The findings from the current run are written up in
[DIFFERENTIAL_TESTING_FINDINGS.md](DIFFERENTIAL_TESTING_FINDINGS.md). The results they are based
on (build record, baseline, campaigns, analysis, benchmark, and charts) are committed in
[`experiment_results/`](experiment_results/README.md).

### Regenerating the Seed Corpus (optional)

`fuzz_seeds/` is committed and is the seed set used for `fuzz_out_v2`. The script picks
valid JSONTestSuite `y_` files that both parsers accept, spread evenly across categories,
and adds 8 synthetic seeds. It never overwrites a non-empty folder:

```bash
python3 scripts/curate_seeds.py --bin-dir bin_v2 --output fuzz_seeds_new           # even selection
python3 scripts/curate_seeds.py --bin-dir bin_v2 --output fuzz_seeds_check --legacy # recreates fuzz_seeds/
```

---

## Version & Tooling Reference

* **cJSON Version:** `v1.7.19`
* **json-c Version:** `v0.16` (Tag: `json-c-0.16-20220414`)
* **Compiler:** Clang (version recorded in `build_manifest.json`)
* **Fuzzer:** `AFL++` (via `afl-clang-fast`)
* **Sanitizers:** AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan)
