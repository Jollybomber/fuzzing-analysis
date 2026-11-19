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
`fuzz_master*.log`.

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
BIN_DIR=bin_v2 RESULTS_DIR=results/baseline_v2 ./scripts/run_baseline_comparison.sh
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

* `--all 3` runs three campaigns at a time, each pinned to its own CPU core. Running more
  at once finishes sooner, but contention makes the speed comparison less reliable.
* `REPEATS=3` (or any number) changes the repeat count; the default is 5.
* The script only runs binaries whose folder contains `build_manifest.json`, refuses to
  reuse an existing campaign folder, and copies the manifest into `OUT_ROOT`.
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

It shows how many campaigns are finished, running, and queued, and for each campaign its
run time, executions per second, coverage, crashes, and hangs. `ALL DONE` appears when
every campaign has finished.

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
* `--expected-repeats` and `--expected-seconds` (default 1800) are what the analyzer checks
  each campaign against; it warns about missing or short runs.
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
| `summary.json`, `replay_summary.json`, `run_manifest.json` | Totals and the exact settings used |

Run the analyzer's unit tests with:

```bash
python3 -m unittest discover -s tests -p 'test_analyze_fuzzing.py'
```

### Regenerating the Seed Corpus (optional)

`fuzz_seeds/` is committed. To rebuild it from JSONTestSuite (needs `bin/cjson_parse` and
`bin/jsonc_parse`):

```bash
python3 scripts/curate_seeds.py
```

---

## Version & Tooling Reference

* **cJSON Version:** `v1.7.19`
* **json-c Version:** `v0.16` (Tag: `json-c-0.16-20220414`)
* **Compiler:** Clang (version recorded in `build_manifest.json`)
* **Fuzzer:** `AFL++` (via `afl-clang-fast`)
* **Sanitizers:** AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan)
