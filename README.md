# cJSON vs. json-c: Security & Differential Analysis

A security-focused comparative analysis framework evaluating **cJSON (v1.7.19)** and **json-c (v0.16)**. This project implements an automated pipeline covering environment setup, symmetric parser wrappers, multi-variant compilation (Normal, AFL++ ASan, AFL++ ASan + UBSan), differential testing across compliance suites and handwritten cases, and AFL++ fuzzing campaigns.

---

## Repository Structure

```text
fuzzing-analysis/
├── builds/                 # Compiled binaries (excluded from git)
├── fuzz_seeds/             # Seed corpus for bootstrapping AFL++
├── results/                # Test logs, differential divergences, and fuzzing artifacts
├── scripts/                # Wrapper harnesses (cjson_parse.c, jsonc_parse.c) and automation scripts
├── src/                    # Library source trees (cjson_src/ and jsonc_src/)
├── tests/                  # JSONTestSuite submodule and handwritten edge-case inputs
├── .gitignore              # Ignore rules for build/fuzz artifacts
├── .gitmodules             # Submodule mapping for JSONTestSuite
└── README.md
```

---

## Getting Started & Workflow

### Step 1: Populate Source Code

Before building, ensure the target library source trees are cloned into your `src/` directory at the pinned versions:

```bash
mkdir -p src

# 1. Clone cJSON (v1.7.19)
git clone --branch v1.7.19 --depth 1 [https://github.com/DaveGamble/cJSON.git](https://github.com/DaveGamble/cJSON.git) src/cjson_src

# 2. Clone json-c (v0.16 / tag json-c-0.16-20220414)
git clone --branch json-c-0.16-20220414 --depth 1 [https://github.com/json-c/json-c.git](https://github.com/json-c/json-c.git) src/jsonc_src

# 3. Initialize JSONTestSuite
git submodule update --init tests/JSONTestSuite

```

### Environment Note (AFL++ Docker Container)

Because `afl-clang-fast` and `afl-fuzz` require a Linux environment, run the build, differential testing, and fuzzing commands inside the official AFL++ container with the repository mounted at `/work`:

```bash
docker run --rm -it \
  --mount "type=bind,source=$PWD,target=/work" \
  --workdir /work \
  aflplusplus/aflplusplus:latest /bin/bash

### Step 2: Build Binaries (Normal & Instrumented Variants)

Run the setup and build automation script to compile three build variants per library:

1. **Normal Baseline** (Optimized `-O3` with standard `gcc` for semantic and differential testing)
2. **AFL++ ASan** (Instrumented with AddressSanitizer for memory safety fuzzing)
3. **AFL++ ASan + UBSan** (Instrumented with Address & Undefined Behavior sanitizers)

```bash
./scripts/setup_and_build.sh

```

Run quick sanity checks on the normal binaries to verify clean JSON output, EOF finalization, and strict error rejection before running the full test suite:

```bash
# 1. Valid empty object -> both should output `{}` and exit 0
./builds/cjson_normal/cjson_parse tests/handwritten_test_cases/empty_structure.json
./builds/jsonc_normal/jsonc_parse tests/handwritten_test_cases/empty_structure.json

# 2. Valid standalone primitive -> both should output `true` and exit 0
./builds/cjson_normal/cjson_parse tests/handwritten_test_cases/naked_literal.json
./builds/jsonc_normal/jsonc_parse tests/handwritten_test_cases/naked_literal.json

# 3. Malformed input (unterminated string) -> both should print an error to stderr and exit 1
./builds/cjson_normal/cjson_parse tests/handwritten_test_cases/unterminated_string.json; echo "cJSON exit=$?"
./builds/jsonc_normal/jsonc_parse tests/handwritten_test_cases/unterminated_string.json; echo "json-c exit=$?"

```


### Step 3: Run Differential Testing

Execute semantic differential testing against both your **handwritten edge-case tests** and the **`JSONTestSuite`** compliance suite. The runner script automatically iterates through test files and logs divergences into the `results/` folder.

```bash
./scripts/run_baseline_comparison.sh

```

* Logs will be output to:
* `results/test_results_handwritten.log`
* `results/test_results_JSONTestSuite.log`



### Step 4: Execute AFL++ Fuzzing Campaigns

Launch 2-hour fuzzing campaigns using your instrumented binaries and seed corpus:

```bash
# Example: Run cJSON with ASan for 2 hours (-V 7200)
./scripts/run_fuzzing.sh cjson asan

# Example: Run json-c with ASan + UBSan
./scripts/run_fuzzing.sh jsonc asan_ubsan

```

---

## Version & Tooling Reference

* **cJSON Version:** `v1.7.19`
* **json-c Version:** `v0.16` (Tag: `json-c-0.16-20220414`)
* **Fuzzer:** `AFL++` (via `afl-clang-fast`)
* **Sanitizers:** AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan)
