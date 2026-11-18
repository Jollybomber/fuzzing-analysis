---

```markdown
# cJSON vs. json-c: Security & Differential Analysis

A security-focused comparative analysis framework evaluating **cJSON (v1.7.19)** and **json-c (v5.5.0)**. This project implements an automated pipeline covering environment setup, multi-variant compilation (Normal, AFL++ ASan, AFL++ ASan + UBSan), automated differential testing across compliance suites and handwritten cases, and high-intensity fuzzing campaigns.

---

## Repository Structure

```text
cjson-jsonc-fuzzing-analysis/
├── builds/                 # Compiled binaries (excluded from git)
├── fuzz_seeds/                  # Lean seed corpus for bootstrapping AFL++
├── results/                # Test logs, differential divergences, and fuzzing artifacts
├── scripts/                # Automation scripts (setup, differential testing, fuzzing)
├── src/                    # Library source trees (cjson_src/ and jsonc_src/)
├── tests/                  # JSONTestSuite and custom/handwritten test cases
├── .gitignore              # Optimized ignore rules for build/fuzz artifacts
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

# 2. Clone json-c (v5.5.0 / tag json-c-0.16)
git clone --branch json-c-0.16-20220414 --depth 1 [https://github.com/json-c/json-c.git](https://github.com/json-c/json-c.git) src/jsonc_src

```

### Step 2: Build Binaries (Normal & Instrumented Variants)

Run the setup and build automation script to compile three build variants per library:

1. **Normal Baseline** (Optimized `-O3` with standard `gcc` for semantic and differential testing)
2. **AFL++ ASan** (Instrumented with AddressSanitizer for memory safety fuzzing)
3. **AFL++ ASan + UBSan** (Instrumented with Address & Undefined Behavior sanitizers)

```bash
chmod +x scripts/setup_and_build.sh
./scripts/setup_and_build.sh

```

### Step 3: Run Differential Testing

Execute semantic differential testing against both your **handwritten edge-case tests** and the **`JSONTestSuite`** compliance suite. The runner script automatically iterates through test files and logs divergences into the `results/` folder.

```bash
chmod +x scripts/run_diff.sh
./scripts/run_diff.sh

```

* Logs will be output to:
* `results/test_results_handwritten.log`
* `results/test_results_JSONTestSuite.log`



### Step 4: Execute AFL++ Fuzzing Campaigns

Launch high-intensity 12-hour fuzzing campaigns using your instrumented binaries and seed corpus:

```bash
chmod +x scripts/run_campaign.sh

# Example: Run cJSON with ASan for 12 hours (-V 43200)
./scripts/run_campaign.sh cjson asan

# Example: Run json-c with ASan + UBSan
./scripts/run_campaign.sh jsonc asan_ubsan

```

---

## Version & Tooling Reference

* **cJSON Version:** `v1.7.19`
* **json-c Version:** `v5.5.0` (Tag: `json-c-0.16-20220414`)
* **Fuzzer:** `AFL++` (via `afl-clang-fast`)
* **Sanitizers:** AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan)

```

```