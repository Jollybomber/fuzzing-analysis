# Differential Testing and Fuzzing Findings: cJSON vs. json-c

Results from the corrected builds (`bin_v2/`): the baseline differential run
(`results/baseline_v2_fixed/`), the 30-campaign AFL++ run (`fuzz_out_v2/`), the analysis of that run
(`results/fuzz_analysis_v2_fixed/`), the fixed-input overhead benchmark (`results/overhead_v2/`),
and the figures and tables (`results/charts_v2/`). Results from the earlier, misconfigured
build (`bin/`, `fuzz_out/`) are not used anywhere in this document.

A committed copy of all of these results, with the campaigns and the full replay compressed, is
in [`experiment_results/`](experiment_results/README.md).

Every count was recomputed from the raw logs. Behaviours described as "verified" were
re-run on the `bin_v2` binaries.

---

## 1. Summary

| Question | Result |
|---|---|
| Do the parsers agree on the JSONTestSuite? | No. **37 of 318** inputs disagree: 24 accept/reject splits and 13 different values. Both accept all 95 must-accept files. |
| Memory or undefined-behaviour bugs found? | **None.** 30 campaigns × 30 min, 14,116,352 executions, 0 crashes, 0 ASan or UBSan reports. The 8 saved "hangs" do not reproduce. |
| Disagreements found by fuzzing | **1,166** accept/reject splits and **1,027** value differences among 10,677 distinct saved inputs. Every one is explained by **13 root causes**. |
| Cost of ASan (same inputs, in-process) | **2.3–5.7× slower** than the normal AFL build, depending on the inputs. |
| Cost of adding UBSan on top of ASan | **About 1–5%** extra (paired; measurable except for cJSON on the fuzz corpus) |
| Cost of ASan during fuzzing (execs/sec) | 2.0× (cJSON) and 2.3× (json-c), p = 0.0079. **This understates the true cost**, because file I/O over the Docker bind mount dominated each execution (§5.2). |
| Most security-relevant behaviours | 1. Duplicate keys (cJSON keeps all and looks up the first; json-c keeps the last). 2. Silent string truncation in cJSON (`\u0000`, raw NUL, invalid `\u` escapes). 3. Integer clamping in json-c and precision loss in cJSON. 4. json-c rewrites lone surrogates as U+FFFD. |

---

## 2. Experimental setup

| Item | Setting |
|---|---|
| Targets | cJSON v1.7.19; json-c 0.16 (tag `json-c-0.16-20220414`) |
| Harness | `scripts/cjson_parse.c` calls `cJSON_ParseWithLengthOpts(data, len+1, &end, 1)` and requires `end == data+len`. `scripts/jsonc_parse.c` uses `JSON_TOKENER_STRICT` and requires every byte to be consumed. Both print the parsed value re-serialized without formatting; exit 0 means accept, exit 1 means reject. |
| Compiler | Ubuntu clang 20.1.2, the same for every build; flags `-O1 -g -fno-omit-frame-pointer` (recorded in `bin_v2/build_manifest.json`) |
| Builds | **plain clang:** `*_parse`, no AFL, no sanitizers; used for differential replay. **normal:** `*_afl_normal`, AFL instrumentation only. **asan:** `*_afl_asan`. **asan_ubsan:** `*_afl_asan_ubsan`. The build script checks each object file for the expected `__asan_`, `__ubsan_` and `__afl_` references. |
| Baseline corpus | 318 JSONTestSuite `test_parsing` files (95 `y_`, 188 `n_`, 35 `i_`) and 25 handwritten security cases |
| Fuzzing seeds | 75 valid JSON files in `fuzz_seeds/` (67 from JSONTestSuite, 8 synthetic) |
| Campaigns | 2 parsers × 3 builds × **5** repeats × 1800 s = 30 campaigns; `-t 1000 -m none`; 3 at a time, each pinned to a core; AFL++ 5.04a in Docker on an 8-core Apple-silicon Mac |
| Replay | Every distinct saved input (queue, crashes and hangs; 10,677 after SHA-256 de-duplication) is run through both plain-clang wrappers. Outputs are compared as exact JSON values: exact decimal numbers, object-key order ignored, duplicate keys kept in order, array order and types kept. |

### Deviations from the proposal
- **5 repeats instead of 3.** With 3 vs 3 runs, an exact Mann-Whitney test can never go below p = 0.10. With 5 vs 5 the minimum is p = 0.0079.
- **`-m none`.** ASan reserves a very large virtual address space, so a memory limit would break the ASan builds. The same setting is used for every build.
- **No stack-trace de-duplication.** There were no sanitizer reports to de-duplicate. Inputs were de-duplicated by SHA-256 instead.
- **Minimization.** The proposal's minimization step is not yet done; see §10.

---

## 3. Baseline differential testing (JSONTestSuite and handwritten cases)

`scripts/diff_driver.py` now uses the same exact value comparison as the fuzzing analysis
(§9, fix H2). Number-spelling differences such as `[1E+2]` vs `[100]` and identical non-UTF-8
output are agreements. The two broken handwritten cases have also been repaired (fix L4).
Results are in `results/baseline_v2_fixed/`; the original `results/baseline_v2/` logs used the
old comparison and the broken cases.

### 3.1 Outcomes

| Subset | Both accept, same value | Both reject | Both accept, different value | Only cJSON accepts | Only json-c accepts | Disagreements |
|---|---:|---:|---:|---:|---:|---:|
| Handwritten (25) | 6 | 6 | 8 | 4 | 1 | **13** |
| JSONTestSuite `y_` (95) | 92 | 0 | 3 | 0 | 0 | **3** |
| JSONTestSuite `n_` (188) | 11 † | 167 | 0 | 6 | 4 | **10** |
| JSONTestSuite `i_` (35) | 10 ‡ | 1 | 10 | 4 | 10 | **24** |
| **JSONTestSuite total (318)** | 113 | 168 | 13 | 10 | 14 | **37 (11.6%)** |

† Both parsers wrongly accept these 11 must-reject files. For 7 of them json-c's output is
not even valid JSON: it echoes the malformed number (`[-2.]`, `[-.123]`), while cJSON
normalizes it (`[-2]`). Both still hold the same value.
‡ Both parsers pass invalid UTF-8 bytes through unchanged. The output bytes are identical.

Compared with the original driver run (11 handwritten and 59 JSONTestSuite disagreements):
- **`floating_precision.json`** is a real value difference that the old comparison missed: cJSON prints 17 significant digits, json-c echoes all 29.
- **`deep_nesting_objects.json`** now really nests 98 objects. cJSON accepts it; json-c rejects it ("nesting too deep").
- **`escaped_quotes.json`** is now valid, and both parsers accept it with the same value.
- **JSONTestSuite: the 59 flagged files reduce to 37.** The old comparison also flagged spelling-only number differences, identical invalid-UTF-8 output, and json-c's invalid-JSON echo of malformed numbers.

Figure 4
(`results/charts_v2/fig4_baseline_outcomes.png`) shows these outcomes.

### 3.2 RFC 8259 conformance (JSONTestSuite)

| | cJSON | json-c |
|---|---:|---:|
| `y_` (must accept) wrongly rejected | 0 / 95 | 0 / 95 |
| `n_` (must reject) wrongly accepted | **17 / 188** | **15 / 188** |
| `i_` (implementation-defined) accepted | 24 / 35 | 30 / 35 |

- **Both accept (11):** `-01`, `-2.`, `0.e1`, `2.e+3`, `2.e-3`, `2.e3`, `-012`, `-.123`,
  `1.`, an unescaped newline in a string, and an unescaped tab in a string.
- **Only cJSON accepts (6):** a NUL after the value (`123\0`), a NUL outside a string, formfeed
  whitespace, a leading zero (`012`), an invalid `\u` escape, and an unescaped control
  character.
- **Only json-c accepts (4):** `NaN`, `Infinity`, `-Infinity`, and a single-quoted key. All are
  accepted even with `JSON_TOKENER_STRICT`.

### 3.3 Baseline root causes (all verified)

| Root cause | Inputs | Example | cJSON | json-c |
|---|---|---|---|---|
| Duplicate keys | 6 (4 handwritten, 2 `y_`) | `{"role":"user","role":"admin"}` | keeps both | `{"role":"admin"}` (last wins) |
| `\u0000` in a string value | 2 | `{"data":"test\u0000string"}` | `{"data":"test"}` | keeps it |
| Integers at or beyond the int64 range | 5 | `-9223372036854775809` | `-9.2233720368547758e+18` (a double) | `-9223372036854775808`: clamped to INT64_MIN; large positive values clamp to UINT64_MAX `18446744073709551615` |
| Exponent overflow or underflow | 7 `i_` (5 overflow, 2 underflow) | `[1e+9999]` | `[null]` on overflow, `[0]` on underflow | echoes the token (`1e+9999`) |
| Over-long decimal | 1 | `floating_precision.json` | 17 digits | echoes all 29 digits |
| Lone or invalid UTF-16 surrogates | 11 | `"\uD800"` | rejects | accepts, outputs U+FFFD |
| `NaN`, `Infinity`, single-quoted keys | 4 `n_` | `[NaN]`, `{'a':0}` | rejects | accepts |
| Control byte or NUL treated as whitespace | 5 | `123\0`, formfeed, UTF-16 without BOM | accepts | rejects |
| Leading zero | 2 | `007` | accepts, outputs `7` | rejects |
| Invalid `\u` escape | 2 | `"\u123G"` | accepts, outputs `""` | rejects |
| Raw control character or NUL inside a string | 1 | `"a<NUL>a"` | accepts, outputs `"a"` | rejects |
| UTF-8 BOM | 1 | BOM followed by `{}` | accepts | rejects |
| Nesting depth | 3 | 98 nested arrays or objects, 500 nested arrays | accepts (limit 1000) | rejects (limit 32) |

---

## 4. Fuzzing campaign results

### 4.1 Validity checks (all verified)
- **Binaries and settings:** all 30 campaigns fuzzed `bin_v2/<parser>_afl_<build>` (per `cmdline`). Their SHA-256 hashes match `build_manifest.json`. Every run lasted 1800–1801 s with the same 75 seeds, `-t 1000 -m none`, and successful CPU binding.
- **Map size per build** (number of instrumented edges):

  | Build | cJSON | json-c |
  |---|---:|---:|
  | normal | 1168 | 1587 |
  | asan | 1163 | 1586 |
  | asan_ubsan | 1727 | 3237 |

  UBSan adds its own instrumented branches, which shows the builds differ as intended. It also means edge counts and `bitmap_cvg` cannot be compared across builds.
- **Stability:** cJSON 100% in every run. json-c 98.1–98.4%: a few seeds take slightly varying paths, which is minor.
- **AFL warnings:** every run logged "some test cases look useless" (30–32 seeds add no new coverage) and "lots of input files". json-c runs also logged "instrumentation output varies across runs" / "instability detected during calibration" for 1–4 inputs per run, which matches their 98.1–98.4% stability. cJSON runs logged neither.

### 4.2 Throughput (Figure 1)

| Parser | Build | Median exec/s (5 runs) | Range | Slowdown vs normal | Exact Mann-Whitney vs normal | vs ASan |
|---|---|---:|---:|---:|---|---|
| cJSON | normal | 372.9 | 331–448 | 1.00× | — | — |
| cJSON | ASan | 182.6 | 168–217 | 2.04× | U=0, p=0.0079 | — |
| cJSON | ASan+UBSan | 184.2 | 168–218 | 2.02× | U=0, p=0.0079 | U=14, p=0.84 |
| json-c | normal | 433.0 | 379–471 | 1.00× | — | — |
| json-c | ASan | 188.4 | 164–194 | 2.30× | U=0, p=0.0079 | — |
| json-c | ASan+UBSan | 191.2 | 165–194 | 2.27× | U=0, p=0.0079 | U=15, p=0.69 |

In both parsers, every normal run was faster than every ASan run. ASan and ASan+UBSan cannot
be told apart. U is reported for the build in the row against the comparison build, so U=0 means
every run of the row's build was slower; the smaller U for the ASan vs ASan+UBSan tests is 11
(cJSON) and 10 (json-c). §5 explains why the absolute speeds are low and the ratio is compressed.

### 4.3 Coverage (Figure 2)

| Parser | Build | Final edges (median) | 95% of final reached | 99% reached |
|---|---|---:|---:|---:|
| cJSON | normal | 272 | ≤1.5 min | 3.5 min |
| cJSON | ASan | 267 | ≤1.5 min | 4.0 min |
| cJSON | ASan+UBSan | 288 | ≤1.5 min | 9.5 min |
| json-c | normal | 516 | 2.0 min | 9.0 min |
| json-c | ASan | 516 | 5.0 min | 21.0 min |
| json-c | ASan+UBSan | 552 | 4.5 min | 21.5 min |

Only cJSON normal fully plateaus: all five runs end at 272 edges, the last new edge by about
13 min. The sanitizer builds, which run at about half the speed, keep adding a few edges late:
- **cJSON ASan:** final edges 266–267; the last new edge came at 607–1720 s.
- **cJSON ASan+UBSan:** all runs end at 288; the last new edge came at 619–1696 s.
- **json-c ASan:** still gaining edges after 25 min in 4 of 5 runs (e.g. run 2 went from 508 to 516).
- **json-c ASan+UBSan:** still gaining after 25 min in 1 of 5 runs.
- **json-c normal:** stopped gaining by about 23 min.

Longer runs would likely add only a handful of edges (1–8 were found after 25 min), so they
are unlikely to change the conclusions.

### 4.4 Crashes, sanitizer reports and hangs
- **Crashes and sanitizer reports:** 0 crashes and 0 ASan or UBSan reports across 14.1 M executions.
- **Hangs:** AFL saved 8, all in cJSON campaigns (2 normal, 3 ASan, 3 ASan+UBSan). Each was replayed 3 times by the analyzer and 5 more times by hand, with `afl-showmap -t 1000` as well. All finish in 2–15 ms with an ordinary parse error.
- **Why the hangs are false positives:** three pairs were saved by different, simultaneously running campaigns within the same wall-clock second (07:16:56, 07:19:00, 08:17:12 UTC). That points to stalls in the Docker VM or the shared folder, not slow inputs.
- **Interpretation:** this is a null result for memory and undefined-behaviour bugs within this budget. It is not proof of absence, but it is consistent with two mature libraries that have been fuzzed extensively before (both are in Google's OSS-Fuzz continuous fuzzing service).

### 4.5 Discovery of disagreements per build

| Parser | Build | First disagreement (s) | Disagreeing inputs saved, median (range) | Root causes found per run | Causes found by any run |
|---|---|---:|---:|---:|---:|
| cJSON | normal | 0 | 87 (74–130) | 8 (7–8) | 10 |
| cJSON | ASan | 0 | 81 (72–111) | 9 (7–10) | 11 |
| cJSON | ASan+UBSan | 0 (0–3) | 69 (58–93) | 9 (8–9) | 10 |
| json-c | normal | 1 (0–4) | 91 (48–107) | 5 (4–8) | 9 |
| json-c | ASan | 2 (2–36) | 44 (38–88) | 6 (4–7) | 10 |
| json-c | ASan+UBSan | 1 (0–3) | 53 (28–70) | 7 (5–8) | 12 |

- **Time to first disagreement** is near zero everywhere. The seeds already contain duplicate keys and large numbers, so the earliest mutations produce disagreements.
- **Fewer inputs, not fewer causes:** the slower json-c sanitizer builds saved fewer disagreeing inputs, but found at least as many distinct root causes. Within 30 minutes, sanitizer overhead did not reduce the variety of semantic findings.

---

## 5. Sanitizer runtime overhead

### 5.1 Fixed-input benchmark (Figure 3; `results/overhead_v2/`)

`scripts/benchmark_overhead.py` links one harness (`scripts/bench_harness.c`) against the
exact library objects that were fuzzed. It loads the inputs into memory and times only
parsing and re-serialization, exactly as the wrappers do them. Each build is timed in 10
paired repetitions, in shuffled order, on one pinned core. Results are the median of the
per-repetition ratios, with bootstrap 95% confidence intervals.

| Corpus | Parser | AFL instrumentation vs plain clang | ASan vs normal | ASan+UBSan vs normal | UBSan's extra cost vs ASan (paired) |
|---|---|---:|---:|---:|---:|
| Conformance (418 small inputs: 318 JSONTestSuite + 25 handwritten + 75 seeds) | cJSON | 1.15× [1.11, 1.18] | **5.66×** [5.53, 5.84] | 5.99× [5.73, 6.15] | +3.0% [+1.9, +8.4] |
| Conformance | json-c | 1.07× [1.03, 1.10] | **4.17×** [4.14, 4.27] | 4.34× [4.26, 4.40] | +3.5% [+2.5, +4.3] |
| Fuzz corpus (10,677 inputs, 8.6 MB) | cJSON | 1.61× [1.58, 1.64] | **2.25×** [2.22, 2.31] | 2.28× [2.23, 2.38] | +1.3% [−0.8, +4.2] |
| Fuzz corpus | json-c | 1.23× [1.20, 1.24] | **2.83×** [2.80, 2.90] | 3.02× [2.95, 3.08] | +5.2% [+4.3, +7.6] |

Median parse-and-print time per input:
- **Conformance corpus:** 0.82–0.96 µs for the plain and normal builds, 4.0–5.4 µs with ASan.
- **Fuzz corpus:** 4.8–8.0 µs for the plain and normal builds, 17.5–24.1 µs with ASan.

**Interpretation:**
- **ASan is the main cost.** It slows parsing about 2.3–5.7×. The slowdown is largest on the many tiny conformance inputs, where allocator and shadow-memory costs per input dominate.
- **UBSan adds little** on top of ASan: about 1–5%, measured as the paired ratio within each repetition. The extra cost is statistically measurable (its interval excludes zero) everywhere except cJSON on the fuzz corpus.
- **AFL's instrumentation alone** costs 7–61%.

### 5.2 Why the fuzzing-speed ratio (about 2×) understates the overhead
- **Most of each execution time was not parsing.** AFL wrote each input to `.cur_input` inside the output folder, and the harness read it back. Both sit on the macOS-to-Docker bind mount (`/work`). That costs about 2.5 ms per execution for the normal build (2.68 ms on `/work` vs 0.19 ms on the container's own `/tmp`) and about 3.7 ms for ASan.
- **Re-measuring off the bind mount shows the real ratio.** In short 25-second test runs with the output on `/tmp`, normal ran 5,297 exec/s against 559 for ASan (cJSON, 9.5×), and json-c ran 4,273 against 535 (8.0×).
- **So:**
  - The p = 0.0079 result shows ASan is slower during fuzzing.
  - The 2× magnitude reflects this particular setup, not ASan itself.
  - Report §5.1 as the overhead measurement. The fuzzing ratio describes campaign throughput in this environment.
- **Caveat on the `/tmp` figures:** even off the bind mount, an ASan execution under AFL took about 1.8 ms (559 exec/s), roughly 100× the in-process parse time (about 17 µs). So the 8–9.5× fuzzing slowdown mostly reflects ASan's per-execution process cost (forking an ASan process with its large shadow memory, and exit), not slower parsing. The two measurements answer different questions: §5.1 is the cost of parsing with ASan, and the `/tmp` ratio is the cost of fuzzing with ASan in fork-server mode.

---

## 6. Disagreements found by fuzzing

### 6.1 Overview
The analyzer replayed all 10,677 distinct saved inputs through both plain-clang wrappers.

| Outcome | Inputs |
|---|---:|
| Both reject | 6,508 |
| Both accept, byte-identical output | 1,932 (including 695 identical invalid-UTF-8 outputs) |
| Both accept, same value, different spelling (e.g. `1.` vs `1`) | 44 |
| **Only cJSON accepts** | **717** |
| **Only json-c accepts** | **449** |
| **Both accept, different value** | **1,027** (including 6 where json-c's output is not strict JSON, e.g. `3.`) |

All 2,903 flagged inputs are deterministic: identical results in all 3 runs (the replay plus 2 confirmations), and again when re-run on `bin_v2` during re-validation.

### 6.2 Root causes (Figure 5)

`scripts/classify_findings.py` assigns every flagged input one primary cause, and the
real binaries confirm it:
- **Accept/reject splits:** the classifier fixes only the suspected feature and re-runs both parsers. All 1,166 resolve to agreement after repair, and in all 1,166 fixing only the primary feature removes or moves the rejection. Ties go to the earliest feature in the input.
- **Value differences:** the classifier models both parsers' output, and the models reproduce the actual output of all 1,027 inputs exactly.
- **Independent checks:**
  - **Accept/reject splits:** rebuilt wrappers that report the rejecting parser's error offset put the error at the classifier's primary feature in 1,166 of 1,166 cases.
  - **Delta-debugging sample:** an input-shrinking (ddmin) check on 140 inputs (70 accept/reject, 70 value) agreed on the primary cause for 133 (95%), and on the set of causes for all 140. The 7 differences are value inputs that also contain an int64-limit number; shrinking kept the simpler precision cause.
  - **Reproducers:** all reproducers below were re-run on `bin_v2`.

| Direction | Root cause | Inputs | Minimal reproducer | cJSON | json-c |
|---|---|---:|---|---|---|
| Only cJSON accepts | Raw NUL byte inside a string | 293 | `["ab<NUL>cd"]` | `["ab"]` | rejects |
| | Invalid `\u` escape (decoded as NUL, then truncated) | 212 | `{"role":"ad\u00ZZmin"}` | `{"role":"ad"}` | rejects |
| | Control byte 0x00–0x20 treated as whitespace | 136 | `[1,<0x0f>2]`, `[1]<NUL>` | `[1,2]`, `[1]` | rejects |
| | Integer with a leading zero | 76 | `[0,07]` | `[0,7]` | rejects |
| Only json-c accepts | Lone or invalid UTF-16 surrogate | 448 | `["\uDC00"]` | rejects | `["�"]` (U+FFFD) |
| | Single-quoted key containing `"` | 1 | `{'a":1,"b':2}` | rejects | `{"a\":1,\"b":2}`: one key |
| Different value | Duplicate keys | 608 | `{"a":1,"a":2}` | `{"a":1,"a":2}` | `{"a":2}` |
| | Integer beyond int64 (226 of 245 actually clamped by json-c) | 245 | `[18446744073709551616]` | `[1.8446744073709552e+19]` | `[18446744073709551615]`: json-c keeps values up to UINT64_MAX exactly, clamps above it and below INT64_MIN |
| | Integer of 2^53 or more | 115 | `[9007199254740993]` | `[9.00719925474099e+15]` | `[9007199254740993]` |
| | Exponent overflow (printing only: both hold `inf` in memory) | 32 | `[1e999]` | `[null]` | `[1e999]` |
| | `\u0000` in a string value | 14 | `["a\u0000b"]` | `["a"]` | `["a\u0000b"]` |
| | Long decimal: json-c echoes the source text, cJSON reprints the double | 12 | `[0.1234567890123456789]` | `[0.12345678901234568]` | echoes input |
| | Exponent underflow (printing only: both hold 0) | 1 | `[1e-999]` | `[0]` | `[1e-999]` |

Many inputs involve more than one cause: 158 accept/reject inputs, mostly invalid escapes
combined with NULs, and 334 value inputs, such as duplicate keys combined with big numbers.

### 6.3 What fuzzing added beyond the baseline
1. **cJSON's number printing can lose precision.** cJSON tries 15 significant digits first and keeps that form if it is within a relative error of DBL_EPSILON. So `753633720368547807` prints as `7.53633720368548e+17` and `-9223.7203684775808` as `-9223.72036847758`. These printed values do not even round-trip to the same double.
   - In the corpus this is less common than the cause counts suggest. In the 12 "long decimal" inputs, cJSON's output is the same double that json-c echoes as long source text; the difference is only in representation.
   - A genuine 15-digit loss (e.g. `-922337.036854775808` printed as `-922337.036854776`) occurs in 5 inputs, all filed under other primary causes.
2. **Invalid escapes and raw NUL bytes truncate cJSON strings at scale.** 505 inputs: an attacker-chosen suffix after `\u00ZZ` or a raw NUL silently disappears.
3. **json-c's leading-zero rule is narrow.** json-c rejects `07` but accepts `00`, `-07`, `01.5` and `068e1`. Both parsers accept number forms JSON forbids (`1.`, `-.5`, `1.e5`), and json-c then outputs them unchanged, which is invalid JSON (12 inputs).
4. **json-c single-quoted keys swallow double quotes.** `{'a":1,"b':2}` is one key to json-c, while a quote-aware reader sees two keys. This is a structural difference, not just leniency.
5. **Nothing differs inside strings for 0x01–0x1F.** Both parsers accept raw control bytes 0x01–0x1F inside strings. Only NUL differs.

These baseline behaviours never produced a disagreement in the fuzzing corpus: BOM, nesting depth, NaN/Infinity and UTF-16. Some such inputs do occur (82 nest deeper than 32 levels, 1 contains `NaN`/`Infinity`, 11 look like UTF-16), but in each one both parsers reject it for another reason.

### 6.4 Output-validity observations (not disagreements)
- **Invalid UTF-8 output (982 inputs):** in every case the input itself contained invalid UTF-8, and both parsers copied it to the output unchanged. Neither validates UTF-8. In 695 of these the outputs are byte-identical.
- **Invalid JSON output (12 inputs):** in every case it is json-c echoing a non-standard number such as `3.` or `-.14159e-10`.

---

## 7. Security implications

Threat model: a gateway or validator parses a request with one library, then forwards
the raw bytes to a backend that parses them with the other. Any difference in acceptance or
value means the two components act on different data. Severity reflects how directly a
difference can change a security decision; it does not rate the libraries in isolation.

| # | Behaviour | Policy that can be bypassed | Severity | Rationale |
|---|---|---|---|---|
| 1 | Duplicate keys: cJSON's lookup returns the first value, json-c keeps the last | "Requests must not set `role` to `admin`" checked with cJSON; json-c backend authorizes | **High** | Attacker-controlled and deterministic. It needs only valid JSON (RFC 8259 merely says keys "should" be unique), so strict-parsing settings don't stop it. 6 baseline and 608 fuzzing inputs. |
| 2 | cJSON string truncation via `\u0000`, a raw NUL, or an invalid `\u` escape | Allow-list or path checks on a string: cJSON sees `"report.txt"` while json-c sees `"report.txt\u0000../../etc/passwd"`, or `"ad\u00ZZmin"` becomes `"ad"` | **High** | Silent and attacker-controlled; the validator checks a different string. The raw-NUL and invalid-escape forms are rejected by json-c, so they matter most when cJSON is the backend. With `\u0000`, json-c's C-string accessor (`json_object_get_string`) also stops at the NUL; only length-aware consumers (`json_object_get_string_len`) see the full string. |
| 3 | Number representation: json-c keeps integers exactly up to UINT64_MAX and clamps beyond that or below INT64_MIN; cJSON stores every number as a double, so it loses precision from 2^53 and sometimes prints only 15 digits | ID or amount checks: different IDs map to the same clamped value, or limits are compared against rounded values | **Medium** | Needs numbers outside normal ranges, but no error is raised on either side. |
| 4 | json-c turns lone surrogates into U+FFFD, which cJSON rejects | Equality or blocklist checks after normalization; distinct inputs become equal strings | **Medium** | Can make two distinct inputs equal, or make one tier reject what the other accepts. |
| 5 | json-c accepts `NaN`/`Infinity` (baseline only) | `amount > limit`: every comparison with NaN is false | **Medium** | Only when json-c is the checking side and the backend tolerates it. |
| 6 | cJSON leniency: control bytes as whitespace, leading zeros, BOM, depth up to 1000 vs 32 | Content filtering or WAF evasion; inconsistent error handling between tiers | **Low** | Changes which tier rejects input; rarely changes a value. |

**Mitigation:**
- **Normalize at the boundary.** Re-serialize the validated object and forward that, rather than the original bytes.
- **Reject risky input.** Reject duplicate keys, NUL characters, invalid escapes and lone surrogates.
- **Use cJSON's length-aware API** with an explicit "rest of the input must be whitespace" check.
- **Treat large numbers as strings.**

---

## 8. Threats to validity
1. **I/O-bound fuzzing.** See §5.2. Absolute exec/s are about 10× below what the container can do. Throughput ratios between builds are compressed.
2. **Core and build confounded.** In this run's scheduler, normal always ran on core 0, ASan on 1, ASan+UBSan on 2. Run 4 was the slowest in every group, which suggests shared host stalls. The 5 repeats are therefore not fully independent. The scheduler now rotates cores (§9, M1).
3. **Coverage and edges are not comparable across builds.** Sanitizer instrumentation changes the edge space.
4. **Finding counts are not bug counts.** The 2,193 disagreeing inputs come from AFL's retained corpus and collapse into 13 root causes. They are not a rate over random inputs.
5. **The harness API matters.** Results depend on how the wrappers call each library, e.g. cJSON's length plus `require_null_terminated`. Other APIs, such as `cJSON_Parse` using `strlen`, behave differently with NUL bytes.
6. **Small budget.** 30 minutes per campaign; json-c coverage had not fully plateaued.

---

## 9. Pipeline bugs found during review, and fixes

| ID | File | Issue | Effect on these results | Status |
|---|---|---|---|---|
| H1 | `scripts/analyze_fuzzing.py` | The value comparison was skipped when an output contained invalid UTF-8 | Value differences undercounted (744 instead of 1,021) | **Fixed.** Outputs are compared with the raw bytes preserved. |
| H1b | `scripts/analyze_fuzzing.py` | The value comparison was also skipped when json-c printed a non-RFC number such as `1.` | 6 value differences missed | **Fixed.** Such numbers are rewritten to an equal RFC form before comparing; the output is still tagged `INVALID_JSON_OUTPUT`. |
| H2 | `scripts/diff_driver.py` | Compared Python int/float types, so `1E2` ≠ `100` and long decimals were rounded; also key-order sensitive | Baseline disagreements inflated (59 instead of 37), and one real difference missed | **Fixed.** Now uses the analyzer's exact comparison; output-validity tags no longer mark a row as a disagreement. |
| M1 | `scripts/run_fuzzing.sh` | Each build always ran on the same core | Overhead confounded with core (affects `fuzz_out_v2`) | **Fixed for future runs.** Build order rotates per round, so with `REPEATS` ≥ 3 every build uses every core. The split is exactly even only when `REPEATS` is a multiple of 3: with 5, each build runs twice on two cores and once on the third. |
| M2 | `scripts/run_fuzzing.sh` | A failed campaign aborted or was ignored, and "All N completed" was still printed | None (30/30 finished) | **Fixed.** Failures are listed, the script exits non-zero, and `fuzz_progress.sh` shows failed campaigns separately. |
| M3 | `scripts/analyze_fuzzing.py`, `run_fuzzing.sh` | False "No pre-run manifest" warning; binary hashes never checked against the build | Spurious warning on every run | **Fixed.** The analyzer checks binaries against `OUT_ROOT/build_manifest.json`; `run_fuzzing.sh` refuses mismatched binaries (leaving no empty folder behind) and writes a per-campaign `run_manifest.json`. |
| M4 | `scripts/run_fuzzing.sh` | `.cur_input` was on the macOS bind mount | Exec/s about 6–10× too low; overhead ratio compressed (§5.2) | **Fixed for future runs.** `AFL_TMPDIR` is container-local; a 20 s cJSON normal test ran 5,339 exec/s against 886 with the old setting. An independent 12 s re-measurement gave 3,860 vs 695, the same order of magnitude. |
| L1 | `scripts/jsonc_parse.c` | Prints "Parse error: success" on trailing bytes | Message only; classification uses exit codes | **Not changed**, to keep the wrappers byte-identical to the fuzzed `bin_v2` build |
| L2 | `scripts/analyze_fuzzing.py` | `--expected-repeats` defaulted to 3 | False warnings | **Fixed** (default 5) |
| L3 | `scripts/curate_seeds.py` | Stride logic only ever picked a category's first or second file; hard-coded `bin/`; skipped the parser check if binaries were missing; deleted `fuzz_seeds/` | Seeds less diverse than intended | **Fixed.** `--legacy` recreates the committed seeds byte-for-byte (verified); the default spreads picks evenly; it never overwrites. |
| L4 | `tests/handwritten_test_cases/` | `deep_nesting_objects.json` unbalanced; `escaped_quotes.json` malformed | These two cases tested nothing | **Fixed** (98-level nesting; a valid escaped-quote string) |

The fuzzing campaigns in `fuzz_out_v2/` were not rerun. None of the fixes invalidates what they
found: the analysis fixes change only how their output is counted (the corrected counts are in
`results/fuzz_analysis_v2_fixed/`). M1 and M4 change future campaigns. With M4's roughly 6×
higher throughput, a rerun would execute many more inputs and may retain more or different
ones. In this run, the core confound and the I/O-bound speeds remain the limitations described
in §5.2 and §8.

Defects found during re-validation and fixed. None changes any reported number; the corrected
outputs were regenerated and every count stayed the same.

| File | Defect | Fix |
|---|---|---|
| `analyze_fuzzing.py`, `diff_driver.py` | Two different outputs that cannot be parsed even leniently were treated as agreement | New `UNCOMPARABLE_OUTPUT` tag counts them as a disagreement. No such output exists in the current data. |
| `analyze_fuzzing.py` | No warning for campaigns without a per-campaign `run_manifest.json`, i.e. those predating the I/O fix | Now warns; `fuzz_out_v2` gets this warning, as it should |
| `diff_driver.py` | A harness exception exited 1, which reads as "discrepancy" | Exits 2 |
| `classify_findings.py` | Deep nesting (up to cJSON's 1000 levels) could hit Python's recursion limit; a parser timeout crashed the run; `--output-dir` was not created | Higher recursion and stack limits; timeouts handled; folder created |
| `classify_findings.py` | Exactly 2^53 counted as a decimal, not an integer cause; three cause labels overstated the difference | `>=` boundary; labels corrected (see §6.2) |
| `run_fuzzing.sh` | Files created before validating arguments; a refused campaign left an empty folder; `OUT_ROOT/build_manifest.json` could be overwritten by a different build | Validates first; removes the empty folder; refuses a mismatched manifest |
| `fuzz_progress.sh` | Failed campaigns shown as running | Shown as failed, with `DONE WITH FAILURES` |
| `make_charts.py` | UBSan's extra cost was a ratio of medians; usage example used old paths | Paired per-repetition ratio with a bootstrap CI (§5.1); paths updated |

Checked and found correct:
- json-c end-of-input handling for top-level scalars
- the cJSON wrapper's full-consumption check
- identical flags across builds
- per-build sanitizer instrumentation
- triage using the right binary for each build
- the exact number comparison
- `fuzz_progress.sh`

---

## 10. Alignment with the brief and the proposal

| Proposal item | Status |
|---|---|
| Two C parsers, same Clang, separate processes; record acceptance, exit, crash, output and diagnostics | Done |
| JSONTestSuite and 20–30 handwritten cases | Done (318 + 25) |
| 50–100 valid seeds | Done (75) |
| Normal, ASan, ASan+UBSan builds; repeated 30-min runs, same timeout and memory limit | Done (5 repeats; deviation explained in §2) |
| Replay and classification into disagreement, crash, ASan, UBSan, malformed | Done (§4.4, §6); "both reject" is ordinary malformed input |
| Coverage, exec/s, unique inputs, time to first finding | Done (§4.2–4.5) |
| Unique ASan/UBSan reports, error category, stack-trace de-duplication | Null result: none found, so nothing to de-duplicate |
| Runtime overhead | Done (§5) |
| Security review with severity rationale | Done (§7) |
| **Minimized discrepancy test cases** | **Not yet.** One minimal hand-written reproducer per cause is in §6.2. Save them as files, or run `afl-tmin` on one example per cause. |
| Visualization and table scripts | Done (`scripts/make_charts.py`, `results/charts_v2/`) |
| Report PDF (threat model, setup, analysis, limitations, implications), slides, 20–30 min video | Not started. This document covers the technical content. |

The brief lists the final upload as due **Fri 13 Nov**, as `asg2-final-<names>.zip`, with team
information and the video link inside the report.

---

## 11. Reproducing these results

Run these inside the AFL++ container from `/work`, except the last command (see the comment).
Each command refuses to overwrite existing output, so on this checkout use new output names; on
a fresh checkout they run as written. Wait for `fuzz_master_v2.log` to show "All 30 fuzzing runs
completed" (about 5 hours) before running the analyzer.

```bash
BUILD_DIR=build_v2 BIN_DIR=bin_v2 ./scripts/setup_and_build.sh
BIN_DIR=/work/bin_v2 RESULTS_DIR=/work/results/baseline_v2_fixed ./scripts/run_baseline_comparison.sh
BIN_DIR=/work/bin_v2 OUT_ROOT=/work/fuzz_out_v2 nohup ./scripts/run_fuzzing.sh --all 3 > fuzz_master_v2.log 2>&1 &
python3 scripts/analyze_fuzzing.py --input fuzz_out_v2 --bin-dir bin_v2 --expected-repeats 5 \
    --replay --timeout 1 --confirm 3 --workers 4 --output results/fuzz_analysis_v2_fixed
python3 scripts/classify_findings.py --analysis results/fuzz_analysis_v2_fixed --fuzz-dir fuzz_out_v2 --bin-dir bin_v2
python3 scripts/benchmark_overhead.py --build-dir build_v2 --bin-dir bin_v2 --fuzz-dir fuzz_out_v2 \
    --reps 10 --output results/overhead_v2          # on an otherwise idle machine
# needs matplotlib, which the container lacks: run this one on the host
python3 scripts/make_charts.py --analysis results/fuzz_analysis_v2_fixed --baseline results/baseline_v2_fixed \
    --overhead results/overhead_v2 --causes results/fuzz_analysis_v2_fixed/root_causes.csv \
    --output results/charts_v2
```
