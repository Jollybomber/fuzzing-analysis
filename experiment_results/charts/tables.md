# Report tables

## Fuzzing throughput (Figure 1)

| Parser | Build | Runs | Median exec/s | Min–max | Slowdown vs normal (median) | Mann-Whitney vs normal | vs ASan |
|---|---|---:|---:|---:|---:|---:|---:|
| cJSON | Normal | 5 | 372.9 | 331–448 | 1.00× | — | — |
| cJSON | ASan | 5 | 182.6 | 168–217 | 2.04× | U=0, p=0.0079 | — |
| cJSON | ASan+UBSan | 5 | 184.2 | 168–218 | 2.02× | U=0, p=0.0079 | U=14, p=0.8413 |
| json-c | Normal | 5 | 433.0 | 379–471 | 1.00× | — | — |
| json-c | ASan | 5 | 188.4 | 164–194 | 2.30× | U=0, p=0.0079 | — |
| json-c | ASan+UBSan | 5 | 191.2 | 165–194 | 2.27× | U=0, p=0.0079 | U=15, p=0.6905 |

With 5 vs 5 runs the smallest possible exact two-sided p-value is 0.0079.

## Coverage plateau (Figure 2)

Edges are indexed to each build's own final median because sanitizer instrumentation changes the edge space; raw edge counts are not comparable across builds. AFL's first plot_data sample is at about 60 s, so the curves start at the first 30 s grid point after every run has a sample (1.5 min); a plateau time of 1.5 min means 'already reached at the first point'.

| Parser | Build | Final edges (median) | Time to 95% | Time to 99% |
|---|---|---:|---:|---:|
| cJSON | Normal | 272 | 1.5 min | 3.5 min |
| cJSON | ASan | 267 | 1.5 min | 4.0 min |
| cJSON | ASan+UBSan | 288 | 1.5 min | 9.5 min |
| json-c | Normal | 516 | 2.0 min | 9.0 min |
| json-c | ASan | 516 | 5.0 min | 21.0 min |
| json-c | ASan+UBSan | 552 | 4.5 min | 21.5 min |

## Fixed-input overhead benchmark (Figure 3)

10 paired repetitions per build, shuffled order, pinned core. Slowdowns are medians of per-repetition ratios with bootstrap 95% confidence intervals.

| Corpus | Parser | Build | Median µs/input | Slowdown vs plain clang | Slowdown vs normal (AFL) |
|---|---|---|---:|---:|---:|
| conformance | cJSON | Plain clang | 0.817 | 1.00× [1.00, 1.00] | 0.87× [0.85, 0.90] |
| conformance | cJSON | Normal | 0.938 | 1.15× [1.11, 1.18] | 1.00× [1.00, 1.00] |
| conformance | cJSON | ASan | 5.344 | 6.51× [6.31, 6.70] | 5.66× [5.53, 5.84] |
| conformance | cJSON | ASan+UBSan | 5.447 | 6.69× [6.63, 7.06] | 5.99× [5.73, 6.15] |
| fuzz | cJSON | Plain clang | 4.843 | 1.00× [1.00, 1.00] | 0.62× [0.61, 0.63] |
| fuzz | cJSON | Normal | 7.750 | 1.61× [1.58, 1.64] | 1.00× [1.00, 1.00] |
| fuzz | cJSON | ASan | 17.497 | 3.64× [3.57, 3.69] | 2.25× [2.22, 2.31] |
| fuzz | cJSON | ASan+UBSan | 17.932 | 3.66× [3.57, 3.82] | 2.28× [2.23, 2.38] |
| conformance | json-c | Plain clang | 0.894 | 1.00× [1.00, 1.00] | 0.94× [0.91, 0.97] |
| conformance | json-c | Normal | 0.961 | 1.07× [1.03, 1.10] | 1.00× [1.00, 1.00] |
| conformance | json-c | ASan | 4.033 | 4.52× [4.41, 4.57] | 4.17× [4.14, 4.27] |
| conformance | json-c | ASan+UBSan | 4.181 | 4.67× [4.55, 4.74] | 4.34× [4.26, 4.40] |
| fuzz | json-c | Plain clang | 6.573 | 1.00× [1.00, 1.00] | 0.81× [0.81, 0.83] |
| fuzz | json-c | Normal | 7.999 | 1.23× [1.20, 1.24] | 1.00× [1.00, 1.00] |
| fuzz | json-c | ASan | 22.888 | 3.45× [3.41, 3.55] | 2.83× [2.80, 2.90] |
| fuzz | json-c | ASan+UBSan | 24.130 | 3.67× [3.62, 3.78] | 3.02× [2.95, 3.08] |

### UBSan's extra cost on top of ASan (paired)

Median over repetitions of (ASan+UBSan time / ASan time) in the same repetition, with a bootstrap 95% confidence interval. An interval above 0% means UBSan's extra cost is measurable.

| Corpus | Parser | Extra cost | 95% CI |
|---|---|---:|---:|
| conformance | cJSON | +3.0% | [+1.9%, +8.4%] |
| conformance | json-c | +3.5% | [+2.5%, +4.3%] |
| fuzz | cJSON | +1.3% | [-0.8%, +4.2%] |
| fuzz | json-c | +5.2% | [+4.3%, +7.6%] |

## Baseline outcomes (Figure 4)

'Same value' uses the driver's exact comparison (scripts/diff_driver.py, shared with analyze_fuzzing.py): exact decimal numbers, so `1E2` equals `100`, and identical non-UTF-8 output counts as equal.

| Subset | Both accept, same value | Both reject | Both accept, different value | Only cJSON accepts | Only json-c accepts | Total |
|---|---:|---:|---:|---:|---:|---:|
| Handwritten | 6 | 6 | 8 | 4 | 1 | 25 |
| JSONTestSuite y_ (must accept) | 92 | 0 | 3 | 0 | 0 | 95 |
| JSONTestSuite n_ (must reject) | 11 | 167 | 0 | 6 | 4 | 188 |
| JSONTestSuite i_ (impl.-defined) | 10 | 1 | 10 | 4 | 10 | 35 |

## Fuzzing disagreements by root cause (Figure 5)

Each distinct input is assigned one primary cause by scripts/classify_findings.py (precedence order documented there). Counts are inputs, not independent bugs.

| Direction | Root cause | Inputs |
|---|---|---:|
| Only cJSON accepts | Raw NUL byte inside a string (cJSON truncates) | 293 |
| Only cJSON accepts | Invalid \u escape (cJSON decodes as NUL, truncates) | 212 |
| Only cJSON accepts | Control byte 0x00-0x20 used as whitespace | 136 |
| Only cJSON accepts | Integer with leading zero | 76 |
| Only json-c accepts | Lone/invalid UTF-16 surrogate (json-c -> U+FFFD) | 448 |
| Only json-c accepts | Single-quoted object key | 1 |
| Both accept, different value | Duplicate object keys (cJSON keeps all, json-c last) | 608 |
| Both accept, different value | Integer beyond int64 (json-c: uint64 or clamped; cJSON: double) | 245 |
| Both accept, different value | Integer of 2^53 or more (cJSON prints 15-17 digits) | 115 |
| Both accept, different value | Exponent overflow (both hold inf; cJSON prints null) | 32 |
| Both accept, different value | \u0000 in string value (cJSON truncates) | 14 |
| Both accept, different value | Long decimal (json-c echoes source text; cJSON reprints the double) | 12 |
| Both accept, different value | Exponent underflow (both hold 0; cJSON prints 0) | 1 |

## Discovery of parser disagreements per build

Per campaign: time until the first fuzzer-generated disagreement was saved, number of distinct disagreeing inputs saved, and number of distinct root causes among them (median and range over 5 runs).

| Parser | Build | First disagreement (s) | Disagreeing inputs saved | Root causes found | Causes found by any run |
|---|---|---:|---:|---:|---|
| cJSON | Normal | 0 (0–0) | 87 (74–130) | 8 (7–8) | 10: BIGINT_BEYOND_INT64, BIGINT_PRECISION, CTRL_WS, DECIMAL_PRECISION, DUPLICATE_KEYS, EXP_OVERFLOW, INVALID_U_ESCAPE, LEADING_ZERO, LONE_SURROGATE, RAW_NUL_IN_STRING |
| cJSON | ASan | 0 (0–0) | 81 (72–111) | 9 (7–10) | 11: BIGINT_BEYOND_INT64, BIGINT_PRECISION, CTRL_WS, DECIMAL_PRECISION, DUPLICATE_KEYS, EXP_OVERFLOW, EXP_UNDERFLOW, INVALID_U_ESCAPE, LEADING_ZERO, LONE_SURROGATE, RAW_NUL_IN_STRING |
| cJSON | ASan+UBSan | 0 (0–3) | 69 (58–93) | 9 (8–9) | 10: BIGINT_BEYOND_INT64, BIGINT_PRECISION, CTRL_WS, DECIMAL_PRECISION, DUPLICATE_KEYS, EXP_OVERFLOW, INVALID_U_ESCAPE, LEADING_ZERO, LONE_SURROGATE, RAW_NUL_IN_STRING |
| json-c | Normal | 1 (0–4) | 91 (48–107) | 5 (4–8) | 9: BIGINT_BEYOND_INT64, BIGINT_PRECISION, CTRL_WS, DUPLICATE_KEYS, INVALID_U_ESCAPE, LEADING_ZERO, LONE_SURROGATE, RAW_NUL_IN_STRING, U0000_TRUNCATION |
| json-c | ASan | 2 (2–36) | 44 (38–88) | 6 (4–7) | 10: BIGINT_BEYOND_INT64, BIGINT_PRECISION, CTRL_WS, DECIMAL_PRECISION, DUPLICATE_KEYS, INVALID_U_ESCAPE, LEADING_ZERO, LONE_SURROGATE, RAW_NUL_IN_STRING, U0000_TRUNCATION |
| json-c | ASan+UBSan | 1 (0–3) | 53 (28–70) | 7 (5–8) | 12: BIGINT_BEYOND_INT64, BIGINT_PRECISION, CTRL_WS, DECIMAL_PRECISION, DUPLICATE_KEYS, EXP_OVERFLOW, INVALID_U_ESCAPE, LEADING_ZERO, LONE_SURROGATE, RAW_NUL_IN_STRING, SINGLE_QUOTE_KEY, U0000_TRUNCATION |

