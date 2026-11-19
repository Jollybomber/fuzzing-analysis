# Sanitizer overhead benchmark

Generated 2026-11-19T11:01:23.611721+00:00. Same inputs for every build; parse + serialize only, in-process; 10 paired repetitions per build, shuffled order, pinned to core 0.

Slowdown = median over repetitions of (variant time / reference time) in the same repetition; brackets are bootstrap 95% confidence intervals.

## Corpus: conformance (418 inputs)

| Parser | Build | Median µs/input | IQR (µs) | CV % | Slowdown vs normal | Slowdown vs plain clang |
|---|---|---:|---:|---:|---:|---:|
| cjson | baseline | 0.817 | 0.805–0.821 | 21.5 | 0.87× [0.85, 0.90] | 1.00× [1.00, 1.00] |
| cjson | normal | 0.938 | 0.925–0.964 | 2.7 | 1.00× [1.00, 1.00] | 1.15× [1.11, 1.18] |
| cjson | asan | 5.344 | 5.315–5.383 | 6.1 | 5.66× [5.53, 5.84] | 6.51× [6.31, 6.70] |
| cjson | asan_ubsan | 5.447 | 5.441–5.792 | 5.1 | 5.99× [5.73, 6.15] | 6.69× [6.63, 7.06] |
| jsonc | baseline | 0.894 | 0.884–0.907 | 3.9 | 0.94× [0.91, 0.97] | 1.00× [1.00, 1.00] |
| jsonc | normal | 0.961 | 0.950–0.972 | 2.6 | 1.00× [1.00, 1.00] | 1.07× [1.03, 1.10] |
| jsonc | asan | 4.033 | 4.007–4.063 | 1.1 | 4.17× [4.14, 4.27] | 4.52× [4.41, 4.57] |
| jsonc | asan_ubsan | 4.181 | 4.174–4.188 | 0.7 | 4.34× [4.26, 4.40] | 4.67× [4.55, 4.74] |

## Corpus: fuzz (10677 inputs)

| Parser | Build | Median µs/input | IQR (µs) | CV % | Slowdown vs normal | Slowdown vs plain clang |
|---|---|---:|---:|---:|---:|---:|
| cjson | baseline | 4.843 | 4.709–4.923 | 9.0 | 0.62× [0.61, 0.63] | 1.00× [1.00, 1.00] |
| cjson | normal | 7.750 | 7.680–7.822 | 3.2 | 1.00× [1.00, 1.00] | 1.61× [1.58, 1.64] |
| cjson | asan | 17.497 | 17.205–17.880 | 3.5 | 2.25× [2.22, 2.31] | 3.64× [3.57, 3.69] |
| cjson | asan_ubsan | 17.932 | 17.292–18.480 | 3.9 | 2.28× [2.23, 2.38] | 3.66× [3.57, 3.82] |
| jsonc | baseline | 6.573 | 6.532–6.617 | 2.1 | 0.81× [0.81, 0.83] | 1.00× [1.00, 1.00] |
| jsonc | normal | 7.999 | 7.927–8.146 | 2.0 | 1.00× [1.00, 1.00] | 1.23× [1.20, 1.24] |
| jsonc | asan | 22.888 | 22.532–23.053 | 1.8 | 2.83× [2.80, 2.90] | 3.45× [3.41, 3.55] |
| jsonc | asan_ubsan | 24.130 | 23.937–24.185 | 2.0 | 3.02× [2.95, 3.08] | 3.67× [3.62, 3.78] |

## Warnings

- None
