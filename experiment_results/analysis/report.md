# AFL++ run analysis

Generated: 2026-11-19T12:21:52.297953+00:00

30 fuzzer instances; 14,116,352 recorded executions; 13,391 saved input occurrences; 10,677 distinct byte sequences.

## Per-configuration results

These are directory labels, not independently proven sanitizer configurations. SD is sample standard deviation across separate runs. Different binaries have different edge spaces.

| Parser | Label | Runs | Executions | Exec/s mean ± SD | Edges mean | Saved crashes | Saved hangs |
|---|---|---:|---:|---:|---:|---:|---:|
| cjson | asan | 5 | 1,719,906 | 191.10 ± 19.94 | 266.8 | 0 | 3 |
| cjson | asan_ubsan | 5 | 1,717,067 | 190.76 ± 19.04 | 288.0 | 0 | 3 |
| cjson | normal | 5 | 3,506,295 | 389.59 ± 47.91 | 272.0 | 0 | 2 |
| jsonc | asan | 5 | 1,645,905 | 182.88 ± 12.41 | 516.8 | 0 | 0 |
| jsonc | asan_ubsan | 5 | 1,653,248 | 183.67 ± 12.81 | 552.4 | 0 | 0 |
| jsonc | normal | 5 | 3,873,931 | 430.44 ± 38.82 | 516.6 | 0 | 0 |

## Validity checks

- Retained seed-derived queue bytes differ. AFL may trim these files; this does NOT prove the initial seeds differed. Preserve a pre-run seed manifest.
- No per-campaign run_manifest.json: the campaign predates run_fuzzing.sh's run records (and its container-local .cur_input), so core, environment and seed hashes are not recorded and exec/s may be limited by file I/O. (30 instances)
- Coverage stability below 100%; path observations have variability. (15 instances)
- Current target/AFL XXH3 fingerprint checks: {'True': 30}. None means unavailable; False means mismatch or unsupported algorithm. SHA-256 is recorded separately.

## Interpretation

- AFL saved crashes/hangs are candidate artifacts, not counts of independent bugs. Deduplicate bytes, replay, inspect diagnostics, and group root causes.
- Zero saved crashes means no crashes were saved under this campaign's configuration and budget; it does not establish safety or absence of semantic disagreements.
- Queue counts include original seeds and retained coverage-increasing inputs, not every mutation executed.
- bitmap_cvg is an AFL instrumentation metric, not source-line coverage. Do not compare raw edge counts between different parsers or differently instrumented binaries as a security ranking.
- Configuration throughput differences are descriptive only. Optimization level, CPU/core assignment, concurrent workload, input mix, and sanitizer configuration confound overhead claims.
- A missing first-crash/first-hang time is not zero. It means no such saved artifact was found; use the run budget as a right-censoring bound, not an observed time to finding.

## Differential replay

Replayed 10,677/10,677 distinct inputs through both normal parser wrappers. Candidate inputs: 2,903. Nonrepeatable candidates: 0.

Status pairs: {'rejected / rejected': 6508, 'accepted / accepted': 3003, 'accepted / rejected': 717, 'rejected / accepted': 449}

Candidate tags: {'VALUE_DIFFERENCE': 1027, 'ACCEPTANCE_DIFFERENCE': 1166, 'INVALID_UTF8_OUTPUT': 982, 'INVALID_JSON_OUTPUT': 12}

Representation-only differences with equal compared values: 29.

Saved fault/input-target combinations replayed: 8; reproduced at least once: 0.

Replay settings: {"timeout_seconds": 1.0, "confirmation_repeats": 3, "workers": 4, "output_limit_bytes": 1048576, "sanitizer_options": "abort on error; leak detection off; symbolization on"}

Replay compares serialized JSON values using exact decimal arithmetic, preserves duplicate values per key, ignores unrelated object-key ordering, and retains array order and JSON types. A number printed differently can still expose serialization/rounding differences rather than different internal values. Each candidate needs interpretation against the input and library APIs.

INVALID_UTF8_OUTPUT and INVALID_JSON_OUTPUT describe accepted output that cannot be decoded as strict UTF-8 JSON; they are not automatically disagreements between parsers. Identical-output candidate counts by tag: {'INVALID_UTF8_OUTPUT': 695}. Candidates also seen in seed-derived queue entries: {'VALUE_DIFFERENCE': 7}. COMPARISON_LIMIT and OUTPUT_LIMIT are analyzer limitations, not parser defects.

The replay corpus is AFL's retained corpus, not every input generated. Finding counts are neither independent bugs nor an unbiased disagreement rate. Small examples are copied into examples/; these are selected representatives, not minimized test cases.

## Files

- summary.json: complete metrics, warnings and current target fingerprints.
- runs.csv / groups.csv: per-instance measurements and independent-repeat summaries.
- timeline.csv: AFL plot_data rows, with campaign and instance provenance.
- corpus.jsonl: SHA-256 deduplication and every saved input's origins.
- replay.jsonl / replay_summary.json / triage.json: generated only with --replay.

- findings.csv: compact candidate index, including the original file path and repeatability.
- source_at_analysis/: snapshots of scripts/wrappers at analysis time, not proof of build-time source.

## References

- AFL++ status fields: https://aflplus.plus/docs/status_screen/
- AFL++ methodology and triage: https://aflplus.plus/docs/fuzzing_in_depth/
