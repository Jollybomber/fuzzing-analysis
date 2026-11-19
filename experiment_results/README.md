# Experiment results

The results the findings are based on
([DIFFERENTIAL_TESTING_FINDINGS.md](../DIFFERENTIAL_TESTING_FINDINGS.md)), all produced with the
corrected `bin_v2` build. Results from the earlier, misconfigured build are not included.

| Folder | Contents | Produced by |
|---|---|---|
| `build/` | `build_manifest.json`: compiler and AFL++ versions, flags, source commits, and the SHA-256 of every binary. `build.log`: the full build output, including the instrumentation checks. | `scripts/setup_and_build.sh` |
| `baseline/` | Differential testing on JSONTestSuite (318 inputs) and the 25 handwritten cases: one JSON line per input (both parsers' status, output and stderr, and the tags) plus readable logs | `scripts/run_baseline_comparison.sh` |
| `fuzzing/fuzz_out_v2.tar.gz` | The 30 AFL++ campaigns (2 parsers × 3 builds × 5 runs × 30 min): `fuzzer_stats`, `plot_data`, `cmdline`, `fuzzer_setup`, `afl.log`, and every saved queue, crash and hang input | `scripts/run_fuzzing.sh` |
| `fuzzing/fuzz_master_v2.log` | Start and finish time of every campaign | `scripts/run_fuzzing.sh` |
| `analysis/` | Campaign statistics (`runs.csv`, `groups.csv`, `timeline.csv`), the replay of all 10,677 distinct saved inputs through both parsers (`replay.jsonl.gz`, `findings.csv`, `corpus.jsonl`), hang/crash triage (`triage.json`), the root cause of every disagreement (`root_causes.csv`, `classified.json`), and a summary (`report.md`) | `scripts/analyze_fuzzing.py`, `scripts/classify_findings.py` |
| `overhead/` | Fixed-input sanitizer overhead benchmark: raw timings (`raw.csv`), summary with confidence intervals (`summary.csv`, `summary.json`, `report.md`), and the input lists | `scripts/benchmark_overhead.py` |
| `charts/` | The five report figures (PNG) and `tables.md`, which has the same numbers as the figures, the Mann-Whitney tests, and the per-build discovery table | `scripts/make_charts.py` |

## Why two files are compressed

- **`fuzzing/fuzz_out_v2.tar.gz`:** the campaigns contain about 15,000 small files, and AFL's file
  names contain colons (`id:000000,time:0,...`), which Windows cannot check out. AFL's internal
  resume files (`fastresume.bin`, `.synced`) are left out; everything else is unchanged.
- **`analysis/replay.jsonl.gz`:** the uncompressed file is 78 MB.

Both archives were checked to restore byte-for-byte to the originals.

## Using the results

Most numbers can be read directly from `analysis/report.md`, `overhead/report.md` and
`charts/tables.md`. To regenerate the figures from these files on any machine with matplotlib:

```bash
python3 scripts/make_charts.py --analysis experiment_results/analysis --baseline experiment_results/baseline \
  --overhead experiment_results/overhead --causes experiment_results/analysis/root_causes.csv \
  --output charts_new
```

To re-run the analysis (inside the AFL++ container, after building `bin_v2` with
`scripts/setup_and_build.sh`), first restore the campaigns into the repository root:

```bash
tar -xzf experiment_results/fuzzing/fuzz_out_v2.tar.gz          # creates fuzz_out_v2/
gzip -dk experiment_results/analysis/replay.jsonl.gz             # only needed for classify_findings.py
```

Paths stored inside these files (for example `input_path` in `findings.csv`, or the input lists in
`overhead/`) refer to the original locations inside the container (`/work/fuzz_out_v2/...`,
`/work/tests/...`). They match once the archive has been extracted into the repository root.
