#!/usr/bin/env python3
"""Generate report figures and tables from the baseline, fuzzing and overhead results.

Run on any machine with matplotlib (the AFL++ container does not ship it):
    python3 scripts/make_charts.py \
        --analysis results/fuzz_analysis_v2_fixed --baseline results/baseline_v2_fixed \
        --overhead results/overhead_v2 --causes results/fuzz_analysis_v2_fixed/root_causes.csv \
        --output results/charts_v2

Every figure has a matching markdown table in tables.md (same numbers, for the report
and for readers who cannot distinguish the colors). Statistical tests are exact
two-sided Mann-Whitney U tests over independent campaign repeats.
"""
import argparse
import csv
import itertools
import random
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("matplotlib is required: pip install matplotlib")

# Reference categorical palette, slots 1-5 (validated: CVD and normal-vision separation).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
TEXT, TEXT2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
CONFIGS = ("normal", "asan", "asan_ubsan")
CONFIG_LABEL = {"normal": "Normal", "asan": "ASan", "asan_ubsan": "ASan+UBSan", "baseline": "Plain clang"}
PARSER_LABEL = {"cjson": "cJSON", "jsonc": "json-c"}

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": TEXT2, "xtick.color": TEXT2,
    "ytick.color": TEXT2, "text.color": TEXT, "axes.titlesize": 11, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False, "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.8, "axes.axisbelow": True, "legend.frameon": False,
})


def mann_whitney(a, b):
    """Exact two-sided Mann-Whitney U test (fine for the small samples used here)."""
    pooled, n = a + b, len(a)

    def u_stat(x, y):
        return sum((p > q) + 0.5 * (p == q) for p in x for q in y)

    u = u_stat(a, b)
    center = n * len(b) / 2
    extreme = total = 0
    for idx in itertools.combinations(range(len(pooled)), n):
        chosen = set(idx)
        x = [pooled[i] for i in idx]
        y = [pooled[i] for i in range(len(pooled)) if i not in chosen]
        total += 1
        extreme += abs(u_stat(x, y) - center) >= abs(u - center) - 1e-9
    return u, extreme / total


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def save(fig, out, name, figures):
    path = out / f"{name}.png"
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    figures.append(path.name)


def fig_throughput(runs, out, figures, tables):
    data = defaultdict(list)
    for r in runs:
        data[(r["parser"], r["config"])].append(float(r["execs_done"]) / float(r["run_time"]))
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6), sharey=True)
    for ax, parser in zip(axes, ("cjson", "jsonc")):
        for i, config in enumerate(CONFIGS):
            values = sorted(data[(parser, config)])
            med = statistics.median(values)
            ax.bar(i, med, width=0.45, color=SERIES[i], alpha=0.25, zorder=1)
            ax.scatter([i] * len(values), values, s=36, color=SERIES[i], edgecolor=SURFACE, linewidth=1.5, zorder=3)
            ax.text(i + 0.26, med, f"{med:.0f}", ha="left", va="center", fontsize=9, color=TEXT)
        ax.set_xticks(range(3), [CONFIG_LABEL[c] for c in CONFIGS])
        ax.set_xlim(-0.5, 2.6)
        ax.set_title(PARSER_LABEL[parser])
        ax.grid(axis="x", visible=False)
    axes[0].set_ylabel("Executions per second")
    fig.suptitle("Fuzzing throughput per build (dots = 5 runs, bar = median)", fontsize=11, x=0.01, ha="left")
    fig.tight_layout()
    save(fig, out, "fig1_fuzzing_throughput", figures)

    lines = ["## Fuzzing throughput (Figure 1)", "",
             "| Parser | Build | Runs | Median exec/s | Min–max | Slowdown vs normal (median) | Mann-Whitney vs normal | vs ASan |",
             "|---|---|---:|---:|---:|---:|---:|---:|"]
    stats = {}
    for parser in ("cjson", "jsonc"):
        normal = data[(parser, "normal")]
        for config in CONFIGS:
            v = data[(parser, config)]
            row = {"median": statistics.median(v), "slowdown": statistics.median(normal) / statistics.median(v)}
            mw_n = "—" if config == "normal" else "U={:.0f}, p={:.4f}".format(*mann_whitney(v, normal))
            mw_a = "U={:.0f}, p={:.4f}".format(*mann_whitney(v, data[(parser, "asan")])) if config == "asan_ubsan" else "—"
            stats[f"{parser}_{config}"] = row
            lines.append(f"| {PARSER_LABEL[parser]} | {CONFIG_LABEL[config]} | {len(v)} | {row['median']:.1f} | "
                         f"{min(v):.0f}–{max(v):.0f} | {row['slowdown']:.2f}× | {mw_n} | {mw_a} |")
    lines += ["", "With 5 vs 5 runs the smallest possible exact two-sided p-value is 0.0079.", ""]
    tables.extend(lines)
    return stats


def fig_coverage(timeline, runs, out, figures, tables):
    """Edges found over time, indexed to each build's final median (edge spaces differ per build)."""
    series = defaultdict(list)
    for r in timeline:
        series[r["campaign"]].append((int(r["relative_time"]), int(r["edges_found"])))
    meta = {r["campaign"]: (r["parser"], r["config"]) for r in runs}
    # AFL writes its first plot_data row after about a minute; start the grid there instead
    # of back-filling earlier times with the first sample.
    first_sample = max(min(t for t, _ in pts) for pts in series.values())
    grid_t = list(range(30 * -(-first_sample // 30), 1801, 30))
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6), sharey=True)
    plateau_rows = []
    for ax, parser in zip(axes, ("cjson", "jsonc")):
        for i, config in enumerate(CONFIGS):
            curves = []
            for campaign, points in series.items():
                if meta.get(campaign) != (parser, config):
                    continue
                points.sort()
                curve, j, last = [], 0, None
                for t in grid_t:
                    while j < len(points) and points[j][0] <= t:
                        last = points[j][1]
                        j += 1
                    curve.append(last)
                curves.append(curve)
            if not curves:
                continue
            final = statistics.median(c[-1] for c in curves)
            med = [statistics.median(c[k] for c in curves) / final * 100 for k in range(len(grid_t))]
            ax.plot([t / 60 for t in grid_t], med, color=SERIES[i], linewidth=2, label=CONFIG_LABEL[config])
            t95 = next(grid_t[k] for k, v in enumerate(med) if v >= 95)
            t99 = next(grid_t[k] for k, v in enumerate(med) if v >= 99)
            plateau_rows.append((parser, config, final, t95, t99))
        ax.set_title(PARSER_LABEL[parser])
        ax.set_xlabel("Minutes")
        ax.set_xlim(0, 30)
    axes[0].set_ylabel("Edges found (% of final median)")
    axes[1].legend(loc="lower right")
    fig.suptitle("Coverage growth over time (median of 5 runs per build)", fontsize=11, x=0.01, ha="left")
    fig.tight_layout()
    save(fig, out, "fig2_coverage_over_time", figures)
    tables.extend(["## Coverage plateau (Figure 2)", "",
                   "Edges are indexed to each build's own final median because sanitizer instrumentation changes the "
                   "edge space; raw edge counts are not comparable across builds. AFL's first plot_data sample is "
                   "at about 60 s, so the curves start at the first 30 s grid point after every run has a sample (1.5 min); a plateau time of 1.5 min means 'already reached at the first point'.", "",
                   "| Parser | Build | Final edges (median) | Time to 95% | Time to 99% |", "|---|---|---:|---:|---:|"])
    for parser, config, final, t95, t99 in plateau_rows:
        tables.append(f"| {PARSER_LABEL[parser]} | {CONFIG_LABEL[config]} | {final:.0f} | {t95 / 60:.1f} min | {t99 / 60:.1f} min |")
    tables.append("")


def fig_overhead(overhead_dir, out, figures, tables):
    summary = json.loads((overhead_dir / "summary.json").read_text())
    results = summary["results"]
    corpora = list(summary["meta"]["corpora"])
    fig, axes = plt.subplots(1, len(corpora), figsize=(4.6 * len(corpora), 3.4), sharey=True, squeeze=False)
    variants = ("normal", "asan", "asan_ubsan")
    for ax, corpus in zip(axes[0], corpora):
        for p_i, parser in enumerate(("cjson", "jsonc")):
            for v_i, variant in enumerate(variants):
                s = next(r for r in results if (r["parser"], r["corpus"], r["variant"]) == (parser, corpus, variant))
                x = p_i * 4 + v_i
                lo, hi = s["slowdown_vs_baseline_ci95"]
                val = s["slowdown_vs_baseline"]
                ax.bar(x, val, width=0.8, color=SERIES[v_i], label=CONFIG_LABEL[variant] if p_i == 0 else None)
                ax.errorbar(x, val, yerr=[[val - lo], [hi - val]], color=TEXT2, capsize=3, linewidth=1)
                ax.text(x, hi, f"{val:.1f}×", ha="center", va="bottom", fontsize=8.5, color=TEXT)
        ax.axhline(1, color=TEXT2, linewidth=1, linestyle=":")
        ax.set_xticks([1, 5], ["cJSON", "json-c"])
        ax.grid(axis="x", visible=False)
        ax.set_title(f"{corpus} corpus ({summary['meta']['corpora'][corpus]['inputs']} inputs)")
    axes[0][0].set_ylabel("Time per input vs plain clang")
    axes[0][-1].legend(loc="upper right")
    fig.suptitle("In-process parsing cost on identical inputs (median of paired repetitions, 95% CI)",
                 fontsize=11, x=0.01, ha="left")
    fig.tight_layout()
    save(fig, out, "fig3_overhead_benchmark", figures)
    tables.extend(["## Fixed-input overhead benchmark (Figure 3)", "",
                   f"{summary['meta']['reps']} paired repetitions per build, shuffled order, pinned core. Slowdowns are "
                   "medians of per-repetition ratios with bootstrap 95% confidence intervals.", "",
                   "| Corpus | Parser | Build | Median µs/input | Slowdown vs plain clang | Slowdown vs normal (AFL) |",
                   "|---|---|---|---:|---:|---:|"])
    for r in results:
        b_lo, b_hi = r["slowdown_vs_baseline_ci95"]
        n_lo, n_hi = r["slowdown_vs_normal_ci95"]
        tables.append(f"| {r['corpus']} | {PARSER_LABEL[r['parser']]} | {CONFIG_LABEL[r['variant']]} | "
                      f"{r['median_us_per_input']:.3f} | {r['slowdown_vs_baseline']:.2f}× [{b_lo:.2f}, {b_hi:.2f}] | "
                      f"{r['slowdown_vs_normal']:.2f}× [{n_lo:.2f}, {n_hi:.2f}] |")
    tables.append("")

    # UBSan's extra cost must be computed from the paired repetitions (ASan+UBSan / ASan in the
    # same repetition), not as a ratio of the two medians.
    per = defaultdict(dict)
    for row in read_csv(overhead_dir / "raw.csv"):
        per[(row["parser"], row["corpus"], row["variant"])][int(row["rep"])] = float(row["ns_per_input"])
    rng = random.Random(summary["meta"].get("seed", 4239))
    tables.extend(["### UBSan's extra cost on top of ASan (paired)", "",
                   "Median over repetitions of (ASan+UBSan time / ASan time) in the same repetition, with a bootstrap "
                   "95% confidence interval. An interval above 0% means UBSan's extra cost is measurable.", "",
                   "| Corpus | Parser | Extra cost | 95% CI |", "|---|---|---:|---:|"])
    for corpus in corpora:
        for parser in ("cjson", "jsonc"):
            asan, both = per[(parser, corpus, "asan")], per[(parser, corpus, "asan_ubsan")]
            ratios = [both[k] / asan[k] for k in asan if k in both]
            draws = sorted(statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(10000))
            tables.append(f"| {corpus} | {PARSER_LABEL[parser]} | {100 * (statistics.median(ratios) - 1):+.1f}% | "
                          f"[{100 * (draws[250] - 1):+.1f}%, {100 * (draws[9749] - 1):+.1f}%] |")
    tables.append("")
    return results


def baseline_outcomes(baseline_dir):
    groups = Counter()
    for suite in ("handwritten", "JSONTestSuite"):
        for line in (baseline_dir / f"test_results_{suite}.jsonl").open():
            row = json.loads(line)
            name = row["basename"]
            subset = "Handwritten" if suite == "handwritten" else {"y": "JSONTestSuite y_ (must accept)",
                                                                   "n": "JSONTestSuite n_ (must reject)",
                                                                   "i": "JSONTestSuite i_ (impl.-defined)"}[name[0]]
            s1, s2 = row["parser1"]["status"], row["parser2"]["status"]
            if s1 == s2 == "accepted":
                same = row["parser1"]["stdout"] == row["parser2"]["stdout"] or row["agreed"]
                outcome = "Both accept, same value" if same else "Both accept, different value"
            elif s1 == s2 == "rejected":
                outcome = "Both reject"
            elif s1 == "accepted" and s2 == "rejected":
                outcome = "Only cJSON accepts"
            elif s1 == "rejected" and s2 == "accepted":
                outcome = "Only json-c accepts"
            else:
                outcome = f"Other ({s1}/{s2})"
            groups[(subset, outcome)] += 1
    return groups


def fig_baseline(baseline_dir, out, figures, tables):
    groups = baseline_outcomes(baseline_dir)
    subsets = ["Handwritten", "JSONTestSuite y_ (must accept)", "JSONTestSuite n_ (must reject)",
               "JSONTestSuite i_ (impl.-defined)"]
    outcomes = ["Both accept, same value", "Both reject", "Both accept, different value",
                "Only cJSON accepts", "Only json-c accepts"]
    extra = sorted({o for (_, o) in groups if o not in outcomes})
    outcomes += extra
    fig, ax = plt.subplots(figsize=(9, 3.4))
    for y, subset in enumerate(reversed(subsets)):
        total = sum(groups[(subset, o)] for o in outcomes)
        left = 0
        for i, outcome in enumerate(outcomes):
            n = groups[(subset, outcome)]
            if not n:
                continue
            width = n / total * 100
            ax.barh(y, width - 0.4, left=left + 0.2, color=SERIES[i % len(SERIES)], height=0.62,
                    label=outcome if y == 0 or outcome not in ax.get_legend_handles_labels()[1] else None)
            if width >= 6:
                ax.text(left + width / 2, y, str(n), ha="center", va="center", fontsize=8.5, color=TEXT)
            left += width
        ax.text(101, y, f"n={total}", va="center", fontsize=8.5, color=TEXT2)
    ax.set_yticks(range(len(subsets)), list(reversed(subsets)))
    ax.set_xlim(0, 100)
    ax.set_xlabel("% of inputs")
    ax.grid(axis="y", visible=False)
    handles, labels = ax.get_legend_handles_labels()
    order = [labels.index(o) for o in outcomes if o in labels]
    ax.legend([handles[i] for i in order], [labels[i] for i in order], loc="upper center",
              bbox_to_anchor=(0.45, -0.22), ncol=3, fontsize=8.5)
    ax.set_title("Baseline differential testing outcomes", loc="left")
    fig.tight_layout()
    save(fig, out, "fig4_baseline_outcomes", figures)
    tables.extend(["## Baseline outcomes (Figure 4)", "",
                   "'Same value' uses the driver's exact comparison (scripts/diff_driver.py, shared with "
                   "analyze_fuzzing.py): exact decimal numbers, so `1E2` equals `100`, and identical non-UTF-8 output "
                   "counts as equal.", "",
                   "| Subset | " + " | ".join(outcomes) + " | Total |", "|---|" + "---:|" * (len(outcomes) + 1)])
    for subset in subsets:
        counts = [groups[(subset, o)] for o in outcomes]
        tables.append(f"| {subset} | " + " | ".join(map(str, counts)) + f" | {sum(counts)} |")
    tables.append("")


def fig_causes(causes_csv, out, figures, tables):
    rows = read_csv(causes_csv)
    counts = Counter((r["direction"], r["root_cause"]) for r in rows)
    directions = ["Only cJSON accepts", "Only json-c accepts", "Both accept, different value"]
    present = [d for d in directions if any(k[0] == d for k in counts)]
    fig, axes = plt.subplots(len(present), 1, figsize=(9, 1.0 + 0.36 * len(counts) + 0.5 * len(present)),
                             gridspec_kw={"height_ratios": [max(1, sum(1 for k in counts if k[0] == d)) for d in present]})
    if len(present) == 1:
        axes = [axes]
    for ax, direction, color in zip(axes, present, SERIES):
        items = sorted(((c, n) for (d, c), n in counts.items() if d == direction), key=lambda x: x[1])
        ax.barh(range(len(items)), [n for _, n in items], color=color, height=0.62)
        for y, (_, n) in enumerate(items):
            ax.text(n, y, f" {n}", va="center", fontsize=8.5, color=TEXT)
        ax.set_yticks(range(len(items)), [c for c, _ in items], fontsize=8.5)
        ax.set_title(f"{direction} ({sum(n for _, n in items)} inputs)", loc="left", fontsize=10)
        ax.grid(axis="y", visible=False)
        ax.set_xlim(0, max(n for _, n in items) * 1.15)
    axes[-1].set_xlabel("Distinct fuzzer-saved inputs (primary root cause)")
    fig.suptitle("Parser disagreements found by fuzzing, by root cause", fontsize=11, x=0.01, ha="left")
    fig.tight_layout()
    save(fig, out, "fig5_fuzzing_disagreement_causes", figures)
    tables.extend(["## Fuzzing disagreements by root cause (Figure 5)", "",
                   "Each distinct input is assigned one primary cause by scripts/classify_findings.py (precedence order "
                   "documented there). Counts are inputs, not independent bugs.", "",
                   "| Direction | Root cause | Inputs |", "|---|---|---:|"])
    for direction in present:
        for (d, c), n in sorted(counts.items(), key=lambda x: -x[1]):
            if d == direction:
                tables.append(f"| {direction} | {c} | {n} |")
    tables.append("")


def table_discovery(analysis_dir, causes_csv, runs, tables):
    """Time to first disagreement and root causes discovered, per campaign and build.

    An input counts for every campaign whose queue/crashes/hangs saved it (AFL file name
    `time:` field). Seeds are excluded, so only fuzzer-generated disagreements count.
    """
    causes = {r["sha256"]: r["root_cause_id"] for r in read_csv(causes_csv)}
    first, found, inputs = {}, defaultdict(set), defaultdict(set)
    for line in (analysis_dir / "corpus.jsonl").open():
        item = json.loads(line)
        cause = causes.get(item["sha256"])
        if cause is None:
            continue
        for origin in item["origins"]:
            if origin.get("is_seed") or origin.get("time_seconds") is None:
                continue
            campaign = origin["campaign"]
            first[campaign] = min(first.get(campaign, float("inf")), origin["time_seconds"])
            found[campaign].add(cause)
            inputs[campaign].add(item["sha256"])
    tables.extend(["## Discovery of parser disagreements per build", "",
                   "Per campaign: time until the first fuzzer-generated disagreement was saved, number of distinct "
                   "disagreeing inputs saved, and number of distinct root causes among them (median and range over 5 runs).", "",
                   "| Parser | Build | First disagreement (s) | Disagreeing inputs saved | Root causes found | Causes found by any run |",
                   "|---|---|---:|---:|---:|---|"])
    for parser in ("cjson", "jsonc"):
        for config in CONFIGS:
            camps = [r["campaign"] for r in runs if (r["parser"], r["config"]) == (parser, config)]
            t = [first[c] for c in camps if c in first]
            n = [len(inputs[c]) for c in camps]
            k = [len(found[c]) for c in camps]
            union = sorted(set().union(*(found[c] for c in camps)))
            t_text = f"{statistics.median(t):.0f} ({min(t):.0f}–{max(t):.0f})" if t else "none"
            tables.append(f"| {PARSER_LABEL[parser]} | {CONFIG_LABEL[config]} | {t_text} | "
                          f"{statistics.median(n):.0f} ({min(n)}–{max(n)}) | {statistics.median(k):.0f} ({min(k)}–{max(k)}) | "
                          f"{len(union)}: {', '.join(union)} |")
    tables.append("")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--analysis", type=Path, required=True, help="analyze_fuzzing.py output directory")
    ap.add_argument("--baseline", type=Path, help="run_baseline_comparison.sh RESULTS_DIR")
    ap.add_argument("--overhead", type=Path, help="benchmark_overhead.py output directory")
    ap.add_argument("--causes", type=Path, help="classify_findings.py output CSV")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        sys.exit(f"Error: {args.output} exists and is not empty")
    args.output.mkdir(parents=True, exist_ok=True)

    figures, tables = [], ["# Report tables", ""]
    runs = read_csv(args.analysis / "runs.csv")
    stats = fig_throughput(runs, args.output, figures, tables)
    fig_coverage(read_csv(args.analysis / "timeline.csv"), runs, args.output, figures, tables)
    if args.overhead:
        fig_overhead(args.overhead, args.output, figures, tables)
    if args.baseline:
        fig_baseline(args.baseline, args.output, figures, tables)
    if args.causes:
        fig_causes(args.causes, args.output, figures, tables)
        table_discovery(args.analysis, args.causes, runs, tables)
    (args.output / "tables.md").write_text("\n".join(tables) + "\n")
    (args.output / "throughput_stats.json").write_text(json.dumps(stats, indent=2) + "\n")
    print("Wrote " + ", ".join(figures + ["tables.md"]) + f" to {args.output}")


if __name__ == "__main__":
    main()
