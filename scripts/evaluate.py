"""Accuracy and benchmark evaluation runner for VaultSight detectors.

Usage:
  # Dev-set evaluation (tuned-on dataset)
  python -m scripts.evaluate --corpus data/evaluation_corpus.json --label "dev"

  # Holdout evaluation (independently generated, untuned)
  python -m scripts.evaluate --corpus data/holdout_corpus.json --label "holdout"

  # Full two-corpus report (default: writes EVALUATION.md)
  python -m scripts.evaluate

Produces EVALUATION.md with:
  - Dev-set metrics (labeled "Tuned-On Development Set")
  - Holdout-set metrics (labeled "Independent Holdout Set")
  - Per-detector breakdown for each
  - FP / FN analysis
"""

import json
import sys
import argparse
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaultsight.detectors.engine import DetectionEngine


def _evaluate_corpus(corpus_path: str, engine: DetectionEngine) -> dict:
    """Run evaluation on a single labeled corpus. Returns raw stats dict."""
    with open(corpus_path, "r", encoding="utf-8") as f:
        corpus = json.load(f)

    stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    false_positives = []
    false_negatives = []

    for item in corpus:
        text = item["text"]
        expected_detector = item.get("expected_detector")
        is_positive = item.get("is_positive", False)

        findings = engine.scan_text(text)
        detected_types = list({f.detector for f in findings})

        if is_positive:
            if expected_detector in detected_types:
                stats[expected_detector]["tp"] += 1
                # Cross-fire: another detector also fired unexpectedly
                for dt in detected_types:
                    if dt != expected_detector:
                        stats[dt]["fp"] += 1
                        false_positives.append({
                            "text": text[:120],
                            "expected": expected_detector,
                            "detected": dt,
                            "reason": "Secondary detector cross-fired on positive sample",
                        })
            else:
                stats[expected_detector]["fn"] += 1
                false_negatives.append({
                    "text": text[:120],
                    "expected": expected_detector,
                    "detected": detected_types,
                    "reason": "Expected detector missed pattern",
                })
        else:
            # Negative sample: any detection is a FP
            if detected_types:
                for dt in detected_types:
                    stats[dt]["fp"] += 1
                    false_positives.append({
                        "text": text[:120],
                        "expected": None,
                        "detected": dt,
                        "reason": f"Falsely detected on negative ({item.get('negative_type', 'unknown')})",
                    })

    total_tp = sum(s["tp"] for s in stats.values())
    total_fp = sum(s["fp"] for s in stats.values())
    total_fn = sum(s["fn"] for s in stats.values())

    detector_metrics = {}
    for det, s in stats.items():
        tp, fp, fn = s["tp"], s["fp"], s["fn"]
        prec = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        detector_metrics[det] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(prec, 4),
            "recall":    round(rec, 4),
            "f1":        round(f1, 4),
        }

    overall_prec = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_rec  = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    overall_f1   = (
        2 * overall_prec * overall_rec / (overall_prec + overall_rec)
        if (overall_prec + overall_rec) > 0 else 0.0
    )

    return {
        "total_samples": len(corpus),
        "total_positives": sum(1 for item in corpus if item.get("is_positive")),
        "total_negatives": sum(1 for item in corpus if not item.get("is_positive")),
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_fn": total_fn,
        "overall_precision": round(overall_prec, 4),
        "overall_recall":    round(overall_rec, 4),
        "overall_f1":        round(overall_f1, 4),
        "detector_metrics":  detector_metrics,
        "false_positives":   false_positives,
        "false_negatives":   false_negatives,
    }


def _section_md(label: str, corpus_path: str, results: dict) -> list[str]:
    """Render one evaluation section as markdown lines."""
    r = results
    lines = [
        f"## {label}",
        f"> Corpus: `{corpus_path}`",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Total samples | {r['total_samples']} "
        f"({r['total_positives']} pos / {r['total_negatives']} neg) |",
        f"| True Positives | {r['total_tp']} |",
        f"| False Positives | {r['total_fp']} |",
        f"| False Negatives | {r['total_fn']} |",
        f"| **Precision** | **{r['overall_precision']*100:.2f}%** |",
        f"| **Recall** | **{r['overall_recall']*100:.2f}%** |",
        f"| **F1-Score** | **{r['overall_f1']*100:.2f}%** |",
        "",
        "### Per-Detector Breakdown",
        "",
        "| Detector | TP | FP | FN | Precision | Recall | F1 |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for det, m in sorted(r["detector_metrics"].items()):
        lines.append(
            f"| `{det}` | {m['tp']} | {m['fp']} | {m['fn']} "
            f"| {m['precision']*100:.1f}% | {m['recall']*100:.1f}% | {m['f1']*100:.1f}% |"
        )

    fp_list = r["false_positives"]
    fn_list = r["false_negatives"]

    lines += [
        "",
        f"### False Positives: {len(fp_list)}",
    ]
    if fp_list:
        for i, fp in enumerate(fp_list[:8], 1):
            lines.append(
                f"{i}. `{fp['detected']}` on: `{fp['text'][:80]}...` — {fp['reason']}"
            )
    else:
        lines.append("None observed.")

    lines += [
        "",
        f"### False Negatives: {len(fn_list)}",
    ]
    if fn_list:
        for i, fn in enumerate(fn_list[:8], 1):
            lines.append(
                f"{i}. Expected `{fn['expected']}`, got `{fn['detected']}` "
                f"— `{fn['text'][:80]}...`"
            )
    else:
        lines.append("None observed.")

    lines.append("")
    return lines


def evaluate(
    dev_corpus: str = "data/evaluation_corpus.json",
    holdout_corpus: str = "data/holdout_corpus.json",
    output_md: str = "EVALUATION.md",
    single_corpus: str | None = None,
    single_label: str | None = None,
):
    engine = DetectionEngine()

    md_lines = [
        "# VaultSight — Detection Engine Accuracy Report",
        "",
        "> [!IMPORTANT]",
        "> All numbers below come from **real runs** on fully synthetic labeled corpora.",
        "> No real personal data or credentials were used at any point.",
        "",
        "> [!NOTE]",
        "> **Benchmark Integrity**",
        "> The *Development Set* was generated with seed 42 and rules were tuned against it.",
        "> The *Independent Holdout Set* was generated with seed 1337, uses different formats",
        "> (mixed-case keys, Kubernetes YAML, GitHub Actions, base64-encoded secrets,",
        "> harder negatives), and rules were **NOT** tuned against it before the baseline run.",
        "",
    ]

    if single_corpus:
        # Single-corpus mode (used from CLI with --corpus flag)
        result = _evaluate_corpus(single_corpus, engine)
        label = single_label or Path(single_corpus).stem.replace("_", " ").title()
        md_lines += _section_md(label, single_corpus, result)
        overall = result
    else:
        # Full two-corpus report
        dev_exists = Path(dev_corpus).exists()
        holdout_exists = Path(holdout_corpus).exists()

        if not dev_exists and not holdout_exists:
            print("ERROR: Neither dev nor holdout corpus found. Run generators first.", file=sys.stderr)
            sys.exit(1)

        if dev_exists:
            dev_result = _evaluate_corpus(dev_corpus, engine)
            md_lines += _section_md(
                "Development Set (Tuned-On — seed 42)", dev_corpus, dev_result
            )
            overall = dev_result
        else:
            print(f"WARNING: Dev corpus not found at {dev_corpus} — skipping.")
            dev_result = None

        if holdout_exists:
            holdout_result = _evaluate_corpus(holdout_corpus, engine)
            md_lines += _section_md(
                "Independent Holdout Set (Untuned — seed 1337)", holdout_corpus, holdout_result
            )
            overall = holdout_result
        else:
            print(f"WARNING: Holdout corpus not found at {holdout_corpus} — skipping.")
            holdout_result = None

    md_lines += [
        "---",
        "",
        "## Known Limitations & Weak Spots",
        "",
        "- **Generic entropy detector**: requires a secret keyword (`password`, `token`, etc.) "
        "within the same line. Naked high-entropy strings without context are intentionally "
        "ignored to avoid noisy false positives on UUIDs, build IDs, and hex hashes.",
        "- **Bare 10-digit Indian mobile numbers** are only flagged when a phone/contact "
        "keyword is nearby or the number is explicitly prefixed with `+91`/`91`.",
        "- **International PII**: rules are currently optimized for Indian (Aadhaar, PAN) "
        "and US identity formats. Other jurisdictions require additional rule authoring.",
        "- **Base64-opaque blobs**: secrets embedded in the *encoded* portion of a base64 "
        "string without a decoded text comment will be missed. Only decoded references are "
        "detectable without active decoding (not implemented).",
    ]

    with open(output_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(f"Evaluation complete -> {output_md}")
    print(
        f"Overall Metrics -> Precision: {overall['overall_precision']*100:.2f}%, "
        f"Recall: {overall['overall_recall']*100:.2f}%, "
        f"F1: {overall['overall_f1']*100:.2f}%"
    )
    return overall


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VaultSight detector evaluation")
    parser.add_argument(
        "--corpus", default=None,
        help="Path to a single labeled corpus JSON (default: runs both dev + holdout)."
    )
    parser.add_argument(
        "--label", default=None,
        help="Human-readable label for the single-corpus run."
    )
    parser.add_argument(
        "--dev-corpus", default="data/evaluation_corpus.json",
        help="Dev-set corpus path (default: data/evaluation_corpus.json)."
    )
    parser.add_argument(
        "--holdout-corpus", default="data/holdout_corpus.json",
        help="Holdout corpus path (default: data/holdout_corpus.json)."
    )
    parser.add_argument(
        "--output", default="EVALUATION.md",
        help="Output markdown file (default: EVALUATION.md)."
    )
    args = parser.parse_args()

    if args.corpus:
        evaluate(single_corpus=args.corpus, single_label=args.label, output_md=args.output)
    else:
        evaluate(
            dev_corpus=args.dev_corpus,
            holdout_corpus=args.holdout_corpus,
            output_md=args.output,
        )
