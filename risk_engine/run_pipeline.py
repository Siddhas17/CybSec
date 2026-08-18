"""End-to-end risk-engine pipeline: builds the attack graph fresh, loads
the trained autoencoder, bridges them into a joint per-flow dataset (see
risk_engine.data_bridge for why this bridge exists), scores every flow,
and reports the section-19 experimental evaluation.

Weights are the fixed baseline documented in risk_engine.config -- never
adjusted based on anything observed here. The val/test split below exists
for reporting structure matching the phase's requested methodology, not
because any tuning loop touches this data (there isn't one).

CLI usage:
    python -m risk_engine.run_pipeline

Writes to risk_engine/output/ (gitignored):
    config.json                 final RiskEngineConfig (weights, thresholds, derived scales)
    data_bridge_report.json     row counts through the joint-dataset build
    evaluation_report.json      distributions, precision/recall, comparison vs anomaly alone
    per_attack_risk.csv         per-canonical-attack-type risk summary (test split)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from sklearn.model_selection import train_test_split

from attack_graph.config import TOPOLOGY_RAW_DIR
from attack_graph.generation.build_graph import build_graph_from_directory
from ml.models.inference import AutoencoderPredictor
from ml.training.train_autoencoder import ARTIFACT_DIR as AUTOENCODER_ARTIFACT_DIR
from risk_engine.config import HIGH_RISK_THRESHOLD, RiskEngineConfig
from risk_engine.data_bridge import attach_graph_context, build_joint_flow_dataset, derive_scale_parameters
from risk_engine.evaluation import (
    benign_vs_attack_separation,
    compare_with_anomaly_alone,
    edge_volume_context_by_category,
    high_risk_precision_recall,
    per_attack_risk_table,
    risk_level_distribution,
    score_dataframe,
    score_distribution_summary,
)

OUTPUT_DIR = Path(__file__).resolve().parent / "output"
CATEGORIES_OF_INTEREST = ["PortScan", "FTP-Patator", "SSH-Patator", "Bot", "Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - Sql Injection"]
RANDOM_SEED = 42


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()

    print("=== Building attack graph (fresh, from ml/datasets/raw_labelled_flows/) ===")
    graph, build_report = build_graph_from_directory(raw_dir=TOPOLOGY_RAW_DIR)
    print(f"  nodes={build_report.node_count:,} edges={build_report.edge_count:,} runtime={build_report.runtime_seconds:.1f}s")

    print("\n=== Loading trained autoencoder (Phase 3 artifacts, read-only) ===")
    predictor = AutoencoderPredictor.load(AUTOENCODER_ARTIFACT_DIR)
    autoencoder_threshold = predictor.threshold
    print(f"  threshold={autoencoder_threshold}")

    print("\n=== Building joint flow dataset (anomaly score + graph identity per flow) ===")
    joint_df, bridge_report = build_joint_flow_dataset(TOPOLOGY_RAW_DIR, predictor)
    print(f"  scored {bridge_report['total_scored_rows']:,} flows (of {bridge_report['total_raw_rows']:,} raw rows)")

    joint_df = attach_graph_context(joint_df, graph)
    scales = derive_scale_parameters(graph)
    print(f"  derived attack_activity_scale={scales['attack_activity_scale']}, temporal_scale_hours={scales['temporal_scale_hours']}")

    config = RiskEngineConfig(
        anomaly_threshold=autoencoder_threshold,
        attack_activity_scale=scales["attack_activity_scale"],
        temporal_scale_hours=scales["temporal_scale_hours"],
    )

    print("\n=== Scoring every flow ===")
    score_start = time.monotonic()
    scored_df = score_dataframe(joint_df, config)
    print(f"  scored {len(scored_df):,} rows in {time.monotonic() - score_start:.1f}s")

    val_df, test_df = train_test_split(
        scored_df, test_size=0.5, random_state=RANDOM_SEED, stratify=scored_df["canonical_label"]
    )
    print(f"\n=== risk_engine val/test split (fresh stratified split over the joint dataset -- see docstring) ===")
    print(f"  val={len(val_df):,} test={len(test_df):,}")

    print("\n=== Validation-split sanity check ===")
    val_summary = score_distribution_summary(val_df)
    val_sep = benign_vs_attack_separation(val_df)
    print(f"  score mean={val_summary['mean']:.2f} median={val_summary['median']:.2f}")
    print(f"  benign mean risk={val_sep['benign']['mean']:.2f}  attack mean risk={val_sep['attack']['mean']:.2f}")

    print("\n=== Final test-split evaluation ===")
    test_summary = score_distribution_summary(test_df)
    test_levels = risk_level_distribution(test_df)
    test_sep = benign_vs_attack_separation(test_df)
    test_pr = high_risk_precision_recall(test_df, threshold=HIGH_RISK_THRESHOLD)
    per_attack = per_attack_risk_table(test_df, high_risk_threshold=HIGH_RISK_THRESHOLD)
    comparison = compare_with_anomaly_alone(
        test_df, anomaly_threshold=autoencoder_threshold, categories_of_interest=CATEGORIES_OF_INTEREST
    )
    edge_volume_context = edge_volume_context_by_category(test_df, categories=CATEGORIES_OF_INTEREST)

    print(f"  score distribution: {test_summary}")
    print(f"  risk level distribution: {test_levels}")
    print(f"  benign vs attack mean risk: {test_sep['benign']['mean']:.2f} vs {test_sep['attack']['mean']:.2f}")
    print(f"  high-risk (>= {HIGH_RISK_THRESHOLD}) precision={test_pr['precision']:.4f} recall={test_pr['recall']:.4f} f1={test_pr['f1']:.4f}")
    print("\n  Comparison vs anomaly-score-alone (stealthy attack categories):")
    for category, result in comparison.items():
        print(f"    {category}: {result}")
    print("\n  Edge-volume context (self-referential-leakage check -- see docs/risk_engine.md):")
    for category, result in edge_volume_context.items():
        print(f"    {category}: {result}")
    print("\n  Per-attack risk table:")
    print(per_attack.to_string(index=False))

    config.save(OUTPUT_DIR / "config.json")
    (OUTPUT_DIR / "data_bridge_report.json").write_text(json.dumps(bridge_report, indent=2), encoding="utf-8")
    per_attack.to_csv(OUTPUT_DIR / "per_attack_risk.csv", index=False)
    (OUTPUT_DIR / "evaluation_report.json").write_text(
        json.dumps(
            {
                "val_summary": val_summary,
                "val_benign_vs_attack": val_sep,
                "test_summary": test_summary,
                "test_risk_level_distribution": test_levels,
                "test_benign_vs_attack": test_sep,
                "test_high_risk_precision_recall": test_pr,
                "comparison_vs_anomaly_alone": comparison,
                "edge_volume_context": edge_volume_context,
                "val_rows": len(val_df),
                "test_rows": len(test_df),
                "total_runtime_seconds": round(time.monotonic() - start, 2),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nTotal runtime: {time.monotonic() - start:.1f}s")
    print(f"Artifacts written under: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
