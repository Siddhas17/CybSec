"""Builds the security-report PDF via ReportLab. One function per section
(spec order: title/date -> system info -> active model -> dataset -> training
info -> evaluation metrics -> anomalies -> risk analysis -> timeline ->
attack graph -> alerts -> prevention -> threat stats -> recommendations ->
overall summary), each appending flowables to a shared `story` list.
Charts come in as already-rendered in-memory PNGs from report_charts.py --
this module never queries a database or computes a metric, it only lays
out numbers report_service.py already gathered.
"""

from __future__ import annotations

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from backend.app.services import report_charts

_STYLES = getSampleStyleSheet()
_H1 = ParagraphStyle("H1", parent=_STYLES["Heading1"], spaceAfter=6)
_H2 = ParagraphStyle("H2", parent=_STYLES["Heading2"], spaceBefore=14, spaceAfter=6)
_BODY = _STYLES["BodyText"]
_NOTE = ParagraphStyle("Note", parent=_STYLES["BodyText"], textColor=colors.HexColor("#555555"), fontSize=8.5, spaceBefore=4, spaceAfter=4)
_TABLE_STYLE = TableStyle(
    [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6edf5")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
)


def _kv_table(pairs: list[tuple[str, object]]) -> Table:
    rows = [[str(k), "--" if v is None else str(v)] for k, v in pairs]
    t = Table(rows, colWidths=[6.5 * cm, 9.5 * cm])
    t.setStyle(_TABLE_STYLE)
    return t


def _data_table(header: list[str], rows: list[list]) -> Table:
    t = Table([header] + [[("--" if c is None else str(c)) for c in r] for r in rows])
    t.setStyle(_TABLE_STYLE)
    return t


def _image(png: io.BytesIO, width_cm: float = 12.0) -> Image:
    img = Image(png)
    aspect = img.imageHeight / img.imageWidth
    img.drawWidth = width_cm * cm
    img.drawHeight = width_cm * cm * aspect
    return img


def _section_title(story: list, generated_at: datetime, generated_by: str) -> None:
    story.append(Paragraph("Intelligent Cybersecurity System Using Attack Graphs", _H1))
    story.append(Paragraph("Security Report", _STYLES["Heading2"]))
    story.append(Paragraph(f"Generated: {generated_at.strftime('%Y-%m-%d %H:%M UTC')} by {generated_by}", _BODY))
    story.append(Spacer(1, 12))


def _section_system_info(story: list, context: dict) -> None:
    story.append(Paragraph("1. System Overview", _H2))
    story.append(Paragraph(context["system_info"], _BODY))


def _section_active_model(story: list, context: dict) -> None:
    story.append(Paragraph("2. Active Model", _H2))
    story.append(_kv_table(list(context["active_model"].items())))


def _section_dataset(story: list, context: dict) -> None:
    story.append(Paragraph("3. Dataset & Training Information", _H2))
    stats = context["dataset_stats"]
    if not stats.get("available"):
        story.append(Paragraph(stats.get("reason", "Dataset statistics unavailable."), _NOTE))
        return
    story.append(
        _kv_table(
            [
                ("Files loaded", len(stats.get("files_loaded") or [])),
                ("Rows before dedup", stats.get("rows_before_dedup")),
                ("Duplicate rows removed", stats.get("exact_duplicate_rows")),
                ("Rows after cleaning", stats.get("rows_after_inf_nan_handling")),
                ("Train / Val / Test split", stats.get("split_sizes")),
            ]
        )
    )


def _section_evaluation_metrics(story: list, context: dict) -> None:
    story.append(Paragraph("4. Model Evaluation Metrics", _H2))
    ae = context["autoencoder_metrics"]
    story.append(Paragraph("Autoencoder -- Anomaly Detection Evaluation (Held-Out Test Set)", _STYLES["Heading3"]))
    if not ae.get("available"):
        story.append(Paragraph(ae.get("reason", "Not evaluated."), _NOTE))
    else:
        story.append(
            Paragraph(
                "This is anomaly-detection evaluation, not classification accuracy -- the model is trained only "
                "on BENIGN traffic and flags deviation from it.",
                _NOTE,
            )
        )
        story.append(
            _kv_table(
                [
                    ("Precision", f"{ae['precision']:.4f}" if ae.get("precision") is not None else None),
                    ("Recall", f"{ae['recall']:.4f}" if ae.get("recall") is not None else None),
                    ("F1", f"{ae['f1']:.4f}" if ae.get("f1") is not None else None),
                    ("ROC-AUC", f"{ae['roc_auc']:.4f}" if ae.get("roc_auc") is not None else None),
                    ("PR-AUC", f"{ae['pr_auc']:.4f}" if ae.get("pr_auc") is not None else None),
                    ("Anomaly threshold", ae.get("threshold")),
                ]
            )
        )
        story.append(Spacer(1, 6))
        story.append(_image(report_charts.confusion_matrix_heatmap_png(ae.get("confusion_matrix") or {}, "Autoencoder Confusion Matrix"), width_cm=8))

    story.append(Spacer(1, 10))
    knn = context["knn_metrics"]
    story.append(Paragraph("KNN -- Supervised Classification Evaluation (Held-Out Test Set)", _STYLES["Heading3"]))
    if not knn.get("available"):
        story.append(Paragraph(knn.get("reason", "KNN evaluation is unavailable until the model is implemented."), _NOTE))
    else:
        story.append(
            Paragraph(
                f"Primary averaging method: {knn.get('primary_averaging_method')}. {knn.get('note_on_averaging', '')}",
                _NOTE,
            )
        )
        story.append(
            _kv_table(
                [
                    ("Accuracy", f"{knn['accuracy']:.4f}" if knn.get("accuracy") is not None else None),
                    ("Precision (weighted)", f"{knn['precision_weighted']:.4f}" if knn.get("precision_weighted") is not None else None),
                    ("Recall (weighted)", f"{knn['recall_weighted']:.4f}" if knn.get("recall_weighted") is not None else None),
                    ("F1 (weighted)", f"{knn['f1_weighted']:.4f}" if knn.get("f1_weighted") is not None else None),
                    ("Precision (macro)", f"{knn['precision_macro']:.4f}" if knn.get("precision_macro") is not None else None),
                    ("Recall (macro)", f"{knn['recall_macro']:.4f}" if knn.get("recall_macro") is not None else None),
                    ("F1 (macro)", f"{knn['f1_macro']:.4f}" if knn.get("f1_macro") is not None else None),
                    ("K", knn.get("k")),
                ]
            )
        )
        story.append(Spacer(1, 6))
        story.append(_image(report_charts.confusion_matrix_heatmap_png(knn.get("confusion_matrix") or {}, "KNN Confusion Matrix"), width_cm=8))
        dist = knn.get("test_class_distribution")
        if dist:
            story.append(Spacer(1, 6))
            story.append(
                Paragraph(
                    f"Test set class distribution: BENIGN {dist['benign_count']:,} ({dist['benign_pct']:.2f}%), "
                    f"ATTACK {dist['attack_count']:,} ({dist['attack_pct']:.2f}%). This dataset is highly imbalanced "
                    "toward BENIGN traffic -- accuracy alone can be misleading; precision/recall/F1 above are the "
                    "more reliable indicators of attack-detection performance.",
                    _NOTE,
                )
            )

    if ae.get("available") and knn.get("available"):
        story.append(Spacer(1, 10))
        story.append(Paragraph("Model Comparison", _STYLES["Heading3"]))
        story.append(
            Paragraph(
                "The autoencoder is unsupervised (BENIGN-only reconstruction); KNN is supervised (BENIGN vs ATTACK "
                "labels). Both are evaluated on the same held-out test split, so this comparison is illustrative "
                "of two different detection strategies, not an apples-to-apples model selection.",
                _NOTE,
            )
        )
        story.append(
            _data_table(
                ["Metric", "Autoencoder", "KNN"],
                [
                    ["Precision", f"{ae.get('precision', 0):.4f}", f"{knn.get('precision_weighted', 0):.4f}"],
                    ["Recall", f"{ae.get('recall', 0):.4f}", f"{knn.get('recall_weighted', 0):.4f}"],
                    ["F1", f"{ae.get('f1', 0):.4f}", f"{knn.get('f1_weighted', 0):.4f}"],
                    ["ROC-AUC", f"{ae.get('roc_auc', 0):.4f}", f"{knn.get('roc_auc', 0):.4f}"],
                ],
            )
        )


def _section_anomaly_and_risk(story: list, context: dict) -> None:
    story.append(PageBreak())
    story.append(Paragraph("5. Detected Anomalies, Attacks & Risk Analysis", _H2))
    summary = context["summary"]
    story.append(
        _kv_table(
            [
                ("Total events", summary.get("total_events")),
                ("Detected anomalies", summary.get("anomaly_count")),
                ("High-risk events", summary.get("high_risk_events")),
                ("Benign events", summary.get("benign_count")),
            ]
        )
    )
    story.append(Spacer(1, 8))
    story.append(_image(report_charts.anomaly_score_distribution_png(context["anomaly_score_buckets"]), width_cm=12))
    story.append(Spacer(1, 8))
    story.append(_image(report_charts.risk_score_distribution_png(context["risk_score_buckets"]), width_cm=12))
    if context["risk_distribution"]:
        story.append(Spacer(1, 8))
        story.append(
            _data_table(
                ["Risk Level", "Count"],
                [[r["risk_level"], r["count"]] for r in context["risk_distribution"]],
            )
        )
    if context["attacks_by_type"]:
        story.append(Spacer(1, 8))
        story.append(_image(report_charts.attacks_by_type_png(context["attacks_by_type"]), width_cm=12))


def _section_timeline_and_graph(story: list, context: dict) -> None:
    story.append(PageBreak())
    story.append(Paragraph("6. Attack Timeline & Attack Graph Summary", _H2))
    story.append(_image(report_charts.attack_timeline_png(context["timeline"]), width_cm=12))
    story.append(Spacer(1, 10))
    story.append(
        _kv_table(
            [
                ("Attack graph nodes", context["graph_node_count"]),
                ("Attack graph edges", context["graph_edge_count"]),
            ]
        )
    )
    if context["top_destinations"]:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Top Attacked Destination IPs", _STYLES["Heading3"]))
        story.append(
            Paragraph(
                "This is a single-machine environment; these are destination IPs observed in captured traffic, "
                "not separate physical victim hosts.",
                _NOTE,
            )
        )
        story.append(
            _data_table(
                ["IP", "Attack Flows", "Total Flows"],
                [[n["ip"], n["attack_flow_count"], n["total_flow_count"]] for n in context["top_destinations"]],
            )
        )


def _section_live_detection(story: list, context: dict) -> None:
    story.append(PageBreak())
    story.append(Paragraph("7. Live Detection Events", _H2))
    live = context["live_vs_offline"]["live"]
    story.append(
        _kv_table(
            [
                ("Total live events", live["total_live_events"]),
                ("Detected anomalies", live["detected_anomalies"]),
                ("Alerts", live["alerts"]),
                ("Prevented / would-block", live["threats_prevented_or_would_block"]),
                ("Average risk score", f"{live['average_risk_score']:.2f}" if live.get("average_risk_score") is not None else None),
            ]
        )
    )
    story.append(Spacer(1, 6))
    story.append(Paragraph(live["live_accuracy_note"], _NOTE))


def _section_alerts_and_prevention(story: list, context: dict) -> None:
    story.append(Paragraph("8. Alerts & Prevention Actions", _H2))
    by_action = context["prevention_by_action"]
    if not by_action:
        story.append(Paragraph("No prevention actions recorded.", _BODY))
    else:
        story.append(_data_table(["Action", "Count"], [[k, v] for k, v in by_action.items()]))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "Prevention in this deployment runs in dry-run mode only -- no traffic has ever actually been blocked; "
            "'blocked'/'would_block' rows above reflect simulated response decisions, not real firewall changes.",
            _NOTE,
        )
    )


def _section_recommendations_and_summary(story: list, context: dict) -> None:
    story.append(PageBreak())
    story.append(Paragraph("9. Threat Statistics & Recommendations", _H2))

    ae = context["autoencoder_metrics"]
    summary = context["summary"]
    recommendations: list[str] = []
    if ae.get("available"):
        fp = (ae.get("confusion_matrix") or {}).get("fp") or 0
        tn = (ae.get("confusion_matrix") or {}).get("tn") or 0
        fpr = ae.get("false_positive_rate")
        if fpr is not None:
            recommendations.append(
                f"The autoencoder produced {fp:,} false positives against {tn + fp:,} benign test flows "
                f"({fpr:.2%} false-positive rate) -- review the anomaly threshold if this rate is operationally too high."
            )
        recall = ae.get("recall")
        if recall is not None and recall < 0.7:
            recommendations.append(
                f"Attack recall on the held-out test set is {recall:.2%} -- a meaningful share of attacks in this "
                "dataset go undetected; see per-attack-type breakdown in ml/models/artifacts/autoencoder/per_attack_evaluation.csv."
            )
    if (summary.get("high_risk_events") or 0) == 0:
        recommendations.append("No high-risk events are currently recorded -- run offline ingestion or the live sensor to populate detection data.")
    if not recommendations:
        recommendations.append("No specific recommendations triggered by the current figures in this report.")

    for r in recommendations:
        story.append(Paragraph(f"- {r}", _BODY))

    story.append(Spacer(1, 10))
    story.append(Paragraph("10. Overall Security Summary", _H2))
    story.append(
        Paragraph(
            f"This report covers {summary.get('total_events', 0):,} recorded events, of which "
            f"{summary.get('anomaly_count', 0):,} were flagged anomalous and {summary.get('high_risk_events', 0):,} "
            f"reached a high-risk classification. System health: {summary.get('system_health', 'unknown')}.",
            _BODY,
        )
    )


def build_pdf(context: dict, generated_by: str, generated_at: datetime) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm, leftMargin=1.8 * cm, rightMargin=1.8 * cm)

    story: list = []
    _section_title(story, generated_at, generated_by)
    _section_system_info(story, context)
    _section_active_model(story, context)
    _section_dataset(story, context)
    _section_evaluation_metrics(story, context)
    _section_anomaly_and_risk(story, context)
    _section_timeline_and_graph(story, context)
    _section_live_detection(story, context)
    _section_alerts_and_prevention(story, context)
    _section_recommendations_and_summary(story, context)

    doc.build(story)
    return buffer.getvalue()
