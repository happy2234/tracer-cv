"""Safe, offline PDF rendering of an already-persisted C5 report."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import hashlib
from pathlib import Path
from typing import Any

from PySide6.QtCore import QRectF, QSizeF, Qt, QMarginsF
from PySide6.QtGui import QPageLayout, QPageSize, QPainter, QPdfWriter, QTextDocument


def display(value: Any, *, limit: int = 10, depth: int = 0) -> str:
    if value is None or value == "":
        return "Unavailable"
    if isinstance(value, dict):
        if depth >= 2:
            return "Structured evidence recorded"
        return "; ".join(f"{key}: {display(item, limit=limit, depth=depth + 1)}" for key, item in list(value.items())[:limit]) or "No values recorded"
    if isinstance(value, (list, tuple)):
        if not value:
            return "None recorded"
        return "; ".join(display(item, limit=limit, depth=depth + 1) for item in value[:limit]) + ("; …" if len(value) > limit else "")
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


def section_content(report: dict[str, Any]) -> list[tuple[str, list[tuple[str, str]]]]:
    """Make a compact analyst view from C5's stored, structured fields."""
    sections: list[tuple[str, list[tuple[str, str]]]] = []
    summary = report.get("executive_summary")
    if isinstance(summary, dict):
        fields = [("Assessment scope", display(summary.get("assessment_scope"))),
                  ("Finding count", display(summary.get("finding_count"))),
                  ("Highest observed severity", display(summary.get("highest_observed_severity"))),
                  ("Severity counts", display(summary.get("severity_counts"))),
                  ("Provenance chain validity", display(summary.get("provenance_chain_valid"))),
                  ("Audit chain validity", display(summary.get("audit_chain_valid"))),
                  ("Distribution shift recorded", display(summary.get("distribution_shift_detected"))),
                  ("Interpretation", display(summary.get("interpretation")))]
        sections.append(("1. Executive Summary", fields))
    else:
        sections.append(("1. Executive Summary", [("Status", "Executive summary unavailable in the persisted C5 report.")]))

    coverage = report.get("asset_coverage")
    rows = []
    if isinstance(coverage, dict):
        for name, value in coverage.items():
            if isinstance(value, dict):
                details = {k: v for k, v in value.items() if k not in {"assessed"}}
                rows.append((str(name).replace("_", " ").title(), display(details)))
    sections.append(("2. Assessment & Asset Coverage", rows or [("Coverage", "Unavailable in the persisted C5 report.")]))

    engine_sections = (
        ("3. Dataset Integrity", "dataset_integrity", ("A1_manifest", "A2_exact_duplicates", "A3_near_duplicates", "A4_ood", "A5_label_consistency", "A6_contributor_risk", "A7_metadata_consistency", "A8_poison_trigger_forensics")),
        ("4. Model Integrity", "model_integrity", ("B1_identity", "B2_behavioral_fingerprint", "B3_model_statistics", "B4_trigger_search")),
    )
    for title, key, engine_names in engine_sections:
        block = report.get(key)
        engine_result = block.get("engine_result") if isinstance(block, dict) else None
        rows = []
        if isinstance(engine_result, dict):
            for engine in engine_names:
                value = engine_result.get(engine)
                if isinstance(value, dict):
                    metrics = {k: v for k, v in value.items() if k in {
                        "status", "reason", "file_count", "dataset_sha256", "duplicate_group_count",
                        "near_duplicate_pair_count", "potential_ood_count", "finding_count", "conflicting_pair_count",
                        "risk_level", "image_finding_count", "candidate_trigger_count", "total_parameters",
                        "trainable_parameters", "activation_status", "record_count", "valid", "reason", "error",
                        "limitations", "warnings",
                    }}
                    rows.append((engine, display(metrics) if metrics else display(value.get("status"))))
        if not rows:
            rows.append(("Status", display(block.get("status") if isinstance(block, dict) else None)))
            if isinstance(block, dict) and block.get("message"):
                rows.append(("Reason", display(block.get("message"))))
        sections.append((title, rows))

    for title, key, fields in (
        ("5. Inference Provenance", "inference_provenance", ("status", "valid", "record_count", "signature_status", "replay_status")),
        ("6. Distribution Shift", "distribution_shift", ("status", "shift_detected", "severity", "overall_shift")),
        ("8. Audit Trail", "audit_trail", ("status", "valid", "entry_count", "finding_count")),
    ):
        block = report.get(key)
        rows = []
        if isinstance(block, dict):
            rows.extend((field, display(block.get(field))) for field in fields if field in block)
            engine_result = block.get("engine_result")
            if isinstance(engine_result, dict):
                for field in fields:
                    if field not in block and field in engine_result:
                        rows.append((field, display(engine_result.get(field))))
        if not rows:
            rows = [("Status", display(block.get("status") if isinstance(block, dict) else None))]
            if isinstance(block, dict) and block.get("message"):
                rows.append(("Reason", display(block.get("message"))))
        if key == "inference_provenance" and isinstance(block, dict):
            engine = block.get("engine_result") if isinstance(block.get("engine_result"), dict) else {}
            records = engine.get("records")
            if isinstance(records, list):
                valid_records = [record for record in records if isinstance(record, dict)]
                signed = sum(bool(record.get("signature")) for record in valid_records)
                rows.append(("Records containing signatures", f"{signed} of {len(valid_records)}"))
            verification = engine.get("verification") if isinstance(engine.get("verification"), dict) else {}
            replay = next((verification[name] for name in ("replay_status", "replay_detected", "replay_findings") if name in verification), None)
            rows.append(("Persisted replay evidence", display(replay) if replay is not None else "Unavailable (not recorded in the C5 result)"))
        sections.append((title, rows))

    findings_block = report.get("findings_and_evidence")
    findings = findings_block.get("findings") if isinstance(findings_block, dict) else None
    finding_rows = []
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            desc = " · ".join(f"{name}: {display(finding.get(key))}" for name, key in (
                ("Severity", "severity"), ("Confidence", "confidence"), ("Category", "category"),
                ("Asset", "affected_asset"), ("Source", "source_engine"), ("Explanation", "explanation"),
                ("Evidence", "evidence"), ("Recommended action", "recommended_action"), ("Limitations", "limitations"),
            ) if finding.get(key) is not None)
            finding_rows.append((f"{display(finding.get('finding_id'))} · {display(finding.get('title'))}", desc or "Finding fields unavailable."))
    sections.insert(6, ("7. Findings & Evidence", finding_rows or [("Findings", "No findings recorded in this C5 report.")]))

    actions = report.get("recommended_actions")
    sections.append(("9. Recommended Actions", [(f"Action {index + 1}", display(action)) for index, action in enumerate(actions)] if isinstance(actions, list) and actions else [("Actions", "No recommendations recorded.")]))
    limitations = report.get("limitations")
    sections.append(("10. Limitations & Coverage", [(f"Limitation {index + 1}", display(item)) for index, item in enumerate(limitations)] if isinstance(limitations, list) and limitations else [("Limitations", "No limitations were recorded in this C5 report.")]))
    return sections


def _html(report: dict[str, Any], assessment: dict[str, Any], exported_at: str) -> str:
    assessment_id = report.get("assessment_id") or assessment.get("assessment_id") or "Unavailable"
    status = assessment.get("status") or "Unavailable"
    assessed_at = assessment.get("completed_at") or assessment.get("started_at") or "Unavailable"
    digest = report.get("report_digest") or "Unavailable"
    rows = []
    findings_block = report.get("findings_and_evidence")
    raw_findings = findings_block.get("findings") if isinstance(findings_block, dict) else []
    finding_severities = [str(item.get("severity", "")).strip().lower() for item in raw_findings if isinstance(item, dict)] if isinstance(raw_findings, list) else []
    for title, pairs in section_content(report):
        rows.append(f'<section><h2>{escape(title)}</h2>')
        if title.endswith("Findings & Evidence"):
            severity_colors = {"critical": "#922f35", "high": "#b64040", "medium": "#a77918", "low": "#418b68", "none": "#607985"}
            for index, (heading, body) in enumerate(pairs):
                severity = finding_severities[index] if index < len(finding_severities) else ""
                color = severity_colors.get(severity, "#607985")
                rows.append(f'<article style="border-left-color:{color}"><h3>{escape(heading)}</h3><p>{escape(body)}</p></article>')
        else:
            rows.append('<table><tbody>')
            for label, value in pairs:
                rows.append(f'<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>')
            rows.append('</tbody></table>')
        rows.append('</section>')
    return f'''<!doctype html><html><head><meta charset="utf-8"><style>
    body {{ font-family: sans-serif; color:#202a35; font-size:10pt; }}
    h1 {{ color:#18384b; font-size:25pt; margin:0 0 4pt; }} h2 {{ color:#18384b; font-size:15pt; border-bottom:1px solid #98aab5; padding-bottom:4pt; margin-top:20pt; }}
    h3 {{ color:#294b60; font-size:11pt; margin:6pt 0 3pt; }} p {{ margin:3pt 0 7pt; }}
    .brand {{ color:#526775; font-size:10pt; letter-spacing:1pt; }} .meta {{ background:#eef2f4; padding:8pt; }}
    table {{ width:100%; border-collapse:collapse; }} th,td {{ text-align:left; vertical-align:top; border-bottom:1px solid #d5dde1; padding:4pt 6pt; }} th {{ width:27%; background:#f5f7f8; }}
    article {{ border-left:3px solid #7c9aac; padding:2pt 8pt; margin:7pt 0; }}
    </style></head><body><div class="brand">TRACER-CV · TRUST, RELIABILITY &amp; ASSURANCE FOR COMPUTER VISION</div>
    <h1>Assurance Report</h1><div class="meta"><b>Assessment ID:</b> {escape(str(assessment_id))}<br/>
    <b>Assessment status:</b> {escape(str(status))}<br/><b>Assessment timestamp:</b> {escape(str(assessed_at))}<br/>
    <b>C5 report version:</b> {escape(str(report.get('report_version') or 'Unavailable'))}<br/>
    <b>C5 report digest:</b> {escape(str(digest))}<br/><b>Operation:</b> Offline / local · no network service required<br/>
    <b>Document export timestamp (UTC):</b> {escape(exported_at)}</div>{''.join(rows)}</body></html>'''


def write_assurance_pdf(report: dict[str, Any], assessment: dict[str, Any], target: str | Path) -> dict[str, str]:
    """Write a paginated local PDF from persisted C5 data; return export digest."""
    target = Path(target).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    exported_at = datetime.now(timezone.utc).isoformat()
    writer = QPdfWriter(str(target))
    writer.setTitle("TRACER-CV Assurance Report")
    writer.setCreator("TRACER-CV")
    writer.setResolution(96)
    writer.setPageLayout(QPageLayout(QPageSize(QPageSize.PageSizeId.A4), QPageLayout.Orientation.Portrait,
                                     QMarginsF(16, 16, 18, 18), QPageLayout.Unit.Millimeter))
    paint_rect = writer.pageLayout().paintRectPixels(writer.resolution())
    footer_height = 34
    doc = QTextDocument()
    doc.setDocumentMargin(0)
    doc.setHtml(_html(report, assessment, exported_at))
    content_size = QSizeF(paint_rect.width(), paint_rect.height() - footer_height)
    doc.setPageSize(content_size)
    page_count = max(1, doc.pageCount())
    painter = QPainter()
    if not painter.begin(writer):
        raise OSError("The local PDF writer could not be initialized.")
    try:
        for page in range(page_count):
            if page and not writer.newPage():
                raise OSError("The local PDF writer could not create a page.")
            painter.save()
            painter.translate(paint_rect.left(), paint_rect.top() - page * content_size.height())
            doc.drawContents(painter, QRectF(0, page * content_size.height(), content_size.width(), content_size.height()))
            painter.restore()
            painter.save()
            painter.setPen(Qt.GlobalColor.darkGray)
            painter.translate(paint_rect.left(), paint_rect.top())
            painter.drawLine(0, int(content_size.height() + 8), int(content_size.width()), int(content_size.height() + 8))
            painter.drawText(0, int(content_size.height() + 23), f"TRACER-CV · {report.get('assessment_id') or assessment.get('assessment_id') or 'Assessment'}")
            painter.drawText(int(content_size.width() - 82), int(content_size.height() + 23), f"Page {page + 1} of {page_count}")
            painter.restore()
    finally:
        painter.end()
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return {"path": str(target), "sha256": digest, "exported_at": exported_at}
