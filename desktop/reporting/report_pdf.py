"""Safe, offline PDF rendering of persisted TRACER-CV assessment data.

All functions are read-only with respect to assessment state: they never
rerun engines, modify findings, update audit records, or mutate any persisted
assessment object.
"""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import hashlib
from pathlib import Path
from typing import Any

from PySide6.QtCore import QRectF, QSizeF, Qt, QMarginsF
from PySide6.QtGui import QPageLayout, QPageSize, QPainter, QPdfWriter, QTextDocument


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def display(value: Any, *, limit: int = 10, depth: int = 0) -> str:
    if value is None or value == "":
        return "Unavailable"
    if isinstance(value, dict):
        if depth >= 2:
            return "Structured evidence recorded"
        return ("; ".join(
            f"{key}: {display(item, limit=limit, depth=depth + 1)}"
            for key, item in list(value.items())[:limit]
        ) or "No values recorded")
    if isinstance(value, (list, tuple)):
        if not value:
            return "None recorded"
        return ("; ".join(
            display(item, limit=limit, depth=depth + 1) for item in value[:limit]
        ) + ("; …" if len(value) > limit else ""))
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


# ---------------------------------------------------------------------------
# Section content extraction (unchanged logic from previous version)
# ---------------------------------------------------------------------------

def section_content(report: dict[str, Any]) -> list[tuple[str, list[tuple[str, str]]]]:
    """Make a compact analyst view from C5's stored, structured fields."""
    sections: list[tuple[str, list[tuple[str, str]]]] = []
    summary = report.get("executive_summary")
    if isinstance(summary, dict):
        fields = [
            ("Assessment scope", display(summary.get("assessment_scope"))),
            ("Finding count", display(summary.get("finding_count"))),
            ("Highest observed severity", display(summary.get("highest_observed_severity"))),
            ("Severity counts", display(summary.get("severity_counts"))),
            ("Provenance chain validity", display(summary.get("provenance_chain_valid"))),
            ("Audit chain validity", display(summary.get("audit_chain_valid"))),
            ("Distribution shift recorded", display(summary.get("distribution_shift_detected"))),
            ("Interpretation", display(summary.get("interpretation"))),
        ]
        sections.append(("1. Executive Summary", fields))
    else:
        sections.append(("1. Executive Summary", [
            ("Status", "Executive summary unavailable in the persisted C5 report."),
        ]))

    coverage = report.get("asset_coverage")
    rows = []
    if isinstance(coverage, dict):
        for name, value in coverage.items():
            if isinstance(value, dict):
                details = {k: v for k, v in value.items() if k not in {"assessed"}}
                rows.append((str(name).replace("_", " ").title(), display(details)))
    sections.append(("2. Assessment & Asset Coverage",
                     rows or [("Coverage", "Unavailable in the persisted C5 report.")]))

    engine_sections = (
        ("3. Dataset Integrity", "dataset_integrity",
         ("A1_manifest", "A2_exact_duplicates", "A3_near_duplicates", "A4_ood",
          "A5_label_consistency", "A6_contributor_risk", "A7_metadata_consistency",
          "A8_poison_trigger_forensics")),
        ("4. Model Integrity", "model_integrity",
         ("B1_identity", "B2_behavioral_fingerprint", "B3_model_statistics",
          "B4_trigger_search")),
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
                        "status", "reason", "file_count", "dataset_sha256",
                        "duplicate_group_count", "near_duplicate_pair_count",
                        "potential_ood_count", "finding_count", "conflicting_pair_count",
                        "risk_level", "image_finding_count", "candidate_trigger_count",
                        "total_parameters", "trainable_parameters", "activation_status",
                        "record_count", "valid", "error", "limitations", "warnings",
                    }}
                    rows.append((engine,
                                 display(metrics) if metrics else display(value.get("status"))))
        if not rows:
            rows.append(("Status",
                         display(block.get("status") if isinstance(block, dict) else None)))
            if isinstance(block, dict) and block.get("message"):
                rows.append(("Reason", display(block.get("message"))))
        sections.append((title, rows))

    for title, key, fields in (
        ("5. Inference Provenance", "inference_provenance",
         ("status", "valid", "record_count", "signature_status", "replay_status")),
        ("6. Distribution Shift", "distribution_shift",
         ("status", "shift_detected", "severity", "overall_shift")),
        ("8. Audit Trail", "audit_trail",
         ("status", "valid", "entry_count", "finding_count")),
    ):
        block = report.get(key)
        rows = []
        if isinstance(block, dict):
            rows.extend(
                (field, display(block.get(field)))
                for field in fields if field in block
            )
            engine_result = block.get("engine_result")
            if isinstance(engine_result, dict):
                for field in fields:
                    if field not in block and field in engine_result:
                        rows.append((field, display(engine_result.get(field))))
        if not rows:
            rows = [("Status",
                     display(block.get("status") if isinstance(block, dict) else None))]
            if isinstance(block, dict) and block.get("message"):
                rows.append(("Reason", display(block.get("message"))))
        if key == "inference_provenance" and isinstance(block, dict):
            engine = (block.get("engine_result")
                      if isinstance(block.get("engine_result"), dict) else {})
            records = engine.get("records")
            if isinstance(records, list):
                valid_records = [r for r in records if isinstance(r, dict)]
                signed = sum(bool(r.get("signature")) for r in valid_records)
                rows.append(("Records containing signatures",
                             f"{signed} of {len(valid_records)}"))
            verification = (engine.get("verification")
                            if isinstance(engine.get("verification"), dict) else {})
            replay = next(
                (verification[n] for n in ("replay_status", "replay_detected",
                                           "replay_findings") if n in verification),
                None,
            )
            rows.append(("Persisted replay evidence",
                         display(replay) if replay is not None
                         else "Unavailable (not recorded in the C5 result)"))
        if key == "distribution_shift" and isinstance(block, dict):
            engine = (block.get("engine_result")
                      if isinstance(block.get("engine_result"), dict) else block)
            if engine.get("overall_shift") is not None:
                rows.append(("Calibration status",
                             "NOT CALIBRATED — this heuristic shift magnitude is not "
                             "an attack or maliciousness probability."))
        sections.append((title, rows))

    findings_block = report.get("findings_and_evidence")
    findings = (findings_block.get("findings")
                if isinstance(findings_block, dict) else None)
    finding_rows = []
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            desc = " · ".join(
                f"{name}: {display(finding.get(k))}"
                for name, k in (
                    ("Severity", "severity"), ("Confidence", "confidence"),
                    ("Category", "category"), ("Asset", "affected_asset"),
                    ("Source", "source_engine"), ("Explanation", "explanation"),
                    ("Evidence", "evidence"), ("Recommended action", "recommended_action"),
                    ("Limitations", "limitations"),
                )
                if finding.get(k) is not None
            )
            finding_rows.append((
                f"{display(finding.get('finding_id'))} · {display(finding.get('title'))}",
                desc or "Finding fields unavailable.",
            ))
    sections.insert(6, ("7. Findings & Evidence",
                        finding_rows or [("Findings",
                                          "No findings recorded in this C5 report.")]))

    actions = report.get("recommended_actions")
    sections.append(("9. Recommended Actions",
                     [(f"Action {i + 1}", display(a)) for i, a in enumerate(actions)]
                     if isinstance(actions, list) and actions
                     else [("Actions", "No recommendations recorded.")]))

    limitations = report.get("limitations")
    sections.append(("10. Limitations & Coverage",
                     [(f"Limitation {i + 1}", display(item))
                      for i, item in enumerate(limitations)]
                     if isinstance(limitations, list) and limitations
                     else [("Limitations",
                            "No limitations were recorded in this C5 report.")]))
    return sections


# ---------------------------------------------------------------------------
# HTML builder — professional cover page + structured body
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "critical": "#922f35",
    "high":     "#b64040",
    "medium":   "#a77918",
    "low":      "#418b68",
    "none":     "#607985",
}

_CSS = """
body { font-family: sans-serif; color: #1e2d38; font-size: 9.5pt; margin: 0; }
h1  { color: #18384b; font-size: 22pt; margin: 0 0 4pt; }
h2  { color: #18384b; font-size: 13pt; border-bottom: 1.5px solid #b0bec5;
      padding-bottom: 4pt; margin-top: 22pt; margin-bottom: 8pt; }
h3  { color: #294b60; font-size: 10.5pt; margin: 6pt 0 3pt; }
p   { margin: 3pt 0 7pt; }
.brand   { color: #526775; font-size: 8.5pt; letter-spacing: 1.5pt; margin-bottom: 6pt; }
.ps      { color: #7a95a8; font-size: 8.5pt; letter-spacing: 1pt; }
.cover   { text-align: center; padding-top: 100px; }
.cover-title { font-size: 28pt; font-weight: 700; color: #18384b; margin: 6pt 0; }
.cover-sub   { font-size: 11pt; color: #435568; margin-bottom: 18pt; }
.cover-meta  { margin: 0 auto; width: 500px; border-collapse: collapse; }
.cover-meta td { padding: 6pt 14pt; font-size: 9.5pt; }
.cover-meta .lbl { text-align: right; color: #526775; }
.cover-meta .val { font-weight: 700; color: #18384b; }
.cover-meta .mono { font-family: monospace; font-size: 8pt; color: #7a95a8; }
.cover-footer { margin-top: 40pt; font-size: 8pt; color: #a0b0bc; letter-spacing: 1pt; }
.meta  { background: #f2f6f8; padding: 8pt 10pt; border-radius: 3px;
         border: 1px solid #dde4ea; margin-bottom: 10pt; font-size: 9pt; }
.scope { background: #eef3f7; padding: 8pt 10pt; border-radius: 3px;
         border: 1px solid #c8d5df; margin-bottom: 12pt; font-size: 9pt; }
table   { width: 100%; border-collapse: collapse; margin-bottom: 6pt; }
th, td  { text-align: left; vertical-align: top; border-bottom: 1px solid #dde4ea;
          padding: 4pt 7pt; }
th      { width: 26%; background: #f5f7f8; color: #435568;
          font-weight: 700; font-size: 8.5pt; }
article { border-left: 3px solid #7c9aac; padding: 3pt 9pt 6pt;
          margin: 8pt 0; background: #fafcfd; border-radius: 0 4px 4px 0; }
.sev-critical { border-left-color: #922f35; }
.sev-high     { border-left-color: #b64040; }
.sev-medium   { border-left-color: #a77918; }
.sev-low      { border-left-color: #418b68; }
.callout { background: #fff8e6; border: 1px solid #f0d090; border-left: 3px solid #c48b24;
           padding: 6pt 9pt; border-radius: 0 4px 4px 0; margin: 8pt 0;
           font-size: 9pt; color: #5a4010; }
"""


def _html(report: dict[str, Any], assessment: dict[str, Any], exported_at: str) -> str:
    assessment_id = (report.get("assessment_id")
                     or assessment.get("assessment_id") or "Unavailable")
    status = assessment.get("status") or "Unavailable"
    assessed_at = (assessment.get("completed_at")
                   or assessment.get("started_at") or "Unavailable")
    digest = report.get("report_digest") or "Unavailable"
    digest_short = str(digest)[:48] + ("…" if len(str(digest)) > 48 else "")

    # Cover page
    cover = f"""
<div class="cover" style="page-break-after:always">
  <div class="brand">TRACER-CV</div>
  <div class="cover-title">Assurance Report</div>
  <div class="cover-sub">Trust, Reliability &amp; Assurance for Computer Vision</div>
  <div class="ps">PS-26228</div>
  <br/>
  <table class="cover-meta">
    <tr><td class="lbl">Assessment ID:</td>
        <td class="val">{escape(str(assessment_id))}</td></tr>
    <tr><td class="lbl">Status:</td>
        <td class="val">{escape(str(status))}</td></tr>
    <tr><td class="lbl">Assessment Date:</td>
        <td>{escape(str(assessed_at))}</td></tr>
    <tr><td class="lbl">PDF Export Date:</td>
        <td>{escape(exported_at)}</td></tr>
    <tr><td class="lbl">C5 Report Digest:</td>
        <td class="mono">{escape(digest_short)}</td></tr>
    <tr><td class="lbl">C5 Report Version:</td>
        <td>{escape(str(report.get('report_version') or 'Unavailable'))}</td></tr>
  </table>
  <div class="cover-footer">OFFLINE OPERATION &middot; LOCAL COMPUTATION &middot; NO NETWORK SERVICES</div>
</div>
"""

    # Capability scope table
    from backend.core.capabilities import CAPABILITIES
    scope_rows = "".join(
        f"<tr><td>{escape(c['id'])}</td><td>{escape(c['name'])}</td>"
        f"<td>{escape(c['status'])}</td></tr>"
        for c in CAPABILITIES
    )
    scope_section = f"""
<section>
  <h2>Assessment Capability Scope</h2>
  <div class="scope">
    A1–A8 dataset integrity &middot; B1–B4 model integrity &middot;
    C1–C5 provenance, shift, findings, audit, report &middot;
    Offline / air-gapped operation &middot; Adapter-dependent model coverage
  </div>
  <table>
    <thead><tr><th>ID</th><th>Capability</th><th>Status</th></tr></thead>
    <tbody>{scope_rows}</tbody>
  </table>
</section>
"""

    # Main content
    findings_block = report.get("findings_and_evidence")
    raw_findings = (findings_block.get("findings")
                    if isinstance(findings_block, dict) else [])
    finding_severities = (
        [str(item.get("severity", "")).strip().lower()
         for item in raw_findings if isinstance(item, dict)]
        if isinstance(raw_findings, list) else []
    )

    body_rows = []
    for title, pairs in section_content(report):
        body_rows.append(f"<section><h2>{escape(title)}</h2>")
        if title.endswith("Findings & Evidence"):
            for index, (heading, body) in enumerate(pairs):
                severity = finding_severities[index] if index < len(finding_severities) else ""
                sev_class = f"sev-{severity}" if severity in _SEVERITY_COLORS else ""
                body_rows.append(
                    f'<article class="{sev_class}">'
                    f"<h3>{escape(heading)}</h3><p>{escape(body)}</p></article>"
                )
        elif "Distribution Shift" in title:
            body_rows.append(
                '<div class="callout"><strong>IMPORTANT:</strong> The heuristic shift '
                'magnitude recorded below is not probabilistically calibrated and must '
                'not be interpreted as an attack probability or a measure of malicious '
                'activity.</div>'
            )
            body_rows.append("<table><tbody>")
            for label, value in pairs:
                body_rows.append(
                    f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>"
                )
            body_rows.append("</tbody></table>")
        else:
            body_rows.append("<table><tbody>")
            for label, value in pairs:
                body_rows.append(
                    f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>"
                )
            body_rows.append("</tbody></table>")
        body_rows.append("</section>")

    return (
        f"<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<style>{_CSS}</style></head><body>"
        f"{cover}"
        f"<div class=\"brand\">TRACER-CV &middot; TRUST, RELIABILITY &amp; ASSURANCE FOR COMPUTER VISION</div>"
        f"<h1>Assurance Report</h1>"
        f"<div class=\"meta\">"
        f"<b>Assessment ID:</b> {escape(str(assessment_id))}&nbsp;&nbsp;"
        f"<b>Status:</b> {escape(str(status))}&nbsp;&nbsp;"
        f"<b>Assessment Date:</b> {escape(str(assessed_at))}<br/>"
        f"<b>PDF Export Date:</b> {escape(exported_at)}&nbsp;&nbsp;"
        f"<b>Operation:</b> Offline / local &middot; no network service required"
        f"</div>"
        f"{scope_section}"
        f"{''.join(body_rows)}"
        f"</body></html>"
    )


# ---------------------------------------------------------------------------
# Shared PDF writer helper
# ---------------------------------------------------------------------------

def _make_writer(target: Path, title: str) -> tuple[QPdfWriter, QPageLayout]:
    writer = QPdfWriter(str(target))
    writer.setTitle(title)
    writer.setCreator("TRACER-CV")
    writer.setResolution(96)
    layout = QPageLayout(
        QPageSize(QPageSize.PageSizeId.A4),
        QPageLayout.Orientation.Portrait,
        QMarginsF(16, 16, 18, 18),
        QPageLayout.Unit.Millimeter,
    )
    writer.setPageLayout(layout)
    return writer, layout


def _render_html_to_pdf(html: str, writer: QPdfWriter,
                         assessment_id: str, footer_left: str) -> None:
    paint_rect = writer.pageLayout().paintRectPixels(writer.resolution())
    footer_height = 36
    doc = QTextDocument()
    doc.setDocumentMargin(0)
    doc.setHtml(html)
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
            painter.translate(paint_rect.left(),
                              paint_rect.top() - page * content_size.height())
            doc.drawContents(
                painter,
                QRectF(0, page * content_size.height(),
                       content_size.width(), content_size.height()),
            )
            painter.restore()
            # Footer
            painter.save()
            painter.setPen(Qt.GlobalColor.darkGray)
            painter.translate(paint_rect.left(), paint_rect.top())
            fy = int(content_size.height() + 10)
            painter.drawLine(0, fy - 4, int(content_size.width()), fy - 4)
            painter.drawText(0, fy + 12, footer_left)
            painter.drawText(
                int(content_size.width() - 90), fy + 12,
                f"Page {page + 1} of {page_count}",
            )
            painter.restore()
    finally:
        painter.end()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_assurance_pdf(
    report: dict[str, Any],
    assessment: dict[str, Any],
    target: str | Path,
) -> dict[str, str]:
    """Write a paginated professional PDF from persisted C5 data.

    Read-only: never modifies report, assessment, findings, audit records,
    or any assessment state. Returns export metadata dict.
    """
    target = Path(target).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    exported_at = datetime.now(timezone.utc).isoformat()
    assessment_id = (report.get("assessment_id")
                     or assessment.get("assessment_id") or "Assessment")
    writer, _ = _make_writer(target, "TRACER-CV Assurance Report")
    html = _html(report, assessment, exported_at)
    footer_left = f"TRACER-CV · PS-26228 · OFFLINE ASSESSMENT · {assessment_id}"
    _render_html_to_pdf(html, writer, assessment_id, footer_left)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return {"path": str(target), "sha256": digest, "exported_at": exported_at}


def write_section_pdf(
    title: str,
    section_data: dict[str, Any],
    target: str | Path,
    *,
    assessment_id: str = "",
) -> dict[str, str]:
    """Write a workspace-specific section PDF from structured data.

    section_data keys:
      description (str): brief section description
      rows (list of (label, value) tuples): table content
      findings (list of dicts, optional): finding blocks

    Read-only: never modifies assessment state. Returns export metadata dict.
    """
    target = Path(target).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    exported_at = datetime.now(timezone.utc).isoformat()

    description = section_data.get("description", "")
    rows = section_data.get("rows") or []
    findings = section_data.get("findings") or []

    id_line = (f"<b>Assessment:</b> {escape(assessment_id)}&nbsp;&nbsp;"
               if assessment_id else "")
    table_rows = "".join(
        f"<tr><th>{escape(str(label))}</th><td>{escape(str(value))}</td></tr>"
        for label, value in rows
    )
    finding_html = ""
    if findings:
        finding_html = "<h2>Findings</h2>"
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            fid = escape(str(finding.get("finding_id", "—")))
            ftitle = escape(str(finding.get("title", "Finding")))
            fsev = str(finding.get("severity", "")).lower()
            sev_class = f"sev-{fsev}" if fsev in _SEVERITY_COLORS else ""
            body = escape(str(finding.get("explanation", "No explanation recorded.")))
            finding_html += (
                f'<article class="{sev_class}">'
                f"<h3>{fid} · {ftitle}</h3><p>{body}</p></article>"
            )

    html = (
        f"<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<style>{_CSS}</style></head><body>"
        f'<div class="brand">TRACER-CV &middot; PS-26228</div>'
        f"<h1>{escape(title)}</h1>"
        f'<div class="meta">{id_line}'
        f"<b>PDF Export Date:</b> {escape(exported_at)}&nbsp;&nbsp;"
        f"<b>Operation:</b> Offline / local</div>"
        f"<p>{escape(description)}</p>"
        f"<table><tbody>{table_rows}</tbody></table>"
        f"{finding_html}"
        f"</body></html>"
    )

    writer, _ = _make_writer(target, f"TRACER-CV — {title}")
    footer_left = f"TRACER-CV · PS-26228 · {title}"
    if assessment_id:
        footer_left = f"TRACER-CV · PS-26228 · {assessment_id}"
    _render_html_to_pdf(html, writer, assessment_id, footer_left)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return {"path": str(target), "sha256": digest, "exported_at": exported_at}
