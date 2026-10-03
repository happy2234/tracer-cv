"""Analyst-facing product coverage and limitations view."""
from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import QLabel, QScrollArea, QTableWidget, QVBoxLayout, QWidget

from backend.core.capabilities import ACCESS_MODES, CAPABILITIES, DATASET_FORMATS, LIMITATIONS, MODEL_FORMATS, PRODUCT_CAPABILITIES, STATES, UNSUPPORTED_ATTACK_CLASSES
from desktop.widgets.components import AnalystTable, MetricCard, SectionCard, SeverityBadge


class CoverageWorkspace(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("coverageWorkspace")
        self.selected_capability: dict[str, Any] | None = None
        self.detail_labels: dict[QTableWidget, QLabel] = {}
        outer = QVBoxLayout(self); outer.setContentsMargins(24, 18, 24, 18)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); layout = QVBoxLayout(body); layout.setSpacing(12); scroll.setWidget(body)
        heading = QLabel("Coverage & Limitations"); heading.setObjectName("pageTitle"); layout.addWidget(heading)
        layout.addWidget(QLabel("Implemented assessment scope and its boundaries. These capability descriptions do not describe the result of an individual assessment."))
        states = {state: sum(item["status"] == state for item in CAPABILITIES) for state in STATES}
        layout.addWidget(MetricCard("Engine capabilities", str(len(CAPABILITIES)), "A1–A8, B1–B4 and C1–C5 from the local registry"))
        layout.addWidget(AnalystTable(["State", "Capabilities"], [[key, value] for key, value in states.items() if value]))

        for category, ids in (("Dataset Integrity", tuple(f"A{i}" for i in range(1, 9))),
                              ("Model Integrity", tuple(f"B{i}" for i in range(1, 5))),
                              ("Provenance / Assurance", tuple(f"C{i}" for i in range(1, 6)))):
            card = SectionCard(category)
            rows = [[item["id"], item["name"], item["status"], item["supported_task"], item["required_access"]]
                    for item in CAPABILITIES if item["id"] in ids]
            table = AnalystTable(["ID", "Capability", "State", "Scope", "Access requirement"], rows)
            table.setObjectName("capabilityTable")
            table.cellClicked.connect(lambda row, col, t=table, c=category: self._select(t, row, c))
            card.content.addWidget(table)
            detail_label = QLabel("Select a capability row to inspect supported data, evidence and limitations.")
            detail_label.setWordWrap(True); card.content.addWidget(detail_label)
            self.detail_labels[table] = detail_label
            layout.addWidget(card)

        card = SectionCard("Dataset Formats")
        card.content.addWidget(AnalystTable(["Format", "State", "Scope"], [[x["format"], x["status"], x["scope"]] for x in DATASET_FORMATS])); layout.addWidget(card)
        card = SectionCard("Model Formats")
        card.content.addWidget(AnalystTable(["Format", "B1", "B2", "B3", "B4", "Reason"], [[x["format"], x["B1"], x["B2"], x["B3"], x["B4"], x["reason"]] for x in MODEL_FORMATS])); layout.addWidget(card)
        card = SectionCard("White-box and Black-box Access")
        card.content.addWidget(AnalystTable(["Capability", "White-box", "Black-box", "Required access"], [[x["capability"], x["white_box"], x["black_box"], x["required_access"]] for x in ACCESS_MODES])); layout.addWidget(card)
        card = SectionCard("Additional assurance capabilities")
        card.content.addWidget(AnalystTable(["Capability", "State", "Scope"], [[x["name"], x["status"], x["scope"]] for x in PRODUCT_CAPABILITIES])); layout.addWidget(card)
        card = SectionCard("Unsupported / Incompletely Addressed Attack Classes")
        for item in UNSUPPORTED_ATTACK_CLASSES:
            label = QLabel("• " + item); label.setWordWrap(True); card.content.addWidget(label)
        layout.addWidget(card)
        card = SectionCard("Engine Limitations")
        for engine, limitations in LIMITATIONS.items():
            for limitation in limitations:
                label = QLabel(f"{engine}: {limitation}"); label.setWordWrap(True); card.content.addWidget(label)
        layout.addWidget(card)
        notice = QLabel("Coverage describes implemented methods. A successful capability or self-test does not establish that an assessed dataset or model is secure.")
        notice.setWordWrap(True); notice.setObjectName("mutedText"); layout.addWidget(notice); layout.addStretch()

    def _select(self, table: QTableWidget, row: int, category: str) -> None:
        identity = table.item(row, 0).text() if table.item(row, 0) else ""
        item = next((cap for cap in CAPABILITIES if cap["id"] == identity), None)
        self.selected_capability = item
        if item and table in self.detail_labels:
            self.detail_labels[table].setText(
                f"{item['id']} — {item['name']} · {item['status']}\n"
                f"Task: {item['supported_task']}\nEvidence: {item['evidence_produced']}\n"
                f"Access: {item['required_access']}\nLimitations: {item['limitations']}"
            )


__all__ = ["CoverageWorkspace"]
