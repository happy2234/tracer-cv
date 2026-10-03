"""Operator view for isolated local self-tests and derived readiness."""
from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

from backend.core.self_test import run_self_tests
from desktop.widgets.components import AnalystTable, EvidenceViewerDialog, MetricCard, SectionCard, SeverityBadge


class SelfTestWorkspace(QWidget):
    def __init__(self, config: Any, active_compute: Any, *, on_navigate=None, parent=None):
        super().__init__(parent)
        self.config, self.active_compute, self.on_navigate = config, active_compute, on_navigate
        self.result: dict[str, Any] | None = None
        self.rows: list[dict[str, Any]] = []
        outer = QVBoxLayout(self); outer.setContentsMargins(24, 18, 24, 18)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); outer.addWidget(scroll)
        body = QWidget(); self.layout_body = QVBoxLayout(body); self.layout_body.setSpacing(12); scroll.setWidget(body)
        heading = QLabel("Self-Test & Deployment Readiness"); heading.setObjectName("pageTitle"); self.layout_body.addWidget(heading)
        self.layout_body.addWidget(QLabel("Local function checks use synthetic inputs and temporary files. They do not assess real datasets/models, run assessment engines, or test network connectivity."))
        self.readiness = MetricCard("Deployment readiness", "NOT RUN", "Run self-test to derive readiness from required and optional checks.")
        self.layout_body.addWidget(self.readiness)
        self.run_button = QPushButton("Run Local Self-Test"); self.run_button.clicked.connect(self.run_checks); self.layout_body.addWidget(self.run_button)
        self.last_run = QLabel("Last run: Not run in this session"); self.layout_body.addWidget(self.last_run)
        self.result_card = SectionCard("Check Results"); self.result_card.setVisible(False)
        self.table = AnalystTable(["Category", "Check", "Status", "Duration (ms)"], [])
        self.table.cellDoubleClicked.connect(self.open_selected)
        self.result_card.content.addWidget(self.table); self.layout_body.addWidget(self.result_card)
        self.explanation = QLabel(""); self.explanation.setWordWrap(True); self.layout_body.addWidget(self.explanation)
        self.layout_body.addStretch()

    def run_checks(self) -> dict[str, Any]:
        self.result = run_self_tests(self.config, self.active_compute)
        self.rows = list(self.result.get("checks", []))
        readiness = str(self.result.get("readiness", "NOT READY"))
        self.readiness.deleteLater()
        self.readiness = MetricCard("Deployment readiness", readiness, self.result.get("readiness_reason", "Unavailable"), tone="review" if "WARNING" in readiness else "normal")
        self.layout_body.insertWidget(2, self.readiness)
        self.last_run.setText(f"Last run: {self.result.get('generated_at', 'Unavailable')}")
        self.table.setRowCount(len(self.rows))
        for index, item in enumerate(self.rows):
            values = [item.get("category", "Unavailable"), item.get("name", "Unavailable"), item.get("status", "Unavailable"), item.get("duration_ms", "Unavailable")]
            for column, value in enumerate(values):
                from PySide6.QtWidgets import QTableWidgetItem
                self.table.setItem(index, column, QTableWidgetItem(str(value)))
        self.table.resizeColumnsToContents(); self.result_card.setVisible(True)
        self.explanation.setText("Readiness indicates only whether required local TRACER-CV functions tested successfully. It does not mean an assessed asset is safe.")
        return self.result

    def open_selected(self, row: int, column: int = 0) -> None:
        if row < 0 or row >= len(self.rows): return
        item = self.rows[row]
        EvidenceViewerDialog(item.get("name", "Self-test detail"), item.get("explanation", "Unavailable"),
                             f"Evidence: {item.get('evidence', 'Unavailable')}\nLimitations: {item.get('limitations') or 'None recorded'}",
                             item, self).exec()


__all__ = ["SelfTestWorkspace"]
