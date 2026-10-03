"""Small analyst-facing synthetic C1 validation dialog."""
from __future__ import annotations

import json

from PySide6.QtWidgets import QDialog, QLabel, QPushButton, QTableWidgetItem, QVBoxLayout

from backend.core.provenance_demo import run_provenance_demonstration
from desktop.widgets.components import AnalystTable, SectionCard


class ProvenanceDemonstrationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.result_data = run_provenance_demonstration()
        self.setWindowTitle("C1 signed provenance · synthetic validation")
        self.resize(900, 580)
        layout = QVBoxLayout(self)
        title = QLabel("SYNTHETIC VALIDATION DATA"); title.setObjectName("pageTitle"); layout.addWidget(title)
        summary = SectionCard("Cryptographic binding demonstration")
        summary.content.addWidget(QLabel("A deterministic local record binds input, model, preprocessing, output, sequence, nonce and predecessor. The cases below exercise C1 verification; they are not operational findings."))
        rows = [[item["scenario_id"], item["expected_behavior"], item["observed_behavior"], "DETECTED" if item["detected"] else "NOT DETECTED"] for item in self.result_data["cases"]]
        self.table = AnalystTable(["Scenario", "Expected", "Observed", "Result"], rows)
        summary.content.addWidget(self.table)
        layout.addWidget(summary)
        self.selected_evidence = QLabel("Select a scenario in the table to inspect its recorded verification evidence.")
        summary.content.addWidget(self.selected_evidence)
        self.table.cellClicked.connect(self._select_case)
        record_card = SectionCard("Original record → cryptographic binding → presented artifact")
        record_card.content.addWidget(QLabel("The original record binds input, model, preprocessing, output and chain fields. Tampering alters a presented field; C1 reports hash, signature, chain or replay evidence without attributing cause."))
        self.record_table = AnalystTable(["Bound field", "Original signed record", "Presented record"], [])
        record_card.content.addWidget(self.record_table)
        layout.addWidget(record_card)
        self._select_case(0, 0)
        limitations = SectionCard("Limitations")
        for note in self.result_data["limitations"]:
            label = QLabel("• " + note); label.setWordWrap(True); limitations.content.addWidget(label)
        layout.addWidget(limitations)
        raw = QPushButton("Technical case data")
        raw.clicked.connect(lambda: self._show_case_json())
        layout.addWidget(raw)
        close = QPushButton("Close"); close.clicked.connect(self.accept); layout.addWidget(close)

    def _show_case_json(self):
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.information(self, "Synthetic verification evidence", json.dumps(self.result_data, indent=2, ensure_ascii=False))

    def _select_case(self, row: int, _column: int):
        if 0 <= row < len(self.result_data["cases"]):
            case = self.result_data["cases"][row]
            fields = ("sequence", "nonce", "input_digest", "model_id", "preprocessing_digest",
                      "output_digest", "previous_record_hash", "record_hash", "signature")
            original = case.get("original_record", {})
            presented = case.get("record", {})
            self.record_table.setRowCount(len(fields))
            for index, field in enumerate(fields):
                left, right = str(original.get(field, "Unavailable")), str(presented.get(field, "Unavailable"))
                self.record_table.setItem(index, 0, QTableWidgetItem(field.replace("_", " ").title()))
                self.record_table.setItem(index, 1, QTableWidgetItem(self._compact(left)))
                self.record_table.setItem(index, 2, QTableWidgetItem(self._compact(right)))
            evidence_rows = [[str(key).replace("_", " ").title(), str(value)] for key, value in case.get("evidence", {}).items()]
            self.selected_evidence.setText("Verification result · " + case["observed_behavior"] + "\n" +
                " · ".join(f"{key}: {value}" for key, value in evidence_rows))

    @staticmethod
    def _compact(value: str) -> str:
        return value if len(value) <= 32 else f"{value[:16]}…{value[-8:]}"


__all__ = ["ProvenanceDemonstrationDialog"]
