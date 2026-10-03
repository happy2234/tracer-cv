"""Small reusable widgets for the local TRACER-CV analyst interface."""
import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QColor, QBrush, QFont
from PySide6.QtWidgets import (
    QApplication, QDialog, QFileDialog, QFrame, QHBoxLayout, QLabel,
    QMessageBox, QPushButton, QSizePolicy, QTableWidget, QTableWidgetItem,
    QTextEdit, QHeaderView, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)


class StatusBadge(QLabel):
    def __init__(self, text: str, tone: str = "info", parent=None):
        super().__init__(text, parent)
        self.setProperty("tone", tone)
        self.setObjectName("statusBadge")
        self.setAlignment(Qt.AlignCenter)


class SeverityBadge(StatusBadge):
    """Semantic status/severity badge shared by analyst-facing views."""
    TONES = {
        "verified": "verified", "valid": "verified", "normal": "verified",
        "completed": "verified", "assessed": "verified", "available": "info",
        "supported": "verified",
        "information": "info", "informational": "info", "info": "info",
        "review": "review", "review_required": "review", "medium": "review",
        "warning": "review", "low": "verified", "partial": "review",
        "conditional": "review", "not_applicable": "unavailable",
        "high": "high", "critical": "critical", "unavailable": "unavailable",
        "disabled": "unavailable", "failed": "unavailable", "error": "unavailable",
        "invalid": "critical",
    }

    def __init__(self, text: str, state: str | None = None, parent=None):
        value = (state or text).strip().lower().replace(" ", "_")
        tone = self.TONES.get(value)
        if tone is None:
            if "critical" in value:
                tone = "critical"
            elif "high" in value:
                tone = "high"
            elif "invalid" in value:
                tone = "critical"
            elif "review" in value or "shift" in value or "warning" in value:
                tone = "review"
            elif "unavailable" in value or "disabled" in value or "not_assessed" in value:
                tone = "unavailable"
            elif ("valid" in value or "complete" in value or "ready" in value
                  or "assessed" in value or "available" in value
                  or "verified" in value):
                tone = "verified"
            else:
                tone = "unavailable"
        super().__init__(text, tone, parent)


class EvidenceViewerDialog(QDialog):
    """Progressive evidence view: readable summary first, JSON only on request."""
    def __init__(self, title, summary, evidence, raw_data, parent=None):
        super().__init__(parent)
        self.title = title
        self.summary = summary
        self.evidence = evidence
        self.raw_data = raw_data
        self.setWindowTitle(f"{title} — Evidence")
        self.resize(800, 580)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        heading = QLabel(title)
        heading.setObjectName("pageTitle")
        layout.addWidget(heading)
        for section_title, body in (("What was observed", summary), ("Evidence", evidence)):
            card = SectionCard(section_title)
            label = QLabel(str(body or "No additional information is available."))
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            card.content.addWidget(label)
            layout.addWidget(card)
        self.technical = SectionCard("Technical Details")
        self.technical.setVisible(False)
        self.raw_section = SectionCard("Raw Evidence")
        self.raw_section.setVisible(False)
        self.json_view = QTextEdit()
        self.json_view.setReadOnly(True)
        self.json_view.setVisible(False)
        self.technical_button = QPushButton("Technical Details")
        self.technical_button.clicked.connect(self.show_technical)
        self.raw_button = QPushButton("Raw Evidence")
        self.raw_button.clicked.connect(self.show_raw)
        self.technical.content.addWidget(self.raw_button)
        self.view_json_button = QPushButton("View JSON")
        self.view_json_button.clicked.connect(self.show_json)
        self.raw_section.content.addWidget(self.view_json_button)
        self.technical.content.addWidget(self.raw_section)
        layout.addWidget(self.technical)
        layout.addWidget(self.json_view)
        self.copy_button = QPushButton("Copy")
        self.copy_button.clicked.connect(self.copy_content)
        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.export_content)
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addWidget(self.technical_button)
        row.addStretch()
        row.addWidget(self.copy_button)
        row.addWidget(self.export_button)
        row.addWidget(self.close_button)
        layout.addLayout(row)

    def show_technical(self):
        self.technical.setVisible(True)
        self.technical_button.setEnabled(False)

    def show_raw(self):
        self.raw_section.setVisible(True)
        self.raw_button.setEnabled(False)

    def show_json(self):
        self.json_view.setPlainText(
            json.dumps(self.raw_data, indent=2, ensure_ascii=False, default=str)
        )
        self.json_view.setVisible(True)
        self.view_json_button.setEnabled(False)

    def copy_content(self):
        text = (json.dumps(self.raw_data, indent=2, ensure_ascii=False, default=str)
                if self.json_view.isVisible()
                else f"{self.title}\n\n{self.summary}\n\n{self.evidence}")
        QApplication.clipboard().setText(text)

    def export_content(self):
        raw_requested = self.json_view.isVisible()
        default_ext = ".json" if raw_requested else ".txt"
        formats = "JSON (*.json);;Text (*.txt)" if raw_requested else "Text (*.txt)"
        target, _ = QFileDialog.getSaveFileName(
            self, "Export evidence",
            f"{self.title.lower().replace(' ', '-')}{default_ext}", formats,
        )
        if not target:
            return
        if not raw_requested and target.lower().endswith(".json"):
            target = str(Path(target).with_suffix(".txt"))
        try:
            if raw_requested and target.lower().endswith(".json"):
                Path(target).write_text(
                    json.dumps(self.raw_data, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
            else:
                Path(target).write_text(
                    f"{self.title}\n\n{self.summary}\n\n{self.evidence}\n",
                    encoding="utf-8",
                )
        except OSError as exc:
            QMessageBox.warning(self, "Evidence export failed", str(exc))


# ---------------------------------------------------------------------------
# Navigation sidebar
# ---------------------------------------------------------------------------

_NAV_GROUPS = [
    ("OVERVIEW", [
        ("MISSION CONTROL", "MISSION CONTROL"),
        ("ASSESSMENTS", "ASSESSMENTS"),
        ("  Current Assessment", "CURRENT ASSESSMENT"),
        ("ASSETS", "ASSETS"),
    ]),
    ("ASSURANCE", [
        ("Dataset", "Dataset"),
        ("Model", "Model"),
        ("Inference Provenance", "Inference Provenance"),
        ("Distribution", "Distribution"),
    ]),
    ("INVESTIGATION", [
        ("FINDINGS", "FINDINGS"),
        ("EVIDENCE", "EVIDENCE"),
        ("AUDIT TRAIL", "AUDIT TRAIL"),
    ]),
    ("REPORTING", [
        ("REPORTS", "REPORTS"),
    ]),
    ("SYSTEM", [
        ("Coverage & Limitations", "Coverage & Limitations"),
        ("Self-Test & Readiness", "Self-Test & Readiness"),
        ("SETTINGS", "SETTINGS"),
    ]),
]


class NavigationSidebar(QFrame):
    """Reusable primary navigation tree; routes are returned as item keys."""

    def __init__(self, airgap_badge, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(230)
        side = QVBoxLayout(self)
        side.setContentsMargins(12, 16, 12, 14)
        side.setSpacing(8)

        brand = QLabel("TRACER-CV")
        brand.setObjectName("brand")
        brand.setWordWrap(True)
        side.addWidget(brand)
        side.addWidget(airgap_badge)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(12)
        self.tree.setObjectName("navigation")
        self.tree.setAnimated(False)

        self.nav_items: dict[str, QTreeWidgetItem] = {}

        for group_label, items in _NAV_GROUPS:
            # Group header — non-selectable label
            group_item = QTreeWidgetItem([group_label])
            group_item.setFlags(Qt.ItemIsEnabled)  # not selectable/checkable
            group_item.setData(0, Qt.UserRole, None)
            font = QFont()
            font.setPointSize(7)
            font.setWeight(QFont.Weight.Bold)
            group_item.setFont(0, font)
            # Use foreground to signal this is a header (styled by app-level logic)
            from PySide6.QtGui import QColor
            group_item.setForeground(0, QColor("#5e7f93"))
            self.tree.addTopLevelItem(group_item)
            group_item.setExpanded(True)

            for display_name, nav_key in items:
                child = QTreeWidgetItem([display_name.strip()])
                child.setData(0, Qt.UserRole, nav_key)
                group_item.addChild(child)
                self.nav_items[nav_key] = child

        side.addWidget(self.tree, 1)

        footer = QLabel("OFFLINE / AIR-GAPPED\nTRACER-CV · PS-26228")
        footer.setObjectName("sidebarFooter")
        side.addWidget(footer)


# ---------------------------------------------------------------------------
# Cards
# ---------------------------------------------------------------------------

class MetricCard(QFrame):
    def __init__(self, title: str, value: str, detail: str = "",
                 tone: str = "normal", parent=None):
        super().__init__(parent)
        self.setObjectName("metricCard")
        self.setProperty("tone", tone)
        self.setMinimumWidth(120)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)
        label = QLabel(title.upper())
        label.setObjectName("metricLabel")
        value_label = QLabel(str(value))
        value_label.setObjectName("metricValue")
        value_label.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(value_label)
        if detail:
            note = QLabel(detail)
            note.setObjectName("mutedText")
            note.setWordWrap(True)
            layout.addWidget(note)


class SectionCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("sectionCard")
        self.setMinimumWidth(180)
        self.content = QVBoxLayout(self)
        self.content.setContentsMargins(14, 12, 14, 14)
        self.content.setSpacing(8)
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        self.content.addWidget(heading)


class StatusCard(QFrame):
    """Dashboard status card with semantic colored left border."""

    def __init__(self, title: str, value: str, detail: str = "",
                 tone: str = "info", parent=None):
        super().__init__(parent)
        self.setObjectName("statusCard")
        self.setProperty("tone", tone)
        self.setMinimumWidth(140)
        self.setMinimumHeight(80)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)
        title_label = QLabel(title.upper())
        title_label.setObjectName("metricLabel")
        value_label = QLabel(str(value))
        value_label.setObjectName("sectionTitle")
        value_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        if detail:
            note = QLabel(detail)
            note.setObjectName("mutedText")
            note.setWordWrap(True)
            layout.addWidget(note)
        # Force style re-evaluation after setting the tone property
        self.style().unpolish(self)
        self.style().polish(self)


# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------

class AnalystTable(QTableWidget):
    def __init__(self, headers, rows=(), parent=None):
        super().__init__(len(rows), len(headers), parent)
        self.setHorizontalHeaderLabels(list(headers))
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.setWordWrap(True)
        self.verticalHeader().setDefaultSectionSize(40)
        self.verticalHeader().setMinimumSectionSize(34)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.horizontalHeader().setStretchLastSection(True)

        for row_index, row in enumerate(rows):
            for column_index, value in enumerate(row):
                column_name = str(headers[column_index]).strip().lower()
                if (column_name in {"severity", "status", "verification"}
                        and str(value).strip().lower() not in {"", "—", "none"}):
                    badge = SeverityBadge(str(value), parent=self)
                    self.setCellWidget(row_index, column_index, badge)
                    continue
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.setItem(row_index, column_index, item)

        self.resizeColumnsToContents()
        # Cap any column wider than 280 px to keep layout manageable;
        # the last column is already set to stretch.
        col_count = self.columnCount()
        for col in range(col_count - 1):
            if self.columnWidth(col) > 280:
                self.setColumnWidth(col, 280)

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)


# ---------------------------------------------------------------------------
# Bar chart
# ---------------------------------------------------------------------------

class MetricBarChart(QFrame):
    """Compact chart for measured count or comparison values."""
    COLORS = {
        "high": "#b64040", "critical": "#922f35", "medium": "#c48b24",
        "review": "#c48b24", "low": "#418b68", "info": "#3e7ea5",
        "normal": "#53829f",
    }

    def __init__(self, title, rows, parent=None):
        super().__init__(parent)
        self.title = title
        self.rows = list(rows)
        self.setObjectName("sectionCard")
        self.setMinimumHeight(max(96, 42 + len(self.rows) * 28))

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(self.palette().text().color())
        painter.drawText(16, 22, self.title)
        max_value = max(
            [abs(float(v)) for row in self.rows
             for v in row[1:] if isinstance(v, (int, float))] + [1.0]
        )
        width = max(80, self.width() - 205)
        y = 48
        for row in self.rows:
            painter.setPen(self.palette().text().color())
            painter.drawText(16, y + 13, str(row[0])[:24])
            for ix, value in enumerate(row[1:]):
                if not isinstance(value, (int, float)):
                    continue
                state = (str(row[-1]).lower()
                         if len(row) > 2 and isinstance(row[-1], str)
                         else ("normal" if ix == 0 else "info"))
                painter.setBrush(
                    QBrush(QColor(self.COLORS.get(state, self.COLORS["normal"])))
                )
                painter.setPen(Qt.NoPen)
                bar_width = max(2, int(width * min(abs(float(value)) / max_value, 1.0)))
                painter.drawRoundedRect(160, y + ix * 8, bar_width, 6, 3, 3)
                painter.setPen(self.palette().text().color())
                painter.drawText(166 + bar_width, y + 6 + ix * 8, f"{value:g}")
            y += 26
        painter.end()
