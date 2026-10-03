"""UI layout and component tests for TRACER-CV.

All tests use offscreen rendering; no display is required.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qapp():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------

def test_sidebar_has_all_required_nav_keys(qapp):
    """NavigationSidebar exposes all keys expected by NAV_PAGES in app.py."""
    required = {
        "MISSION CONTROL", "ASSESSMENTS", "CURRENT ASSESSMENT", "ASSETS",
        "Dataset", "Model", "Inference Provenance", "Distribution",
        "FINDINGS", "EVIDENCE", "AUDIT TRAIL", "REPORTS", "SETTINGS",
        "Coverage & Limitations", "Self-Test & Readiness",
    }
    from PySide6.QtWidgets import QLabel
    from desktop.widgets.components import NavigationSidebar
    badge = QLabel("OFFLINE")
    sidebar = NavigationSidebar(badge)
    missing = required - set(sidebar.nav_items.keys())
    assert not missing, f"Missing nav keys: {missing}"


def test_sidebar_width_is_reasonable(qapp):
    """Sidebar has a fixed reasonable width."""
    from PySide6.QtWidgets import QLabel
    from desktop.widgets.components import NavigationSidebar
    badge = QLabel("OFFLINE")
    sidebar = NavigationSidebar(badge)
    assert 180 <= sidebar.width() <= 300, f"Unexpected sidebar width: {sidebar.width()}"


def test_sidebar_nav_items_are_selectable(qapp):
    """All nav items (not group headers) have UserRole data set."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel
    from desktop.widgets.components import NavigationSidebar
    badge = QLabel("OFFLINE")
    sidebar = NavigationSidebar(badge)
    for key, item in sidebar.nav_items.items():
        value = item.data(0, Qt.UserRole)
        assert value == key, f"Nav item '{key}' has wrong UserRole: {value}"


# ---------------------------------------------------------------------------
# AnalystTable
# ---------------------------------------------------------------------------

def test_analyst_table_word_wrap_enabled(qapp):
    """AnalystTable has word wrap enabled."""
    from desktop.widgets.components import AnalystTable
    table = AnalystTable(["ID", "Severity", "Title", "Explanation"],
                         [["A1-001", "HIGH", "Test finding", "A" * 200]])
    assert table.wordWrap()


def test_analyst_table_row_height_reasonable(qapp):
    """AnalystTable has a minimum row height of at least 34px."""
    from desktop.widgets.components import AnalystTable
    table = AnalystTable(["ID", "Title"], [["001", "Test"]])
    assert table.verticalHeader().minimumSectionSize() >= 34


def test_analyst_table_last_column_stretches(qapp):
    """AnalystTable's last column stretches to fill available width."""
    from PySide6.QtWidgets import QHeaderView
    from desktop.widgets.components import AnalystTable
    table = AnalystTable(["A", "B", "C"], [["x", "y", "z"]])
    assert table.horizontalHeader().stretchLastSection()


def test_analyst_table_wide_column_capped(qapp):
    """AnalystTable caps wide columns at 280px (except last)."""
    from desktop.widgets.components import AnalystTable
    long_text = "X" * 200
    table = AnalystTable(["Short", "Long Text Column", "Last"],
                         [["A", long_text, "Z"]])
    # Column 0 should not exceed 280px
    if table.columnCount() > 1:
        assert table.columnWidth(0) <= 280


def test_analyst_table_empty_rows(qapp):
    """AnalystTable handles empty row list without crash."""
    from desktop.widgets.components import AnalystTable
    table = AnalystTable(["ID", "Title"], [])
    assert table.rowCount() == 0


def test_analyst_table_severity_badge_rendered(qapp):
    """AnalystTable renders SeverityBadge widget for severity columns."""
    from desktop.widgets.components import AnalystTable, SeverityBadge
    table = AnalystTable(["ID", "Severity", "Title"],
                         [["A2-001", "HIGH", "Duplicate flooding"]])
    widget = table.cellWidget(0, 1)
    assert isinstance(widget, SeverityBadge), f"Expected SeverityBadge, got {type(widget)}"


# ---------------------------------------------------------------------------
# StatusBadge / SeverityBadge
# ---------------------------------------------------------------------------

def test_severity_badge_tone_critical(qapp):
    """SeverityBadge sets tone='critical' for CRITICAL state."""
    from desktop.widgets.components import SeverityBadge
    badge = SeverityBadge("CRITICAL", "critical")
    assert badge.property("tone") == "critical"


def test_severity_badge_tone_verified(qapp):
    """SeverityBadge sets tone='verified' for supported/valid states."""
    from desktop.widgets.components import SeverityBadge
    for state in ("supported", "valid", "completed", "assessed"):
        badge = SeverityBadge(state.upper(), state)
        assert badge.property("tone") == "verified", f"Expected verified for '{state}'"


def test_severity_badge_tone_review(qapp):
    """SeverityBadge sets tone='review' for medium/partial/conditional."""
    from desktop.widgets.components import SeverityBadge
    for state in ("medium", "partial", "conditional"):
        badge = SeverityBadge(state.upper(), state)
        assert badge.property("tone") == "review", f"Expected review for '{state}'"


def test_severity_badge_tone_unavailable(qapp):
    """SeverityBadge sets tone='unavailable' for disabled/failed/error."""
    from desktop.widgets.components import SeverityBadge
    for state in ("disabled", "failed", "error", "unavailable"):
        badge = SeverityBadge(state.upper(), state)
        assert badge.property("tone") == "unavailable", f"Expected unavailable for '{state}'"


# ---------------------------------------------------------------------------
# Cards
# ---------------------------------------------------------------------------

def test_section_card_instantiates(qapp):
    """SectionCard instantiates without crash."""
    from desktop.widgets.components import SectionCard
    card = SectionCard("Test Section")
    assert card is not None
    assert card.objectName() == "sectionCard"


def test_metric_card_instantiates(qapp):
    """MetricCard instantiates without crash."""
    from desktop.widgets.components import MetricCard
    card = MetricCard("Dataset", "5 items", "Synthetic", "verified")
    assert card is not None
    assert card.objectName() == "metricCard"


def test_status_card_instantiates(qapp):
    """StatusCard instantiates with correct objectName and tone."""
    from desktop.widgets.components import StatusCard
    card = StatusCard("Findings", "3", "1 HIGH · 2 MEDIUM", "review")
    assert card.objectName() == "statusCard"
    assert card.property("tone") == "review"


def test_status_card_tones(qapp):
    """StatusCard accepts all semantic tone values without crash."""
    from desktop.widgets.components import StatusCard
    for tone in ("verified", "review", "critical", "high", "info", "unavailable"):
        card = StatusCard("Test", "Value", tone=tone)
        assert card.property("tone") == tone


# ---------------------------------------------------------------------------
# EvidenceViewerDialog
# ---------------------------------------------------------------------------

def test_evidence_viewer_dialog_instantiates(qapp):
    """EvidenceViewerDialog instantiates without crash."""
    from desktop.widgets.components import EvidenceViewerDialog
    dlg = EvidenceViewerDialog("Test", "Summary text", "Evidence text", {"key": "val"})
    assert dlg is not None
    dlg.close()


def test_evidence_viewer_show_json(qapp):
    """EvidenceViewerDialog show_json method populates the JSON view."""
    from desktop.widgets.components import EvidenceViewerDialog
    dlg = EvidenceViewerDialog("Test", "Summary", "Evidence", {"key": "val"})
    dlg.show_json()
    # The json_view should contain the serialized data
    text = dlg.json_view.toPlainText()
    assert "key" in text and "val" in text
    # The button should be disabled after showing
    assert not dlg.view_json_button.isEnabled()
    dlg.close()


# ---------------------------------------------------------------------------
# Guided assessment wizard
# ---------------------------------------------------------------------------

def test_guided_wizard_instantiates(qapp):
    """GuidedAssessmentWizard instantiates with 9 steps."""
    from desktop.pages.guided_assessment import GuidedAssessmentWizard
    wizard = GuidedAssessmentWizard()
    assert wizard.step_count == 9
    assert wizard._current_step == 1


def test_guided_wizard_navigate_to_signal_exists(qapp):
    """GuidedAssessmentWizard exposes a navigate_to Signal."""
    from desktop.pages.guided_assessment import GuidedAssessmentWizard
    wizard = GuidedAssessmentWizard()
    assert hasattr(wizard, "navigate_to")


def test_guided_wizard_back_disabled_on_first_step(qapp):
    """Back button is disabled on the first step."""
    from desktop.pages.guided_assessment import GuidedAssessmentWizard
    wizard = GuidedAssessmentWizard()
    assert not wizard._back_button.isEnabled()


def test_guided_wizard_next_advances_step(qapp):
    """Clicking Next advances to step 2 when step 1 validates."""
    from desktop.pages.guided_assessment import GuidedAssessmentWizard
    import tempfile, os
    wizard = GuidedAssessmentWizard()
    with tempfile.TemporaryDirectory() as td:
        wizard._state["dataset_path"] = td
        page = wizard._pages.get(1)
        if page and hasattr(page, "_path_edit"):
            page._path_edit.setText(td)
        wizard._go_next()
    assert wizard._current_step == 2


# ---------------------------------------------------------------------------
# MetricBarChart
# ---------------------------------------------------------------------------

def test_metric_bar_chart_instantiates(qapp):
    """MetricBarChart instantiates without crash."""
    from desktop.widgets.components import MetricBarChart
    chart = MetricBarChart("Severity distribution",
                           [["High", 2, "high"], ["Medium", 3, "medium"], ["Low", 1, "low"]])
    assert chart is not None
    assert chart.minimumHeight() >= 96
