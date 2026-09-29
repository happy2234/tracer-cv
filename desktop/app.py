import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)
from desktop.pages.dataset_integrity import DatasetIntegrityPage

PAGES = [
    ("Dashboard", "Dashboard"),
    ("Dataset Integrity", "Dataset Integrity"),
    ("Model Integrity", "Model Integrity"),
    ("Inference Provenance", "Inference Provenance"),
    ("Distribution Shift", "Distribution Shift"),
    ("Findings & Evidence", "Findings & Evidence"),
    ("Audit Trail", "Audit Trail"),
    ("Assurance Report", "Assurance Report"),
    ("Configuration", "Configuration"),
    ("Coverage & Limitations", "Coverage & Limitations"),
]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("TRACER-CV")
        self.resize(1400, 850)
        self.setMinimumSize(1100, 700)

        self.setStyleSheet("""
            QMainWindow {
                background: #f4f6f8;
            }

            QFrame#sidebar {
                background: #17202a;
            }

            QLabel#productName {
                color: white;
                font-size: 22px;
                font-weight: 700;
            }

            QLabel#productSubtitle {
                color: #aeb8c2;
                font-size: 11px;
            }

            QLabel#offlineStatus {
                color: #8fd19e;
                background: #1e3a29;
                border: 1px solid #315d40;
                border-radius: 5px;
                padding: 7px;
                font-size: 11px;
                font-weight: 600;
            }

            QPushButton#navButton {
                background: transparent;
                color: #c9d1d9;
                border: none;
                border-radius: 5px;
                text-align: left;
                padding: 11px 14px;
                font-size: 13px;
            }

            QPushButton#navButton:hover {
                background: #263442;
                color: white;
            }

            QPushButton#navButton[selected="true"] {
                background: #2f4050;
                color: white;
                font-weight: 600;
                border-left: 3px solid #72a7d6;
            }

            QFrame#topbar {
                background: white;
                border-bottom: 1px solid #d9dee3;
            }

            QLabel#pageTitle {
                color: #17202a;
                font-size: 22px;
                font-weight: 700;
            }

            QLabel#pageSubtitle {
                color: #66727d;
                font-size: 12px;
            }

            QFrame#contentCard {
                background: white;
                border: 1px solid #dfe4e8;
                border-radius: 8px;
            }

            QLabel#cardTitle {
                color: #26323d;
                font-size: 13px;
                font-weight: 600;
            }

            QLabel#cardValue {
                color: #17202a;
                font-size: 25px;
                font-weight: 700;
            }

            QLabel#muted {
                color: #77838e;
                font-size: 12px;
            }
        """)

        self.build_ui()

    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)

        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ---------------------------------------------------------
        # Sidebar
        # ---------------------------------------------------------
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(250)

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 22, 16, 18)
        sidebar_layout.setSpacing(5)

        product_name = QLabel("TRACER-CV")
        product_name.setObjectName("productName")

        product_subtitle = QLabel(
            "Trust, Reliability & Assurance\n"
            "for Computer Vision"
        )
        product_subtitle.setObjectName("productSubtitle")

        sidebar_layout.addWidget(product_name)
        sidebar_layout.addWidget(product_subtitle)
        sidebar_layout.addSpacing(22)

        self.nav_buttons = []
        self.page_index = {}

        for index, (button_text, page_name) in enumerate(PAGES):
            button = QPushButton(button_text)
            button.setObjectName("navButton")
            button.setCursor(Qt.PointingHandCursor)
            button.setProperty("selected", index == 0)

            button.clicked.connect(
                lambda checked=False, i=index: self.switch_page(i)
            )

            sidebar_layout.addWidget(button)

            self.nav_buttons.append(button)
            self.page_index[page_name] = index

        sidebar_layout.addStretch()

        offline = QLabel("OFFLINE / AIR-GAPPED")
        offline.setObjectName("offlineStatus")
        offline.setAlignment(Qt.AlignCenter)

        sidebar_layout.addWidget(offline)

        version = QLabel("TRACER-CV v0.1.0")
        version.setObjectName("productSubtitle")
        version.setAlignment(Qt.AlignCenter)

        sidebar_layout.addSpacing(8)
        sidebar_layout.addWidget(version)

        # ---------------------------------------------------------
        # Main area
        # ---------------------------------------------------------
        main_area = QWidget()
        main_layout = QVBoxLayout(main_area)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Top bar
        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar.setFixedHeight(78)

        topbar_layout = QVBoxLayout(topbar)
        topbar_layout.setContentsMargins(28, 13, 28, 10)
        topbar_layout.setSpacing(3)

        self.page_title = QLabel("Dashboard")
        self.page_title.setObjectName("pageTitle")

        self.page_subtitle = QLabel(
            "System assurance overview"
        )
        self.page_subtitle.setObjectName("pageSubtitle")

        topbar_layout.addWidget(self.page_title)
        topbar_layout.addWidget(self.page_subtitle)

        main_layout.addWidget(topbar)

        # Pages
        self.stack = QStackedWidget()

        for _, page_name in PAGES:
         if page_name == "Dataset Integrity":
           self.stack.addWidget(DatasetIntegrityPage())
         else:
          self.stack.addWidget(self.create_page(page_name))

        main_layout.addWidget(self.stack)

        root_layout.addWidget(sidebar)
        root_layout.addWidget(main_area)

    def create_page(self, page_name):
        page = QWidget()

        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 25, 28, 28)
        layout.setSpacing(18)

        if page_name == "Dashboard":
            self.create_dashboard(layout)
        else:
            self.create_placeholder_page(layout, page_name)

        return page

    def create_dashboard(self, layout):
        intro = QLabel(
            "TRACER-CV provides offline assurance for computer vision "
            "datasets, models, inference outputs and distribution changes."
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)

        layout.addWidget(intro)

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(14)

        cards = [
            ("Dataset Integrity", "NOT ASSESSED", "No dataset scan performed"),
            ("Model Integrity", "NOT ASSESSED", "No model assessment performed"),
            ("Inference Provenance", "NOT ASSESSED", "No inference records"),
            ("Distribution Shift", "NOT ASSESSED", "No reference comparison"),
        ]

        for title, value, description in cards:
            card = QFrame()
            card.setObjectName("contentCard")

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(18, 17, 18, 17)
            card_layout.setSpacing(7)

            title_label = QLabel(title)
            title_label.setObjectName("cardTitle")

            value_label = QLabel(value)
            value_label.setObjectName("cardValue")
            value_label.setWordWrap(True)

            description_label = QLabel(description)
            description_label.setObjectName("muted")
            description_label.setWordWrap(True)

            card_layout.addWidget(title_label)
            card_layout.addWidget(value_label)
            card_layout.addWidget(description_label)
            card_layout.addStretch()

            cards_layout.addWidget(card)

        layout.addLayout(cards_layout)

        findings_card = QFrame()
        findings_card.setObjectName("contentCard")

        findings_layout = QVBoxLayout(findings_card)
        findings_layout.setContentsMargins(18, 18, 18, 18)
        findings_layout.setSpacing(8)

        findings_title = QLabel("Recent Assurance Findings")
        findings_title.setObjectName("cardTitle")

        findings_text = QLabel(
            "No assurance assessment has been performed yet.\n\n"
            "Start with Dataset Integrity to create the first "
            "TRACER-CV evidence record."
        )
        findings_text.setObjectName("muted")
        findings_text.setWordWrap(True)

        findings_layout.addWidget(findings_title)
        findings_layout.addWidget(findings_text)
        findings_layout.addStretch()

        layout.addWidget(findings_card)
        layout.addStretch()

    def create_placeholder_page(self, layout, page_name):
        card = QFrame()
        card.setObjectName("contentCard")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(22, 22, 22, 22)
        card_layout.setSpacing(10)

        title = QLabel(page_name)
        title.setObjectName("cardTitle")

        status = QLabel("NOT ASSESSED")
        status.setObjectName("cardValue")

        description = QLabel(
            "This TRACER-CV assurance module has not been implemented yet."
        )
        description.setObjectName("muted")
        description.setWordWrap(True)

        card_layout.addWidget(title)
        card_layout.addWidget(status)
        card_layout.addWidget(description)
        card_layout.addStretch()

        layout.addWidget(card)
        layout.addStretch()

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)

        page_name = PAGES[index][1]
        self.page_title.setText(page_name)

        subtitles = {
            "Dashboard": "System assurance overview",
            "Dataset Integrity": "Assess training and evaluation data integrity",
            "Model Integrity": "Assess model identity and behavioral integrity",
            "Inference Provenance": "Bind inputs, models, configuration and outputs",
            "Distribution Shift": "Assess changes between reference and observed data",
            "Findings & Evidence": "Review assurance findings and supporting evidence",
            "Audit Trail": "Review tamper-evident assurance activity",
            "Assurance Report": "Generate a human-readable assurance report",
            "Configuration": "Configure local TRACER-CV assessment settings",
            "Coverage & Limitations": "Review supported and unsupported assurance coverage",
        }

        self.page_subtitle.setText(subtitles.get(page_name, ""))

        for i, button in enumerate(self.nav_buttons):
            button.setProperty("selected", i == index)

            # Force Qt to refresh the dynamic stylesheet property.
            button.style().unpolish(button)
            button.style().polish(button)


def main():
    app = QApplication(sys.argv)

    app.setApplicationName("TRACER-CV")
    app.setApplicationVersion("0.1.0")

    font = QFont("DejaVu Sans", 10)
    app.setFont(font)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
