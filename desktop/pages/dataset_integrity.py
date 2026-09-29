from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from backend.engines.dataset.duplicates import find_exact_duplicates
from backend.engines.dataset.near_duplicates import find_near_duplicates
from backend.engines.dataset.ood import assess_ood
from backend.engines.dataset.label_consistency import (
    assess_label_consistency,
)

class DatasetIntegrityPage(QWidget):
    def __init__(self):
        super().__init__()

        # ---------------------------------------------------------
        # A1-A3 dataset path
        # ---------------------------------------------------------
        self.selected_path = None

        # ---------------------------------------------------------
        # A4 OOD paths
        # ---------------------------------------------------------
        self.ood_reference_path = None
        self.ood_candidate_path = None

                # ---------------------------------------------------------
        # A5 Label Consistency paths
        # ---------------------------------------------------------
        self.label_dataset_path = None
        self.label_labels_path = None

        self.build_ui()

    def build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 25, 28, 28)
        layout.setSpacing(16)

        # =========================================================
        # HEADER
        # =========================================================
        header = QFrame()
        header.setObjectName("contentCard")

        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(20, 18, 20, 18)
        header_layout.setSpacing(8)

        title = QLabel("Dataset Integrity Assessment")
        title.setObjectName("cardTitle")

        description = QLabel(
            "Assess dataset identity, duplication, near-duplication, "
            "and appearance-space distribution anomalies."
        )
        description.setObjectName("muted")
        description.setWordWrap(True)

        header_layout.addWidget(title)
        header_layout.addWidget(description)

        layout.addWidget(header)

        # =========================================================
        # A1-A3 DATASET DIRECTORY
        # =========================================================
        selection = QFrame()
        selection.setObjectName("contentCard")

        selection_layout = QVBoxLayout(selection)
        selection_layout.setContentsMargins(20, 18, 20, 18)
        selection_layout.setSpacing(10)

        selection_title = QLabel(
            "Dataset Directory"
        )
        selection_title.setObjectName("cardTitle")

        selection_description = QLabel(
            "A1 cryptographic manifest, A2 exact duplicates, "
            "and A3 near-duplicates."
        )
        selection_description.setObjectName("muted")
        selection_description.setWordWrap(True)

        row = QHBoxLayout()
        row.setSpacing(10)

        self.path_label = QLabel(
            "No dataset selected"
        )
        self.path_label.setObjectName("muted")
        self.path_label.setWordWrap(True)

        browse_button = QPushButton(
            "Select Folder"
        )
        browse_button.setCursor(
            Qt.PointingHandCursor
        )
        browse_button.clicked.connect(
            self.select_folder
        )

        self.scan_button = QPushButton(
            "Scan Dataset"
        )
        self.scan_button.setCursor(
            Qt.PointingHandCursor
        )
        self.scan_button.setEnabled(False)
        self.scan_button.clicked.connect(
            self.scan_dataset
        )

        row.addWidget(
            self.path_label,
            1,
        )
        row.addWidget(
            browse_button
        )
        row.addWidget(
            self.scan_button
        )

        selection_layout.addWidget(
            selection_title
        )
        selection_layout.addWidget(
            selection_description
        )
        selection_layout.addLayout(row)

        layout.addWidget(selection)

        # =========================================================
        # A1 RESULT SUMMARY
        # =========================================================
        self.summary = QFrame()
        self.summary.setObjectName(
            "contentCard"
        )
        self.summary.hide()

        summary_layout = QVBoxLayout(
            self.summary
        )
        summary_layout.setContentsMargins(
            20,
            18,
            20,
            18,
        )
        summary_layout.setSpacing(8)

        summary_title = QLabel(
            "Integrity Result"
        )
        summary_title.setObjectName(
            "cardTitle"
        )

        self.result_label = QLabel()
        self.result_label.setWordWrap(True)

        summary_layout.addWidget(
            summary_title
        )
        summary_layout.addWidget(
            self.result_label
        )

        layout.addWidget(
            self.summary
        )

        # =========================================================
        # A1 FILE MANIFEST
        # =========================================================
        self.table = QTableWidget(
            0,
            3,
        )

        self.table.setHorizontalHeaderLabels(
            [
                "Relative Path",
                "SHA-256",
                "Size (bytes)",
            ]
        )

        self.table.setColumnWidth(
            0,
            430,
        )
        self.table.setColumnWidth(
            1,
            520,
        )
        self.table.setColumnWidth(
            2,
            120,
        )

        self.table.setAlternatingRowColors(
            True
        )
        self.table.hide()

        layout.addWidget(
            self.table
        )

        # =========================================================
        # A2 EXACT DUPLICATES
        # =========================================================
        self.duplicates_card = QFrame()
        self.duplicates_card.setObjectName(
            "contentCard"
        )
        self.duplicates_card.hide()

        duplicates_layout = QVBoxLayout(
            self.duplicates_card
        )
        duplicates_layout.setContentsMargins(
            20,
            18,
            20,
            18,
        )
        duplicates_layout.setSpacing(10)

        duplicates_title = QLabel(
            "Exact Duplicate Detection"
        )
        duplicates_title.setObjectName(
            "cardTitle"
        )

        self.duplicates_summary = QLabel()
        self.duplicates_summary.setObjectName(
            "muted"
        )
        self.duplicates_summary.setWordWrap(
            True
        )

        self.duplicates_table = QTableWidget(
            0,
            3,
        )

        self.duplicates_table.setHorizontalHeaderLabels(
            [
                "Group",
                "SHA-256",
                "Files",
            ]
        )

        self.duplicates_table.setColumnWidth(
            0,
            80,
        )
        self.duplicates_table.setColumnWidth(
            1,
            520,
        )
        self.duplicates_table.setColumnWidth(
            2,
            450,
        )

        self.duplicates_table.setAlternatingRowColors(
            True
        )

        duplicates_layout.addWidget(
            duplicates_title
        )
        duplicates_layout.addWidget(
            self.duplicates_summary
        )
        duplicates_layout.addWidget(
            self.duplicates_table
        )

        layout.addWidget(
            self.duplicates_card
        )

        # =========================================================
        # A3 NEAR DUPLICATES
        # =========================================================
        self.near_duplicates_card = QFrame()
        self.near_duplicates_card.setObjectName(
            "contentCard"
        )
        self.near_duplicates_card.hide()

        near_duplicates_layout = QVBoxLayout(
            self.near_duplicates_card
        )
        near_duplicates_layout.setContentsMargins(
            20,
            18,
            20,
            18,
        )
        near_duplicates_layout.setSpacing(10)

        near_duplicates_title = QLabel(
            "Near-Duplicate Detection"
        )
        near_duplicates_title.setObjectName(
            "cardTitle"
        )

        self.near_duplicates_summary = QLabel()
        self.near_duplicates_summary.setObjectName(
            "muted"
        )
        self.near_duplicates_summary.setWordWrap(
            True
        )

        self.near_duplicates_table = QTableWidget(
            0,
            4,
        )

        self.near_duplicates_table.setHorizontalHeaderLabels(
            [
                "File A",
                "File B",
                "Hamming Distance",
                "Threshold",
            ]
        )

        self.near_duplicates_table.setColumnWidth(
            0,
            300,
        )
        self.near_duplicates_table.setColumnWidth(
            1,
            300,
        )
        self.near_duplicates_table.setColumnWidth(
            2,
            150,
        )
        self.near_duplicates_table.setColumnWidth(
            3,
            100,
        )

        self.near_duplicates_table.setAlternatingRowColors(
            True
        )

        near_duplicates_layout.addWidget(
            near_duplicates_title
        )
        near_duplicates_layout.addWidget(
            self.near_duplicates_summary
        )
        near_duplicates_layout.addWidget(
            self.near_duplicates_table
        )

        layout.addWidget(
            self.near_duplicates_card
        )

        # =========================================================
        # A4 OOD ASSESSMENT
        # =========================================================
        ood_selection = QFrame()
        ood_selection.setObjectName(
            "contentCard"
        )

        ood_layout = QVBoxLayout(
            ood_selection
        )
        ood_layout.setContentsMargins(
            20,
            18,
            20,
            18,
        )
        ood_layout.setSpacing(12)

        ood_title = QLabel(
            "OOD / Reference-Distribution Assessment"
        )
        ood_title.setObjectName(
            "cardTitle"
        )

        ood_description = QLabel(
            "Compare a candidate dataset against a trusted "
            "reference dataset using an offline appearance-space "
            "nearest-reference detector."
        )
        ood_description.setObjectName(
            "muted"
        )
        ood_description.setWordWrap(
            True
        )

        # ---------------------------------------------------------
        # Reference dataset
        # ---------------------------------------------------------
        reference_title = QLabel(
            "Trusted Reference Dataset"
        )
        reference_title.setObjectName(
            "cardTitle"
        )

        reference_row = QHBoxLayout()
        reference_row.setSpacing(10)

        self.ood_reference_label = QLabel(
            "No reference dataset selected"
        )
        self.ood_reference_label.setObjectName(
            "muted"
        )
        self.ood_reference_label.setWordWrap(
            True
        )

        reference_button = QPushButton(
            "Select Reference"
        )
        reference_button.setCursor(
            Qt.PointingHandCursor
        )
        reference_button.clicked.connect(
            self.select_ood_reference
        )

        reference_row.addWidget(
            self.ood_reference_label,
            1,
        )
        reference_row.addWidget(
            reference_button
        )

        # ---------------------------------------------------------
        # Candidate dataset
        # ---------------------------------------------------------
        candidate_title = QLabel(
            "Candidate Dataset"
        )
        candidate_title.setObjectName(
            "cardTitle"
        )

        candidate_row = QHBoxLayout()
        candidate_row.setSpacing(10)

        self.ood_candidate_label = QLabel(
            "No candidate dataset selected"
        )
        self.ood_candidate_label.setObjectName(
            "muted"
        )
        self.ood_candidate_label.setWordWrap(
            True
        )

        candidate_button = QPushButton(
            "Select Candidate"
        )
        candidate_button.setCursor(
            Qt.PointingHandCursor
        )
        candidate_button.clicked.connect(
            self.select_ood_candidate
        )

        candidate_row.addWidget(
            self.ood_candidate_label,
            1,
        )
        candidate_row.addWidget(
            candidate_button
        )

        # ---------------------------------------------------------
        # Run button
        # ---------------------------------------------------------
        self.ood_scan_button = QPushButton(
            "Run OOD Assessment"
        )
        self.ood_scan_button.setCursor(
            Qt.PointingHandCursor
        )
        self.ood_scan_button.setEnabled(
            False
        )
        self.ood_scan_button.clicked.connect(
            self.assess_ood
        )

        ood_layout.addWidget(
            ood_title
        )
        ood_layout.addWidget(
            ood_description
        )

        ood_layout.addWidget(
            reference_title
        )
        ood_layout.addLayout(
            reference_row
        )

        ood_layout.addWidget(
            candidate_title
        )
        ood_layout.addLayout(
            candidate_row
        )

        ood_layout.addWidget(
            self.ood_scan_button
        )

        layout.addWidget(
            ood_selection
        )

        # =========================================================
        # A4 OOD RESULT
        # =========================================================
        self.ood_result_card = QFrame()
        self.ood_result_card.setObjectName(
            "contentCard"
        )
        self.ood_result_card.hide()

        ood_result_layout = QVBoxLayout(
            self.ood_result_card
        )
        ood_result_layout.setContentsMargins(
            20,
            18,
            20,
            18,
        )
        ood_result_layout.setSpacing(10)

        ood_result_title = QLabel(
            "OOD Assessment Result"
        )
        ood_result_title.setObjectName(
            "cardTitle"
        )

        self.ood_result_summary = QLabel()
        self.ood_result_summary.setObjectName(
            "muted"
        )
        self.ood_result_summary.setWordWrap(
            True
        )

        self.ood_table = QTableWidget(
            0,
            4,
        )

        self.ood_table.setHorizontalHeaderLabels(
            [
                "Candidate File",
                "Nearest Reference",
                "Distance",
                "Result",
            ]
        )

        self.ood_table.setColumnWidth(
            0,
            300,
        )
        self.ood_table.setColumnWidth(
            1,
            180,
        )
        self.ood_table.setColumnWidth(
            2,
            150,
        )
        self.ood_table.setColumnWidth(
            3,
            180,
        )

        self.ood_table.setAlternatingRowColors(
            True
        )

        ood_result_layout.addWidget(
            ood_result_title
        )
        ood_result_layout.addWidget(
            self.ood_result_summary
        )
        ood_result_layout.addWidget(
            self.ood_table
        )

        layout.addWidget(
            self.ood_result_card
        )

        # =========================================================
        # A5 LABEL CONSISTENCY
        # =========================================================
        self.build_label_consistency_ui(layout)

        layout.addStretch()
    # =============================================================
    # A1-A3 DATASET SELECTION
    # =============================================================

    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Dataset Directory",
        )

        if not folder:
            return

        self.selected_path = Path(
            folder
        )

        self.path_label.setText(
            str(self.selected_path)
        )

        self.scan_button.setEnabled(
            True
        )

    # =============================================================
    # A1-A3 DATASET SCAN
    # =============================================================

    def scan_dataset(self):
        if self.selected_path is None:
            return

        try:
            from backend.engines.dataset.manifest import (
                build_manifest,
            )

            # A1
            manifest = build_manifest(
                self.selected_path
            )

            # A2
            duplicates = find_exact_duplicates(
                manifest["files"]
            )

            # A3
            near_duplicates = find_near_duplicates(
                self.selected_path,
                threshold=8,
            )

        except Exception as exc:
            self.summary.show()

            self.result_label.setText(
                f"SCAN FAILED\n\n{exc}"
            )

            return

        self.show_result(
            manifest,
            duplicates,
            near_duplicates,
        )

    # =============================================================
    # A1-A3 RESULTS
    # =============================================================

    def show_result(
        self,
        manifest,
        duplicates,
        near_duplicates,
    ):
        self.summary.show()
        self.table.show()

        result_text = (
            "STATUS: COMPLETED\n\n"
            f"Files scanned: "
            f"{manifest['file_count']}\n"
            f"Dataset SHA-256: "
            f"{manifest['dataset_sha256']}\n"
            f"Merkle root: "
            f"{manifest['merkle_root']}"
        )

        self.result_label.setText(
            result_text
        )

        # ---------------------------------------------------------
        # A1 manifest
        # ---------------------------------------------------------
        self.table.setRowCount(0)

        for file_info in manifest["files"]:
            row = self.table.rowCount()

            self.table.insertRow(row)

            self.table.setItem(
                row,
                0,
                QTableWidgetItem(
                    file_info["path"]
                ),
            )

            self.table.setItem(
                row,
                1,
                QTableWidgetItem(
                    file_info["sha256"]
                ),
            )

            self.table.setItem(
                row,
                2,
                QTableWidgetItem(
                    str(
                        file_info[
                            "size_bytes"
                        ]
                    )
                ),
            )

        # ---------------------------------------------------------
        # A2
        # ---------------------------------------------------------
        self.show_duplicate_results(
            duplicates
        )

        # ---------------------------------------------------------
        # A3
        # ---------------------------------------------------------
        self.show_near_duplicate_results(
            near_duplicates
        )

    def show_duplicate_results(
        self,
        duplicates,
    ):
        self.duplicates_card.show()

        group_count = duplicates[
            "duplicate_group_count"
        ]

        file_count = duplicates[
            "duplicate_file_count"
        ]

        if group_count == 0:
            self.duplicates_summary.setText(
                "STATUS: PASSED\n\n"
                "No exact duplicate files were detected."
            )

            self.duplicates_table.setRowCount(
                0
            )

            return

        self.duplicates_summary.setText(
            "STATUS: FINDINGS DETECTED\n\n"
            f"Duplicate groups: {group_count}\n"
            f"Files involved: {file_count}"
        )

        self.duplicates_table.setRowCount(
            0
        )

        for index, group in enumerate(
            duplicates["groups"],
            start=1,
        ):
            row = (
                self.duplicates_table.rowCount()
            )

            self.duplicates_table.insertRow(
                row
            )

            self.duplicates_table.setItem(
                row,
                0,
                QTableWidgetItem(
                    str(index)
                ),
            )

            self.duplicates_table.setItem(
                row,
                1,
                QTableWidgetItem(
                    group["sha256"]
                ),
            )

            self.duplicates_table.setItem(
                row,
                2,
                QTableWidgetItem(
                    "\n".join(
                        group["files"]
                    )
                ),
            )

    def show_near_duplicate_results(
        self,
        near_duplicates,
    ):
        self.near_duplicates_card.show()

        pair_count = near_duplicates[
            "near_duplicate_pair_count"
        ]

        image_count = near_duplicates[
            "images_hashed"
        ]

        threshold = near_duplicates[
            "threshold"
        ]

        if pair_count == 0:
            self.near_duplicates_summary.setText(
                "STATUS: PASSED\n\n"
                f"Images analyzed: {image_count}\n"
                f"No near-duplicate pairs detected "
                f"at dHash threshold {threshold}."
            )

            self.near_duplicates_table.setRowCount(
                0
            )

            return

        self.near_duplicates_summary.setText(
            "STATUS: FINDINGS DETECTED\n\n"
            f"Images analyzed: {image_count}\n"
            f"Near-duplicate pairs: {pair_count}\n"
            f"dHash threshold: {threshold}"
        )

        self.near_duplicates_table.setRowCount(
            0
        )

        for pair in near_duplicates[
            "pairs"
        ]:
            row = (
                self.near_duplicates_table.rowCount()
            )

            self.near_duplicates_table.insertRow(
                row
            )

            self.near_duplicates_table.setItem(
                row,
                0,
                QTableWidgetItem(
                    pair["file_a"]
                ),
            )

            self.near_duplicates_table.setItem(
                row,
                1,
                QTableWidgetItem(
                    pair["file_b"]
                ),
            )

            self.near_duplicates_table.setItem(
                row,
                2,
                QTableWidgetItem(
                    str(
                        pair[
                            "hamming_distance"
                        ]
                    )
                ),
            )

            self.near_duplicates_table.setItem(
                row,
                3,
                QTableWidgetItem(
                    str(
                        pair["threshold"]
                    )
                ),
            )

    # =============================================================
    # A4 OOD SELECTION
    # =============================================================

    def select_ood_reference(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Trusted Reference Dataset",
        )

        if not folder:
            return

        self.ood_reference_path = Path(
            folder
        )

        self.ood_reference_label.setText(
            str(
                self.ood_reference_path
            )
        )

        self.update_ood_button()

    def select_ood_candidate(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Candidate Dataset",
        )

        if not folder:
            return

        self.ood_candidate_path = Path(
            folder
        )

        self.ood_candidate_label.setText(
            str(
                self.ood_candidate_path
            )
        )

        self.update_ood_button()

    def update_ood_button(self):
        enabled = (
            self.ood_reference_path
            is not None
            and self.ood_candidate_path
            is not None
        )

        self.ood_scan_button.setEnabled(
            enabled
        )

    # =============================================================
    # A4 OOD ASSESSMENT
    # =============================================================

    def assess_ood(self):
        if (
            self.ood_reference_path is None
            or self.ood_candidate_path is None
        ):
            return

        try:
            result = assess_ood(
                self.ood_reference_path,
                self.ood_candidate_path,
            )

        except Exception as exc:
            self.ood_result_card.show()

            self.ood_result_summary.setText(
                f"ASSESSMENT FAILED\n\n{exc}"
            )

            self.ood_table.setRowCount(
                0
            )

            return

        self.show_ood_result(
            result
        )

    # =============================================================
    # A4 OOD RESULTS
    # =============================================================

    def show_ood_result(
        self,
        result,
    ):
        self.ood_result_card.show()

        reference_count = result[
            "reference_image_count"
        ]

        candidate_count = result[
            "candidate_image_count"
        ]

        threshold = result[
            "threshold"
        ]

        potential_ood_count = result[
            "potential_ood_count"
        ]

        self.ood_result_summary.setText(
            "STATUS: COMPLETED\n\n"
            f"Reference images: "
            f"{reference_count}\n"
            f"Candidate images: "
            f"{candidate_count}\n"
            f"Threshold: "
            f"{threshold:.6f}\n"
            f"Potential OOD observations: "
            f"{potential_ood_count}\n\n"
            "Note: This is an appearance-space "
            "detector. A potential OOD finding does "
            "not establish malicious intent or semantic OOD."
        )

        self.ood_table.setRowCount(
            0
        )

        for item in result[
            "results"
        ]:
            row = (
                self.ood_table.rowCount()
            )

            self.ood_table.insertRow(
                row
            )

            self.ood_table.setItem(
                row,
                0,
                QTableWidgetItem(
                    item["file"]
                ),
            )

            nearest_reference = (
                item[
                    "nearest_reference_index"
                ]
            )

            self.ood_table.setItem(
                row,
                1,
                QTableWidgetItem(
                    f"Reference #{nearest_reference + 1}"
                ),
            )

            self.ood_table.setItem(
                row,
                2,
                QTableWidgetItem(
                    f"{item['distance']:.6f}"
                ),
            )

            if item[
                "potential_ood"
            ]:
                status = (
                    "POTENTIAL OOD"
                )
            else:
                status = (
                    "IN DISTRIBUTION"
                )

            self.ood_table.setItem(
                row,
                3,
                QTableWidgetItem(
                    status
                ),
            )




                    # =============================================================
    # A5 LABEL CONSISTENCY ASSESSMENT
    # =============================================================

    def build_label_consistency_ui(self, layout):
        label_selection = QFrame()
        label_selection.setObjectName("contentCard")

        label_layout = QVBoxLayout(label_selection)
        label_layout.setContentsMargins(20, 18, 20, 18)
        label_layout.setSpacing(12)

        label_title = QLabel(
            "Label Consistency Assessment"
        )
        label_title.setObjectName("cardTitle")

        label_description = QLabel(
            "Validate YOLO annotations and identify potential "
            "label conflicts among visually similar images."
        )
        label_description.setObjectName("muted")
        label_description.setWordWrap(True)

        # ---------------------------------------------------------
        # Dataset
        # ---------------------------------------------------------
        dataset_title = QLabel("Dataset Directory")
        dataset_title.setObjectName("cardTitle")

        dataset_row = QHBoxLayout()
        dataset_row.setSpacing(10)

        self.label_dataset_label = QLabel(
            "No dataset selected"
        )
        self.label_dataset_label.setObjectName("muted")
        self.label_dataset_label.setWordWrap(True)

        dataset_button = QPushButton(
            "Select Dataset"
        )
        dataset_button.setCursor(
            Qt.PointingHandCursor
        )
        dataset_button.clicked.connect(
            self.select_label_dataset
        )

        dataset_row.addWidget(
            self.label_dataset_label,
            1,
        )
        dataset_row.addWidget(
            dataset_button
        )

        # ---------------------------------------------------------
        # Labels directory
        # ---------------------------------------------------------
        labels_title = QLabel("Labels Directory")
        labels_title.setObjectName("cardTitle")

        labels_row = QHBoxLayout()
        labels_row.setSpacing(10)

        self.label_labels_dir_label = QLabel(
            "No labels directory selected"
        )
        self.label_labels_dir_label.setObjectName("muted")
        self.label_labels_dir_label.setWordWrap(True)

        labels_button = QPushButton(
            "Select Labels"
        )
        labels_button.setCursor(
            Qt.PointingHandCursor
        )
        labels_button.clicked.connect(
            self.select_labels_directory
        )

        labels_row.addWidget(
            self.label_labels_dir_label,
            1,
        )
        labels_row.addWidget(
            labels_button
        )

        # ---------------------------------------------------------
        # Run button
        # ---------------------------------------------------------
        self.label_scan_button = QPushButton(
            "Run Label Assessment"
        )
        self.label_scan_button.setCursor(
            Qt.PointingHandCursor
        )
        self.label_scan_button.setEnabled(False)
        self.label_scan_button.clicked.connect(
            self.assess_label_consistency
        )

        label_layout.addWidget(label_title)
        label_layout.addWidget(label_description)

        label_layout.addWidget(dataset_title)
        label_layout.addLayout(dataset_row)

        label_layout.addWidget(labels_title)
        label_layout.addLayout(labels_row)

        label_layout.addWidget(
            self.label_scan_button
        )

        layout.addWidget(label_selection)

        # ---------------------------------------------------------
        # A5 result
        # ---------------------------------------------------------
        self.label_result_card = QFrame()
        self.label_result_card.setObjectName(
            "contentCard"
        )
        self.label_result_card.hide()

        label_result_layout = QVBoxLayout(
            self.label_result_card
        )
        label_result_layout.setContentsMargins(
            20,
            18,
            20,
            18,
        )
        label_result_layout.setSpacing(10)

        result_title = QLabel(
            "Label Consistency Result"
        )
        result_title.setObjectName("cardTitle")

        self.label_result_summary = QLabel()
        self.label_result_summary.setObjectName(
             "muted"
             )
        self.label_result_summary.setWordWrap(True)
        self.label_result_summary.setFixedHeight(170)
        self.label_conflict_table = QTableWidget(
            0,
            6,
        )

        self.label_conflict_table.setHorizontalHeaderLabels(
            [
                "Image A",
                "Image B",
                "dHash",
                "Appearance Similarity",
                "Classes A",
                "Classes B",
            ]
        )

        self.label_conflict_table.setColumnWidth(
            0,
            260,
        )
        self.label_conflict_table.setColumnWidth(
            1,
            260,
        )
        self.label_conflict_table.setColumnWidth(
            2,
            100,
        )
        self.label_conflict_table.setColumnWidth(
            3,
            150,
        )
        self.label_conflict_table.setColumnWidth(
            4,
            120,
        )
        self.label_conflict_table.setColumnWidth(
            5,
            120,
        )

        self.label_conflict_table.setAlternatingRowColors(
            True
        )
        self.label_conflict_table.setFixedHeight(90)


        label_result_layout.addWidget(
            result_title
        )
        label_result_layout.addWidget(
            self.label_result_summary
        )
        label_result_layout.addWidget(
            self.label_conflict_table
        )

        layout.addWidget(
            self.label_result_card
        )

            # =============================================================
    # A5 LABEL CONSISTENCY SELECTION
    # =============================================================

    def select_label_dataset(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Dataset Directory",
        )

        if not folder:
            return

        self.label_dataset_path = Path(folder)

        self.label_dataset_label.setText(
            str(self.label_dataset_path)
        )

        self.update_label_scan_button()

    def select_labels_directory(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Labels Directory",
        )

        if not folder:
            return

        self.label_labels_path = Path(folder)

        self.label_labels_dir_label.setText(
            str(self.label_labels_path)
        )

        self.update_label_scan_button()

    def update_label_scan_button(self):
        enabled = (
            self.label_dataset_path is not None
            and self.label_labels_path is not None
        )

        self.label_scan_button.setEnabled(
            enabled
        )

        # =============================================================
    # A5 LABEL CONSISTENCY ASSESSMENT
    # =============================================================

    def assess_label_consistency(self):
        if (
            self.label_dataset_path is None
            or self.label_labels_path is None
        ):
            return

        try:
            result = assess_label_consistency(
                self.label_dataset_path,
                self.label_labels_path,
            )

        except Exception as exc:
            self.label_result_card.show()

            self.label_result_summary.setText(
                f"ASSESSMENT FAILED\n\n{exc}"
            )

            self.label_conflict_table.setRowCount(0)

            return

        self.show_label_consistency_result(result)

    # =============================================================
    # A5 LABEL CONSISTENCY RESULTS
    # =============================================================

    def show_label_consistency_result(self, result):
        self.label_result_card.show()

        images = result[
            "images_discovered"
        ]

        missing = result[
            "missing_label_count"
        ]

        malformed = result[
            "malformed_label_count"
        ]

        empty = result[
            "empty_label_count"
        ]

        near_duplicate_pairs = result[
            "near_duplicate_pair_count"
        ]

        conflicting_pairs = result[
            "conflicting_pair_count"
        ]

        finding_count = result[
            "finding_count"
        ]

        if finding_count == 0:
            status = "STATUS: PASSED"
        else:
            status = "STATUS: FINDINGS DETECTED"

        self.label_result_summary.setText(
            f"{status}\n\n"
            f"Images discovered: {images}\n"
            f"Missing labels: {missing}\n"
            f"Malformed labels: {malformed}\n"
            f"Empty labels: {empty}\n"
            f"Near-duplicate pairs: {near_duplicate_pairs}\n"
            f"Conflicting near-duplicate pairs: "
            f"{conflicting_pairs}\n"
            f"Total findings: {finding_count}\n\n"
            "Note: A conflicting label among visually similar "
            "images is a potential label inconsistency, not proof "
            "that either annotation is incorrect."
        )


        self.label_conflict_table.setRowCount(0)

        for pair in result[
            "conflicting_pairs"
        ]:
            row = (
                self.label_conflict_table.rowCount()
            )

            self.label_conflict_table.insertRow(
                row
            )

            self.label_conflict_table.setItem(
                row,
                0,
                QTableWidgetItem(
                    pair["file_a"]
                ),
            )

            self.label_conflict_table.setItem(
                row,
                1,
                QTableWidgetItem(
                    pair["file_b"]
                ),
            )

            self.label_conflict_table.setItem(
                row,
                2,
                QTableWidgetItem(
                    str(
                        pair["hamming_distance"]
                    )
                ),
            )

            self.label_conflict_table.setItem(
                row,
                3,
                QTableWidgetItem(
                    f"{pair['appearance_similarity']:.3f}"
                ),
            )

            self.label_conflict_table.setItem(
                row,
                4,
                QTableWidgetItem(
                    str(pair["classes_a"])
                ),
            )

            self.label_conflict_table.setItem(
                row,
                5,
                QTableWidgetItem(
                    str(pair["classes_b"])
                ),
            )






