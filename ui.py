from typing import List, Optional

import binaryninjaui

if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QAbstractItemView,
        QAbstractScrollArea,
        QDialog,
        QDialogButtonBox,
        QLabel,
        QSizePolicy,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
    )
else:
    from PySide2.QtCore import Qt
    from PySide2.QtWidgets import (
        QAbstractItemView,
        QAbstractScrollArea,
        QDialog,
        QDialogButtonBox,
        QLabel,
        QSizePolicy,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
    )


from . import hashdb_api as api


class _HashAlgorithmInfoTable(QTableWidget):
    def __init__(self, parent=None):
        super(_HashAlgorithmInfoTable, self).__init__(parent)

        self.verticalHeader().hide()
        self.setShowGrid(False)

        self.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )  # always select the entire row
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        self.setSizePolicy(
            QSizePolicy(
                QSizePolicy.Policy.Expanding,  # horizontal
                QSizePolicy.Policy.Expanding,  # vertical
            )
        )
        self.setSizeAdjustPolicy(
            QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents
        )  # perform the actual auto-expansion according to the size policy

        self.setWordWrap(True)
        self.setTextElideMode(Qt.TextElideMode.ElideNone)

        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(False)

    def populate(self, hash_algorithms: List[api.Algorithm]) -> None:
        self.setRowCount(len(hash_algorithms))
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(["Algorithm", "Type", "Description"])

        for row_idx, algorithm in enumerate(hash_algorithms):
            algorithm_table_items = [
                QTableWidgetItem(algorithm.algorithm),
                QTableWidgetItem(f"{algorithm.type}"),
                QTableWidgetItem(algorithm.description),
            ]
            for column_idx, algorithm_table_item in enumerate(algorithm_table_items):
                self.setItem(row_idx, column_idx, algorithm_table_item)

        # trigger a resize
        self.resizeColumnsToContents()
        self.resizeRowsToContents()


class _HashAlgorithmInfoDialog(QDialog):
    def __init__(self, title: str, prompt: str, parent=None):
        super(_HashAlgorithmInfoDialog, self).__init__(parent)

        self.setWindowTitle(title)
        self.infoTextLabel = QLabel(prompt)
        self.algorithmInfoTable = _HashAlgorithmInfoTable()
        self.buttonBox = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )

        layout = QVBoxLayout()
        layout.addWidget(self.infoTextLabel)
        layout.addWidget(self.algorithmInfoTable)
        layout.addWidget(self.buttonBox)
        self.setLayout(layout)

        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

    def exec_and_get_selected_choice_idx(self) -> Optional[int]:
        dialog_return_code: QDialog.DialogCode = (
            self.exec()
        )  # block until dialog closes
        if dialog_return_code == QDialog.DialogCode.Accepted:
            return self.algorithmInfoTable.currentRow()
        else:
            return None


def get_algorithm_choice(
    context, title: str, prompt_text: str, algorithm_choices: List[api.Algorithm]
) -> Optional[int]:
    hash_algorithm_info_dialog = _HashAlgorithmInfoDialog(
        title=title, prompt=prompt_text, parent=context.widget
    )
    hash_algorithm_info_dialog.algorithmInfoTable.populate(algorithm_choices)
    return hash_algorithm_info_dialog.exec_and_get_selected_choice_idx()
