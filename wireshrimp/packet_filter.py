#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn (stephen@bunn.io)
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

from PyQt5 import QtCore, QtGui, QtWidgets


class PacketFilterWidget(QtWidgets.QLineEdit):
    on_valid = QtCore.pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self._init_ui()

    def _init_ui(self) -> None:
        self.textChanged.connect(self.validate_text)
        self.setStyleSheet('font: bold; font-family: Courier;')

    def _build_clauses(self, text: str) -> list:
        filter_clauses = []
        for clause in text.split('&'):
            clause = clause.strip()
            if len(clause) > 0:
                if len(clause.split('=')) >= 2:
                    (key, *_, value) = clause.split('=')
                    if len(key.split('.')) == 2 and len(value) > 0:
                        (layer, attribute) = key.split('.')
                        filter_clauses.append((
                            (layer.strip(), attribute.strip()),
                            value.strip()
                        ))
        return filter_clauses

    def validate_text(self, text: str) -> None:
        self.on_valid.emit(self._build_clauses(text))
