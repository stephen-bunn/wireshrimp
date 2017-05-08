#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn (stephen@bunn.io)
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

import scapy.all as scapy
from PyQt5 import QtCore, QtGui, QtWidgets


class PacketListWidget(QtWidgets.QWidget):
    on_selected = QtCore.pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__()
        self._packets = []
        self._filter_clauses = None
        self.parent = parent
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        self._packet_list = QtWidgets.QListWidget(self)
        self._packet_list.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection
        )
        self._packet_list.selectionModel().selectionChanged\
            .connect(self.packet_selected)
        layout.addWidget(self._packet_list)
        self.setLayout(layout)
        self.setStyleSheet('font: bold; font-family: Courier;')

    def _filter_packet(self, packet: scapy.Packet) -> bool:
        if not self._filter_clauses:
            return True
        clause_evals = []
        for ((layer, attribute), value) in self._filter_clauses:
            truthy_clause = True
            try:
                if layer[0] == '!':
                    truthy_clause = False
                    layer = layer[1:]
                layer_reference = getattr(scapy, layer)
                if attribute == 'exists':
                    clause_evals.append(str(int(
                        packet.haslayer(layer_reference)
                    )) == value)
                else:
                    if packet.haslayer(layer_reference):
                        packet_layer = packet[layer_reference]
                        packet_attribute = str(
                            getattr(packet_layer, attribute)
                        )
                        clause_evals.append(
                            (packet_attribute == value)
                            if truthy_clause else
                            (packet_attribute != value)
                        )
                    else:
                        clause_evals.append(False)
            except AttributeError as exc:
                clause_evals.append(False)
        return all(clause_evals)

    def refresh_filter(self) -> None:
        for packet_item in range(self._packet_list.count()):
            packet_item = self._packet_list.item(packet_item)
            packet_item.setHidden(not self._filter_packet(
                packet_item.data(QtCore.Qt.UserRole)
            ))

    def current_items(self) -> list:
        return self._packet_list.selectedItems()

    def add_packet(self, packet: scapy.Packet) -> None:
        packet_item = QtWidgets.QListWidgetItem(packet.summary())
        packet_item.setData(QtCore.Qt.UserRole, packet)
        self._packet_list.addItem(packet_item)
        if self._filter_packet(packet) and \
                self.parent.parent.auto_select_action.isChecked():
            self._packet_list.clearSelection()
            self._packet_list.setCurrentItem(packet_item)
            self._packet_list.scrollToBottom()
        self.refresh_filter()

    def clear_packets(self) -> None:
        for packet in self._packet_list.selectedItems():
            packet_index = self._packet_list.row(packet)
            self._packet_list.takeItem(packet_index)

    def packet_selected(
        self,
        selected: QtCore.QItemSelection, deselected: QtCore.QItemSelection
    ) -> None:
        self.on_selected.emit(self._packet_list.selectedItems())

    def filter_changed(self, clauses: list) -> None:
        if len(clauses) <= 0:
            self._filter_clauses = None
        else:
            self._filter_clauses = clauses
        self.refresh_filter()
