#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn (stephen@bunn.io)
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

import os

from .packet_digest import PacketDigestDialog

import scapy.all as scapy
from PyQt5 import QtCore, QtGui, QtWidgets


class PacketSnifferThread(QtCore.QThread):
    on_start  = QtCore.pyqtSignal(str)
    on_end    = QtCore.pyqtSignal(tuple)
    on_packet = QtCore.pyqtSignal(object)

    def __init__(self, interface: str, filter_: str=None, parent: object=None):
        QtCore.QThread.__init__(self, parent)
        self._interface = interface
        self._filter = filter_
        self.daemon = True
        self._sniffed = 0
        self._stopped = False

    def stop(self) -> None:
        self._stopped = True

    def is_stopped(self) -> bool:
        return self._stopped

    def run(self) -> None:
        self.on_start.emit(self._interface)
        while not self.is_stopped():
            try:
                packet = scapy.sniff(
                    iface=self._interface,
                    store=1, count=1
                )[0]
                if not self.is_stopped():
                    self._sniffed += 1
                    self.on_packet.emit(packet)
            except OSError as exc:
                pass
        self.on_end.emit((self._interface, self._sniffed))
        self.exit(0)


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
            try:
                layer_reference = getattr(scapy, layer)
                if packet.haslayer(layer_reference):
                    packet_layer = packet[layer_reference]
                    clause_evals.append(
                        str(getattr(packet_layer, attribute)) == value
                    )
                else:
                    clause_evals.append(False)
            except AttributeError as exc:
                clause_evals.append(False)
        return all(clause_evals)

    def apply_filter(self) -> None:
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
        self.apply_filter()

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
        self.apply_filter()


class PacketInspectorWidget(QtWidgets.QWidget):

    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        self._inspect_tree = QtWidgets.QTreeWidget(self)
        self._inspect_tree.setHeaderHidden(True)
        layout.addWidget(self._inspect_tree)
        self._label_font = QtGui.QFont('Courier')
        self._label_font.setWeight(QtGui.QFont.Bold)
        self.setLayout(layout)
        self.setStyleSheet('font-family: Courier;')

    def _expand_packet_layers(self, packet: scapy.Packet):
        yield packet
        while packet.payload:
            packet = packet.payload
            yield packet

    def clear_packets(self) -> None:
        self._inspect_tree.clear()

    def packet_selected(self, packet_items: list) -> None:
        if len(packet_items) == 1:
            packet = packet_items[0].data(QtCore.Qt.UserRole)
            self.setEnabled(True)
            self._inspect_tree.clear()
            for layer in self._expand_packet_layers(packet):
                layer_item = QtWidgets.QTreeWidgetItem(self._inspect_tree)
                layer_item.setText(0, layer.name)
                layer_item.setFont(0, self._label_font)
                for field_name in [field.name for field in layer.fields_desc]:
                    field = getattr(layer, field_name)
                    field_item = QtWidgets.QTreeWidgetItem(layer_item)
                    if isinstance(field, list) and len(field) > 0:
                        field_item.setFont(0, self._label_font)
                        field_item.setText(0, field_name)
                        for nested_field in field:
                            nested_item = QtWidgets.QTreeWidgetItem(field_item)
                            if isinstance(nested_field, list):
                                for (key, value, *_) in nested_field:
                                    nested_item.setText(0, (
                                        '{key}: {value}'
                                    ).format(key=key, value=value))
                            elif isinstance(nested_field, tuple):
                                (key, value, *_) = nested_field
                                nested_item.setText(0, (
                                    '{key}: {value}'
                                ).format(key=key, value=value))
                            else:
                                nested_item.setText(0, str(nested_field))
                    else:
                        field_item.setText(0, (
                            '{field_name}: {field}'
                        ).format(field_name=field_name, field=field))
            self._inspect_tree.expandToDepth(1)
        else:
            self.setEnabled(False)


class PacketFilterWidget(QtWidgets.QLineEdit):
    on_valid = QtCore.pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self._init_ui()

    def _init_ui(self) -> None:
        self.textChanged.connect(self.validate_text)
        self.setStyleSheet('font-family: Courier;')

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


class PacketViewWidget(QtWidgets.QWidget):
    on_start  = QtCore.pyqtSignal(str)
    on_end    = QtCore.pyqtSignal(tuple)
    on_packet = QtCore.pyqtSignal(object)

    def __init__(self, interface: str, parent=None):
        super().__init__()
        self._interface = interface
        self.parent = parent
        self._packets = []
        self._init_ui()

    def _init_ui(self) -> None:
        self._packet_list = PacketListWidget(parent=self)
        self._packet_list.on_selected.connect(self.packet_selected)
        self._packet_inspector = PacketInspectorWidget(parent=self)
        self._packet_filter = PacketFilterWidget(parent=self)
        self._packet_filter.on_valid.connect(self._packet_list.filter_changed)

        self._view_splitter = QtWidgets.QSplitter(self)
        self._view_splitter.addWidget(self._packet_list)
        self._view_splitter.addWidget(self._packet_inspector)
        self._view_splitter.setSizes([700, 300])

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self._packet_filter)
        layout.addWidget(self._view_splitter)
        self.setLayout(layout)

    def is_sniffing(self) -> bool:
        if hasattr(self, '_sniffer_thread'):
            return not self._sniffer_thread.is_stopped()
        return False

    def toggle_sniffer(self) -> None:
        if not hasattr(self, '_sniffer_thread') or \
                self._sniffer_thread.is_stopped():
            self._sniffer_thread = PacketSnifferThread(
                self._interface, filter_=self._packet_filter.text()
            )
            self._sniffer_thread.on_start.connect(self.on_start.emit)
            self._sniffer_thread.on_end.connect(self.on_end.emit)
            self._sniffer_thread.on_packet.connect(self.packet_sniffed)
            self._sniffer_thread.start()
        else:
            self._sniffer_thread.stop()

    def clear_packets(self) -> None:
        self._packet_list.clear_packets()
        self._packet_inspector.clear_packets()

    def digest_packet(self) -> None:
        selected_packets = self._packet_list.current_items()
        if len(selected_packets) == 1:
            digest_widget = PacketDigestDialog(
                selected_packets[0].data(QtCore.Qt.UserRole)
            )
            digest_widget.exec_()
        elif len(selected_packets) > 1:
            QtWidgets.QMessageBox.information(
                self, 'Inspect Error',
                'Only one packet can be inspected at a time'
            )
        else:
            QtWidgets.QMessageBox.information(
                self, 'Inspect Error',
                'No packet is selected for inspection'
            )

    def save_packets(self) -> None:
        selected_packets = self._packet_list.current_items()
        if len(selected_packets) > 0:
            (save_to, save_type) = QtWidgets.QFileDialog.getSaveFileName(
                self, 'Saving {count} packets'.format(
                    count=len(selected_packets)
                ), os.getcwd()
            )
            if save_to:
                for packet in selected_packets:
                    scapy.wrpcap(save_to, packet, append=True)
        else:
            QtWidgets.QMessageBox.information(
                self, 'Save Error',
                'No packets were selected to save'
            )

    def packet_sniffed(self, packet: scapy.Packet) -> None:
        self.on_packet.emit(packet)
        self._packet_list.add_packet(packet)

    def packet_selected(self, packet_items: list):
        self._packet_inspector.packet_selected(packet_items)
