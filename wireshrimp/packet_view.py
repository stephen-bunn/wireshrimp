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

    def __init__(self, interface: str, parent: object=None):
        QtCore.QThread.__init__(self, parent)
        self._interface = interface
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
    on_selected = QtCore.pyqtSignal(tuple)

    def __init__(self, scroll_to_bottom=False, parent=None):
        super().__init__()
        self._packets = []
        self._scroll_to_bottom = scroll_to_bottom
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

    def current_packets(self) -> int:
        return [
            self._packets[index.row()]
            for index in self._packet_list.selectedIndexes()
        ]

    def add_packet(self, packet: scapy.Packet) -> None:
        self._packets.append(packet)
        packet_item = QtWidgets.QListWidgetItem(packet.summary())
        self._packet_list.addItem(packet_item)
        self._packet_list.clearSelection()
        self._packet_list.setCurrentItem(packet_item)
        if self._scroll_to_bottom:
            self._packet_list.scrollToBottom()

    def clear_packets(self) -> None:
        self._packets = []
        self._packet_list.clear()

    def packet_selected(
        self,
        selected: QtCore.QItemSelection, deselected: QtCore.QItemSelection
    ) -> None:
        try:
            if len(selected.indexes()) <= 1:
                packet_index = selected.indexes()[0].row()
                self.on_selected.emit((
                    packet_index, self._packets[packet_index]
                ))
            else:
                self.on_selected.emit((None, None))
        except IndexError as exc:
            pass


class PacketInspectorWidget(QtWidgets.QWidget):

    def __init__(self, parent=None):
        super().__init__()
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

    def packet_selected(self, index: int, packet: scapy.Packet) -> None:
        if packet:
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


class PacketViewWidget(QtWidgets.QWidget):
    on_start  = QtCore.pyqtSignal(str)
    on_end    = QtCore.pyqtSignal(tuple)
    on_packet = QtCore.pyqtSignal(object)

    def __init__(self, interface: str):
        super().__init__()
        self._interface = interface
        self._packets = []
        self._init_ui()

    def _init_ui(self) -> None:
        self._packet_list = PacketListWidget(
            scroll_to_bottom=True, parent=self
        )
        self._packet_list.on_selected.connect(self.packet_selected)

        self._packet_inspector = PacketInspectorWidget(parent=self)

        self._view_splitter = QtWidgets.QSplitter(self)
        self._view_splitter.addWidget(self._packet_list)
        self._view_splitter.addWidget(self._packet_inspector)
        self._view_splitter.setSizes([700, 300])

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self._view_splitter)
        self.setLayout(layout)

    def is_sniffing(self) -> bool:
        if hasattr(self, '_sniffer_thread'):
            return not self._sniffer_thread.is_stopped()
        return False

    def toggle_sniffer(self) -> None:
        if not hasattr(self, '_sniffer_thread') or \
                self._sniffer_thread.is_stopped():
            self._sniffer_thread = PacketSnifferThread(self._interface)
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
        selected_packets = self._packet_list.current_packets()
        if len(selected_packets) == 1:
            digest_widget = PacketDigestDialog(selected_packets[0])
            digest_widget.exec_()
        else:
            QtWidgets.QMessageBox.information(
                self, 'Inspect Error',
                'Only one packet can be inspected at a time'
            )

    def save_packets(self) -> None:
        selected_packets = self._packet_list.current_packets()
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

    def packet_selected(self, *args: tuple):
        self._packet_inspector.packet_selected(*args[0])
