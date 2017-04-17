#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn (stephen@bunn.io)
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

import os

from . import (
    packet_sniffer,
    packet_list,
    packet_inspect,
    packet_filter,
    packet_digest
)

import scapy.all as scapy
from PyQt5 import QtCore, QtGui, QtWidgets


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
        self._packet_list = \
            packet_list.PacketListWidget(parent=self)
        self._packet_list.on_selected.connect(self.packet_selected)

        self._packet_inspector = \
            packet_inspect.PacketInspectorWidget(parent=self)

        self._packet_filter = \
            packet_filter.PacketFilterWidget(parent=self)
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
            self._sniffer_thread = packet_sniffer.PacketSnifferThread(
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
            digest_widget = packet_digest.PacketDigestDialog(
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
                for packet_item in selected_packets:
                    packet = packet_item.data(QtCore.Qt.UserRole)
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
