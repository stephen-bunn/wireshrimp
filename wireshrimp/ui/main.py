#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn <r>
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

"""
main.py
.. module::
    :platform: Linux, MacOSX, Win32
    :synopsis:
    :modified: 04-10-2017 11:44:50
.. moduleauthor:: Stephen Bunn <r>
"""

import sys
import threading

import netifaces
import blinker
import scapy.all as scapy
import scapy_http.http
from PyQt5 import QtCore, QtGui
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSplitter, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTreeWidget, QTreeWidgetItem,
    QListWidget, QListWidgetItem, QPushButton, QStatusBar
)


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = 'Wireshrimp'
        self.left = 50
        self.top = 50
        self.width = 780
        self.height = 500
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        self.tabs = QTabWidget()
        for interface in netifaces.interfaces():
            packet_list = PacketList(interface)
            self.tabs.addTab(packet_list, interface)
        self.setCentralWidget(self.tabs)
        self.show()


class SnifferThread(QtCore.QThread):
    on_start = QtCore.pyqtSignal(str)
    on_packet = QtCore.pyqtSignal(object)
    on_end = QtCore.pyqtSignal(tuple)

    def __init__(self, interface: str, parent: object=None):
        QtCore.QThread.__init__(self, parent)
        self._interface = interface
        self._sniffed_count = 0
        self._stopped = False

    def stop(self):
        self._stopped = True

    def run(self):
        self.on_start.emit(self._interface)
        while not self._stopped:
            try:
                sniffed = scapy.sniff(
                    iface=self._interface, store=1, count=1
                )[0]
                if not self._stopped:
                    self.on_packet.emit(sniffed)
            except OSError as exc:
                pass
        self.on_end.emit((self._interface, self._sniffed_count))
        self.exit(0)


class PacketList(QWidget):
    on_start = QtCore.pyqtSignal(str)
    on_packet = QtCore.pyqtSignal(object)
    on_end = QtCore.pyqtSignal(tuple)

    def __init__(self, interface_name: str):
        super().__init__()
        self._interface = interface_name
        self._packets = []

        self._list_widget = QListWidget(self)
        self._list_widget.setStyleSheet('font: bold; font-family: Courier;')
        self._selection_model = self._list_widget.selectionModel()
        self._selection_model.selectionChanged.connect(self.packet_selected)

        self._button = QPushButton('Start')
        self._button.released.connect(self.start_sniff)

        self._tree_widget = QTreeWidget(self)
        self._tree_widget.setHeaderHidden(True)
        self._tree_widget.setStyleSheet('font-family: Courier;')

        splitter = QSplitter(self)
        splitter.addWidget(self._list_widget)
        splitter.addWidget(self._tree_widget)
        splitter.setSizes([700, 300])

        layout = QVBoxLayout()
        layout.addWidget(self._button)
        layout.addWidget(splitter)
        self.setLayout(layout)

    @property
    def interface(self) -> str:
        return self._interface

    def _expand_packet_layers(self, packet: scapy.Packet):
        yield packet
        while packet.payload:
            packet = packet.payload
            yield packet

    def start_sniff(self) -> None:
        self._button.released.disconnect()
        self._sniff_thread = SnifferThread(self.interface)
        self._sniff_thread.daemon = True
        self._sniff_thread.on_start.connect(self.on_start.emit)
        self._sniff_thread.on_packet.connect(self.sniffed)
        self._sniff_thread.on_end.connect(self.on_end.emit)
        self._button.setText('Stop')
        self._button.released.connect(self._sniff_thread.stop)
        self._button.released.connect(self.stop_sniff)
        self._sniff_thread.start()

    def stop_sniff(self) -> None:
        self._button.disconnect()
        self._button.setText('Start')
        self._button.released.connect(self.start_sniff)

    def sniffed(self, packet: scapy.Packet) -> None:
        self.on_packet.emit(packet)
        self._packets.append(packet)
        packet_item = QListWidgetItem(packet.summary())
        self._list_widget.addItem(packet_item)
        self._list_widget.scrollToBottom()

    def packet_selected(
        self,
        selected: QtCore.QItemSelection, deselected: QtCore.QItemSelection
    ):
        self._tree_widget.clear()
        packet = self._packets[selected.indexes()[0].row()]
        for layer in self._expand_packet_layers(packet):
            layer_item = QTreeWidgetItem(self._tree_widget)
            layer_font = QtGui.QFont()
            layer_font.setWeight(QtGui.QFont.Bold)
            layer_item.setFont(0, layer_font)
            layer_item.setText(0, layer.name)
            for field_name in [field.name for field in layer.fields_desc]:
                field = getattr(layer, field_name)
                field_item = QTreeWidgetItem(layer_item)
                if isinstance(field, list):
                    if len(field) > 0:
                        field_item.setText(0, field_name)
                        for nested in field:
                            nested_item = QTreeWidgetItem(field_item)
                            nested_item.setText(0, str(nested))
                        continue
                field_item.setText(0, ('{field_name}: {field}').format(
                    field_name=field_name, field=getattr(layer, field_name)
                ))
        self._tree_widget.expandToDepth(1)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
