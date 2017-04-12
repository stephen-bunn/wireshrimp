#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn <r>
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

"""
packet_list.py
.. module::
    :platform: Linux, MacOSX, Win32
    :synopsis:
    :modified: 04-10-2017 10:33:11
.. moduleauthor:: Stephen Bunn <r>
"""

import sys

import scapy.all as scapy
from PyQt5 import QtCore
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QListWidget, QPushButton
)


class SnifferThread(QtCore.QThread):
    on_packet = QtCore.pyqtSignal(object)

    def __init__(self, interface_name: str):
        QtCore.QThread.__init__(self)
        self._interface = interface_name

    @property
    def interface(self) -> str:
        return self._interface

    def packet_prn(self, packet: scapy.Packet) -> None:
        self.on_packet.emit((self.interface, packet))

    def run(self):
        scapy.sniff(iface=self.interface, prn=self.packet_prn, store=0)


class PacketList(QWidget):

    def __init__(self, interface_name: str):
        super().__init__()
        self._interface = interface_name
        self._list_widget = QListWidget()
        self._button = QPushButton('Start')
        self._button.clicked.connect(self.start_sniff)
        layout = QVBoxLayout()
        layout.addWidget(self._button)
        layout.addWidget(self._list_widget)
        self.setLayout(layout)

    @property
    def interface(self) -> str:
        return self._interface

    def start_sniff(self) -> None:
        self._sniff_thread = SnifferThread(self.interface)
        self._sniff_thread.on_packet.connect(self.sniffed)
        self._sniff_thread.start()
        self._button.setText('Stop')
        self._button.clicked.connect(self.stop_sniff)

    def stop_sniff(self) -> None:
        self._sniff_thread.kill()
        self._button.setText('Start')
        self._button.clicked.connect(self.start_sniff)

    def sniffed(self, data: tuple) -> None:
        self._list_widget.addItem(data[-1].summary())
        self._list_widget.scrollToBottom()


# if __name__ == '__main__':
#     app = QApplication(sys.argv)
#     window = PacketList('enp0s25')
#     window.resize(640, 480)
#     window.show()
#     sys.exit(app.exec_())
