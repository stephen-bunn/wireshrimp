#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn (stephen@bunn.io)
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

import hexview
import scapy.all as scapy
from PyQt5 import QtWidgets


class PacketDigestDialog(QtWidgets.QDialog):

    def __init__(self, packet: scapy.Packet, parent=None):
        super().__init__(parent)
        self._packet = packet
        self._init_ui()

    def _init_ui(self) -> None:
        self.setWindowTitle(self._packet.summary())
        layout = QtWidgets.QVBoxLayout(self)
        self.frame = QtWidgets.QFrame()
        self._hexview_widget = hexview.HexViewWidget(
            bytearray(bytes(self._packet)), self.frame
        )
        layout.addWidget(self._hexview_widget)
        self.setLayout(layout)
