#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn (stephen@bunn.io)
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

import hexview
import scapy.all as scapy
from PyQt5 import QtWidgets


class PacketDigestDialog(QtWidgets.QDialog):
    """ Packet digest dialog widget.
    """

    def __init__(self, packet: scapy.Packet, parent=None):
        """ Initializes the packet digest view.

        :param packet: The packet to digest
        :type packet: scapy.Packet
        :param parent: The parent of the digest dialog
        :type parent: QtWidgets.QDialog
        """

        super().__init__(parent)
        self._packet = packet
        self._init_ui()

    def _init_ui(self) -> None:
        """ Initialize child widgets and widget connections.

        :returns: Does not return
        :rtype: None
        """

        self.setWindowTitle(self._packet.summary())
        layout = QtWidgets.QVBoxLayout(self)

        # build a frame for the hexview widget
        self.frame = QtWidgets.QFrame()
        self._hexview_widget = hexview.HexViewWidget(
            bytearray(bytes(self._packet)), self.frame
        )

        layout.addWidget(self._hexview_widget)
        self.setLayout(layout)
