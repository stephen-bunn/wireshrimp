#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn <r>
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

"""
packet_inspect.py
.. module::
    :platform: Linux, MacOSX, Win32
    :synopsis:
    :modified: 04-10-2017 10:51:34
.. moduleauthor:: Stephen Bunn <r>
"""

import sys

import scapy.all as scapy
from PyQt5 import QtCore
from PyQt5.QtWidgets import (
    QApplication, QWidget,
    QTreeView
)


class PacketLayerNode(object):

    def __init__(self, packet_layer):
        pass


class PacketNode(object):

    def __init__(self, packet: scapy.Packet):
        self._packet = packet
        self._children = list(
            layer.summary()
            for layer in self._expand_layers(self._packet)
        )
        self._parent = None
        self._row = 0

    def _expand_layers(self, packet: scapy.Packet):
        yield packet
        while packet.payload:
            packet = packet.payload
            yield packet

    def parent(self):
        return self._parent

    def row(self):
        return self._row

    def data(self, in_column: int):
        if in_column >= 0 and in_column < self.childCount():
            return self._children[in_column]

    def columnCount(self):
        return 0

    def childCount(self) -> int:
        return len(self._children)

    def child(self, in_row: int):
        if in_row >= 0 and in_row < self.childCount():
            return self._children[in_row]


class PacketModel(QtCore.QAbstractItemModel):

    def __init__(self, packet: scapy.Packet):
        QtCore.QAbstractItemModel.__init__(self)
        self._root = PacketNode(packet)

    def rowCount(self, in_index: int):
        if in_index.isValid():
            return in_index.internalPointer().childCount()
        return self._root.childCount()

    def columnCount(self, in_index: int):
        return 1


if __name__ == '__main__':
    packet = scapy.sniff(iface='enp0s25', store=1, count=1)
    app = QApplication(sys.argv)
    v = QTreeView()
    v.setModel(PacketModel(packet[0]))
    v.show()
    sys.exit(app.exec_())
