#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn (stephen@bunn.io)
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

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
