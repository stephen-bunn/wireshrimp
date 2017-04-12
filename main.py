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
    :created: 04-06-2017 21:21:33
    :modified: 04-06-2017 21:21:33
.. moduleauthor:: Stephen Bunn <r>
"""
import sys

import wireshrimp

import scapy.all as scapy
import scapy_http.http
from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtWidgets import QApplication, QListWidget

app = QApplication(sys.argv)
list_widget = QListWidget()
list_widget.show()


net = wireshrimp.Network()
sniffers = [wireshrimp.InterfaceSniffer(iface) for iface in [net.gateway]]

packets = {}

def callback(sender, **data):
    if sender.name not in packets:
        packets[sender.name] = []
    packets[sender.name].append(data['packet'])
    list_widget.addItem(data['packet'].summary())
    # print((data['packet']['IP'].src, data['packet']['IP'].dst,))

try:
    for iface_sniff in sniffers:
        iface_sniff.on_packet.connect(callback)
        iface_sniff.start()
    for iface_sniff in sniffers:
        iface_sniff.thread.join()
finally:
    pass

sys.exit(app.exec_())
