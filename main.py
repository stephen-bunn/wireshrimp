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
import logging

import wireshrimp

from PyQt5 import QtWidgets

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
app = QtWidgets.QApplication(sys.argv)
window = wireshrimp.app.WireshrimpMainWindow()
window.show()
sys.exit(app.exec_())
