#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn <r>
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

"""
app.py
.. module::
    :platform: Linux, MacOSX, Win32
    :synopsis:
    :created: 04-06-2017 21:52:05
    :modified: 04-06-2017 21:52:05
.. moduleauthor:: Stephen Bunn <r>
"""

import sys

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtWidgets import QApplication, QListWidget


app = QApplication(sys.argv)
list_widget = QListWidget()
list_widget.show()

ls = ['text', 'text2', 'text3']
list_widget.addItems(ls)
sys.exit(app.exec_())
