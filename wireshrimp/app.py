#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn (stephen@bunn.io)
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

import os
import sys

from . import const
from .packet_view import PacketViewWidget

import netifaces
from PyQt5 import QtGui, QtWidgets


class WireshrimpMainWindow(QtWidgets.QMainWindow):

    def __init__(self, width: int=780, height: int=500):
        super().__init__()

        (self.width, self.height) = (width, height)
        self.icon = const.icon
        self.title = '{const.module_name} v{const.version}'.format(const=const)
        self._init_ui()

    def _init_ui(self) -> None:
        self.root_check()

        self.setWindowTitle(self.title)
        self.setWindowIcon(QtGui.QIcon(self.icon))
        self.resize(self.width, self.height)

        exit_action = QtWidgets.QAction(self.style().standardIcon(
            QtWidgets.QStyle.SP_DialogCloseButton
        ), 'Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.quit_application)

        self.sniff_action = QtWidgets.QAction(self.style().standardIcon(
            QtWidgets.QStyle.SP_MediaPlay
        ), 'Toggle Sniffing', self)
        self.sniff_action.setShortcut('Ctrl+Space')
        self.sniff_action.triggered.connect(self.toggle_sniff)

        clear_action = QtWidgets.QAction(self.style().standardIcon(
            QtWidgets.QStyle.SP_DialogDiscardButton
        ), 'Clear Packets', self)
        clear_action.setShortcut('Ctrl+W')
        clear_action.triggered.connect(self.clear_packets)

        digest_action = QtWidgets.QAction(self.style().standardIcon(
            QtWidgets.QStyle.SP_FileDialogContentsView
        ), 'Inspect Packet', self)
        digest_action.setShortcut('Ctrl+I')
        digest_action.triggered.connect(self.digest_packet)

        write_action = QtWidgets.QAction(self.style().standardIcon(
            QtWidgets.QStyle.SP_DialogSaveButton
        ), 'Save selected to PCAP', self)
        write_action.setShortcut('Ctrl+S')
        write_action.triggered.connect(self.save_packets)

        self.toolbar = self.addToolBar(self.title)
        self.toolbar.addAction(exit_action)
        self.toolbar.addAction(self.sniff_action)
        self.toolbar.addAction(clear_action)
        self.toolbar.addAction(digest_action)
        self.toolbar.addAction(write_action)

        self.tabs = QtWidgets.QTabWidget()
        for interface in netifaces.interfaces():
            self.tabs.addTab(PacketViewWidget(interface), interface)
        self.tabs.currentChanged.connect(self.tab_changed)
        self.setCentralWidget(self.tabs)

    def root_check(self):
        if not os.geteuid() == 0:
            QtWidgets.QMessageBox.information(
                self, 'Not Root', (
                    '{self.title} requires that it be run as a root user for '
                    'packet sniffing'
                ).format(self=self)
            )
            sys.exit(1)

    def quit_application(self):
        if QtWidgets.QMessageBox.question(
            self, ('Exiting {self.title}').format(self=self),
            'Are you sure you want to exit the application?',
            QtWidgets.QMessageBox.Yes, QtWidgets.QMessageBox.No
        ) == QtWidgets.QMessageBox.Yes:
            QtWidgets.qApp.quit()

    def tab_changed(self, tab_index: int):
        desired_icon = (
            QtWidgets.QStyle.SP_MediaStop
            if self.tabs.currentWidget().is_sniffing() else
            QtWidgets.QStyle.SP_MediaPlay
        )
        self.sniff_action.setIcon(self.style().standardIcon(desired_icon))

    def toggle_sniff(self):
        self.tabs.currentWidget().toggle_sniffer()
        self.tab_changed(None)

    def clear_packets(self):
        self.tabs.currentWidget().clear_packets()

    def digest_packet(self):
        self.tabs.currentWidget().digest_packet()

    def save_packets(self):
        self.tabs.currentWidget().save_packets()
