#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn (stephen@bunn.io)
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

import scapy.all as scapy
from PyQt5 import QtCore, QtGui, QtWidgets


class PacketInspectorWidget(QtWidgets.QWidget):

    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        self._inspect_tree = QtWidgets.QTreeWidget(self)
        self._inspect_tree.setHeaderHidden(True)
        layout.addWidget(self._inspect_tree)
        self._label_font = QtGui.QFont('Courier')
        self._label_font.setWeight(QtGui.QFont.Bold)
        self.setLayout(layout)
        self.setStyleSheet('font-family: Courier;')

    def _expand_packet_layers(self, packet: scapy.Packet):
        yield packet
        while packet.payload:
            packet = packet.payload
            yield packet

    def clear_packets(self) -> None:
        self._inspect_tree.clear()

    def packet_selected(self, packet_items: list) -> None:
        if len(packet_items) == 1:
            packet = packet_items[0].data(QtCore.Qt.UserRole)
            self.setEnabled(True)
            self._inspect_tree.clear()
            for layer in self._expand_packet_layers(packet):
                layer_item = QtWidgets.QTreeWidgetItem(self._inspect_tree)
                layer_item.setText(0, layer.name)
                layer_item.setFont(0, self._label_font)
                for field_name in [field.name for field in layer.fields_desc]:
                    field = getattr(layer, field_name)
                    field_item = QtWidgets.QTreeWidgetItem(layer_item)
                    if isinstance(field, list) and len(field) > 0:
                        field_item.setFont(0, self._label_font)
                        field_item.setText(0, field_name)
                        for nested_field in field:
                            nested_item = QtWidgets.QTreeWidgetItem(field_item)
                            if isinstance(nested_field, list):
                                for (key, value, *_) in nested_field:
                                    nested_item.setText(0, (
                                        '{key}: {value}'
                                    ).format(key=key, value=value))
                            elif isinstance(nested_field, tuple):
                                (key, value, *_) = nested_field
                                nested_item.setText(0, (
                                    '{key}: {value}'
                                ).format(key=key, value=value))
                            else:
                                nested_item.setText(0, str(nested_field))
                    else:
                        field_item.setText(0, (
                            '{field_name}: {field}'
                        ).format(field_name=field_name, field=field))
            self._inspect_tree.expandToDepth(1)
        else:
            self.setEnabled(False)
