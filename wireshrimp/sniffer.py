#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

"""
sniffer.py
.. module::
    :platform: Linux, MacOSX, Win32
    :synopsis:
    :created: 04-06-2017 20:11:13
    :modified: 04-06-2017 20:11:13
.. moduleauthor:: Stephen Bunn
"""

import abc
import threading

from .network import Interface

import blinker
import scapy.all as scapy
import scapy_http.http


class AbstractSniffer(object, metaclass=abc.ABCMeta):
    on_packet = blinker.Signal()

    def __repr__(self):
        return ('<{self.__class__.__name__} "{self.name}">').format(self=self)

    @abc.abstractproperty
    def name(self) -> str:
        raise NotImplementedError()

    @abc.abstractproperty
    def thread(self) -> threading.Thread:
        raise NotImplementedError()

    @abc.abstractmethod
    def start(self) -> None:
        raise NotImplementedError()

    def packet_prn(self, packet: scapy.Packet) -> None:
        self.on_packet.send(self, packet=packet)

    def start(self) -> None:
        self.thread.start()


class InterfaceSniffer(AbstractSniffer):

    def __init__(self, interface: Interface):
        self._interface = interface

    @property
    def name(self) -> str:
        return self.interface.name

    @property
    def interface(self) -> Interface:
        return self._interface

    @property
    def thread(self) -> threading.Thread:
        if not hasattr(self, '_thread'):
            self._thread = threading.Thread(
                target=scapy.sniff,
                kwargs=dict(
                    iface=self.name,
                    prn=self.packet_prn,
                    store=0
                ),
                daemon=True
            )
        return self._thread
