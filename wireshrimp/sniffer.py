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
    _thread = False

    @abc.abstractmethod
    def start(self) -> None:
        raise NotImplementedError()

    def stop(self) -> None:
        pass


class InterfaceSniffer(AbstractSniffer):

    def __init__(self, interface: Interface):
        self._interface = interface
        self._thread = threading.Thread(
            target=scapy.sniff,
            kwargs=dict(
                iface=self.interface.name,
                store=0,
                prn=self.on_packet
            ),
            daemon=True
        )

    @property
    def interface(self) -> Interface:
        return self._interface

    def start(self) -> None:
        self._thread.start()
