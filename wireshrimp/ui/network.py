#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

"""
network.py
.. module::
    :platform: Linux, MacOSX, Win32
    :synopsis:
    :created: 04-06-2017 20:27:37
    :modified: 04-06-2017 20:27:37
.. moduleauthor:: Stephen Bunn
"""

from typing import List, Tuple

import netifaces


class Interface(object):

    def __init__(self, name: str):
        self._name = name

    def __repr__(self):
        return ('<{self.__class__.__name__} "{self.name}">').format(self=self)

    def __getitem__(self, addr: int):
        try:
            return netifaces.ifaddresses(self.name)[addr]
        except KeyError as exc:
            raise AttributeError((
                "no address type '{addr}' in {self}"
            ).format(self=self, addr=addr))

    @property
    def name(self) -> str:
        return self._name


class Network(object):
    _address_types = [
        attr
        for attr in dir(netifaces)
        if attr.startswith('AF')
    ]

    def __init__(self):
        for addr_type in self._address_types:
            if not hasattr(self, addr_type):
                setattr(self, addr_type, getattr(netifaces, addr_type))

    def __len__(self):
        return len(self.interfaces)

    def __getitem__(self, iface: str):
        for interface in self.interfaces:
            if interface.name == iface:
                return interface
        raise AttributeError((
            "no interface named '{interface}'"
        ).format(interface=interface))

    @property
    def interfaces(self) -> List[Interface]:
        return [Interface(iface) for iface in netifaces.interfaces()]

    @property
    def gateway(self) -> Tuple[str, str]:
        return Interface(netifaces.gateways()['default'][self.AF_INET][-1])
