#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn <r>
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

"""
sift.py
.. module::
    :platform: Linux, MacOSX, Win32
    :synopsis:
    :created: 04-07-2017 08:08:08
    :modified: 04-07-2017 08:08:08
.. moduleauthor:: Stephen Bunn <r>
"""

from typing import List

from . import const

import scapy.all as scapy


class Sifter(object):

    def __init__(self, filter_logic: str):
        self._filter_logic = filter_logic

    def sift(self, packets: List[scapy.Packet]) -> List[scapy.Packet]:
        pass
