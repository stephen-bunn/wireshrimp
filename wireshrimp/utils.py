#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn <r>
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

"""
utils.py
.. module::
    :platform: Linux, MacOSX, Win32
    :synopsis:
    :created: 04-07-2017 08:22:21
    :modified: 04-07-2017 08:22:21
.. moduleauthor:: Stephen Bunn <r>
"""

import io
import sys


class stdout_capture(list):

    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._string_io = io.StringIO()
        return self

    def __exit__(self, *args):
        self.extend(self._string_io.getvalue().splitlines())
        del self._string_io
        sys.stdout = self._stdout
