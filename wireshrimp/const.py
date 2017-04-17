#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2017 Stephen Bunn
# GNU GPLv3 <https://www.gnu.org/licenses/gpl-3.0.en.html>

"""
const.py
.. module::
    :platform: Linux, MacOSX, Win32
    :synopsis:
    :created: 04-06-2017 20:13:16
    :modified: 04-06-2017 20:14:12
.. moduleauthor:: Stephen Bunn
"""

import os
import sys
import json
import logging
import logging.handlers
import datetime


class _const(object):
    """ Module constants class.
    """

    _module_name = 'Wireshrimp'
    _version = {'major': 1, 'minor': 0, 'patch': 0}
    _authors = (
        'Stephen Bunn <stephen@bunn.io>',
    )

    __allowed_setters = (
        'log_dir', 'log_exceptions', 'log_level', 'log_format',
        '_log_dir', '_log_exceptions', '_log_level', '_log_format',
    )

    class ModuleConstantException(Exception):
        """ Custom exception for constants namespace.
        """

        _code = 7001

        def __init__(self, message: str, code: int=None):
            """ Exception initializer.

            :param message: The message of the exception
            :type message: str
            :param code: The code of the exception
            :type code: int
            """

            super().__init__(message)
            self.code = (code if code else self._code)

    def __init__(self):
        """ Constants initializer.
        """

        self._is_bootstrapped = False
        self._log_exceptions = False
        self._log_level = logging.DEBUG
        self._log_format = (
            '%(asctime)s - %(levelname)s - '
            '%(filename)s:%(lineno)s<%(funcName)s> '
            '%(message)s'
        )
        self._log_handlers = []

    def __setattr__(self, name: str, value):
        """ The classes attribute setter handler.

        :param name: The name of the attribute
        :type name: str
        :param value: The value of the attribute
        """

        if name in self.__allowed_setters:
            super().__setattr__(name, value)
        else:
            if name in self.__dict__:
                raise self.ModuleConstantException((
                    "cannot rebind const({})"
                ).format(name))
            self.__dict__[name] = value

    def __delattr__(self, name: str):
        """ The classes attribute deletion handler.

        :param name: The name of the attribute
        :type name: str
        """

        if name in self.__dict__:
            raise self.ModuleConstantException((
                "cannot unbind const({})"
            ).format(name))
        raise NameError(name)

    @property
    def module_name(self) -> str:
        """ The human readable module name of the module.
        """

        return self._module_name

    @property
    def icon(self) -> str:
        """ The icon path of the GUI.
        """

        return os.path.join(self.base_dir, 'icon.png')

    @property
    def version(self) -> tuple:
        """ The version of the module.
        """

        return '{major}.{minor}.{patch}'.format(**self._version)

    @property
    def author(self) -> str:
        """ The primary author of the module.
        """

        return self._authors[0]

    @property
    def base_dir(self) -> str:
        """ The base directory of the module.
        """

        return os.path.dirname(os.path.realpath(os.path.abspath(__file__)))

    @property
    def parent_dir(self) -> str:
        """ The parent of the base directory.
        """

        return os.path.dirname(self.base_dir)

    @property
    def log_dir(self) -> str:
        """ The logging directroy which should be used.
        """

        if not hasattr(self, '_log_dir'):
            today = datetime.datetime.now()
            self._log_dir = os.path.join(self.parent_dir, os.sep.join([
                'logs',
                str(today.year),
                str(today.month)
            ]))
            if not os.path.isdir(self._log_dir):
                os.makedirs(self._log_dir)
        return self._log_dir

    @log_dir.setter
    def log_dir(self, value: str):
        """ The logging directory setter constants.

        :param value: The new logging directory (must exist)
        :type value: str
        """

        if os.path.isdir(value):
            self._log_dir = value

    @property
    def log_level(self) -> int:
        """ The logging level of the module logger.
        """

        return self._log_level

    @log_level.setter
    def log_level(self, value: int):
        """ The logging level setter of the module logger.

        :param value: The new logging level of the module loggers
        :type value: int
        """

        self._log_level = value
        for handler in self._log_handlers:
            handler.setLevel(value)

    @property
    def log_format(self) -> str:
        """ The logging format of the module logger.
        """

        return self._log_format

    @log_format.setter
    def log_format(self, value: str):
        """ The logging format setter of the module logger.

        :param value: The new logging format of the module loggers
        :type value: str
        """

        self._log_format = value
        formatter = logging.Formatter(value)
        for handler in self._log_handlers:
            handler.setFormatter(formatter)

    @property
    def log(self) -> logging.Logger:
        """ The module logger.
        """

        if not hasattr(self, '_log'):
            self._log = logging.getLogger(self._module_name)
            self._log.setLevel(self.log_level)
            self._log.propagate = False

            today = datetime.datetime.now()
            file_handler = logging.handlers.RotatingFileHandler(
                filename=os.path.join(
                    self.log_dir,
                    '{}.log'.format(today.strftime('%m%d%Y'))
                ),
                mode='a',
                maxBytes=(1024 * 1024),
                backupCount=5
            )
            self._log_handlers.append(file_handler)
            self._log.addHandler(file_handler)

            stream_handler = logging.StreamHandler()
            self._log_handlers.append(stream_handler)
            self._log.addHandler(stream_handler)

            formatter = logging.Formatter(self.log_format)
            for handler in self._log_handlers:
                handler.setFormatter(formatter)

        return self._log

    @property
    def log_exceptions(self) -> bool:
        """ The flag to enable logging exceptions.
        """

        return self._log_exceptions

    @log_exceptions.setter
    def log_exceptions(self, value: bool):
        """ The flag logging exceptions setter.

        :param value: True if logging exceptions is enabled, otherwise False
        :type value: bool
        """

        self._log_exceptions = value
        sys.excepthook = (
            self._exception_handler
            if self._log_exceptions else
            sys.excepthook
        )

    @property
    def is_root(self) -> bool:
        """ True if the script was started as root.
        """

        return os.geteuid() == 0

    def _exception_handler(
        self,
        exctype: Exception.__class__, value: Exception, tb
    ):
        """ The custom module logging exception handler.

        :param exctype: The exception class
        :type exctype: Exception.__class__
        :param value: The exception itself
        :type value: Exception
        :param tb: The traceback of the exception
        """

        self.log.exception((
            'EXCEPTION::{exctype} {value}'
        ).format(exctype=value.__class__.__name__, value=value))
        sys.__excepthook__(exctype, value, tb)

    def bootstrap(self):
        if not self._is_bootstrapped:
            assert (sys.version_info.major == 3), \
                ('{self.module_name} requires Python 3').format(self=self)
            self._is_bootstrapped = True


# NOTE: Do not remove, enables constants, requires python>=3.x
sys.modules[__name__] = _const()
