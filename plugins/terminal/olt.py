# -*- coding: utf-8 -*-
# (c) 2016 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from ansible_collections.ansible.netcommon.plugins\
                        .plugin_utils.terminal_base import TerminalBase


class TerminalModule(TerminalBase):
    terminal_stdout_re = [
        re.compile(
            rb"[\r\n]?^[\w\+\-\.:\/\[\]]+(?:\(config+\))?(?:[>#]) ?$",
            re.M)
    ]

    #: compiled bytes regular expressions to remove ANSI codes
    ansi_re = [
        re.compile(rb"\x1b\[\?1h\x1b="),  # CSI ? 1 h ESC =
        re.compile(rb"\x08."),  # [Backspace] .
        re.compile(rb"\x1b\[m"),  # ANSI reset code
    ]

    terminal_stderr_re = [
        # Command error
        re.compile(
            rb"^(\{[^\}]+\}:$([\r\n]$)+^\s+Command:$\s+.*?$)?"
            rb"(\s*[\^]([\r\n]+))?^\%"
            rb"(?! The password is not strong, please change the password\.)"
            rb"\s+([^\r\n]+)([\r\n]+)",
            re.M
        ),
        # Login timeout
        re.compile(
            rb"^\s+Configuration console time out, please retry to log on$",
            re.M
        ),
    ]

    terminal_initial_prompt = [
        rb"[\r\n]?^[\w\+\-\.:\/\[\]]+(?:\(config+\))?(?:[>#]) ?$",
    ]

    terminal_config_prompt = re.compile(
        rb"[\r\n]?^[\w\+\-\.:\/\[\]]+(?:\(config+\))?(?:[>#]) ?$")

    def __init__(self, connection):
        super(TerminalModule, self).__init__(connection)

    def get_privilege_level(self):
        prompt = self._get_prompt()
        return 1 + prompt.endswith(b"#") * 14

    def on_open_shell(self):
        self._exec_cli_command(b"terminal length 0")

    def on_become(self, passwd=None):
        pass

    def on_unbecome(self):
        pass
