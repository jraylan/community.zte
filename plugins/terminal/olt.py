#
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
import time
import threading

from ansible.utils.display import Display
from ansible_collections.ansible.netcommon.plugins\
                        .plugin_utils.terminal_base import TerminalBase


display = Display()


class BufferStallMonitor:
    """
    Monitor for detecting stalled output buffers on devices that pause
    output even with paging disabled. Sends Enter (CRLF) to resume
    outputwhen no new data is received within the stall timeout.
    """

    def __init__(self, connection, stall_timeout=60.0, check_interval=5):
        """
        Initialize the buffer stall monitor.

        :param connection: The connection object with _ssh_shell
                           attribute.
        :param stall_timeout: Seconds to wait before sending Enter
        :param check_interval: Seconds between stall checks
        """
        self._connection = connection
        self._stall_timeout = stall_timeout
        self._check_interval = check_interval
        self._last_data_time = None
        self._last_data_len = 0
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._lock = threading.Lock()
        self._active = False
        self._send_count = 0

    def _monitor_loop(self):
        """Background thread that monitors for stalled output."""
        display.vvvv("OLT terminal: Stall monitor started")
        while not self._stop_event.is_set():
            with self._lock:
                if not self._active:
                    break

                if self._last_data_time is not None:
                    elapsed = time.time() - self._last_data_time
                    if elapsed >= self._stall_timeout:
                        # Output has stalled, send Enter to resume
                        try:
                            ssh_shell = getattr(
                                self._connection, "_ssh_shell", None
                            )
                            if ssh_shell is not None:
                                self._send_count += 1
                                display.vvvv(
                                    "OLT terminal: Output stalled for "
                                    "%.1fs, sending Enter #%d to resume"
                                    % (elapsed, self._send_count)
                                )
                                ssh_shell.sendall(b"\r\n")
                                # Reset timer after sending
                                self._last_data_time = time.time()
                        except Exception as e:
                            display.vvvv(
                                "OLT terminal: Error sending Enter: %s"
                                % str(e)
                            )

            self._stop_event.wait(self._check_interval)
        display.vvvv(
            "OLT terminal: Stall monitor stopped (sent %d enters)"
            % self._send_count
        )

    def start(self):
        """Start monitoring for stalled output."""
        with self._lock:
            self._active = True
            self._last_data_time = time.time()
            self._last_data_len = 0
            self._send_count = 0
            self._stop_event.clear()

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()

    def stop(self):
        """Stop monitoring."""
        with self._lock:
            self._active = False
        self._stop_event.set()
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=1.0)
            self._monitor_thread = None

    def update(self, data_len=None):
        """
        Update the monitor when new data is received.

        :param data_len: Current total length of received data
        """
        with self._lock:
            if data_len is not None and data_len != self._last_data_len:
                self._last_data_time = time.time()
                self._last_data_len = data_len
            elif data_len is None:
                self._last_data_time = time.time()


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

    # Stall detection settings for OLT devices that pause output
    # even with paging disabled
    STALL_TIMEOUT = 60.0  # Seconds to wait before considering output stalled
    STALL_CHECK_INTERVAL = 5  # Seconds between stall checks

    def __init__(self, connection):
        super(TerminalModule, self).__init__(connection)
        self._stall_monitor = None

    def _exec_cli_command(self, cmd, check_rc=True):
        """
        Executes the CLI command on the remote device and returns
        the output.

        This implementation includes stall detection for OLT devices
        that pause output even with paging disabled. If the output
        stalls for more than STALL_TIMEOUT seconds, an Enter (CRLF)
        is automatically sent to resume output.

        :arg cmd: Byte string command to be executed
        :arg check_rc: Check return code (unused, kept for
        compatibility)
        """
        # Start stall monitor before executing command
        self._stall_monitor = BufferStallMonitor(
            self._connection,
            stall_timeout=self.STALL_TIMEOUT,
            check_interval=self.STALL_CHECK_INTERVAL,
        )
        self._stall_monitor.start()

        try:
            result = self._connection.exec_command(cmd)
        finally:
            # Always stop the monitor when command completes
            if self._stall_monitor is not None:
                self._stall_monitor.stop()
                self._stall_monitor = None

        # Handle different return types from exec_command
        # network_cli returns bytes/str directly when _ssh_shell is active
        # Other connections may return (rc, stdout, stderr) tuple
        if isinstance(result, tuple):
            # Extract stdout from tuple (rc, stdout, stderr)
            if len(result) >= 2:
                result = result[1]
            else:
                result = b""

        if isinstance(result, memoryview):
            result = result.tobytes()

        if isinstance(result, bytes):
            result = result.decode("utf-8", errors="ignore").encode("utf-8")
        elif isinstance(result, str):
            result = result.encode("utf-8", errors="ignore")

        return result

    def get_privilege_level(self):
        prompt = self._get_prompt()
        return 1 + prompt.endswith(b"#") * 14

    def on_open_shell(self):
        self._exec_cli_command(b"terminal length 0")

    def on_become(self, passwd=None):
        pass

    def on_unbecome(self):
        pass
