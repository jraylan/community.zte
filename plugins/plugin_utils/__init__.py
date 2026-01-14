# -*- coding: utf-8 -*-

import time
import threading
import os
from datetime import datetime


class BufferStallMonitor:
    """
    Monitor for detecting stalled output on OLT devices.
    Sends Enter (CRLF) to resume when output stalls.
    """

    def __init__(self, connection, stall_timeout=60.0, check_interval=5):
        self._connection = connection
        self._stall_timeout = stall_timeout
        self._check_interval = check_interval
        self._last_data_time = None
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._lock = threading.Lock()
        self._active = False
        self._send_count = 0
        self._debug_file = None
        self._instance_id = "%s-%d" % (
            datetime.now().strftime("%H:%M:%S.%f")[:-3],
            os.getpid()
        )

    def _log(self, msg):
        self._connection.queue_message("vvvv", msg)
        if self._debug_file:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            full_msg = "[%s] [%s] %s\n" % (ts, self._instance_id, msg)
            self._debug_file.write(full_msg)
            self._debug_file.flush()
            os.fsync(self._debug_file.fileno())

    def __enter__(self):
        self._debug_file = open(
            "/tmp/olt_stall_monitor.log", "a", buffering=1
        )
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
        if self._debug_file:
            self._debug_file.close()
            self._debug_file = None

    def _monitor_loop(self):
        self._log("Monitor thread running")
        while not self._stop_event.is_set():
            with self._lock:
                if not self._active:
                    break
                if self._last_data_time is not None:
                    elapsed = time.time() - self._last_data_time
                    if elapsed >= self._stall_timeout:
                        try:
                            ssh = getattr(
                                self._connection, "_ssh_shell", None
                            )
                            if ssh is not None:
                                self._send_count += 1
                                self._log(
                                    "Stalled %.1fs, Enter #%d"
                                    % (elapsed, self._send_count)
                                )
                                ssh.sendall(b"\r\n")
                                self._last_data_time = time.time()
                            else:
                                self._log("WARN: _ssh_shell unavailable")
                        except Exception as e:
                            self._log("Error: %s" % str(e))
            self._stop_event.wait(self._check_interval)
        self._log("Monitor finished (sent %d enters)" % self._send_count)

    def start(self):
        with self._lock:
            self._active = True
            self._last_data_time = time.time()
            self._send_count = 0
            self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()

    def stop(self):
        with self._lock:
            self._active = False
        self._stop_event.set()
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=1.0)
            self._monitor_thread = None
