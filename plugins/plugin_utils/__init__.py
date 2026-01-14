# -*- coding: utf-8 -*-

import time
import threading
import os
from datetime import datetime


class BufferStallMonitor:
    """
    Monitor for detecting stalled output on OLT devices.
    Sends Enter (CRLF) to resume when output stalls.

    Monitors multiple indicators to detect stall:
    - _window_count: Counter of received data windows
    - _last_recv_window: Last received data window content

    If neither indicator changes within stall_timeout, sends Enter.
    """

    DEBUG = False

    def __init__(
        self,
        connection,
        stall_timeout=60.0,
        check_interval=5,
        debug=False,
    ):
        self._connection = connection
        self._stall_timeout = stall_timeout
        self._check_interval = check_interval
        self._last_window_count = 0
        self._last_recv_window_id = None
        self._last_change_time = None
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
        self.DEBUG = debug

    def _log(self, msg):
        try:
            self._connection.queue_message("vvvv", msg)
        except Exception:
            pass
        if self._debug_file:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            full_msg = "[%s] [%s] %s\n" % (ts, self._instance_id, msg)
            self._debug_file.write(full_msg)
            self._debug_file.flush()
            os.fsync(self._debug_file.fileno())

    def __enter__(self):
        if self.DEBUG:
            self._debug_file = open(
                "olt_stall_monitor.log", "a", buffering=1)
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
        if self._debug_file:
            self._debug_file.close()
            self._debug_file = None

    def _get_activity_indicators(self):
        """
        Get current activity indicators from the connection.
        Returns tuple: (window_count, recv_window_id)
        """
        window_count = 0
        recv_window_id = None

        try:
            # _window_count increments each time data is received
            window_count = getattr(
                self._connection, "_window_count", 0
            ) or 0
        except Exception:
            pass

        try:
            # _last_recv_window contains last received data
            recv_window = getattr(
                self._connection, "_last_recv_window", None
            )
            if recv_window is not None:
                # Use id() to detect if the object changed
                recv_window_id = id(recv_window)
        except Exception:
            pass

        return (window_count, recv_window_id)

    def _has_activity_changed(self, current, previous):
        """Check if any activity indicator has changed."""
        curr_count, curr_window = current
        prev_count, prev_window = previous

        # If window_count increased, there's activity
        if curr_count != prev_count:
            return True

        # If _last_recv_window object changed, there's activity
        if curr_window != prev_window:
            return True

        return False

    def _monitor_loop(self):
        self._log("Monitor thread running")
        while not self._stop_event.is_set():
            with self._lock:
                if not self._active:
                    break

                current = self._get_activity_indicators()

                # Check if any indicator has changed
                previous = (self._last_window_count, self._last_recv_window_id)

                if self._has_activity_changed(current, previous):
                    # Activity detected, reset timer
                    self._last_window_count = current[0]
                    self._last_recv_window_id = current[1]
                    self._last_change_time = time.time()
                    self._log(
                        "Activity: window_count=%d" % current[0]
                    )
                elif self._last_change_time is not None:
                    # No activity, check for stall
                    elapsed = time.time() - self._last_change_time
                    if elapsed >= self._stall_timeout:
                        try:
                            ssh = getattr(
                                self._connection, "_ssh_shell", None
                            )
                            if ssh is not None:
                                self._send_count += 1
                                self._log(
                                    "STALL detected! %.1fs no activity, "
                                    "sending Enter #%d"
                                    % (elapsed, self._send_count)
                                )
                                ssh.sendall(b"\r\n")
                                self._last_change_time = time.time()
                            else:
                                self._log("WARN: _ssh_shell unavailable")
                        except Exception as e:
                            self._log("Error sending Enter: %s" % str(e))

            self._stop_event.wait(self._check_interval)
        self._log(
            "Monitor finished (sent %d enters)" % self._send_count
        )

    def start(self):
        with self._lock:
            self._active = True
            initial = self._get_activity_indicators()
            self._last_window_count = initial[0]
            self._last_recv_window_id = initial[1]
            self._last_change_time = time.time()
            self._send_count = 0
            self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()
        self._log("Monitor thread started")

    def stop(self):
        with self._lock:
            self._active = False
        self._stop_event.set()
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=1.0)
            self._monitor_thread = None
