#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dependency-free, terminal-only activity indicator for adcs-tool.

The indicator writes exclusively to stderr and only when attached to a TTY.
It never changes the Python API's return values or the CLI's stdout (JSON).
"""
from __future__ import annotations

import shutil
import sys
import threading
from typing import TextIO


class CliProgress:
    """Show a spinner for slow commands and counts during SQLite indexing."""

    _FRAMES = "|/-\\"

    def __init__(self, label: str = "Working...", *, stream: TextIO | None = None,
                 enabled: bool | None = None) -> None:
        self._stream = sys.stderr if stream is None else stream
        self._enabled = self._stream.isatty() if enabled is None else enabled
        self._label = label
        self._counts: tuple[int, int, int] | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_width = 0

    def __enter__(self) -> CliProgress:
        if self._enabled:
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback) -> None:
        if self._thread is not None:
            self._stop.set()
            self._thread.join()
            with self._lock:
                try:
                    self._stream.write("\r" + " " * self._last_width + "\r")
                    self._stream.flush()
                except (OSError, ValueError):
                    pass  # stderr may have been closed by the invoking program.

    def status(self, message: str) -> None:
        """Use the same cache-phase messages as the Textual GUI."""
        if self._enabled:
            with self._lock:
                self._label = message
                self._counts = None

    def progress(self, done: int, new_total: int, certificate_total: int) -> None:
        """Receive the GUI's (processed, new certificates, all files) tuple."""
        if self._enabled:
            with self._lock:
                self._counts = (done, new_total, certificate_total)

    def _message(self) -> str:
        """Called with the lock held; formatting is separate from rendering."""
        if self._counts is None:
            return self._label
        done, new_total, certificate_total = self._counts
        if new_total == 0:
            return f"Checking SQLite cache — {certificate_total} certificate(s)"
        percent = min(100, int(100 * done / new_total))
        return (f"Loading SQLite cache: {done}/{new_total} new certificate(s) "
                f"({percent}%) — {certificate_total} total")

    def _animate(self) -> None:
        frame = 0
        while not self._stop.is_set():
            with self._lock:
                message = f"{self._FRAMES[frame % len(self._FRAMES)]} {self._message()}"
                # Limit to the terminal width: wrapping would leave stray lines.
                width = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns - 1)
                message = message[:width]
                try:
                    self._stream.write("\r" + message +
                                       " " * max(0, self._last_width - len(message)))
                    self._stream.flush()
                except (OSError, ValueError):
                    return
                self._last_width = len(message)
            frame += 1
            self._stop.wait(0.1)
