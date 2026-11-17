"""Timestamp-ordered replay through an in-process queue.

A producer pushes fixed time windows of flows into a ``queue.Queue``; a consumer
scores them and emits alerts. Kafka can replace the queue via the same
``FlowSource`` protocol without touching the scoring logic.
"""
from __future__ import annotations

import queue
import threading
from collections.abc import Callable, Iterator
from typing import Protocol

import pandas as pd

_SENTINEL = object()


class FlowSource(Protocol):
    def windows(self) -> Iterator[tuple[pd.Timestamp, pd.DataFrame]]: ...


class ReplaySource:
    def __init__(self, flows: pd.DataFrame, window_minutes: int = 5) -> None:
        self.flows = flows.sort_values("timestamp", kind="stable")
        self.freq = f"{window_minutes}min"

    def windows(self) -> Iterator[tuple[pd.Timestamp, pd.DataFrame]]:
        for start, w in self.flows.groupby(pd.Grouper(key="timestamp", freq=self.freq)):
            if len(w):
                yield start, w


def run_stream(source: FlowSource, handler: Callable[[pd.Timestamp, pd.DataFrame], None], maxsize: int = 64) -> int:
    """Producer/consumer replay. Returns number of windows processed."""
    q: queue.Queue = queue.Queue(maxsize=maxsize)
    processed = 0

    def producer() -> None:
        for item in source.windows():
            q.put(item)
        q.put(_SENTINEL)

    th = threading.Thread(target=producer, daemon=True)
    th.start()
    while True:
        item = q.get()
        if item is _SENTINEL:
            break
        handler(*item)
        processed += 1
    th.join()
    return processed
