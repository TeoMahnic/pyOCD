# pyOCD debugger
# Copyright (c) 2017-2019,2026 Arm Limited
# COpyright (c) 2021-2022 Chris Reed
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections.abc
import logging
from pathlib import Path
from typing import (Any, BinaryIO, TYPE_CHECKING, Iterable, List, Optional, Sequence, Union)

from ..utility.server import StreamServer

if TYPE_CHECKING:
    from .events import TraceEvent

LOG = logging.getLogger(__name__)


class TraceDataSink:
    """Raw SWV trace output handler configured from session settings."""

    def __init__(self, session: Any) -> None:
        raw_file = session.options.get('swv_raw_file')
        if raw_file:
            self._sink = _TraceFileSink(Path(raw_file).expanduser())
        elif session.options.get('swv_raw_enable'):
            self._sink = _TraceServerSink(
                session.options.get('swv_raw_port'),
                session.options.get('serve_local_only'),
                'SWV raw',
            )
        else:
            raise ValueError('SWV raw output is not configured')

    @property
    def is_open(self) -> bool:
        """Whether data can be written for the current capture."""
        return self._sink.is_open

    def start_capture(self, changed: bool) -> None:
        """Start a trace capture, resetting output if the configuration changed."""
        self._sink.start_capture(changed)

    def write(self, data: bytes) -> int:
        """Write raw trace data."""
        return self._sink.write(data)

    def flush(self) -> None:
        """Flush data at the end of a capture."""
        self._sink.flush()

    def shutdown(self) -> None:
        """Release the output destination."""
        self._sink.shutdown()


class _TraceFileSink:
    """Raw trace data written to a file from capture through flush."""

    def __init__(self, path: Path, create_parent: bool = False) -> None:
        self._path = path
        self._create_parent = create_parent
        self._file: Optional[BinaryIO] = None
        self._has_captured = False

    @property
    def is_open(self) -> bool:
        return self._file is not None

    def start_capture(self, changed: bool) -> None:
        self.flush()
        if self._create_parent:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open('wb' if changed or not self._has_captured else 'ab')
        self._has_captured = True

    def write(self, data: bytes) -> int:
        if self._file is None:
            return 0
        self._file.write(data)
        return len(data)

    def flush(self) -> None:
        if self._file is not None:
            self._file.flush()
            self._file.close()
            self._file = None

    def shutdown(self) -> None:
        self.flush()


class _TraceServerSink:
    """Raw trace data delivered to a TCP client by a StreamServer."""

    def __init__(self, port: int, serve_local_only: bool, name: str) -> None:
        self._server = StreamServer(
            port,
            serve_local_only=serve_local_only,
            name=name,
            is_read_only=True,
        )

    @property
    def is_open(self) -> bool:
        return False

    def start_capture(self, changed: bool) -> None:
        pass

    def write(self, data: bytes) -> int:
        return self._server.write(data)

    def flush(self) -> None:
        pass

    def shutdown(self) -> None:
        self._server.stop()


class TraceEventSink:
    """@brief Abstract interface for a trace event sink."""
    def receive(self, event: "TraceEvent") -> None:
        """@brief Handle a single trace event.
        @param self
        @param event An instance of TraceEvent or one of its subclasses.
        """
        raise NotImplementedError()

class TraceEventFilter(TraceEventSink):
    """@brief Abstract interface for a trace event filter."""

    def __init__(self, sink: Optional[TraceEventSink] = None) -> None:
        self._sink = sink

    def connect(self, sink: TraceEventSink) -> None:
        """@brief Connect the downstream trace sink or filter."""
        self._sink = sink

    def receive(self, event: "TraceEvent") -> None:
        """@brief Handle a single trace event.

        Passes the event through the filter() method. If one or more objects are returned, they
        are then passed to the trace sink connected to this filter (which may be another filter).

        @param self
        @param event An instance of TraceEvent or one of its subclasses.
        """
        filtered_event = self.filter(event)
        if (filtered_event is not None) and (self._sink is not None):
            if isinstance(event, collections.abc.Iterable):
                for event_item in event:
                    self._sink.receive(event_item)
            else:
                self._sink.receive(event)

    def filter(self, event: "TraceEvent") -> Union[None, "TraceEvent", Sequence["TraceEvent"]]:
        """@brief Filter a single trace event.

        @param self
        @param event An instance of TraceEvent or one of its subclasses.
        @return Either None, a single TraceEvent, or a sequence of TraceEvents.
        """
        raise NotImplementedError()

class TraceEventTee(TraceEventSink):
    """@brief Trace event sink that replicates events to multiple sinks."""

    def __init__(self) -> None:
        self._sinks: List[TraceEventSink] = []

    def connect(self, sinks: Iterable[TraceEventSink]) -> None:
        """@brief Connect one or more downstream trace sinks.

        @param self
        @param sinks If this parameter is a single object, it will be added to the list of
          downstream trace event sinks. If it is an iterable (list, tuple, etc.), then it will
          completely replace the current list of trace event sinks.
        """
        if isinstance(sinks, collections.abc.Iterable):
            self._sinks = list(sinks)
        elif sinks not in self._sinks:
            self._sinks.append(sinks)

    def receive(self, event: "TraceEvent") -> None:
        """@brief Replicate a single trace event to all connected downstream trace event sinks.

        @param self
        @param event An instance of TraceEvent or one of its subclasses.
        """
        for sink in self._sinks:
            sink.receive(event)

