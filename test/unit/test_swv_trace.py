# pyOCD debugger
# Copyright (c) 2026 Arm Limited
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

from types import SimpleNamespace
from unittest import mock

import pytest

from pyocd.core import exceptions
from pyocd.core.session import Session
from pyocd.debug.sequences.delegates import TraceSetup
from pyocd.probe.debug_probe import DebugProbe
from pyocd.target.pack.cbuild_run import TraceSink
from pyocd.trace.sink import (TraceBufferSinks, TraceDataSink)
from pyocd.trace.swv import SWVReader
from pyocd.utility.notification import Notification


def make_reader(raw_file=None, trace_setup=TraceSetup.LEGACY, ctrace_run=True):
    core = mock.Mock()
    delegate = (
        None
        if trace_setup == TraceSetup.LEGACY
        else SimpleNamespace(trace_setup=trace_setup)
    )
    target = SimpleNamespace(cores={0: core}, debug_sequence_delegate=delegate)
    probe = mock.Mock()
    probe.swo_read.return_value = b''
    session = SimpleNamespace(
        target=target,
        probe=probe,
        ctrace_run=mock.Mock() if ctrace_run else None,
        options={
            'swv_raw_file': str(raw_file) if raw_file is not None else None,
        },
        Event=Session.Event,
    )
    reader = SWVReader(session)
    if raw_file is not None:
        reader._raw_output = TraceDataSink(session)
    return reader, core, probe


def notify(reader, event, data=None):
    reader._trace_data_handler(Notification(event, reader._session, data))


def write_raw_data(reader, data):
    assert reader._raw_output is not None
    reader._raw_output.write(data)


class TestRawTraceFile:
    def test_changed_capture_truncates_and_flush_appends_probe_data(
            self,
            tmp_path,
            ):
        raw_path = tmp_path / "trace.raw"
        raw_path.write_bytes(b'old data')
        reader, _, probe = make_reader(raw_path)
        data = iter([b'tail'])
        probe.swo_read.side_effect = lambda: next(data, b'')

        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)
        assert reader._raw_output is not None
        assert reader._raw_output.is_open
        write_raw_data(reader, b'capture')
        notify(reader, Session.Event.TRACE_DATA_FLUSH)

        assert raw_path.read_bytes() == b'capturetail'
        assert not reader._raw_output.is_open

    def test_flush_waits_for_late_probe_data(self, tmp_path):
        raw_path = tmp_path / "trace.raw"
        reader, _, probe = make_reader(raw_path)
        data = iter([b'', b'late', b'tail'])
        probe.swo_read.side_effect = lambda: next(data, b'')

        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)
        notify(reader, Session.Event.TRACE_DATA_FLUSH)

        assert raw_path.read_bytes() == b'latetail'

    def test_unchanged_capture_appends_to_existing_file(self, tmp_path):
        raw_path = tmp_path / "trace.raw"
        reader, _, _ = make_reader(raw_path)

        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)
        write_raw_data(reader, b'first')
        notify(reader, Session.Event.TRACE_DATA_FLUSH)
        notify(reader, Session.Event.TRACE_DATA_CAPTURE, False)
        write_raw_data(reader, b'second')
        notify(reader, Session.Event.TRACE_DATA_FLUSH)

        assert raw_path.read_bytes() == b'firstsecond'

    def test_non_ctrace_capture_truncates_once_then_appends(self, tmp_path):
        raw_path = tmp_path / "trace.raw"
        raw_path.write_bytes(b'old data')
        reader, _, _ = make_reader(raw_path, ctrace_run=False)

        notify(reader, Session.Event.TRACE_DATA_CAPTURE, False)
        write_raw_data(reader, b'first')
        notify(reader, Session.Event.TRACE_DATA_FLUSH)
        notify(reader, Session.Event.TRACE_DATA_CAPTURE, False)
        write_raw_data(reader, b'second')
        notify(reader, Session.Event.TRACE_DATA_FLUSH)

        assert raw_path.read_bytes() == b'firstsecond'

    def test_repeated_unchanged_capture_does_not_truncate_open_file(
            self,
            tmp_path,
            ):
        raw_path = tmp_path / "trace.raw"
        reader, _, _ = make_reader(raw_path)

        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)
        write_raw_data(reader, b'first')
        notify(reader, Session.Event.TRACE_DATA_CAPTURE, False)
        write_raw_data(reader, b'second')
        notify(reader, Session.Event.TRACE_DATA_FLUSH)

        assert raw_path.read_bytes() == b'firstsecond'

    def test_changed_capture_replaces_open_file(self, tmp_path):
        raw_path = tmp_path / "trace.raw"
        reader, _, _ = make_reader(raw_path)

        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)
        write_raw_data(reader, b'discarded')
        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)
        write_raw_data(reader, b'kept')
        notify(reader, Session.Event.TRACE_DATA_FLUSH)

        assert raw_path.read_bytes() == b'kept'

    def test_capture_does_not_create_custom_output_directory(self, tmp_path, caplog):
        raw_path = tmp_path / "custom" / "trace.raw"
        reader, _, _ = make_reader(raw_path)

        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)

        assert not raw_path.parent.exists()
        assert reader._raw_output is not None
        assert not reader._raw_output.is_open
        assert "Failed to open SWV raw output" in caplog.text

    def test_capture_creates_trace_output_directory(self, tmp_path):
        raw_path = tmp_path / ".trace" / "trace.raw"
        reader, _, _ = make_reader(raw_path)

        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)
        write_raw_data(reader, b'trace')
        notify(reader, Session.Event.TRACE_DATA_FLUSH)

        assert raw_path.read_bytes() == b'trace'

    def test_capture_without_output_filename_is_a_no_op(self):
        reader, _, _ = make_reader()

        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)

        assert reader._raw_output is None

    def test_probe_error_during_flush_is_nonfatal_and_closes_file(
            self,
            tmp_path,
            caplog,
            ):
        raw_path = tmp_path / "trace.raw"
        reader, _, probe = make_reader(raw_path)
        probe.swo_read.side_effect = exceptions.ProbeError("test failure")
        notify(reader, Session.Event.TRACE_DATA_CAPTURE, True)

        notify(reader, Session.Event.TRACE_DATA_FLUSH)

        assert reader._raw_output is not None
        assert not reader._raw_output.is_open
        assert "Failed to update SWV raw output file" in caplog.text


class TestTraceBufferSinks:
    def make_session(self):
        return SimpleNamespace(
            options={'serve_local_only': True},
            Event=Session.Event,
            subscribe=mock.Mock(),
            unsubscribe=mock.Mock(),
        )

    def test_server_starts_when_outputs_are_initialized(self):
        session = self.make_session()
        trace_buffer = TraceSink('trace-buffer', 'etr', 'server', server_port=5555)

        with mock.patch('pyocd.trace.sink.StreamServer') as stream_server:
            outputs = TraceBufferSinks(session, {'etr': trace_buffer})

        stream_server.assert_called_once_with(
            5555,
            serve_local_only=True,
            name='Trace buffer etr raw',
            is_read_only=True,
        )
        outputs.shutdown()

    def test_file_output_creates_trace_directory(self, tmp_path):
        session = self.make_session()
        raw_path = tmp_path / '.trace' / 'trace.raw'
        trace_buffer = TraceSink('trace-buffer', 'etr', 'file', file=str(raw_path))
        outputs = TraceBufferSinks(session, {'etr': trace_buffer})

        outputs._trace_data_handler(Notification(Session.Event.TRACE_DATA_CAPTURE, session, True))
        assert outputs.write('etr', b'trace') == 5
        outputs._trace_data_handler(Notification(Session.Event.TRACE_DATA_FLUSH, session))

        assert raw_path.read_bytes() == b'trace'
        outputs.shutdown()

    def test_failed_capture_output_is_not_cached(self):
        session = self.make_session()
        trace_buffer = TraceSink('trace-buffer', 'etr', 'file', file='trace.raw')
        initial_output = mock.Mock()
        initial_output.start_capture.side_effect = OSError('first failure')
        failed_output = mock.Mock()
        failed_output.start_capture.side_effect = OSError('second failure')
        working_output = mock.Mock()
        working_output.write.return_value = 4

        with mock.patch(
                'pyocd.trace.sink.TraceDataSink',
                side_effect=[initial_output, failed_output, working_output],
                ) as trace_data_sink:
            outputs = TraceBufferSinks(session, {'etr': trace_buffer})
            outputs._trace_data_handler(Notification(Session.Event.TRACE_DATA_CAPTURE, session, True))
            with pytest.raises(ValueError, match="failed to write trace buffer 'etr'"):
                outputs.write('etr', b'data')
            assert outputs.write('etr', b'data') == 4

        assert trace_data_sink.call_count == 3
        outputs.shutdown()


class TestTraceSetup:
    def test_non_ctrace_reader_subscribes_to_capture_notifications(self):
        reader, _, probe = make_reader(ctrace_run=False)
        probe.capabilities = {DebugProbe.Capability.SWO}
        reader._session.subscribe = mock.Mock()

        with mock.patch.object(reader, '_init_components', return_value=True), \
                mock.patch.object(reader, 'start'):
            assert reader.init(100_000_000, 1_000_000, None)

        reader._session.subscribe.assert_any_call(
            reader._trace_data_handler,
            Session.Event.TRACE_DATA_CAPTURE,
            reader._session,
        )

    def test_full_trace_setup_does_not_initialize_legacy_components(self):
        reader, _, _ = make_reader(trace_setup=TraceSetup.FULL)

        assert reader._init_components(100_000_000, 1_000_000)
