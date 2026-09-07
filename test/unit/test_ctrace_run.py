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

import logging
import threading
from types import SimpleNamespace
from unittest import mock

import pytest
import yaml

from pyocd.core import exceptions
from pyocd.core.session import Session
from pyocd.coresight.coresight_target import CoreSightTarget
from pyocd.debug.sequences.delegates import TraceSetup
from pyocd.trace.ctrace_run import (
    CORESIGHT_LAR_KEY,
    CORESIGHT_LAR_OFFSET,
    DEMCR,
    DEMCR_TRCENA,
    CTraceRun,
    CTraceRunError,
)


def make_ctrace_run(tmp_path, use_project_path=True):
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    cbuild_run = SimpleNamespace(
        trace=SimpleNamespace(enabled=(object(),)),
        proj_path=str(project_dir),
        proj_path_name=(
            str(project_dir / "Blinky.cproject.yml")
            if use_project_path else None
        ),
        solution_set="Blinky+Board",
    )
    session = SimpleNamespace(
        cbuild_run=cbuild_run,
        options={'cbuild_run': str(build_dir / "Blinky.cbuild-run.yml")},
        Event=Session.Event,
        subscribe=mock.Mock(),
    )
    trace_root = project_dir if use_project_path else build_dir
    trace_path = trace_root / ".trace" / "Blinky+Board.ctrace-run.yml"
    trace_path.parent.mkdir()
    return CTraceRun(session), trace_path


def write_ctrace_run(path, references):
    path.write_text(yaml.safe_dump({
        'ctrace-run': {
            'generated-by': 'unit test',
            'ctrace-setup': {'ignored': True},
            'ctrace-refs': references,
        },
    }), encoding='utf-8')


def make_target(*pnames):
    cores = {}
    for core_number, pname in enumerate(pnames):
        core = mock.Mock()
        core.node_name = pname
        core.read32.return_value = 0
        cores[core_number] = core
    return SimpleNamespace(cores=cores, selected_core_or_raise=cores[0])


class NotifyingRLock:
    def __init__(self):
        self._lock = threading.RLock()
        self._attempt_count = 0
        self._attempt_count_lock = threading.Lock()
        self.second_attempt = threading.Event()

    def __enter__(self):
        with self._attempt_count_lock:
            self._attempt_count += 1
            if self._attempt_count == 2:
                self.second_attempt.set()
        self._lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._lock.release()


class TestCTraceRun:
    def test_apply_uses_derived_project_path_and_register_names(
            self,
            tmp_path,
            ):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'dwt-source',
            'type': 'dwt',
            'regs': [
                {'name': 'DWT_CTRL', 'value': '0x1001'},
                {'name': 'ITM_TCR', 'value': 2},
            ],
        }])
        target = make_target('CM7')

        assert ctrace_run.apply(target)
        target.selected_core_or_raise.write32.assert_has_calls([
            mock.call(DEMCR, DEMCR_TRCENA),
            mock.call(0xE0001000 + CORESIGHT_LAR_OFFSET, CORESIGHT_LAR_KEY),
            mock.call(0xE0001000, 0x1001),
            mock.call(0xE0000000 + CORESIGHT_LAR_OFFSET, CORESIGHT_LAR_KEY),
            mock.call(0xE0000E80, 2),
        ])

    def test_apply_uses_cbuild_run_directory_without_project_path(
            self,
            tmp_path,
            ):
        ctrace_run, trace_path = make_ctrace_run(
            tmp_path,
            use_project_path=False,
        )
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'pmu-source',
            'type': 'pmu',
            'regs': [{'name': 'PMU_CTRL', 'value': 1}],
        }])
        target = make_target('CM7')

        assert ctrace_run.apply(target)
        target.selected_core_or_raise.write32.assert_any_call(0xE0003E04, 1)

    def test_apply_accepts_unrecognized_trace_type(self, tmp_path):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'future-source',
            'type': 'future-type',
            'regs': [{'name': 'PMU_CTRL', 'value': 1}],
        }])
        target = make_target('CM7')

        assert ctrace_run.apply(target)
        target.selected_core_or_raise.write32.assert_any_call(0xE0003E04, 1)

    def test_masked_register_write_preserves_unmasked_bits(self, tmp_path):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'dwt-source',
            'type': 'dwt',
            'regs': [{'name': 'DWT_CTRL', 'value': 0xAA, 'mask': 0xFF}],
        }])
        target = make_target('CM7')
        target.selected_core_or_raise.read32.side_effect = lambda address: {
            DEMCR: DEMCR_TRCENA,
            0xE0001000: 0xA5A50055,
        }[address]

        assert ctrace_run.apply(target)
        target.selected_core_or_raise.write32.assert_any_call(
            0xE0001000,
            0xA5A500AA,
        )

    def test_unchanged_file_is_not_reapplied(self, tmp_path):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        reference = {
            'ctrace-ref': 'pmu-source',
            'type': 'pmu',
            'regs': [{'name': 'PMU_CTRL', 'value': 1}],
        }
        write_ctrace_run(trace_path, [reference])
        target = make_target('CM7')

        assert ctrace_run.apply(target)
        target.selected_core_or_raise.reset_mock()
        assert not ctrace_run.apply(target)
        target.selected_core_or_raise.write32.assert_not_called()

        reference['regs'][0]['value'] = 2
        write_ctrace_run(trace_path, [reference])
        assert ctrace_run.apply(target)
        target.selected_core_or_raise.write32.assert_any_call(0xE0003E04, 2)

    def test_concurrent_apply_only_applies_once(self, tmp_path):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'pmu-source',
            'type': 'pmu',
            'regs': [{'name': 'PMU_CTRL', 'value': 1}],
        }])
        target = make_target('CM7')
        apply_started = threading.Event()
        release_apply = threading.Event()
        original_apply = ctrace_run._apply_to_target
        notifying_lock = NotifyingRLock()
        ctrace_run._lock = notifying_lock

        def blocked_apply(*args):
            apply_started.set()
            assert release_apply.wait(1.0)
            return original_apply(*args)

        with mock.patch.object(ctrace_run, '_apply_to_target', side_effect=blocked_apply) as apply_mock:
            results = []
            first_thread = threading.Thread(target=lambda: results.append(ctrace_run.apply(target)))
            second_thread = threading.Thread(target=lambda: results.append(ctrace_run.apply(target)))
            first_thread.start()
            assert apply_started.wait(1.0)
            second_thread.start()
            assert notifying_lock.second_attempt.wait(1.0)
            release_apply.set()
            for thread in (first_thread, second_thread):
                thread.join(timeout=1.0)
                assert not thread.is_alive()

        assert sorted(results) == [False, True]
        apply_mock.assert_called_once()

    def test_reload_defers_reapplication_until_next_capture(self, tmp_path):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'pmu-source',
            'type': 'pmu',
            'regs': [{'name': 'PMU_CTRL', 'value': 1}],
        }])
        target = make_target('CM7')

        assert ctrace_run.apply(target)
        target.selected_core_or_raise.reset_mock()
        assert ctrace_run.reload()
        target.selected_core_or_raise.write32.assert_not_called()

        assert ctrace_run.apply(target)
        target.selected_core_or_raise.write32.assert_any_call(0xE0003E04, 1)

    def test_missing_file_is_a_no_op(self, tmp_path):
        ctrace_run, _ = make_ctrace_run(tmp_path)
        target = make_target('CM7')

        assert not ctrace_run.apply(target)
        target.selected_core_or_raise.write32.assert_not_called()

    def test_invalid_file_is_nonfatal_and_repeated_error_is_debug(self, tmp_path, caplog):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'bad-source',
            'type': 'dwt',
            'regs': [{'name': 'UNKNOWN_REGISTER', 'value': 1}],
        }])
        target = make_target('CM7')
        caplog.set_level(logging.DEBUG, logger='pyocd.trace.ctrace_run')

        assert not ctrace_run.apply(target)
        assert not ctrace_run.apply(target)
        messages = [record for record in caplog.records if record.message.startswith("Failed to apply ctrace-run configuration")]
        assert [record.levelno for record in messages] == [logging.ERROR, logging.DEBUG]
        target.selected_core_or_raise.write32.assert_not_called()

    def test_target_access_error_is_nonfatal(self, tmp_path, caplog):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'dwt-source',
            'type': 'dwt',
            'regs': [{'name': 'DWT_CTRL', 'value': 1}],
        }])
        target = make_target('CM7')
        target.selected_core_or_raise.read32.side_effect = (
            exceptions.TransferError("test failure")
        )

        assert not ctrace_run.apply(target)
        assert "Failed to enable trace access" in caplog.text

    def test_multicore_registers_are_routed_by_pname(self, tmp_path):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        write_ctrace_run(trace_path, [
            {
                'ctrace-ref': 'cm7-source',
                'type': 'dwt',
                'pname': 'CM7',
                'regs': [{'name': 'DWT_CTRL', 'value': 1}],
            },
            {
                'ctrace-ref': 'cm4-source',
                'type': 'itm',
                'pname': 'CM4',
                'regs': [{'name': 'ITM_TCR', 'value': 2}],
            },
        ])
        target = make_target('CM7', 'CM4')

        assert ctrace_run.apply(target)
        target.cores[0].write32.assert_any_call(0xE0001000, 1)
        target.cores[1].write32.assert_any_call(0xE0000E80, 2)

    def test_missing_pname_on_multicore_target_is_nonfatal(self, tmp_path, caplog):
        ctrace_run, trace_path = make_ctrace_run(tmp_path)
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'dwt-source',
            'type': 'dwt',
            'regs': [{'name': 'DWT_CTRL', 'value': 1}],
        }])
        target = make_target('CM7', 'CM4')

        assert not ctrace_run.apply(target)
        assert "Missing processor name" in caplog.text
        target.cores[0].write32.assert_not_called()
        target.cores[1].write32.assert_not_called()

    @pytest.mark.parametrize("trace", [None, SimpleNamespace(enabled=())])
    def test_constructor_requires_enabled_cbuild_trace(self, tmp_path, trace):
        cbuild_run = None if trace is None else SimpleNamespace(trace=trace)
        session = SimpleNamespace(cbuild_run=cbuild_run, options={})

        with pytest.raises(CTraceRunError):
            CTraceRun(session)


class TestTraceLifecycle:
    def test_trace_start_initializes_trace_buffer_sinks_before_delegate(self):
        trace_buffers = {'buffer': mock.Mock()}
        session = SimpleNamespace(
            Event=Session.Event,
            subscribe=mock.Mock(),
        )
        target = SimpleNamespace(
            trace_enabled=True,
            _trace_buffer_sinks=None,
            debug_sequence_delegate=SimpleNamespace(trace_buffers=trace_buffers),
            session=session,
        )
        target._ensure_trace_buffer_sinks = lambda: CoreSightTarget._ensure_trace_buffer_sinks(target)
        target._shutdown_trace_buffer_sinks = lambda: CoreSightTarget._shutdown_trace_buffer_sinks(target)

        def call_delegate(*args, **kwargs):
            assert target._trace_buffer_sinks is mock.sentinel.outputs
            return True

        target.call_delegate = mock.Mock(side_effect=call_delegate)

        with mock.patch('pyocd.coresight.coresight_target.TraceBufferSinks') as trace_buffer_sinks:
            trace_buffer_sinks.return_value = mock.sentinel.outputs
            CoreSightTarget.trace_start(target)

        trace_buffer_sinks.assert_called_once_with(session, trace_buffers)
        assert target._trace_buffer_sinks is mock.sentinel.outputs

    def test_trace_stop_shuts_down_trace_buffer_sinks(self):
        trace_buffer_sinks = mock.Mock()
        target = SimpleNamespace(
            trace_enabled=True,
            _trace_buffer_sinks=trace_buffer_sinks,
            call_delegate=mock.Mock(return_value=True),
        )
        target._shutdown_trace_buffer_sinks = lambda: CoreSightTarget._shutdown_trace_buffer_sinks(target)

        CoreSightTarget.trace_stop(target)

        trace_buffer_sinks.shutdown.assert_called_once_with()
        assert target._trace_buffer_sinks is None

    def test_capture_applies_ctrace_after_delegate(self):
        order = []
        ctrace_run = mock.Mock()
        ctrace_run.apply.side_effect = (lambda target: order.append('ctrace') or True)
        session = SimpleNamespace(ctrace_run=ctrace_run, Event=Session.Event,
                                  notify=mock.Mock(side_effect=lambda *args: order.append('notify')))
        target = mock.Mock(session=session, cores={})
        target.call_delegate.side_effect = (lambda *args, **kwargs: order.append('delegate') or True)

        CoreSightTarget.trace_capture(target)

        assert order == ['delegate', 'ctrace', 'notify']
        session.notify.assert_called_once_with(Session.Event.TRACE_DATA_CAPTURE, session, True)

    def test_capture_applies_ctrace_after_full_debug_sequence(self):
        order = []
        ctrace_run = mock.Mock()
        ctrace_run.apply.side_effect = (lambda target: order.append('ctrace') or False)
        delegate = mock.Mock(trace_setup=TraceSetup.FULL)
        delegate.run_sequence.side_effect = (lambda *args, **kwargs: order.append('sequence'))
        session = SimpleNamespace(ctrace_run=ctrace_run, Event=Session.Event,
                                  notify=mock.Mock(side_effect=lambda *args: order.append('notify')))
        target = mock.Mock(session=session, cores={}, debug_sequence_delegate=delegate,
                           selected_core_or_raise=SimpleNamespace(node_name='CM7'))
        target.call_delegate.return_value = False
        target.has_debug_sequence.return_value = True

        CoreSightTarget.trace_capture(target)

        assert order == ['sequence', 'ctrace', 'notify']
        delegate.run_sequence.assert_called_once_with('TraceCapture')
        session.notify.assert_called_once_with(Session.Event.TRACE_DATA_CAPTURE, session, False)

    def test_flush_notifies_after_delegate(self):
        order = []
        session = SimpleNamespace(Event=Session.Event, notify=mock.Mock(side_effect=lambda *args: order.append('notify')))
        target = mock.Mock(session=session, cores={})
        target.call_delegate.side_effect = (lambda *args, **kwargs: order.append('delegate') or True)

        CoreSightTarget.trace_flush(target)

        assert order == ['delegate', 'notify']
        session.notify.assert_called_once_with(Session.Event.TRACE_DATA_FLUSH, session)

    def test_ctrace_invalidates_on_trace_restart(self, tmp_path):
        session = SimpleNamespace(
            cbuild_run=SimpleNamespace(
                trace=SimpleNamespace(enabled=(object(),)),
                proj_path=None,
                proj_path_name=None,
                solution_set='Blinky+Board',
            ),
            options={
                'cbuild_run': str(tmp_path / 'Blinky.cbuild-run.yml'),
            },
            Event=Session.Event,
            subscribe=mock.Mock(),
        )
        ctrace_run = CTraceRun(session)
        trace_path = tmp_path / '.trace' / 'Blinky+Board.ctrace-run.yml'
        trace_path.parent.mkdir()
        write_ctrace_run(trace_path, [{
            'ctrace-ref': 'pmu-source',
            'type': 'pmu',
            'regs': [{'name': 'PMU_CTRL', 'value': 1}],
        }])
        target = make_target('CM7')

        assert ctrace_run.apply(target)
        target.cores[0].reset_mock()

        session.subscribe.assert_called_once_with(ctrace_run._trace_restart_handler, Session.Event.TRACE_RESTART, session)
        subscribed_callback = session.subscribe.call_args.args[0]
        subscribed_callback(mock.Mock())

        assert ctrace_run.apply(target)
        target.cores[0].write32.assert_any_call(0xE0003E04, 1)

    def test_reset_notifies_trace_restart_after_trace_start(self):
        order = []
        target = mock.Mock()
        target.trace_start.side_effect = lambda: order.append('trace-start')
        session = SimpleNamespace(
            _trace_started=True,
            target=target,
            notify=mock.Mock(side_effect=lambda *args: order.append('notify')),
        )

        Session._reset_handler(session, mock.Mock())

        assert order == ['trace-start', 'notify']
        session.notify.assert_called_once_with(Session.Event.TRACE_RESTART, session)
