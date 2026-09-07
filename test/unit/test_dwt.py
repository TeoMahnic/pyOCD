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

from unittest import mock

from pyocd.coresight.dwt import DEMCR, DWT


DWT_BASE = 0xE0001000


class MockAccessPort:
    def __init__(self, comparator_count=4, dwt_ctrl=0):
        self.memory = {
            DEMCR: 0,
            DWT_BASE + DWT.DWT_CTRL: (
                comparator_count << DWT.DWT_CTRL_NUM_COMP_SHIFT
            ) | dwt_ctrl,
        }
        self.write_memory = mock.Mock(side_effect=self._write_memory)
        self.write32 = mock.Mock(side_effect=self._write_memory)

    def read_memory(self, address):
        return self.memory.get(address, 0)

    def _write_memory(self, address, value):
        self.memory[address] = value


def make_dwt(dwt_class=DWT, comparator_count=4, dwt_ctrl=0):
    ap = MockAccessPort(comparator_count, dwt_ctrl)
    return dwt_class(ap, addr=DWT_BASE), ap


class TestDWT:
    def test_init_is_idempotent_and_preserves_control_bits(self):
        existing_ctrl = DWT.DWT_CTRL_PCSAMPLENA_MASK
        dwt, ap = make_dwt(dwt_ctrl=existing_ctrl)

        dwt.init()
        first_write_count = ap.write_memory.call_count
        dwt.init()

        assert ap.write_memory.call_count == first_write_count
        ap.write32.assert_called_once_with(
            DWT_BASE + DWT.DWT_CTRL,
            existing_ctrl
            | (4 << DWT.DWT_CTRL_NUM_COMP_SHIFT)
            | DWT.DWT_CTRL_CYCCNTENA_MASK,
        )
