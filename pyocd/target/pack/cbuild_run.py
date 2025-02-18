# pyOCD debugger
# Copyright (c) 2025 Arm Limited
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
import yaml
import os

from .flash_algo import PackFlashAlgo
from .. import (normalise_target_type_name, TARGET)
from ...coresight.coresight_target import CoreSightTarget
from ...core.session import Session
from ...core.memory_map import (
    MemoryMap,
    MemoryType,
    MEMORY_TYPE_CLASS_MAP,
)


LOG = logging.getLogger(__name__)

class CbuildRunTarget:
    """@brief Namespace for Cbuild-Run target generation utilities
    """

    def __init__(self, cbuild_run):
        self._cbuild_run = cbuild_run
        self._memory_map = None
        self._regions = []

    def _sort_algorithms(self, algorithm: dict) -> tuple:
        # Prioritize default entries 
        is_default = algorithm.get('default', False)
        # Next sort by Pname
        has_pname = 'pname' in algorithm
        # Sorting key: False comes first, so default and pname are prioritized
        return (not is_default, not has_pname)

    def _build_memory_map(self) -> None:
        # Ensure memory resource exists before proceeding
        if 'memory' not in self._cbuild_run.system_resources:
            return

        algorithms = sorted(self._cbuild_run.programming, key=self._sort_algorithms)

        for memory in self._cbuild_run.system_resources['memory']:
            # Determine memory type based on access permissions
            if ('p' in memory['access']):
                type = MemoryType.DEVICE
            elif ('w' in memory['access']):
                type = MemoryType.RAM
            else:
                type = MemoryType.ROM

            # Define attributes for memory region
            attrs = {
                'name': memory['name'],
                'start': memory['start'],
                'length': memory['size'],
                'access': memory['access'],
                'is_default': memory.get('default', None),
                'is_boot_memory': memory.get('startup', None),
                'is_testable': memory.get('default', None),
                'pname': memory.get('pname', None),
                'uninit': memory.get('uninit', None),
                'alias': memory.get('alias', None),
                'sector_size': 0
            }

            for algorithm in algorithms:
                memory_end = memory['start'] + memory['size']
                algorithm_end = algorithm['start'] + algorithm['size']

                if (memory['start'] >= algorithm['start']) and (memory_end <= algorithm_end):
                    if memory.get('pname', None) and algorithm.get('pname', None):
                        if memory['pname'] != algorithm['pname']:
                            # Skip this algorithm if Pname does not match
                            continue

                    # If memory region is within an algorithm range, classify as FLASH
                    type = MemoryType.FLASH
                    # Add additional attributes related to the algorithm
                    attrs['_RAMstart'] = algorithm.get('ram-start', None)
                    attrs['_RAMsize'] = algorithm.get('ram-size', None)
                    if attrs['_RAMstart'] and not attrs['_RAMsize']:
                        LOG.warning(f"Flash algorithm '{algorithm['algorithm']}' "
                                    "has RAMstart but is missing RAMsize")
                    attrs['flm'] = PackFlashAlgo(os.path.expandvars(algorithm['algorithm']))
                    break

            # Create appropriate memory region object and store it
            region = MEMORY_TYPE_CLASS_MAP[type](**attrs)
            self._regions.append(region)

    @property
    def memory_map(self) -> MemoryMap:
        # Build memory map on first access
        if self._memory_map is None:
            self._build_memory_map()
            self._memory_map = MemoryMap(self._regions)

        return self._memory_map

    @staticmethod
    def _cbuild_target_init(self, session: Session) -> None:
        #TODO
        super(self.__class__, self).__init__(session, self._cbuid_device.memory_map)


class CbuildRun:
    """@brief Parser for the .cbuild-run.yml file (CSolution Run and Debug Management).
    """

    def __init__(self, yml_path: str) -> None:
        """@brief Constructor.

        @param self This object.
        @param yml_path Path to the .cbuild-run.yml file.

        """
        self._valid = False
        try:
            with open(yml_path, '+r') as yml_file:
                self._data = yaml.safe_load(yml_file)
                if 'cbuild-run' in self._data:
                    self._valid = True
        except IOError as err:
            LOG.warning("Error attempting to access .cbuild-run.yml file '%s': %s", yml_path, err)

    @property
    def target(self) -> str:
        """@brief Target.
        @return Value of 'device' without Vendor.
        """
        if self._valid and ('device' in self._data['cbuild-run']):
            return self._data['cbuild-run']['device'].split('::')[1]
        else:
            return ''

    @property
    def programming(self) -> dict:
        if self._valid:
            return self._data['cbuild-run'].get('programming', {})
        return {}

    @property
    def system_resources(self) -> dict:
        if self._valid:
            return self._data['cbuild-run'].get('system-resources', {})
        return {}

    @property
    def system_descriptions(self) -> dict:
        if self._valid:
            return self._data['cbuild-run'].get('system-descriptions', {})
        return {}

    @property
    def device_pack(self) -> list:
        """@brief Device Pack (DFP).
        @return Value of 'device-pack'.
        """
        if self._valid and ('device-pack' in self._data['cbuild-run']):
            vendor, _pack = self._data['cbuild-run']['device-pack'].split('::', 1)
            name, version = _pack.split('@', 1)
            pack = f"${{CMSIS_PACK_ROOT}}/{vendor}/{name}/{version}"
            return [os.path.expandvars(pack)]
        else:
            return []

    def populate_target(self, target: str) -> None:
        """@brief Generates and populates the target defined by the .cbuild-run.yml file.
        @param self This object.
        @param target Target.
        """
        if self._valid:
            if target == normalise_target_type_name(self.target):

                # Check if we're even going to populate this target.
                if target in TARGET:
                    LOG.debug("did not populate target from cbuild-run.yml for device %s because "
                              "there is already a %s target installed", self.target, target)
                    return

                # Generate target subclass and install it.
                tgt = type(target.capitalize(), (CoreSightTarget,), {
                           "_cbuid_device": CbuildRunTarget(self),
                           "__init__": CbuildRunTarget._cbuild_target_init
                })
                if tgt:
                    TARGET[target] = tgt
