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

from .. import (normalise_target_type_name, TARGET)
from ...coresight.coresight_target import CoreSightTarget

LOG = logging.getLogger(__name__)

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
                           "XXX_pack_device": None,
                })
                if tgt:
                    TARGET[target] = tgt
