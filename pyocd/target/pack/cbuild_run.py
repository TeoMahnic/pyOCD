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
import io
from pathlib import Path

from dataclasses import dataclass
from typing import (cast, Optional, Set, Dict, List, Tuple, IO)
from .flash_algo import PackFlashAlgo
from .. import (normalise_target_type_name, TARGET)
from .reset_sequence_maps import (RESET_SEQUENCE_TO_TYPE_MAP, RESET_TYPE_TO_SEQUENCE_MAP)
from ...coresight.cortex_m import CortexM
from ...coresight.coresight_target import CoreSightTarget
from ...coresight.ap import (APAddressBase, APv1Address, APv2Address)
from ...core import exceptions
from ...core.target import Target
from ...core.session import Session
from ...core.core_target import CoreTarget
from ...core.memory_map import (MemoryMap, MemoryType, MEMORY_TYPE_CLASS_MAP)
from ...utility.sequencer import CallSequence
from ...probe.debug_probe import DebugProbe
from ...debug.sequences.scope import Scope
from ...debug.sequences.delegates import DebugSequenceDelegate
from ...debug.sequences.functions import DebugSequenceCommonFunctions
from ...debug.svd.loader import SVDFile
from ...debug.sequences.sequences import (
    Block,
    DebugSequence,
    DebugSequenceNode,
    IfControl,
    WhileControl,
    DebugSequenceExecutionContext
)

LOG = logging.getLogger(__name__)

@dataclass
class ProcessorInfo:
    """@brief Descriptor for a processor defined in a DFP."""
    ## The Pname attribute, or Dcore if not Pname was provided.
    name: str = "unknown"
    ## PE unit number within an MPCore. For single cores this will be 0.
    unit: int = 0
    ## Total number of cores in an MPCore.
    total_units: int = 1
    ## Address of AP through which the PE can be accessed.
    ap_address: APAddressBase = APv1Address(-1)
    ## Base address of the PE's memory mapped debug registers. Not used and 0 for M-profile.
    address: int = 0
    ## SVD file path relative to the pack.
    svd_path: Optional[str] = None
    ## Default reset sequence name.
    default_reset_sequence: str = "ResetSystem"


class CbuildRunTargetMethods:
    """@brief Namespace for Cbuild-Run target generation utilities
    """
    @staticmethod
    def _cbuild_target_init(self, session: Session) -> None:
        """@brief Constructor for dynamically created target class."""
        super(self.__class__, self).__init__(session, self._cbuild_device.memory_map)
        self.vendor = self._cbuild_device.vendor
        self.part_number = self._cbuild_device.target
        self._svd_location = SVDFile(filename=self._cbuild_device.svd)
        self.debug_sequence_delegate = CbuildRunDebugSequenceDelegate(self, self._cbuild_device)

    @staticmethod
    def _cbuild_target_create_init_sequence(self) -> CallSequence:
        """@brief Creates an init task to set the default reset type."""
        seq = super(self.__class__, self).create_init_sequence()
        seq.wrap_task('discovery',
            lambda seq: seq.insert_after('create_cores',
                            ('configure_core_reset', self.configure_core_reset)
                            )
            )
        return seq

    @staticmethod
    def _cbuild_target_configure_core_reset(self) -> None: #TODO check and cleanup
        for core_num, core in self.cores.items():
            core_ap_addr = core.ap.address
            try:
                proc_info = self._cbuild_device.processors_ap_map[core_ap_addr]
            except KeyError:
                LOG.debug("core #%d not specified in DFP", core_num)
                continue

            # Get this processor's list of sequences.
            sequences = self.debug_sequence_delegate.sequences_for_pname(proc_info.name)

            def is_reset_sequence_enabled(name: str) -> bool:
                return (name not in sequences) or sequences[name].is_enabled

            # Set the supported reset types by filtering existing supported reset types.
            updated_reset_types: Set[Target.ResetType] = set()
            for resettype in core._supported_reset_types:
                # These two types are not in the map, and should always be present.
                if resettype in (Target.ResetType.SW, Target.ResetType.SW_EMULATED):
                    updated_reset_types.add(resettype)
                    continue

                resettype_sequence_name = RESET_TYPE_TO_SEQUENCE_MAP[resettype]
                if is_reset_sequence_enabled(resettype_sequence_name):
                    updated_reset_types.add(resettype)

            # Special case to enable processor reset even when the core doesn't support VECTRESET, if
            # there is a non-default ResetProcessor sequence definition.
            if ((Target.ResetType.SW_CORE not in updated_reset_types) # type:ignore
                    and ('ResetProcessor' in sequences)
                    and sequences['ResetProcessor'].is_enabled):
                updated_reset_types.add(Target.ResetType.SW_CORE) # type:ignore

            core._supported_reset_types = updated_reset_types
            LOG.debug(f"updated DFP core #{core_num} reset types: {core._supported_reset_types}")

            default_reset_seq = proc_info.default_reset_sequence

            # Check that the default reset sequence is a standard sequence. The specification allows for
            # custom reset sequences to be used, but that is not supported by pyocd yet.
            # TODO support custom default reset sequences (requires a new reset type)
            if default_reset_seq not in RESET_SEQUENCE_TO_TYPE_MAP:
                if default_reset_seq in sequences:
                    # Custom reset sequence, not yet supported by pyocd.
                    LOG.warning("DFP device definition error: custom reset sequences are not yet supported "
                                "by pyocd; core #%d (%s) requested default reset sequence %s",
                                core_num, proc_info.name, default_reset_seq)
                else:
                    # Invalid/unknown default reset sequence.
                    LOG.warning("DFP device definition error: specified default reset sequence %s "
                                "for core #%d (%s) does not exist",
                                default_reset_seq, core_num, proc_info.name)

            # Handle multicore debug mode causing secondary cores to default to processor reset.
            did_force_core_reset = False
            if (self.session.options.get('enable_multicore_debug')
                    and (core_num != self.session.options.get('primary_core'))):
                if not is_reset_sequence_enabled('ResetProcessor'):
                    LOG.warning("Multicore debug mode cannot select processor reset for secondary core "
                                "#%d (%s) because it is disabled by the DFP; using emulated processor "
                                "reset instead", core_num, proc_info.name)
                    core.default_reset_type = Target.ResetType.SW_EMULATED
                    continue
                else:
                    default_reset_seq = 'ResetProcessor'
                    did_force_core_reset = True

            # Verify that the specified default reset sequence hasn't been disabled.
            if not is_reset_sequence_enabled(default_reset_seq):
                # Only log a warning if we didn't decide to use core reset due to multicore mode.
                if not did_force_core_reset:
                    LOG.warning("DFP device definition conflict: specified default reset sequence %s "
                            "for core #%d (%s) is disabled by the DFP",
                            default_reset_seq, core_num, proc_info.name)

                # Map from disabled default to primary and secondary fallbacks.
                RESET_FALLBACKS: Dict[str, Tuple[str, str]] = {
                    'ResetSystem':      ('ResetProcessor', 'ResetHardware'),
                    'ResetHardware':    ('ResetSystem', 'ResetProcessor'),
                    'ResetProcessor':   ('ResetSystem', 'ResetHardware'),
                }

                # Select another default.
                fallbacks = RESET_FALLBACKS[default_reset_seq]
                if is_reset_sequence_enabled(fallbacks[0]):
                    default_reset_seq = fallbacks[0]
                elif is_reset_sequence_enabled(fallbacks[1]):
                    default_reset_seq = fallbacks[1]
                else:
                    LOG.warning("DFP device definition conflict: all reset types are disabled for "
                            "core #%d (%s) by the DFP; using emulated core reset",
                            default_reset_seq, core_num)
                    core.default_reset_type = Target.ResetType.SW_EMULATED
                    continue

            LOG.info("Setting core #%d (%s) default reset sequence to %s",
                    core_num, proc_info.name, default_reset_seq)
            core.default_reset_type = RESET_SEQUENCE_TO_TYPE_MAP[default_reset_seq]

    @staticmethod
    def _cbuild_target_add_core(_self, core: CoreTarget) -> None:
        """@brief Override to set node name of added core to its pname."""
        pname = _self._cbuild_device.processors_ap_map[cast(CortexM, core).ap.address].name
        core.node_name = pname
        CoreSightTarget.add_core(_self, core)


class CbuildRun:
    """@brief Parser for the .cbuild-run.yml file (CSolution Run and Debug Management).
    """
    def __init__(self, yml_path: str) -> None:
        """@brief Constructor.
        @param self This object.
        @param yml_path Path to the .cbuild-run.yml file.
        """
        self._vars = None
        self._sequences = None
        self._memory_map: Optional[MemoryMap] = None
        self._valid_dps: List[int] = []
        self._apids: Dict[int, APAddressBase] = {}
        self._built_apid_map: bool = False
        self._processors_map: Dict[str, ProcessorInfo] = {}
        self._processors_ap_map: Dict[APAddressBase, ProcessorInfo] = {}

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
    def part_number(self) -> str:
        return self.target

    @property
    def vendor(self) -> str:
        """@brief Target Vendor
        @return Value of 'device' without Target.
        """
        if self._valid and ('device' in self._data['cbuild-run']):
            return self._data['cbuild-run']['device'].split('::')[0]
        else:
            return ''

    @property
    def families(self) -> List[str]:
        return ['']

    @property
    def memory_map(self) -> MemoryMap:
        if self._memory_map is None:
            self._build_memory_map()
        return self._memory_map

    @property
    def svd(self) -> Optional[IO[bytes]]:
        #TODO handle multicore
        try:
            for item in self.system_descriptions:
                if item['type'] == 'svd':
                    svd_path = Path(os.path.expandvars(item['file']))
                    return io.BytesIO(svd_path.read_bytes())
        except (KeyError, IndexError):
            return None

    @property
    def debug_sequences(self) -> dict:
        if self._valid and ('debug-sequences' in self._data['cbuild-run']):
            if self._sequences is None:
                self._sequences = self._data['cbuild-run'].get('debug-sequences', {})
            return self._sequences
        return {}

    @property
    def debug_vars(self) -> dict:
        if self._valid and ('debug-vars' in self._data['cbuild-run']):
            if self._vars is None:
                self._vars = self._data['cbuild-run'].get('debug-vars', {})
            return self._vars
        return {}

    @property
    def valid_dps(self) -> List[int]:
        if not self._valid_dps:
            self._build_valid_dps()
        return self._valid_dps

    @property
    def uses_apid(self) -> bool:
        return len(self.apid_map) > 0

    @property
    def apid_map(self) -> Dict[int, APAddressBase]:
        if not self._built_apid_map:
            self._build_aps_map()
        return self._apids

    @property
    def processors_map(self) -> Dict[str, ProcessorInfo]:
        if not self._processors_map:
            self._build_aps_map()
        return self._processors_map

    @property
    def processors_ap_map(self) -> Dict[APAddressBase, ProcessorInfo]:
        if not self._processors_ap_map:
            self._processors_ap_map = {
                proc.ap_address: proc
                for proc in self.processors_map.values()
            }
        return self._processors_ap_map

    @property
    def programming(self) -> dict:
        """@brief Programming
        @return 'programming' section of cbuild-run.
        """
        if self._valid:
            return self._data['cbuild-run'].get('programming', {})
        return {}

    @property
    def system_resources(self) -> dict:
        """@brief System Resources
        @return 'system-resources' section of cbuild-run.
        """
        if self._valid:
            return self._data['cbuild-run'].get('system-resources', {})
        return {}

    @property
    def system_descriptions(self) -> dict:
        """@brief System Descriptions
        @return 'system-descriptions' section of cbuild-run.
        """
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
                    LOG.debug(f"did not populate target from cbuild-run.yml for device {self.target} because "
                              f"there is already a {target} target installed")
                    return

                # Generate target subclass and install it.
                tgt = type(target.capitalize(), (CoreSightTarget,), {
                           "_cbuild_device": self,
                           "__init__": CbuildRunTargetMethods._cbuild_target_init,
                           "create_init_sequence": CbuildRunTargetMethods._cbuild_target_create_init_sequence,
                           "configure_core_reset": CbuildRunTargetMethods._cbuild_target_configure_core_reset,
                           "add_core": CbuildRunTargetMethods._cbuild_target_add_core
                })
                TARGET[target] = tgt

    def _build_memory_map(self) -> None:
        """@brief Memory Map generated from cbuild-run file"""
        # Ensure memory resource exists before proceeding
        if 'memory' not in self.system_resources:
            self._memory_map = MemoryMap()

        def _sort_algorithms(algorithm: dict) -> tuple:
            # Prioritize default entries
            is_default = algorithm.get('default', False)
            # Next sort by Pname
            has_pname = 'pname' in algorithm
            # Sorting key: False comes first, so default and pname are prioritized
            return (not is_default, not has_pname)

        regions = []
        algorithms = sorted(self.programming, key=_sort_algorithms)

        for memory in self.system_resources['memory']:
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

                #TODO Gather all algorithms that cover the memory
                if (memory['start'] >= algorithm['start']) and (memory_end <= algorithm_end):
                    if memory.get('pname', None) and algorithm.get('pname', None):
                        if memory['pname'] != algorithm['pname']:
                            # Skip this algorithm if 'Pname' exists and does not match
                            continue

                    # If memory region is within an algorithm range, classify as FLASH
                    type = MemoryType.FLASH
                    # Add additional attributes related to the algorithm
                    if 'ram-start' in algorithm:
                        attrs['_RAMstart'] = algorithm['ram-start']
                    if 'ram-size' in algorithm:
                        attrs['_RAMsize'] = algorithm['ram-size']
                    if ('_RAMstart' in attrs) and ('_RAMsize' not in attrs):
                        LOG.warning(f"Flash algorithm '{algorithm['algorithm']}' "
                                    "has RAMstart but is missing RAMsize")
                    attrs['flm'] = PackFlashAlgo(os.path.expandvars(algorithm['algorithm']))
                    break

            # Create appropriate memory region object and store it
            regions.append(MEMORY_TYPE_CLASS_MAP[type](**attrs))

        self._memory_map = MemoryMap(regions)

    def _build_valid_dps(self) -> None:
        if 'debugger' in self._data['cbuild-run']:
            for debugger in self._data['cbuild-run']['debugger']:
                dp = debugger.get('dp', None)
                if dp is not None:
                    self._valid_dps.append(dp)
        if not self._valid_dps:
            # Use default __dp of 0.
            self._valid_dps.append(0)

    def _build_aps_map(self) -> None:
        self._built_apid_map = True

        if 'processor' in self._data['cbuild-run']:
            for processor in self._data['cbuild-run']['processor']:
                if 'pname' in processor:
                    pname = processor['pname']
                else:
                    pname = processor['core']

                address = 0
                if 'accessports' in processor:
                    for accessport in processor['accessports']:
                        ap_dp = accessport.get('dp', 0)
                        if ap_dp not in self.valid_dps:
                            LOG.warning(f"dp attribute is invalid ({ap_dp})")
                        apid = accessport['apid']

                        #APv2
                        if 'address' in accessport:
                            address = accessport['address']
                            ap_address = APv2Address(accessport['address'], ap_dp, apid)
                        elif 'index' in accessport:
                            ap_address = APv1Address(accessport['index'], ap_dp, apid)
                        else:
                            raise exceptions.InternalError("Invalid accessport")

                        # Save this AP address.
                        self._apids[apid] = ap_address
                else:
                    # Otherwise define a default AP #0.
                    ap_address = APv1Address(0)

                svd_path = None
                for item in self.system_descriptions:
                    if item['type'] == 'svd':
                        if ('pname' in item) and pname != item['pname']:
                            continue
                        svd_path = os.path.expandvars(item['file'])
                        break

                reset_sequence = processor.get('resetsequence', 'ResetSystem')
                self._processors_map[pname] = ProcessorInfo(name=pname,
                                                          unit=processor.get('punit', 0),
                                                          total_units=processor.get('punits', 1),
                                                          ap_address=ap_address,
                                                          address=address,
                                                          svd_path=svd_path,
                                                          default_reset_sequence=reset_sequence)

        if not self._processors_map:
            LOG.warning("No 'processor' node was found")
            # Add dummy processor.
            pname = 'unknown'
            ap_address = APv1Address(0)
            self._processors_map[pname] = ProcessorInfo(name=pname,
                                                       ap_address=ap_address)


class CbuildRunSequences:
    def __init__(self, yml_vars, yml_sequences) -> None:
        self._debug_vars = yml_vars
        self._debug_sequences = yml_sequences

        self._debugvars: Optional[Block] = None
        self._sequences: Set[DebugSequence] = set()
        self._control_nodes = {'if', 'while'}

    @property
    def variables(self) -> Optional[Block]:
        if (self._debugvars is None) and (self._debug_vars.get('vars') is not None):
            self._debugvars = Block(self._debug_vars['vars'], info='debugvars')
        return self._debugvars

    @property
    def sequences(self) -> Set[DebugSequence]:
        if self._sequences == set():
            self._build_sequences()
        return self._sequences

    def _build_sequences(self) -> None:
        for elem in self._debug_sequences:
            name = elem.get('name', None)
            if name is None:
                LOG.warning("invalid debug sequence; missing name")
                continue

            pname = elem.get('pname', None)
            info = elem.get('info', None)
            sequence = DebugSequence(name, True, pname, info)

            if 'blocks' in elem:
                for child in elem['blocks']:
                    self._build_sequence_node(sequence, child)
            self._sequences.add(sequence)

    def _build_sequence_node(self, parent: DebugSequenceNode, elem: dict) -> None:
        info = elem.get('info', "")
        if any(node in elem for node in self._control_nodes):
            if 'if' in elem:
                node = IfControl(elem['if'], info)
            elif 'while' in elem:
                node = WhileControl(elem['while'], info, int(elem.get('timeout', "0")))

            parent.add_child(node)

            if 'blocks' in elem:
                for child in elem['blocks']:
                    self._build_sequence_node(node, child)
            elif 'execute' in elem:
                child = {k: v for k, v in elem.items() if k not in self._control_nodes}
                self._build_sequence_node(node, child)
        else:
            if 'execute' in elem:
                is_atomic = True if 'atomic' in elem else False
                node = Block(elem['execute'], is_atomic, info)
                parent.add_child(node)


class CbuildRunDebugSequenceDelegate(DebugSequenceDelegate):
    ## Map from pyocd reset types to the __connection variable reset type field.
    # 0=error, 1=hw, 2=SYSRESETREQ, 3=VECTRESET
    RESET_TYPE_MAP = {
        Target.ResetType.HW: 1,
        Target.ResetType.SW: 2, # TODO pick default sw reset type
        Target.ResetType.SW_SYSRESETREQ: 2,
        Target.ResetType.SW_VECTRESET: 3,
        Target.ResetType.SW_EMULATED: 2, # no direct match
    }

    def __init__(self, target: CoreSightTarget, device: CbuildRun) -> None:
        self._target = target
        self._session = target.session
        self._device = device
        self._cbuild_run_sequences = CbuildRunSequences(device.debug_vars, device.debug_sequences)
        self._sequences: Set[DebugSequence] = self._cbuild_run_sequences.sequences
        self._debugvars: Optional[Scope] = None
        self._functions = DebugSequenceCommonFunctions()

    @property
    def all_sequences(self) -> Set[DebugSequence]:
        return self._sequences

    @property
    def cmsis_pack_device(self) -> CbuildRun:
        return self._device

    def get_root_scope(self, context: DebugSequenceExecutionContext) -> Scope:
        if self._debugvars is not None:
            return self._debugvars

        self._debugvars = Scope(name='debugvars')
        debugvars_block = self._cbuild_run_sequences.variables
        if debugvars_block is not None:
            with context.push(debugvars_block, self._debugvars):
                debugvars_block.execute(context)

        # Make all vars read-only.
        self._debugvars.freeze()

        if LOG.isEnabledFor(logging.INFO):
            for name in sorted(self._debugvars.variables):
                value = self._debugvars.get(name)
                LOG.info(f"debugvar '{name}' = {value:#x} ({value:d})")

        return self._debugvars

    def run_sequence(self, name: str, pname: Optional[str] = None) -> Optional[Scope]:
        pname_desc = f" ({pname})" if (pname and LOG.isEnabledFor(logging.DEBUG)) else ""

        # Error out for invalid sequence.
        if not self.has_sequence_with_name(name, pname):
            raise NameError(name)

        # Get sequence object.
        seq = self.get_sequence_with_name(name, pname)

        # If the sequence is disabled, we won't run it.
        if not seq.is_enabled:
            LOG.debug(f"Not running disabled debug sequence '{name}'{pname_desc}")
            return None

        LOG.debug(f"Running debug sequence '{name}'{pname_desc}")

        # Create runtime context and contextified functions instance.
        context = DebugSequenceExecutionContext(self._session, self, pname)

        # Map optional pname to AP address. If the pname is not specified, then use the device's
        # first available AP. If not APs are known (eg haven't been discovered yet) then use 0.
        if pname:
            proc_map = self._device.processors_map
            ap_address = proc_map[pname].ap_address
        else:
            ap = self._target.first_ap
            if ap is not None:
                ap_address = ap.address
            else:
                ap_address = APv1Address(0)

        # Set the default AP in the exec context.
        context.default_ap = ap_address

        with context:
            try:
                executed_scope = seq.execute(context)
            except exceptions.Error as err:
                if pname:
                    LOG.error(f"Error while running debug sequence '{name}' (core {pname}): {err}")
                else:
                    LOG.error(f"Error while running debug sequence '{name}': {err}")
                raise

        return executed_scope


    def sequences_for_pname(self, pname: Optional[str]) -> Dict[str, DebugSequence]:
        # Return *only* sequences with no Pname when passed pname=None. Otherwise we'd have
        # to mangle the dict keys to include pname since there can be multiple sequences with
        # the same name but different
        return {
            seq.name: seq
            for seq in self._sequences
            if (seq.pname is None) or (seq.pname == pname)
        }

    def has_sequence_with_name(self, name: str, pname: Optional[str] = None) -> bool:
        return name in self.sequences_for_pname(pname)

    def get_sequence_with_name(self, name: str, pname: Optional[str] = None) -> DebugSequence:
        return self.sequences_for_pname(pname)[name]

    def get_protocol(self) -> int:
        """@brief Return the value for the __protocol variable.
        __protocol fields:
        - [15:0] 0=error, 1=JTAG, 2=SWD, 3=cJTAG
        - [16] SWJ-DP present?
        - [17] switch through dormant state?
        """
        session = self._target.session
        assert session.probe, "must have a valid probe"
        # Not having a wire protocol set is allowed if performing pre-reset since it will only
        # execute ResetHardware (or equivalent), which can only access pins and such (theoretically).
        assert self._session.context_state.is_performing_pre_reset or session.probe.wire_protocol, \
            "must have valid, connected probe"
        if session.probe.wire_protocol == DebugProbe.Protocol.JTAG:
            protocol = 1
        elif session.probe.wire_protocol == DebugProbe.Protocol.SWD:
            protocol = 2
        else:
            protocol = 0 # Error
        if session.options.get('dap_swj_enable'):
            protocol |= 1 << 16
        if session.options.get('dap_swj_use_dormant'):
            protocol |= 1 << 17
        return protocol

    def get_connection_type(self) -> int:
        """@brief Return the value for the __connection variable.
        __connection fields:
        - [7:0] connection type: 0=error/disconnected, 1=for debug, 2=for flashing
        - [15:8] reset type: 0=error, 1=hw, 2=SYSRESETREQ, 3=VECTRESET
        - [16] connect under reset?
        - [17] pre-connect reset?
        """
        ctype = 1
        ctype |= self.RESET_TYPE_MAP.get(self._session.options.get('reset_type'), 0) << 8

        connect_mode = self._target.session.options.get('connect_mode')
        if connect_mode == 'under-reset':
            ctype |= 1 << 16

        # The pre-reset bit should only be set when running ResetHardware for a connect pre-reset.
        # This is stored in the is_performing_pre_reset session state variable, set by CoreSightTarget's
        # pre_connect() method.
        if self._session.context_state.is_performing_pre_reset:
            ctype |= 1 << 17
        return ctype

    def get_traceout(self) -> int:
        """@brief Return the value for the __traceout variable.
        __traceout fields:
        - [0] SWO enabled?
        - [1] parallel trace enabled?
        - [2] trace buffer enabled?
        - [21:16] selected parallel trace port size
        """
        # Set SWO bit depending on the option value.
        return 1 if self._target.session.options.get('enable_swv') else 0

    def get_sequence_functions(self) -> DebugSequenceCommonFunctions:
        return self._functions
