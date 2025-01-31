import logging

from collections import namedtuple
from typing import List, Tuple, Optional, Generator, Callable
from volatility3.plugins.windows import iisinfo
from volatility3.framework.objects import utility, String
from volatility3.framework import interfaces, renderers, symbols, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins import yarascan
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist
import re

vollog = logging.getLogger(__name__)

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False

REQUEST_LEVEL_EVENTS = {
    "RQ_BEGIN_REQUEST":{
        "bitmask": 0x00000001,
        "offset": 0
        },
    "RQ_AUTHENTICATE_REQUEST":{
        "bitmask": 0x00000002,
        "offset": 16
        },
    "RQ_AUTHORIZE_REQUEST":{
        "bitmask": 0x00000004,
        "offset": 32
        },
    "RQ_RESOLVE_REQUEST_CACHE":{
        "bitmask": 0x00000008,
        "offset": 48
        },
    "RQ_MAP_REQUEST_HANDLER":{
        "bitmask": 0x00000010,
        "offset": 64
        },
    "RQ_ACQUIRE_REQUEST_STATE":{
        "bitmask": 0x00000020,
        "offset": 80
        },
    "RQ_PRE_EXECUTE_REQUEST_HANDLER":{
        "bitmask": 0x00000040,
        "offset": 96
        },
    "RQ_EXECUTE_REQUEST_HANDLER":{
        "bitmask": 0x00000080,
        "offset": 112
        },
    "RQ_RELEASE_REQUEST_STATE":{
        "bitmask": 0x00000100,
        "offset": 128
        },
    "RQ_UPDATE_REQUEST_CACHE":{
        "bitmask": 0x00000200,
        "offset": 144
        },
    "RQ_LOG_REQUEST":{
        "bitmask": 0x00000400,
        "offset": 160
        },
    "RQ_END_REQUEST":{
        "bitmask": 0x00000800,
        "offset": 176
        },
    "RQ_CUSTOM_NOTIFICATION":{
        "bitmask": 0x10000000,
        "offset": 216
        },
    "RQ_SEND_RESPONSE":{
        "bitmask": 0x20000000,
        "offset": 192
        },
    "RQ_READ_ENTITY":{
        "bitmask": 0x40000000,
        "offset": 208
        },
    "RQ_MAP_PATH":{
        "bitmask": 0x80000000,
        "offset": 200
        },
}

GLOBAL_EVENTS = {
    "GL_STOP_LISTENING":{
        "bitmask": 0x00000002,
        "offset": 0
        },
    "GL_CACHE_CLEANUP":{
        "bitmask": 0x00000004,
        "offset": 8
        },
    "GL_CACHE_OPERATION":{
        "bitmask": 0x00000010,
        "offset": 16
        },
    "GL_HEALTH_CHECK":{
        "bitmask": 0x00000020,
        "offset": 24
        },
    "GL_CONFIGURATION_CHANGE":{
        "bitmask": 0x00000040,
        "offset": 32
        },
    "GL_FILE_CHANGE":{
        "bitmask": 0x00000080,
        "offset": 40
        },
    "GL_PRE_BEGIN_REQUEST":{
        "bitmask": 0x00000100,
        "offset": 48
        },
    "GL_APPLICATION_START":{
        "bitmask": 0x00000200,
        "offset": 56
        },
    "GL_APPLICATION_RESOLVE_MODULES":{
        "bitmask": 0x00000400,
        "offset": 64
        },
    "GL_APPLICATION_STOP":{
        "bitmask": 0x00000800,
        "offset": 72
        },
    "GL_RSCA_QUERY":{
        "bitmask": 0x00001000,
        "offset": 80
        },
    "GL_TRACE_EVENT":{
        "bitmask": 0x00002000,
        "offset": 88
        },
    "GL_CUSTOM_NOTIFICATION":{
        "bitmask": 0x00004000,
        "offset": 96
        },
    "GL_THREAD_CLEANUP":{
        "bitmask": 0x00008000,
        "offset": 112
        },
}

class IISEvent(iisinfo.IISInfo):
    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.function_sig = b"\x7f\x00\x00"
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # create a list of requirements for vadyarascan
        vadyarascan_requirements = [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="iisinfo", plugin=iisinfo.IISInfo, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 1, 0)
            ),
            requirements.PluginRequirement(
                name="yarascan", plugin=yarascan.YaraScan, version=(2, 0, 0)
            ),
            requirements.ListRequirement(name = 'pid',
                             description = 'Filter on specific process ID',
                             element_type = int,
                             optional = True),
            requirements.ListRequirement(name = 'name',
                             description = 'Filter on a specific Module Name',
                             element_type = str,
                             optional = True),
        ]

        # get base yarascan requirements for command line options
        yarascan_requirements = yarascan.YaraScan.get_yarascan_option_requirements()

        # return the combined requirements
        return yarascan_requirements + vadyarascan_requirements

    @classmethod
    def get_rip_target(cls, inst) -> int:
        try:
            opnd = inst.operands[1]
        except:
            try:
                opnd = inst.operands[0]
            except capstone.CsError:
                return None
        
        if opnd.type != capstone.x86.X86_OP_MEM:
            return None

        return inst.address + inst.size + opnd.mem.disp

    @classmethod
    def check_builtin(cls, dis, address, proc_layer, displacement):
        found_mov = False
        last_lea = None
        vftable_address = None

        while not found_mov:
            try:
                bytes = proc_layer.read(address, 64)
            except:
                return None
            for inst in dis.disasm(bytes, address):
                if inst.mnemonic == "int3":
                    return None
                elif inst.mnemonic == "lea":
                    opnd = inst.operands[1]
                    if inst.reg_name(opnd.mem.base) == "rip":
                        last_lea = inst
                elif inst.mnemonic == "mov":
                    opnd = inst.operands[1]
                    if opnd.value.mem.base != 0:
                        if opnd.value.mem.disp == displacement:
                            found_mov = True
                            if last_lea is None:
                                return None
                            vftable_address = cls.get_rip_target(last_lea)
                            return vftable_address
            address += 64
        return vftable_address

    @classmethod
    def handle_jump_table(
        cls,
        dis,
        address: int, 
        proc_layer: interfaces.layers.DataLayerInterface
        ) -> int:
        """
        This function will pull the needed address from the
        the jump tables present in modules compiled with debug symbols
        """
        bytes = proc_layer.read(address, 8)
        for inst in dis.disasm(bytes, address):
            jump = inst
        return int(jump.op_str, 16)
    
    @classmethod
    def find_vftable_lea(cls, dis, address, proc_layer):
        """
        This function is used to discover the lea mnemonic with 
        an operand that is the module's vftable when creating the
        Module Object.
        """
        while 1:
            try:
                bytes = proc_layer.read(address, 64)
            except:
                return None
            for inst in dis.disasm(bytes, address):
                    if inst.mnemonic == "int3":
                        return None
                    elif inst.mnemonic == "lea":
                        opnd = inst.operands[1]
                        if inst.reg_name(opnd.mem.base) == "rip":
                            vftable_address = cls.get_rip_target(inst)
                            address_string = proc_layer.read(vftable_address, 8)
                            if b"\x7f\x00\x00" in address_string:
                                return vftable_address
            address += 64

    @classmethod
    def debug_handle(cls, dis, address, proc_layer, displacement):
        """
        Handles the processing of modules that have debug symbols
        and jump tables.
        """
        factory_found = False
        found_vftable = False
        call_holder = None
        factory_call = None

        address = cls.handle_jump_table(dis, address, proc_layer)

        while not factory_found:
            try:
                bytes = proc_layer.read(address, 64)
            except:
                return None
            for inst in dis.disasm(bytes, address):
                if inst.mnemonic == "int3":
                    break
                elif inst.mnemonic == "call":
                    for i in inst.operands:
                        if i.value.mem.base != 0:
                            if i.value.mem.disp == displacement:
                                factory_found = True
                                factory_call = call_holder
                                break
                        call_holder = inst
            address += 64
        factory_jump = int(factory_call.op_str, 16)
        address = cls.handle_jump_table(dis, factory_jump, proc_layer)

        if displacement == 0x10:
            address = cls.find_vftable_lea(dis, address, proc_layer)
            address = cls.handle_jump_table(dis, int.from_bytes(proc_layer.read(address, 8), "little"), proc_layer)
            while not found_vftable:
                try:
                    bytes = proc_layer.read(address, 64)
                except:
                    return None
                for inst in dis.disasm(bytes, address):
                    if inst.mnemonic == "int3":
                        return None
                    elif inst.mnemonic == "call":
                        jump_address = cls.handle_jump_table(dis, int(inst.op_str, 16), proc_layer)
                        vftable_address = cls.find_vftable_lea(dis, jump_address, proc_layer)
                        if vftable_address is None:
                            continue
                        else:
                            return vftable_address
                address += 64
        else:
            return cls.find_vftable_lea(dis, address, proc_layer)

    @classmethod
    def find_vftable(cls, dis, address, proc_layer, displacement):
        last_lea = None
        vftable_address = None
        found_call = False
        found_vftable = False
    
        if proc_layer.read(address, 1) == b"\xe9":
            vftable_address = cls.debug_handle(dis, address, proc_layer, displacement)

        else:
            while not found_call:
                try:
                    bytes = proc_layer.read(address, 64)
                except:
                    return None
                for inst in dis.disasm(bytes, address):
                    if inst.mnemonic == "int3":
                        break
                    elif inst.mnemonic == "lea":
                        opnd = inst.operands[1]
                        if inst.reg_name(opnd.mem.base) == "rip":
                            last_lea = inst
                    elif inst.mnemonic == "call" or inst.mnemonic == "jmp":
                        for i in inst.operands:
                            if i.value.mem.base != 0:
                                if i.value.mem.disp == displacement:
                                    found_call = True
                                    if last_lea is None:
                                        return None
                                    break
                address += 64
            if displacement == 0x10:
                factory = cls.get_rip_target(last_lea)
                get_module = int.from_bytes(proc_layer.read(factory, 8), "little")
                return cls.find_vftable_lea(dis, get_module, proc_layer, b"\x7f\x00\x00")
            else:
                return cls.get_rip_target(last_lea)
        return vftable_address
            

    @classmethod
    def combine_bitmasks(cls, bytes):
        bitmask = 0
        for offset in range(0, len(bytes), 4):
            bitmask += int.from_bytes(bytes[offset:offset+4], "little")
        return bitmask
    
    @classmethod
    def identify_events(
        cls,
        proc_layer: interfaces.layers.DataLayerInterface,
        bitmask: int,
        event_bitmask: dict,
        vftable: int,
        post_requests: bool) -> List[str]:
        """
        Uses the bitmask to determine which requests or global
        events a module is handling

        Args: 
            proc_layer: the layer to scan for addresses
            bitmask: bitmask data pulled from Virtual Module
            event_bitmask: dictionary of bitmasks for certain events
            vftable: The module event vftable
            post_requests: Boolean flag to handle post_requests.
                           PostRequests use the same bitmask as
                           the normal Request and are in the same
                           vftable offset by 8 bytes.
                                Example:
                                    Request Event: 0x0
                                    PostRequest Event: 0x8
        """
        displacement = 0
        events = []
        for event, value in event_bitmask.items():
            if bitmask & value["bitmask"]:
                if vftable is None:
                    discovered_event = f"{event} 0"
                else:
                    if post_requests:
                        displacement = 8
                    offset_bytes = proc_layer.read(vftable + int(value["offset"]) + displacement, 8)
                    offset = int.from_bytes(offset_bytes, "little")
                    discovered_event = f"{event} {offset}"
                events.append(discovered_event)
        return events
    
    @classmethod
    def event_discovery(
        cls, 
        proc_layer, 
        vrtm_address, 
        register_address
        ) -> Tuple[List[str], List[str], List[str]]:
        """
        Checks all posible event bitmask locations and process them with
        helper functions.

        Args:
            proc_layer: Layer to read for data
            vrtm_address: Address of the virtual module object in memory
            register_address: Address of the exported RegisterModule function
        """
        pre_events = []
        post_events = []
        global_events = []
        vftable = None
        dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        dis.detail = True

        vftable = cls.find_vftable(dis, register_address, proc_layer, 0x10)
        if vftable is None:
            vftable = cls.check_builtin(dis, register_address, proc_layer, 0x10)

        pre_notifications = proc_layer.read(vrtm_address, 20)
        pre_bitmasks = cls.combine_bitmasks(pre_notifications)
        if pre_bitmasks != 0:
            pre_events = cls.identify_events(proc_layer, 
                pre_bitmasks, REQUEST_LEVEL_EVENTS, vftable, False)

        post_notifications  = proc_layer.read(vrtm_address + 28, 4)
        post_bitmasks = cls.combine_bitmasks(post_notifications)
        if post_bitmasks != 0:
            post_events = cls.identify_events(proc_layer, 
                post_bitmasks, REQUEST_LEVEL_EVENTS, vftable, True)

        global_notifications = proc_layer.read(vrtm_address + 40, 20)
        global_bitmasks = cls.combine_bitmasks(global_notifications)
        if global_bitmasks != 0:
            global_vftable = cls.find_vftable(dis, register_address, proc_layer, 0x18)
            if global_vftable is None:
                global_vftable = cls.check_builtin(dis, register_address, proc_layer, 0x18)
                pass
            global_events = cls.identify_events(proc_layer, 
                global_bitmasks, GLOBAL_EVENTS, global_vftable, False)

        return pre_events, post_events, global_events

    def _generator(self
    ) -> Generator[Tuple[int, Tuple[str, int]], None, None]:
        if not has_capstone:
            vollog.warning("capstone is not installed")
        kernel = self.context.modules[self.config["kernel"]]
        name_filter = self.config.get("name", None)
        pid_filter = self.config.get('pid', None)
        labels = [
            "Request", 
            "PostRequest",
            "Global"
            ]
        for proc, proc_layer_name, architecture in self.get_tasks_to_scan(
            self.context, kernel.layer_name, kernel.symbol_table_name):
            if pid_filter and proc.UniqueProcessId not in pid_filter:
                continue
            if architecture == "intel":
                vollog.warning(f"{proc.UniqueProcessId}: Process is not 64-Bit")
                continue

            proc_layer = self.context.layers[proc_layer_name]

            vads = self.get_vad_maps(proc)
            for address in self._get_rule_hits(
                self.context, proc_layer, vads, self.vrtm_signature
            ):
                module_name, _, __, register_address = self.process_module(
                    proc_layer, address)
                events = self.event_discovery(proc_layer, address+104, register_address)
                for label, event_category in zip(labels, events):
                    if name_filter and module_name not in name_filter:
                        continue
                    for event in event_category:
                        event_data = event.split(" ")
                        yield 0, (
                            module_name,
                            proc.UniqueProcessId,
                            label,
                            event_data[0],
                            format_hints.Hex(int(event_data[1]))
                        )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Module Name", str),
                ("PID", int),
                ("Event Type", str),
                ("Event", str),
                ("Event Address", format_hints.Hex)
            ],
            self._generator()
        )