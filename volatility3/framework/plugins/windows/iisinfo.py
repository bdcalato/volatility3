import logging

from typing import List, Tuple, Optional, Generator

from volatility3.framework.objects import utility, String
from volatility3.framework import interfaces, renderers, symbols, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins import yarascan
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

class IISInfo(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.vrtm_signature = "/\\x56\\x52\\x54\\x4d\\x03/"
    
    @classmethod
    def get_requirements(
        cls
    ) -> List[interfaces.configuration.RequirementInterface]:
        
        scan_requirements = [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 1, 0)
            ),
            requirements.PluginRequirement(
                name="yarascan", plugin=yarascan.YaraScan, version=(2, 0, 0)
            ),
        ]

        return scan_requirements

    @classmethod
    def get_tasks_to_scan(
        cls, 
        context: interfaces.context.ContextInterface, 
        layer_name: str, 
        symbol_table_name: str
    ) -> Generator[Tuple[interfaces.objects.ObjectInterface, str, str], None, None]:
        """
        Scans for all IIS Worker Processes on the system.
        Can also detect if the process is in 32-bit mode (currently not unused)
        """
        is_32bit_arch = not symbols.symbol_table_is_64bit(context, symbol_table_name)

        for proc in pslist.PsList.list_processes(
        context,
        layer_name,
        symbol_table_name):
            proc_name = utility.array_to_string(proc.ImageFileName)

            # ignores all tasks that are not the IIS Worker Process
            if proc_name in ["w3wp.exe"]:
                try: 
                    proc_layer_name = proc.add_process_layer()
                except exceptions.InvalidAddressException:
                    continue

                if is_32bit_arch or proc.get_is_wow64():
                    architecture = "intel"
                else:
                    architecture = "intel64"
            
                yield proc, proc_layer_name, architecture
    
    @classmethod
    def get_vad_maps(self,
        task: interfaces.objects.ObjectInterface,
    ) -> List[Tuple[int, int, str]]:
        """
        This method gathers address ranges from memory.
        It intentionally filters out memory associated loaded
        dll's or other files as the plugin is searching for heap
        allocated memory.
        """
        vads: List[Tuple[int, int, str]] = []

        scan_max = 10 * 1000 * 1000

        vad_root = task.get_vad_root()

        for vad in vad_root.traverse():
            if vad.get_size() < scan_max:
                name = vad.get_file_name()
                # Seeking heap memory so filter out all vad's with file names
                # We just want the heap memory of the process
                if type(name) is not String:
                    vads.append((vad.get_start(), vad.get_size(), name))
        
        return vads

    @classmethod
    def _get_rule_hits(
        cls,
        context: interfaces.objects.ObjectInterface,
        proc_layer: interfaces.layers.DataLayerInterface,
        vads: List[Tuple[int, int, str]],
        pattern: str,
    ) -> Generator[Tuple[int, Optional[str]], None, None]:
        """
        This method utilizes the yarascanner in order to find
        Virtual Modules objects in memory.
        
        Args:
            proc_layer: the layer to get read from
            vads: address ranges to be scanned for patter
            pattern: the sequence of bytes to be searched for
                     in provided address ranges
        """
        sections = [(vad[0], vad[1]) for vad in vads]

        rule = yarascan.YaraScanner.get_rule(pattern)

        for hit in proc_layer.scan(
            context=context,
            scanner=yarascan.YaraScanner(rules=rule),
            sections=sections,
        ):
            address = hit[0]

            yield address

    @classmethod
    def get_string(cls,
        proc_layer: interfaces.layers.DataLayerInterface,
        address: int
    ) -> str:
        """
        This method is used to parse module names and
        their absolute system paths which are stored
        as utf-16 strings in memory
        
        Args:
            proc_layer: layer to be read from
            address: The pointer value address of the string needed
        """
        address_bytes = proc_layer.read(address, 8)
        str_address = int.from_bytes(address_bytes, byteorder='little')

        byte_list = bytearray()
        
        while True:
            byte = proc_layer.read(str_address, 2)
            if byte == b"\x00\x00": 
                break
            byte_list.extend(byte)
            str_address += 2

        return byte_list.decode('utf-16')

    @classmethod
    def get_module_dll(
        cls, 
        proc_layer: interfaces.layers.DataLayerInterface, 
        address: int
    ) -> Tuple[int, int, str]:
        """
        This function follow the pointer to the Module DLL Structure to extra 
        more information such as the image base of the DLL, the offset of the
        RegisterModule function, and the system path of the DLL
        """
        mod_dll_address= proc_layer.read(address, 8)
        mod_dll_address = int.from_bytes(mod_dll_address, byteorder='little')

        image_base = proc_layer.read(mod_dll_address + 40, 8)
        image_base = int.from_bytes(image_base, byteorder='little')

        register_module = proc_layer.read(mod_dll_address + 48, 8)
        register_module = int.from_bytes(register_module, byteorder='little')

        system_path = cls.get_string(proc_layer, mod_dll_address + 88)

        return image_base, register_module, system_path
    
    @classmethod
    def process_module(
        cls,
        proc_layer: interfaces.layers.DataLayerInterface,
        address: int
    ) -> Tuple[str, str, int, int]:

        module_name = cls.get_string(proc_layer, address + 64)

        image_base, register_module, system_path = cls.get_module_dll(
            proc_layer, address + 88)

        return module_name, system_path, image_base, register_module

    def _generator(self
    ) -> Generator[Tuple[int, Tuple[str, int]], None, None]:
        kernel = self.context.modules[self.config["kernel"]]

        for proc, proc_layer_name, architecture in self.get_tasks_to_scan(
            self.context, kernel.layer_name, kernel.symbol_table_name):

            if architecture == "intel":
                vollog.warning(f"{proc.UniqueProcessId}: Process is not 64-Bit")
                continue

            proc_layer = self.context.layers[proc_layer_name]

            vads = self.get_vad_maps(proc)

            for address in self._get_rule_hits(
                self.context, proc_layer, vads, self.vrtm_signature
            ):
                data = self.process_module(proc_layer, address)
                yield 0, (
                        data[0],
                        proc.UniqueProcessId,
                        data[1],
                        format_hints.Hex(data[2]),
                        format_hints.Hex(data[3]),
                )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Module Name", str),
                ("PID", int),
                ("Path", str),
                ("Image Base", format_hints.Hex),
                ("RegisterModule", format_hints.Hex),
            ],
            self._generator()
        )
