import win32api
import winappdbg
import pefile
from pefile import Structure
from difflib import Differ
from itertools import groupby
from ctypes import *
from ctypes.wintypes import DWORD, HMODULE, MAX_PATH, BYTE, ULONG, HANDLE, USHORT
import ctypes, psutil, threading
from capstone import *

NTDLL = ctypes.windll.ntdll
KERNEL32 = ctypes.windll.kernel32
PSAPI = ctypes.windll.psapi
IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Change address size by system architecture
if winappdbg.System.bits == 64:
    PTR = ctypes.c_uint64
else:
    PTR = ctypes.c_void_p

def list_reloc(relocations, size, virtualAddress):
    list_relocs = [False] * size
    for reloc in relocations:
        for relocEntry in reloc.entries:
            addr2 = relocEntry.rva - virtualAddress
            if addr2 >= 0:
                for i in range(addr2, addr2 + sizeof(PTR) + 1):
                    if (i + 1) < size:
                        list_relocs[i + 1] = True
    return list_relocs

def parse_relocations(proc, moduleBaseAddress, pe, data_rva, rva, size):
        data = proc.read(moduleBaseAddress + data_rva, size)
        file_offset = pe.get_offset_from_rva(data_rva)

        entries = []
        for idx in xrange( len(data) / 2 ):

            entry = pe.__unpack_data__(
                pe.__IMAGE_BASE_RELOCATION_ENTRY_format__,
                data[idx*2:(idx+1)*2],
                file_offset = file_offset )

            if not entry:
                break
            word = entry.Data

            reloc_type = (word>>12)
            reloc_offset = (word & 0x0fff)
            relocationData = pefile.RelocationData(
                    struct = entry,
                    type = reloc_type,
                    base_rva = rva,
                    rva = reloc_offset+rva)

            if relocationData.struct.Data > 0 and \
               (relocationData.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW'] or \
                relocationData.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']):
                entries.append(relocationData)
            file_offset += entry.sizeof()

        return entries


def get_relocations(pe, proc, moduleBaseAddress):
    try:
        relocations = []
        relocTable = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']]
        rva = relocTable.VirtualAddress
        size = relocTable.Size

        if (size == 0):
            return []
        rlc_size = pefile.Structure(pe.__IMAGE_BASE_RELOCATION_format__).sizeof()
        end = rva + size
        while rva<end:
            try:
                rlc = pe.__unpack_data__(
                    pe.__IMAGE_BASE_RELOCATION_format__,
                    proc.read(moduleBaseAddress + rva, rlc_size),
                    file_offset = pe.get_offset_from_rva(rva) )
            except PEFormatError:
                rlc = None
            
            if not rlc:
                break
            reloc_entries = parse_relocations(proc, moduleBaseAddress, pe, rva+rlc_size, rlc.VirtualAddress, rlc.SizeOfBlock-rlc_size )

            relocations.append(
                pefile.BaseRelocationData(
                    struct = rlc,
                    entries = reloc_entries))

            if not rlc.SizeOfBlock:
                break
            rva += rlc.SizeOfBlock

        return relocations
    except Exception as ex:
        print(str(ex))

def analyze_process(pid):
    proc = winappdbg.Process(pid)
    process_patches = {'pid' : pid, 'file': proc.get_filename(), 'modules': [] }

    if proc.get_bits() != winappdbg.System.bits:
        return

    # Initialize disassembler
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    for module_base_addr in proc.get_module_bases():
        module = proc.get_module_at_address(module_base_addr)
        module_obj = {'file': module.get_filename(), 'base_address': module_base_addr, 'patches': [], 'additional_sections': []}

        try:
            module_data = proc.read(module_base_addr, module.get_size())
            pe_mem = pefile.PE(data = module_data, fast_load = True)
            pe_disk = pefile.PE(name = module.get_filename(), fast_load = True)

            # We assume that the section Characteristics field could have been modified at runtime, 
            # so we trust each section's Characteristics from disk, even if it's not marked as executable in memory -
            # this is since a section can be marked not executable but the pages in it marked as executable.
            disk_exec_sections = [section for section in pe_disk.sections if section.Characteristics & IMAGE_SCN_MEM_EXECUTE]
            disk_section_names = [section.Name for section in disk_exec_sections]
            mem_exec_sections = [section for section in pe_mem.sections if section.Characteristics & IMAGE_SCN_MEM_EXECUTE \
                                    or section.Name in disk_section_names]
            
            # Sort the section lists by name for sanity checking and easier looping later on
            mem_exec_sections.sort(key = lambda section: section.Name)
            disk_exec_sections.sort(key = lambda section: section.Name)

            if not len(disk_exec_sections):
                # Module has no executable sections on disk
                continue;
            elif len(mem_exec_sections) != len(disk_exec_sections) or \
                any(mem_exec_sections[idx].Name != disk_exec_sections[idx].Name for idx in range(len(mem_exec_sections))):
                # Incompatible number of executable sections, or mismatching section names.
                additional_sections = [section.Name for section in mem_exec_sections if section.Name not in disk_section_names]
                module_obj['additional_sections'].append(additional_sections)
                continue

            for idx in range(0, len(mem_exec_sections)):
                mem_section_data = proc.read(module_base_addr + mem_exec_sections[idx].VirtualAddress, mem_exec_sections[idx].Misc_VirtualSize)
                disk_section_data = disk_exec_sections[idx].get_data()[:mem_exec_sections[idx].Misc_VirtualSize]

                # Compare text sections between disk and memory
                if mem_section_data == disk_section_data:
                    continue

                relocations = get_relocations(pe_mem, proc, module_base_addr)
                list_relocs = list_reloc(relocations, mem_exec_sections[idx].Misc_VirtualSize, mem_exec_sections[idx].VirtualAddress)
                last_patch_position = -1
                current_patch = None

                for i in range(mem_exec_sections[idx].Misc_VirtualSize):
                    # Check if there's a differential between memory and disk, taking to account base relocations
                    if disk_section_data[i] != mem_section_data[i] and not list_relocs[i]:
                        if i == last_patch_position + 1:
                            current_patch['mem_bytes'] += mem_section_data[i]
                            current_patch['disk_bytes'] += disk_section_data[i]
                        else:
                            current_patch = {'offset': mem_exec_sections[idx].VirtualAddress + i , 
                                             'mem_bytes': mem_section_data[i], 
                                             'disk_bytes': disk_section_data[i] }
                            module_obj['patches'].append(current_patch)
                        last_patch_position = i
            
            # If there are patches, convert bytes to REIL
            if len(module_obj['patches']) > 0:
                for patch in module_obj['patches']:
                    patch['mem_code'] = ""
                    patch['disk_code'] = ""
                    for (address, size, mnemonic, op_str) in md.disasm_lite(patch['mem_bytes'], patch['offset']):
                        patch['mem_code'] += "{0:#x}:\t{1}\t{2}\n".format(address, mnemonic, op_str)
                    for (address, size, mnemonic, op_str) in md.disasm_lite(patch['disk_bytes'], patch['offset']):
                        patch['disk_code'] += "{0:#x}:\t{1}\t{2}\n".format(address, mnemonic, op_str))
                process_patches['modules'].append(module_obj)
            elif len(module_obj['additional_sections']) > 0:
                process_patches['modules'].append(module_obj)
        except OSError as ex:
            if ex.winerror != 299:
                print(str(ex))
    return process_patches

def print_process_patches(process_patches):
    print("Patches in PID {0}, File {1}".format(process_patches['pid'], process_patches['file']))
    for module in process_patches['modules']:
        print("Module {}".format(module['file']))
        for patch in module['patches']:
            print("Disk Code: ")
            print("{}".format(patch['disk_code']))
            print("Memory Code: ")
            print("{}".format(patch['mem_code'])
        for section in module['additional_sections']:
            print("Additional executable section: ")
            print("{}".format(section.Name))
    

def get_process_patches(process_id=None):
    processes_patches = []
    if not process_id:
        process_ids = [pid for pid in psutil.pids() if pid != 0]
    else:
        process_ids = [process_id]

    for pid in process_ids:
        try:
            process_patches = analyze_process(pid)
            if process_patches is not None and (len(process_patches['modules']) > 0 or \
                len(process_patches['additional_sections']) > 0):
                print_process_patches(process_patches)
                processes_patches.append(process_patches)
            else:
                print("No patches in process ID: {}".format(pid)
        except Exception as ex:
            print("Error analyzing process ID: {}".format(pid)
    return processes_patches

if __name__ == "__main__":
    patches = get_process_patches()
    print({}.format(patches))