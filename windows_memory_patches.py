import win32api
import winappdbg
import pefile
from pefile import Structure
from difflib import Differ
from itertools import groupby
from ctypes import *
from ctypes.wintypes import DWORD, HMODULE, MAX_PATH, BYTE, ULONG, HANDLE, USHORT
import ctypes, psutil, threading
import win32con
from capstone import *

NTDLL = ctypes.windll.ntdll
KERNEL32 = ctypes.windll.kernel32
PSAPI = ctypes.windll.psapi

# Change address size by system architecture
if winappdbg.System.bits == 64:
    PTR = ctypes.c_uint64
else:
    PTR = ctypes.c_void_p

def list_reloc(relocations, size, virtualAddress):
    listReloc = [False] * size
    for reloc in relocations:
        for relocEntry in reloc.entries:
            addr2 = relocEntry.rva - virtualAddress
            if addr2 >= 0:
                for i in range(addr2, addr2 + sizeof(PTR) + 1):
                    if (i + 1) < size:
                        listReloc[i + 1] = True
    return listReloc

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
        print str(ex)

def analyze_process(pid):
    proc = winappdbg.Process(pid)
    process_patches = {'pid' : pid, 'file': proc.get_filename(), 'modules': [] }

    if proc.get_bits() != winappdbg.System.bits:
        return

    # Initialize disassembler
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    for module_base_addr in proc.get_module_bases():
        module = proc.get_module_at_address(module_base_addr)
        moduleObj = {'file': module.get_filename(), 'base_address': module_base_addr, 'patches' : []}

        try:
            # Get memory text section
            moduleData = proc.read(module_base_addr, module.get_size())
            pe_mem = pefile.PE(data = moduleData, fast_load = True)

            textSectionInfo_mem = [s for s in pe_mem.sections if s.Name.replace('\x00', '') == '.text']
            if len(textSectionInfo_mem) == 0:
                # Module has no .text section
                continue;
            else:
                textSectionInfo_mem = textSectionInfo_mem[0]
            textSectionData_mem = proc.read(module_base_addr + textSectionInfo_mem.VirtualAddress, textSectionInfo_mem.Misc_VirtualSize)

            # Get disk text section
            pe_disk = pefile.PE(name = module.get_filename(), fast_load = True)
            textSectionInfo_disk = [s for s in pe_disk.sections if s.Name.replace('\x00', '') == '.text']
            if len(textSectionInfo_disk) == 0:
                # Module has no .text section
                continue;
            else:
                textSectionInfo_disk = textSectionInfo_disk[0]
            textSectionData_disk = textSectionInfo_disk.get_data()[:textSectionInfo_mem.Misc_VirtualSize]

            # Compare text sections between disk and memory
            if (textSectionData_disk != textSectionData_mem):
                relocations = get_relocations(pe_mem, proc, module_base_addr)
                listReloc = list_reloc(relocations, textSectionInfo_mem.Misc_VirtualSize, textSectionInfo_mem.VirtualAddress)
                lastPatchPosition = -1
                current_patch = None

                for i in range(textSectionInfo_mem.Misc_VirtualSize):
                    # Check if there's a differential between memory and disk, taking to account base relocations
                    if textSectionData_disk[i] != textSectionData_mem[i] and not listReloc[i]:
                        if i == lastPatchPosition + 1:
                            current_patch['mem_bytes'] += textSectionData_mem[i]
                            current_patch['disk_bytes'] += textSectionData_mem[i]
                        else:
                            current_patch = {'offset': textSectionInfo_mem.VirtualAddress + i , 
                                             'mem_bytes': textSectionData_mem[i], 
                                             'disk_bytes': textSectionData_disk[i] }
                            moduleObj['patches'].append(current_patch)
                        lastPatchPosition = i
            
            # If there are patches, convert bytes to REIL
            if len(moduleObj['patches']) > 0:
                for patch in moduleObj['patches']:
                    patch['mem_code'] = ""
                    patch['disk_code'] = ""
                    for (address, size, mnemonic, op_str) in md.disasm_lite(patch['mem_bytes'], patch['offset']):
                        patch['mem_code'] += "0x%x:\t%s\t%s" % (address, mnemonic, op_str) + "\n"
                    for (address, size, mnemonic, op_str) in md.disasm_lite(patch['disk_bytes'], patch['offset']):
                        patch['disk_code'] += "0x%x:\t%s\t%s" % (address, mnemonic, op_str) + "\n"
                process_patches['modules'].append(moduleObj)

        except OSError as ex:
            if ex.winerror != 299:
                print str(ex)
    return process_patches

def print_process_patches(process_patches):
    print "Patches in PID %s, File %s" % (process_patches['pid'], process_patches['file'])
    for module in process_patches['modules']:
        print "Module %s" % module['file']
        for patch in module['patches']:
            print "Disk Code: "
            print patch['disk_code']
            print "Memory Code: "
            print patch['mem_code']
    

def get_process_patches(process_id=None):
    processes_patches = []
    if not process_id:
        process_ids = [pid for pid in psutil.pids() if pid != 0]
    else:
        process_ids = [process_id]

    for pid in process_ids:
        try:
            process_patches = analyze_process(pid)
            if process_patches != None and len(process_patches['modules']) > 0:
                print_process_patches(process_patches)
                processes_patches.append(process_patches)
            else:
                print "No patches in process ID: %s" % pid
        except Exception as ex:
            print "Error analyzing process ID: %s" % pid
    return processes_patches

if __name__ == "__main__":
    patches = get_process_patches()
    print patches