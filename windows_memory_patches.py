import ctypes

import capstone
import pefile
import psutil
import winappdbg

NTDLL = ctypes.windll.ntdll
KERNEL32 = ctypes.windll.kernel32
PSAPI = ctypes.windll.psapi
IMAGE_SCN_MEM_EXECUTE = 0x20000000

# Change address size by system architecture
if winappdbg.System.bits == 64:
    PTR = ctypes.c_uint64
else:
    PTR = ctypes.c_void_p


def list_relocations(relocations, size, virtual_address):
    relocations_list = [False] * size
    for relocation in relocations:
        for relocation_entry in relocation.entries:
            addr2 = relocation_entry.rva - virtual_address
            if addr2 >= 0:
                for i in range(addr2, addr2 + ctypes.sizeof(PTR) + 1):
                    if (i + 1) < size:
                        relocations_list[i + 1] = True
    return relocations_list


def parse_relocations(proc, module_base_address, pe, data_rva, rva, size):
    data = proc.read(module_base_address + data_rva, size)
    file_offset = pe.get_offset_from_rva(data_rva)

    entries = []
    for idx in range(len(data) / 2):

        entry = pe.__unpack_data__(
            pe.__IMAGE_BASE_RELOCATION_ENTRY_format__,
            data[idx * 2:(idx + 1) * 2],
            file_offset=file_offset)

        if not entry:
            break
        word = entry.Data

        relocation_type = (word >> 12)
        relocation_offset = (word & 0x0fff)
        relocation_data = pefile.RelocationData(
            struct=entry,
            type=relocation_type,
            base_rva=rva,
            rva=relocation_offset + rva)

        if relocation_data.struct.Data > 0 and \
                (relocation_data.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW'] or
                 relocation_data.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']):
            entries.append(relocation_data)
        file_offset += entry.sizeof()

    return entries


def get_relocations(pe, proc, module_base_address):
    try:
        relocations = []
        relocation_table = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']]
        rva = relocation_table.VirtualAddress
        size = relocation_table.Size

        if size == 0:
            return []

        rlc_size = pefile.Structure(pe.__IMAGE_BASE_RELOCATION_format__).sizeof()
        end = rva + size
        while rva < end:
            try:
                rlc = pe.__unpack_data__(
                    pe.__IMAGE_BASE_RELOCATION_format__,
                    proc.read(module_base_address + rva, rlc_size),
                    file_offset=pe.get_offset_from_rva(rva))
            except pefile.PEFormatError:
                rlc = None

            if not rlc:
                break
            relocation_entries = parse_relocations(proc, module_base_address, pe, rva + rlc_size, rlc.VirtualAddress,
                                                   rlc.SizeOfBlock - rlc_size)

            relocations.append(
                pefile.BaseRelocationData(
                    struct=rlc,
                    entries=relocation_entries))

            if not rlc.SizeOfBlock:
                break
            rva += rlc.SizeOfBlock

        return relocations
    except Exception as ex:
        print(str(ex))


def analyze_process(pid):
    proc = winappdbg.Process(pid)
    process_patches = {'pid': pid, 'file': proc.get_filename(), 'modules': []}

    if proc.get_bits() != winappdbg.System.bits:
        return

    # Initialize disassembler
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    for module_base_addr in proc.get_module_bases():
        module = proc.get_module_at_address(module_base_addr)
        module_obj = {'file': module.get_filename(),
                      'base_address': module_base_addr,
                      'patches': [],
                      'additional_sections': []}

        try:
            module_data = proc.read(module_base_addr, module.get_size())
            pe_mem = pefile.PE(data=module_data, fast_load=True)
            pe_disk = pefile.PE(name=module.get_filename(), fast_load=True)

            # We assume that the section Characteristics field could have been modified at runtime, 
            # so we trust each section's Characteristics from disk, even if it's not marked as executable in memory -
            # this is since a section can be marked not executable but the pages in it marked as executable.
            disk_exec_sections = [section for section in pe_disk.sections if
                                  section.Characteristics & IMAGE_SCN_MEM_EXECUTE]
            disk_section_names = [section.Name for section in disk_exec_sections]
            mem_exec_sections = [section for section in pe_mem.sections if
                                 section.Characteristics & IMAGE_SCN_MEM_EXECUTE
                                 or section.Name in disk_section_names]

            # Sort the section lists by name for sanity checking and easier looping later on
            mem_exec_sections.sort(key=lambda s: s.Name)
            disk_exec_sections.sort(key=lambda s: s.Name)

            if not len(disk_exec_sections):
                # Module has no executable sections on disk
                continue
            elif len(mem_exec_sections) != len(disk_exec_sections) or \
                    any(mem_exec_sections[idx].Name != disk_exec_sections[idx].Name for idx in
                        range(len(mem_exec_sections))):
                # Incompatible number of executable sections, or mismatching section names.
                additional_sections = [section.Name for section in mem_exec_sections if
                                       section.Name not in disk_section_names]
                module_obj['additional_sections'].append(additional_sections)
                continue

            for idx in range(0, len(mem_exec_sections)):
                mem_section_data = proc.read(module_base_addr + mem_exec_sections[idx].VirtualAddress,
                                             mem_exec_sections[idx].Misc_VirtualSize)
                disk_section_data = disk_exec_sections[idx].get_data()[:mem_exec_sections[idx].Misc_VirtualSize]

                # Compare text sections between disk and memory
                if mem_section_data == disk_section_data:
                    continue

                # Handle a case where there is no data in disk section
                if disk_section_data == '':
                    module_obj['patches'].append({'offset': mem_exec_sections[idx].VirtualAddress,
                                                  'mem_bytes': mem_section_data,
                                                  'disk_bytes': disk_section_data})
                else:
                    relocations = get_relocations(pe_mem, proc, module_base_addr)
                    relocations_list = list_relocations(relocations, mem_exec_sections[idx].Misc_VirtualSize,
                                                        mem_exec_sections[idx].VirtualAddress)
                    last_patch_position = None
                    current_patch = None

                    for i in range(mem_exec_sections[idx].Misc_VirtualSize):
                        # Check if there's a differential between memory and disk, taking to account base relocations
                        if not relocations_list[i] and (
                                i > len(disk_section_data) - 1 or disk_section_data[i] != mem_section_data[i]):
                            curr_disk_section_byte = ''

                            if i < len(disk_section_data):
                                curr_disk_section_byte = disk_section_data[i]

                            if last_patch_position is not None and i == last_patch_position + 1:
                                current_patch['mem_bytes'] += mem_section_data[i]
                                current_patch['disk_bytes'] += curr_disk_section_byte
                            else:
                                current_patch = {'offset': mem_exec_sections[idx].VirtualAddress + i,
                                                 'mem_bytes': mem_section_data[i],
                                                 'disk_bytes': curr_disk_section_byte}
                                module_obj['patches'].append(current_patch)
                            last_patch_position = i

            # If there are patches, convert bytes to REIL
            if module_obj['patches']:
                for patch in module_obj['patches']:
                    patch['mem_code'] = ""
                    patch['disk_code'] = ""
                    for (address, size, mnemonic, op_str) in md.disasm_lite(patch['mem_bytes'], patch['offset']):
                        patch['mem_code'] += "{0:#x}:\t{1}\t{2}\n".format(address, mnemonic, op_str)
                    for (address, size, mnemonic, op_str) in md.disasm_lite(patch['disk_bytes'], patch['offset']):
                        patch['disk_code'] += "{0:#x}:\t{1}\t{2}\n".format(address, mnemonic, op_str)
                process_patches['modules'].append(module_obj)
            elif module_obj['additional_sections']:
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
            if patch['disk_code'] != '' and patch['mem_code'] != '':
                print("Disk Code: ")
                print("{}".format(patch['disk_code']))
                print("Memory Code: ")
                print("{}".format(patch['mem_code']))
        for section in module['additional_sections']:
            print("Additional executable section: ")
            print("{}".format(section.Name))


def get_process_patches(process_ids=None):
    processes_patches = []
    if not process_ids:
        process_ids = [pid for pid in psutil.pids() if pid != 0]

    for pid in process_ids:
        try:
            process_patches = analyze_process(pid)
            if process_patches is not None and len(process_patches['modules']) > 0:
                print_process_patches(process_patches)
                processes_patches.append(process_patches)
            else:
                print("No patches in process ID: {}".format(pid))
        except Exception as ex:
            print("Error analyzing process ID: {}".format(pid))
    return processes_patches


if __name__ == "__main__":
    system = winappdbg.System()
    system.request_debug_privileges()
    system.scan_processes()

    patches = get_process_patches()
