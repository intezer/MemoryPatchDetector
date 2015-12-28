# Memory Patch Detector
Detects code differentials between executables in disk and the corresponding processes/modules in memory

## Requirements
    pip install ctypes
    pip install winappdbg
    pip install pywin32
    pip install pypiwin32
    pip install pefile
    pip install capstone

## Usage
    python windows_memory_patches.py
    
## Notes
    The script needs Administrator/SYSTEM privileges in order to analyze all the processes in memory.
    At the moment, it doesn't check WoW64 processes at all.