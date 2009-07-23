#!/usr/bin/env python

import sys

sys.path.append(r'c:\code\python\public\pyemu')
sys.path.append(r'c:\code\python\public\pyemu\lib')

import pydasm

from PyCPU import *
from PyDebug import *
from PyEmu import PEPyEmu

rawinstruction = "\x66\x89\x45\xF6"
instruction = pydasm.get_instruction(rawinstruction, pydasm.MODE_32)
pyinstruction = PyInstruction(instruction)
disasm = pydasm.get_instruction_string(instruction, pydasm.FORMAT_INTEL, 0).rstrip(" ")

#DebugInstruction(pyinstruction)

emu = PEPyEmu()
emu.cpu.set_debug(1)
emu.set_register("EDX", 0xfe)

print "EAX: 0x%08x EDX: 0x%08x" % (emu.cpu.EAX, emu.cpu.EDX)
print "Executing [%s]..." % disasm,

# An oversight in pydasm mnemonic parsing
pyinstruction.mnemonic = pyinstruction.mnemonic.split()
if pyinstruction.mnemonic[0] in ["rep", "repe", "repne", "lock"]:
    pyinstruction.mnemonic = pyinstruction.mnemonic[1]
else:
    pyinstruction.mnemonic = pyinstruction.mnemonic[0]

# Check if we support this instruction
if pyinstruction.mnemonic in emu.cpu.supported_instructions:
    # Execute!
    if not emu.cpu.supported_instructions[pyinstruction.mnemonic](pyinstruction):
        sys.exit(-1)
else:
    print "[!] Unsupported instruction %s" % pyinstruction.mnemonic
    sys.exit(-1)
    
print "Done"
print "EAX: 0x%08x EDX: 0x%08x" % (emu.cpu.EAX, emu.cpu.EDX)
