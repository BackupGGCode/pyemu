#!/usr/bin/env python

import sys, os, time, struct, re, string

# !!! set your pyemu path plz2u !!!
sys.path.append(r'C:\Code\Python\public\pyemu')
sys.path.append(r'C:\Code\Python\public\pyemu\lib')

from PyEmu import *

def my_memory_access_handler(emu, address, value, size, type):
    print "[*] Hit my_memory_access_handler %x: %s (%x, %x, %x, %s)" % (emu.get_register("EIP"), emu.get_disasm(), address, value, size, type)
    
    return True

emu = IDAPyEmu()

textstart = SegByName(".text")
textend = SegEnd(textstart)

print "[*] Loading text section bytes into memory"

currenttext = textstart
while currenttext <= textend:
    emu.set_memory(currenttext, GetOriginalByte(currenttext), size=1)
    currenttext += 1

print "[*] Text section loaded into memory"

datastart = SegByName(".data")
dataend = SegEnd(datastart)

print "[*] Loading data section bytes into memory"

currentdata = datastart
while currentdata <= dataend:
    emu.set_memory(currentdata, GetOriginalByte(currentdata), size=1)
    currentdata += 1

print "[*] Data section loaded into memory"

print "[*] Loading import section bytes into memory"
importstart = SegByName(".idata")
importend = SegEnd(importstart)

currentimport = importstart
fakeaddress = 0x70000000
while currentimport <= importend:
    importname = Name(currentimport)
    
    emu.os.add_fake_library(importname, fakeaddress)
    emu.set_memory(currentimport, fakeaddress, size=4)
    
    currentimport += 4
    fakeaddress += 4

print "[*] Import section loaded into memory"

def getmodulehandlea(name, address):
    print "boooyeah"
    
    return False
    
# Start the program counter at the current location in the disassembly window
emu.set_register("EIP", ScreenEA())

# Set up our memory access handler
emu.set_memory_access_handler(my_memory_access_handler)

# Set our library handler
emu.set_library_handler("_imp__GetModuleHandleA", getmodulehandlea)
emu.set_register("EIP", 0x01012475)
emu.debug(1)

while emu.get_register("EIP") != 0x01012491:
    emu.dump_regs()
    if not emu.execute():
        print "[!] Problem executing"
        break

print "[*] Done"