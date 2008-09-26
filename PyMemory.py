#!/usr/bin/env python

########################################################################
#
# PyEmu: scriptable x86 emulator
#
# Cody Pierce - cpierce@tippingpoint.com - 2007
#
# License: None
#
########################################################################

import struct, sys, string

'''
PyMemoryPage:

    A class that allows us to define some properties and methods for each
    page of memory in our cache.  This could be used to further define
    permissions and attributes as needed
'''
class PyMemoryPage:
    DEBUG = 0
    PAGESIZE = 4096
    
    READ = 0x1
    WRITE = 0x2
    EXECUTE = 0x4
    
    def __init__(self, address, data="", permissions=0x0):
        self.address = address
        self.data = data
        self.permissions = permissions
        
    def get_data(self):
        return self.data
    
    def get_permissions(self):
        return self.permissions
    
    def set_data(self, data):
        self.data = data
    
    def set_permissions(self, permissions):
        self.permissions = permissions
    
    def set_debug(self, level):
        self.DEBUG = level
            
    def set_r(self):
        self.permissions |= self.READ
    
    def set_w(self):
        self.permissions |= self.WRITE
        
    def set_x(self):
        self.permissions |= self.EXECUTE
    
    def set_rw(self):
        self.permissions |= self.READ
        self.permissions |= self.WRITE
    
    def set_rx(self):
        self.permissions |= self.READ
        self.permissions |= self.EXECUTE
        
    def set_rwx(self):
        self.permissions |= self.READ
        self.permissions |= self.WRITE
        self.permissions |= self.EXECUTE
        
    def is_r(self):
        return self.permissions & self.READ
    
    def is_w(self):
        return self.permissions & self.WRITE
    
    def is_x(self):
        return self.permissions & self.WRITE
    
    def is_rx(self):
        if (self.permissions & self.READ) and (self.permissions & self.EXECUTE):
            return True
        else:
            return False
    
    def is_rwx(self):
        if (self.permissions & self.READ) and (self.permissions & self.WRITE) and (self.permissions & self.EXECUTE):
            return True
        else:
            return False
        
'''
PyMemory:
    
    The base class for handling memory requests from the PyCPU and PyEmu.
    This class should be extended by any custom memory managers.
'''
class PyMemory:
    DEBUG = 0
    PAGESIZE = 4096
    
    def __init__(self, emu):
        self.emu = emu
        self.pages = {}
        self.fault = True
    
    def __get_memory_pages(self, address, size):
        rawbytes = ""
        
        page = address & 0xfffff000
        offset = address & 0x00000fff
        
        (d, m) = divmod(size, self.PAGESIZE)
        print d, m
        
        #pages = range(page, page + (d * self.PAGESIZE) + m, self.PAGESIZE)
        pages = range(page, page + (d * self.PAGESIZE), self.PAGESIZE)
        for page in pages:
            print "%08x" % page
            if page not in self.pages:
                print "[!] 0x%08x not in our pages" % page
                raise Exception('dumb')
            
            for b in range(self.PAGESIZE - 1):
                rawbytes += self.pages[page].data[b]
        
        if m:
            page = (address + size) & 0xfffff000
            print "*%08x" % page
            if page not in self.pages:
                    print "[!] 0x%08x not in our pages" % page
                    raise Exception('dumb')
                    
            for b in range(m):
                rawbytes += self.pages[page].data[b]
        
        return rawbytes
    #
    # get_memory: Fetches memory first checking local cache, then
    #             calling the child memory allocator
    #
    def get_memory(self, address, size):
        page = address & 0xfffff000
        offset = address & 0x00000fff
        
        if self.DEBUG >= 2:
            print "[*] Trying to get memory @ %x" % (address)
        
        if size > self.PAGESIZE:
            print "[*] Trying to fetch across pages"
            return self.__get_memory_pages(address, size)
            
        # Check our cache and fetch if not found
        if page in self.pages:
            # Return from our cache
            rawbytes = ""
            for x in xrange(0, size):
                if (page + offset + x) >= (page + self.PAGESIZE):
                    newpage = (page + offset + x) & 0xfffff000
                    if newpage not in self.pages:
                        if not self.get_page(newpage):
                            print "[!] Invalid memory"
                            
                            return self.emu.raise_exception("GP", page + offset + x)
                        else:
                            page = newpage
                            offset = 0x00000000
                            
                            for y in xrange(0, size - x):
                                rawbytes += self.pages[page].data[offset+y]
                            
                            break
                    else:
                        page = newpage
                        offset = 0x00000000
                        
                        for y in xrange(0, size - x):
                            try:
                                rawbytes += self.pages[page].data[offset+y]
                            except:
                                print "size %x, %x, %x" % (size, x, size - x)
                                print "raw %x" % len(rawbytes)
                                val = list(self.pages.keys())
                                val.sort()
                                for key in val:
                                    #print "0x%08x (%x)" % (key, len(self.pages[key].data))
                                    print "0x%08x" % key
                                print "problem %x, %x, %x" % (page, offset, y)
                                raise Exception("blah")
                                #rawbytes = self.pages[0x13000].data[0x1000]
                                #return rawbytes
                        
                        break
                        
                rawbytes += self.pages[page].data[offset+x]
            
            if size == 1:
                return struct.unpack("<B", rawbytes)[0]
            elif size == 2:
                return struct.unpack("<H", rawbytes)[0]
            elif size == 4:
                return struct.unpack("<L", rawbytes)[0]
            else:
                return rawbytes
        else:
            if self.DEBUG >= 2:
                print "[*] Couldnt find page %x fetching" % (page)
                
            # We need to fetch this
            if not self.get_page(page):
                print "[!] Invalid memory"
                
                return self.emu.raise_exception("GP", address)
            else:
                rawbytes = ""
                for x in xrange(0, size):
                    if (page + offset + x) >= (page + self.PAGESIZE):
                        newpage = (page + offset + x) & 0xfffff000
                        if newpage not in self.pages:
                            if not self.get_page(newpage):
                                print "[!] Invalid memory"
                                
                                return self.emu.raise_exception("GP", page + offset + x)
                            else:
                                page = newpage
                                offset = 0x00000000
                                
                                for y in xrange(0, size - x):
                                    rawbytes += self.pages[page].data[offset+y]
                                
                                break
                        else:
                            page = newpage
                            offset = 0x00000000
                            
                            for y in xrange(0, size - x):
                                rawbytes += self.pages[page].data[offset+y]
                            
                            break
                            
                    rawbytes += self.pages[page].data[offset+x]
                
                if size == 1:
                    return struct.unpack("<B", rawbytes)[0]
                elif size == 2:
                    return struct.unpack("<H", rawbytes)[0]
                elif size == 4:
                    return struct.unpack("<L", rawbytes)[0]
                else:
                    return rawbytes
                        
        return False
    
    #
    # set_memory: Set an address to a specific value.  This can be a
    #             integer or string.
    #
    def set_memory(self, address, value, size):
        page = address & 0xfffff000
        offset = address & 0x00000fff
        
        if self.DEBUG > 2:
            print "[*] Trying to set memory @ %x value %x size %d" % (address, value, size)
            
        if isinstance(value, int) or isinstance(value, long):
            if size == 1:
                packedvalue = struct.pack("<B", int(value))
            elif size == 2:
                packedvalue = struct.pack("<H", int(value))
            elif size == 4:
                packedvalue = struct.pack("<L", int(value))
            else:
                print "[!] Couldnt pack new value of size %d" % (size)
                
                return False
        elif isinstance(value, str):
            # We need to pack the values into native endian
            packedvalue = value[::-1]
        else:
            print "[!] Dont understand this value type %s" % type(value)
            
            return False
            
        # Check our page if not fetch
        if page in self.pages:
            newdata = self.pages[page].data[:offset]
            for x in xrange(0, size):
                newdata += packedvalue[x]
            newdata += self.pages[page].data[offset + size:]
            
            self.pages[page].set_data(newdata)
            
            return True
        else:
            # We need to fetch this
            if not self.get_page(page):
                print "[!] Invalid memory"
                
                return self.emu.raise_exception("GP", address)
            else:
                newdata = self.pages[page].data[:offset]
                for x in xrange(0, size):
                    newdata += packedvalue[x]
                newdata += self.pages[page].data[offset + size:]
                
                self.pages[page].set_data(newdata)
                
                return True
            
        return False
    
    #
    # is_valid: A helper function to check for a address in our cache
    #
    def is_valid(self, address):
        page = address & 0xfffff000
        
        if page not in self.pages:
            return False
        else:
            return True
            
    def get_page(self, page):
        print "[*] We dont know, this should be overloaded"
        
        return False
    
    def set_debug(self, level):
        self.DEBUG = level
    
    #
    # dump_pages: This will dump all the currently cached memory pages.
    #             This could potentially be a lot of data.
    #  
    def dump_pages(self, data=False):
        for addr in self.pages.keys():
            if data:
                print "[*] 0x%08x: size [%d] data [%s]" % (addr, len(self.pages[addr]), repr(self.pages[addr]))
            else:
                print "[*] 0x%08x: size [%d]" % (addr, len(self.pages[addr].data))
                
        return True

'''
PyDbgMemory:

    This is the pydbg memory manager.  It extends the base PyMemory class
    This is responsible for nothing more than handling requests for
    memory if needed.  In this case a fetch of unknown memory will make a
    call to ReadProcessMemory via the dbg instance.
'''
class PyDbgMemory(PyMemory):
    def __init__(self, emu, dbg):
        self.dbg = dbg
        
        PyMemory.__init__(self, emu)
   
    #
    # allocate_page: Allocates a page for addition into the cache
    # 
    def allocate_page(self, page):
        newpage = PyMemoryPage(page)
        newpage.set_data("A" * newpage.PAGESIZE)
        newpage.set_rwx()
        
        self.pages[page] = newpage
        
        return True
        
    #
    # get_page: This fetches the page from pydbg
    #
    def get_page(self, page):
        try:
            newpagedata = self.dbg.read_process_memory(page, self.PAGESIZE)
        except:
            print "[!] Couldnt read mem page @ 0x%08x" % page
            
            return False
        
        newpage = PyMemoryPage(page)
        newpage.set_data(newpagedata)
        newpage.set_rwx()
        
        self.pages[page] = newpage
        
        return True

'''
IDAMemory:

    This is the ida memory manager. It extends the base PyMemory class
    and is responsible for handling any unknown memory requests.  In IDA
    this is a tricky call cause we can either throw an exception on invalid
    memory accesses or go ahead and fulfill them in case the user did not
    set everything up properly.  Its really a personal choice.
'''
class IDAMemory(PyMemory):
    def __init__(self, emu):
        PyMemory.__init__(self, emu)
    
    #
    # allocate_page: Allocates a page for addition into the cache
    #
    def allocate_page(self, page):
        newpage = PyMemoryPage(page)
        newpage.set_data("A" * newpage.PAGESIZE)
        newpage.set_rwx()
        
        self.pages[page] = newpage
        
        return True
        
    #
    # get_page: Handles unknown memory requests from the base class.
    #           This is where we return memory (or throw an exception)
    #
    def get_page(self, page):
        if self.fault:
            return False
            
        # Grab a new page object
        return self.allocate_page(page)

'''
PEMemory:

    This is the raw PE file memory handler that is responsible for handling
    requests from the base class.  Like the others it requests memory when
    needed.
'''
class PEMemory(PyMemory):
    def __init__(self, emu):
        PyMemory.__init__(self, emu)

    #
    # allocate_page: Allocates a page for addition into the cache
    #
    def allocate_page(self, page):
        newpage = PyMemoryPage(page)
        newpage.set_data("A" * newpage.PAGESIZE)
        newpage.set_rwx()
        
        self.pages[page] = newpage
        
        return True
    #
    # get_page: Stores a page in the base class cache
    #
    def get_page(self, page):
        if self.fault:
            return False
            
        # Grab a new page object
        return self.allocate_page(page)