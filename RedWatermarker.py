#!/usr/bin/python3
#
# Author:
#     Mariusz Banach / mgeeky '22, (@mariuszbit)
#     <mb@binary-offensive.com>
#
# Requirements:
#   - pefile
#   - yara-python
#

import os, re, sys
import string
import shutil
import tempfile
import argparse

import pefile
import yara

options = {
    'debug' : False,
    'verbose' : False,
    'check' : False,
    'dos_stub' : '',
    'checksum' : 0,
    'overlay' : '',
    'section' : '',
}

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

    def verbose(txt):
        if options['verbose']:
            print('[>] ' + txt)

    def dbg(txt):
        if options['debug']:
            print('[dbg] ' + txt)

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

class PeWatermarker:
    SupportedVersionFields = {
        'CompanyName',
        'FileDescription',
        'FileVersion',
        'InternalName',
        'OriginalFileName',
        'ProductName',
        'ProductVersion',
    }

    def __init__(self, options, logger, infile, outfile):
        self.options = options
        self.pe = None
        self.logger = logger
        self.infile = infile
        self.outfile = outfile

    def openFile(self):
        self.pe = pefile.PE(self.infile, fast_load=False)

    def watermark(self):
        try:
            modified = False
            self.openFile()

            #
            # do not change order of below methods
            #

            modified |= self.checksum()
            modified |= self.dosStub()
            modified |= self.section(modified)

            # overlay needs to be the last one
            modified |= self.overlay(modified)

            if modified:
                Logger.dbg('Saving modified PE file...')
                self.pe.write(self.outfile)

            elif not self.options['check']:
                Logger.dbg('File was not modified in any way.')

            return True

        except pefile.PEFormatError:
            Logger.warn('Input file is not a valid PE file.')
            return False

        except Exception as e:
            raise

        finally:
            self.pe.close()

    def checkIt(self, where, rule_name, watermark):
        if type(watermark) == bytes:
            watermark = watermark.decode()

        ruleContent = f'''
            rule {rule_name} 
            {{  
                strings:
                    $str1 = "{watermark}"

                condition:
                    $str1
            }}
        '''

        Logger.dbg(f'Matching against YARA rule:\n{ruleContent}\n')

        rule = yara.compile(source = ruleContent)
        matches = rule.match(data = self.pe.__data__)

        if len(matches) > 0:
            Logger.ok(f'File contains watermark in {where}.')
            return True

        else:
            Logger.err(f'File did not contain watermark in {where}.')
            return False

    def section(self, modified):
        if len(self.options['section']) > 0:
            name, marker = self.options['section'].split(',')

            if self.options['check']:
                self.checkIt('PE section', 'watermark_in_pe_section', marker)
                return False

            Logger.dbg('Appending new PE section.')

            if modified:
                self.pe.write(self.outfile)
            self.pe.close()

            out = self.addNewPESection(self.outfile, name, marker.encode())

            with open(self.outfile, 'rb') as f:
                self.pe = pefile.PE(data = f.read(), fast_load = False)

            return out

        return False

    def dosStub(self):
        if len(self.options['dos_stub']) > 0:
            dosMarker = self.options['dos_stub'].encode()

            if self.options['check']:
                self.checkIt('DOS Stub', 'watermark_in_dos_stub', dosMarker)
                return False

            elfanew = self.pe.DOS_HEADER.e_lfanew
            a = self.pe.DOS_HEADER.sizeof()
            b = elfanew

            currentDosStub = self.pe.__data__[a:b]

            if len(dosMarker) >= len(currentDosStub):
                Logger.err(f'Provided --dos-stub is too long. Must not be longer than {len(currentDosStub)} characters!')
                return False

            if currentDosStub.startswith(dosMarker):
                Logger.info('Watermark already injected to DOS Stub. Skipping it...')
                return False

            currentDosStub = dosMarker + currentDosStub[len(dosMarker):]

            self.pe.set_bytes_at_offset(a, dosMarker)

            Logger.ok('Injected watermark to PE DOS stub.')

            return True

        return False

    def checksum(self):
        if self.options['checksum'] != 0:
            if self.options['check']:
                if self.pe.OPTIONAL_HEADER.CheckSum == self.options['checksum']:
                    Logger.ok('File contained watermark in Checksum field.')
                else:
                    Logger.err('File did not contain watermark in Checksum field.')

                return False

            Logger.ok(f'Setting PE checksum to {self.options["checksum"]} (0x{self.options["checksum"]:x})')
            self.pe.OPTIONAL_HEADER.CheckSum = int((self.options['checksum']) & 0xffffffff)

            return True

        return False

    def overlay(self, modified):
        if self.options['overlay']:
            watermark = self.options['overlay'].encode()

            overlay = self.pe.get_overlay()

            if self.options['check']:
                self.checkIt('Overlay', 'watermark_in_overlay', watermark)
                return False

            if overlay is not None and watermark in overlay:
                Logger.err('Watermark already present in PE file overlay. Skipping overlay watermarking...')
                return False

            else:
                Logger.ok('Appended watermark to PE overlay.')

                if modified:
                    self.pe.write(self.outfile)
                self.pe.close()

                with open(self.outfile, 'ab') as f:
                    f.write(watermark)

                with open(self.outfile, 'rb') as f:
                    self.pe = pefile.PE(data = f.read(), fast_load = False)

                return True

        return False

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
                Logger.info('File already contained injected PE section. Overriding it...')
                sections.pop_back()
                pe.write(filename)

            return True

        except Exception as e:
            Logger.err(f'Could not remove PE section! Error: {e}')
            return False

        finally:
            if pe:
                pe.close()

    def addNewPESection(self, filename, sectName, sectionData):    
        Logger.info('Adjusting resulted PE file headers to insert additional PE section') 

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
                Characteristics = 0x40000040, 
                Data = sectionData
            )

            pe.write(filename)

            Logger.ok(f'New section named "{sectName}" added.')
            return True

        except SectionDoublePError as e:
            Logger.err('Exception occured while injecting a new PE section: ' + str(e))
            return False

        except Exception as e:
            Logger.err(f'Could not append PE section! Error: {e}')
            return False

        finally:
            if pe:
                pe.close()

def opts(argv):
    global options

    o = argparse.ArgumentParser(
        usage = 'RedWatermarker.py [options] <infile>'
    )
    
    req = o.add_argument_group('Required arguments')
    req.add_argument('infile', help = 'Input implant file')
    
    opt = o.add_argument_group('Optional arguments')
    opt.add_argument('-C', '--check', action='store_true', help = 'Do not actually inject watermark. Check input file if it contains specified watermarks.')
    opt.add_argument('-v', '--verbose', action='store_true', help = 'Verbose mode.')
    opt.add_argument('-d', '--debug', action='store_true', help = 'Debug mode.')
    opt.add_argument('-o', '--outfile', metavar='PATH', default='', help = 'Path where to save output file with watermark injected. If not given, will modify infile.')

    exe = o.add_argument_group('PE Executables Watermarking')
    exe.add_argument('-t', '--dos-stub', default='', metavar='STR', help = 'Insert watermark into PE DOS Stub (This program cannot be run...).')
    exe.add_argument('-c', '--checksum', default=0, metavar='NUM', help = 'Preset PE checksum with this value (4 bytes). Must be number. Can start with 0x for hex value.')
    exe.add_argument('-e', '--overlay',  default='', metavar='STR', help = 'Append watermark to the file\'s Overlay (at the end of the file).')
    exe.add_argument('-s', '--section',  default='', metavar='NAME,STR', help = 'Append a new PE section named NAME and insert watermark there. Section name must be shorter than 8 characters. Section will be marked Read-Only, non-executable.')

    args = o.parse_args()
    options.update(vars(args))

    if args.checksum != 0:
        try:
            base = 10
            args.checksum = args.checksum.lower()

            if args.checksum.startswith('0x') or \
                'a' in args.checksum or 'b' in args.checksum or 'c' in args.checksum or \
                'd' in args.checksum or 'e' in args.checksum or 'f' in args.checksum:
                base = 16

            num = int(args.checksum, base)

            if num >= 2**32:
                Logger.fatal('Specified checksum number is too large! Must be no bigger than 2^32-1 (0xffffffff)!')

            options['checksum'] = num

        except Exception as e:
            Logger.fatal('Invalid --checksum value, could not be casted to integer!')

    if len(args.section) > 0:
        if ',' not in args.section:
            Logger.fatal('Invalid --section value, needs to be NAME,STR where NAME is a section name. Example: .foobar,injected-marker')

        name, marker = args.section.split(',')
        if len(name) > 7:
            Logger.fatal('Section name must not be long than 7 characters!')

    return args

def main(argv):
    
    try:
        print('''
                      ;                                                                                                               
                      ED.                                                                                                             
                     ,E#Wi                                                                                                            
  j.               f#iE###G.                                                                                                          
  EW,            .E#t E#fD#W;                                                                                                         
  E##j          i#W,  E#t t##L                                                                                                        
  E###D.       L#D.   E#t  .E#K,                                                                                                      
  E#jG#W;    :K#Wfff; E#t    j##f                                                                                                     
  E#t t##f   i##WLLLLtE#t    :E#K:                                                                                                    
  E#t  :K#E:  .E#L    E#t   t##L                                                                                                      
  E#KDDDD###i   f#E:  E#t .D#W;                  ,;                                                      G:              ,;           
  E#f,t#Wi,,,    ,WW; E#tiW#G.                 f#i j.                                          j.        E#,    :      f#i j.         
  E#t  ;#W: ;     .D#;E#K##i .. GEEEEEEEL    .E#t  EW,                 ..       :           .. EW,       E#t  .GE    .E#t  EW,        
  DWi   ,K.DL       ttE##D. ;W, ,;;L#K;;.   i#W,   E##j               ,W,     .Et          ;W, E##j      E#t j#K;   i#W,   E##j       
  f.     :K#L     LWL E#t  j##,    t#E     L#D.    E###D.            t##,    ,W#t         j##, E###D.    E#GK#f    L#D.    E###D.     
  EW:   ;W##L   .E#f  L:  G###,    t#E   :K#Wfff;  E#jG#W;          L###,   j###t        G###, E#jG#W;   E##D.   :K#Wfff;  E#jG#W;    
  E#t  t#KE#L  ,W#;     :E####,    t#E   i##WLLLLt E#t t##f       .E#j##,  G#fE#t      :E####, E#t t##f  E##Wi   i##WLLLLt E#t t##f   
  E#t f#D.L#L t#K:     ;W#DG##,    t#E    .E#L     E#t  :K#E:    ;WW; ##,:K#i E#t     ;W#DG##, E#t  :K#E:E#jL#D:  .E#L     E#t  :K#E: 
  E#jG#f  L#LL#G      j###DW##,    t#E      f#E:   E#KDDDD###i  j#E.  ##f#W,  E#t    j###DW##, E#KDDDD###E#t ,K#j   f#E:   E#KDDDD###i
  E###;   L###j      G##i,,G##,    t#E       ,WW;  E#f,t#Wi,,,.D#L    ###K:   E#t   G##i,,G##, E#f,t#Wi,,E#t   jD    ,WW;  E#f,t#Wi,,,
  E#K:    L#W;     :K#K:   L##,    t#E        .D#; E#t  ;#W: :K#t     ##D.    E#t :K#K:   L##, E#t  ;#W: j#t          .D#; E#t  ;#W:  
  EG      LE.     ;##D.    L##,     fE          tt DWi   ,KK:...      #G      .. ;##D.    L##, DWi   ,KK: ,;            tt DWi   ,KK: 
  ;       ;@      ,,,      .,,       :                                j          ,,,      .,,                                         
                                                                                                                                      
''')
    except:
        print('''

    :: RedWatermarker
''')

    print(r'''    Watermark thy implants, track them in VirusTotal
    Mariusz Banach / mgeeky '22, (@mariuszbit)
    <mb@binary-offensive.com>
''')

    args = opts(argv)
    if not args:
        return False

    outfile = ''
    temp = None

    if not options['check']:
        if len(args.outfile) > 0:
            outfile = args.outfile

        else:
            temp = tempfile.NamedTemporaryFile(delete=False)
            shutil.copy(args.infile, temp.name)
            outfile = temp.name
            Logger.dbg(f'Outfile is a temporary file: {outfile}')

    pewat = PeWatermarker(options, Logger, args.infile, outfile)
    result = pewat.watermark()

    if result and not options['check']:
        if len(args.outfile) > 0:
            Logger.ok(f'Watermarked file saved to: {args.outfile}')
        else:
            shutil.copy(outfile, args.infile)
            Logger.ok(f'Watermarked file in place.')

    if temp and not options['check']:
        Logger.dbg('Removing temporary file...')
        temp.close()
        os.unlink(temp.name)

if __name__ == '__main__':
    main(sys.argv)
