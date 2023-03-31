#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import string
import pefile


class PackerUpx(IPacker):
    default_upx_args = ''
    upx_cmdline_template = '<command> <options> -o <outfile> <infile>'

    metadata = {
        'author': ['Markus F.X.J. Oberhumer', 'László Molnár', 'John F. Reiser.'],
        'url': 'https://upx.github.io',
        'licensing': 'open-source',
        'description': 'Universal PE Executables Compressor - highly reliable, works with x86 & x64',
        'type': PackerType.PECompressor,
        'input': ['PE', ],
        'output': ['PE', ],
    }

    default_options = {
        'upx_compress': '',
        'upx_corrupt': 1,
    }

    def __init__(self, logger, options):
        self.upx_args = PackerUpx.default_upx_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'UPX'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--upx-path', metavar='PATH', dest='upx_path',
                                help='(required) Path to UPX binary capable of compressing x86/x64 executables.')

            parser.add_argument('--upx-compress', metavar='LEVEL', dest='upx_compress', default='',
                                help='Compression level [1-9]: 1 - compress faster, 9 - compress better. Can also be "best" for greatest compression level possible.')

            parser.add_argument('--upx-corrupt', metavar='bool', type=int, choices=range(0, 2), default=1,
                                dest='upx_corrupt', help='If set to 1 enables UPX metadata corruption to prevent "upx -d" unpacking. This corruption won\'t affect executable\'s ability to launch. Default: enabled (1)')

            parser.add_argument('--upx-args', metavar='ARGS', dest='upx_args',
                                help='Optional UPX-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['upx_path'] = configPath( self.options['upx_path'])

            if not os.path.isfile(self.options['upx_path']):
                self.logger.fatal('--upx-path option must be specified!')

            for k, v in PackerUpx.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            try:
                level = self.options['upx_compress']

                if level == '':
                    self.upx_args += ' '
                elif level == 'best':
                    self.upx_args += ' --best'
                else:
                    level = int(self.options['upx_compress'])

                    if level < 1 or level > 9:
                        raise ValueError

                    self.upx_args += ' -{}'.format(level)

            except ValueError:
                self.logger.fatal(
                    '--upx-compress level must be <1-9> or "best"!')

            if 'upx_args' in self.options.keys() and self.options['upx_args'] != None \
                    and len(self.options['upx_args']) > 0:
                self.upx_args += ' ' + self.options['upx_args']

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        ver = shell(
            self.logger, self.options['upx_path'] + ' --version').split('\n')[0].strip()

        self.logger.info(f'Working with {ver}')
        out = ''

        try:
            out = shell(self.logger, IPacker.build_cmdline(
                PackerUpx.upx_cmdline_template,
                self.options['upx_path'],
                self.upx_args,
                infile,
                outfile
            ), output=self.options['verbose'] or self.options['debug'], timeout=self.options['timeout'])

            if os.path.isfile(outfile):
                if self.options['upx_corrupt'] == 1:
                    return self.tamper(outfile)
                else:
                    return True
            else:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    outfile
                ))

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                    self.logger.info(f'''{PackerUpx.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from packer:
----------------------------------------
{e}
----------------------------------------
''')

        except Exception as e:
            raise

        return False

    def tamper(self, outfile):
        self.logger.info(
            f'Corrupting output UPX artifact so that decompression won\'t be easy...')

        pe = None
        try:
            pe = pefile.PE(outfile)

            newSectionNames = (
                '.text',
                '.data',
                '.rdata',
                '.idata',
                '.pdata',
            )

            num = 0
            sectnum = 0

            section_table_offset = (pe.DOS_HEADER.e_lfanew + 4 +
                                    pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader)

            self.logger.info('Step 1. Rename UPX sections...')
            for sect in pe.sections:
                section_offset = section_table_offset + sectnum * 0x28
                sectnum += 1

                if sect.Name.decode().lower().startswith('upx'):
                    newname = newSectionNames[num].encode(
                    ) + ((8 - len(newSectionNames[num])) * b'\x00')
                    self.logger.dbg('\tRenamed UPX section ({}) => ({})'.format(
                        sect.Name.decode(), newSectionNames[num]
                    ))
                    num += 1
                    pe.set_bytes_at_offset(section_offset, newname)

            self.logger.info('Step 2. Removing obvious indicators...')
            pos = pe.__data__.find(b'UPX!')
            if pos != -1:
                self.logger.dbg(
                    '\tRemoved "UPX!" (UPX_MAGIC_LE32) magic value...')
                pe.set_bytes_at_offset(pos, b'\x00' * 4)

                prev = pe.__data__[pos-5:pos-1]
                if all(chr(c) in string.printable for c in prev):
                    self.logger.dbg(
                        '\tRemoved "{}" indicator...'.format(prev.decode()))
                    pe.set_bytes_at_offset(pos-5, b'\x00' * 4)

                self.logger.info('Step 3. Corrupting PackHeader...')

                version = pe.__data__[pos + 4]
                _format = pe.__data__[pos + 5]
                method = pe.__data__[pos + 6]
                level = pe.__data__[pos + 7]

                self.logger.dbg('\tOverwriting metadata (version={}, format={}, method={}, level={})...'.format(
                    version, _format, method, level
                ))

                pe.set_bytes_at_offset(pos + 4, b'\x00')
                pe.set_bytes_at_offset(pos + 5, b'\x00')
                pe.set_bytes_at_offset(pos + 6, b'\x00')
                pe.set_bytes_at_offset(pos + 7, b'\x00')

                #
                # Src:
                #   https://github.com/upx/upx/blob/36670251fdbbf72f6ce165148875d369cae8f415/src/packhead.cpp#L187
                #   https://github.com/upx/upx/blob/36670251fdbbf72f6ce165148875d369cae8f415/src/stub/src/include/header.S#L33
                #
                u_adler = pe.get_dword_from_data(pe.__data__, pos + 8)
                c_adler = pe.get_dword_from_data(pe.__data__, pos + 12)
                u_len = pe.get_dword_from_data(pe.__data__, pos + 16)
                c_len = pe.get_dword_from_data(pe.__data__, pos + 20)
                origsize = pe.get_dword_from_data(pe.__data__, pos + 24)
                filter_id = pe.__data__[pos + 28]
                filter_cto = pe.__data__[pos + 29]
                unused = pe.__data__[pos + 30]
                header_chksum = pe.__data__[pos + 31]

                self.logger.dbg('\tCorrupting stored lengths and sizes:')

                self.logger.dbg(
                    '\t\t- uncompressed_adler (u_adler): ({} / 0x{:x}) => (0)'.format(u_adler, u_adler))
                pe.set_dword_at_offset(pos + 8, 0)
                self.logger.dbg(
                    '\t\t- compressed_adler (c_adler): ({} / 0x{:x}) => (0)'.format(c_adler, c_adler))
                pe.set_dword_at_offset(pos + 12, 0)
                self.logger.dbg(
                    '\t\t- uncompressed_len (u_len): ({} / 0x{:x}) => (0)'.format(u_len, u_len))
                pe.set_dword_at_offset(pos + 16, 0)
                self.logger.dbg(
                    '\t\t- compressed_len (c_len): ({} / 0x{:x}) => (0)'.format(c_len, c_len))
                pe.set_dword_at_offset(pos + 20, 0)
                self.logger.dbg(
                    '\t\t- original file size: ({} / 0x{:x}) => (0)'.format(origsize, origsize))
                pe.set_dword_at_offset(pos + 24, 0)
                self.logger.dbg(
                    '\t\t- filter id: ({} / 0x{:x}) => (0)'.format(filter_id, filter_id))
                pe.set_bytes_at_offset(pos + 28, b'\x00')
                self.logger.dbg(
                    '\t\t- filter cto: ({} / 0x{:x}) => (0)'.format(filter_cto, filter_cto))
                pe.set_bytes_at_offset(pos + 29, b'\x00')
                self.logger.dbg(
                    '\t\t- unused: ({} / 0x{:x}) => (0)'.format(unused, unused))
                pe.set_bytes_at_offset(pos + 30, b'\x00')
                self.logger.dbg(
                    '\t\t- header checksum: ({} / 0x{:x}) => (0)'.format(header_chksum, header_chksum))
                pe.set_bytes_at_offset(pos + 31, b'\x00')

            pe.parse_sections(section_table_offset)
            pe.write(outfile)

            return True

        except Exception as e:
            self.logger.err(
                f'Exception thrown while tampering with UPXed file!\n{e}')
            return False

        finally:
            if pe:
                pe.close()
