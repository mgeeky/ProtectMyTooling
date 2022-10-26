#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import string
import shutil
import random


class PackerAtomPePacker(IPacker):
    default_atompepacker_args = ''
    atompepacker_cmdline_template = '<command> <infile> <options>'

    metadata = {
        'author': 'ORCA (@ORCx41, ORCx41@gmail.com)',
        'url': 'https://github.com/ORCx41/AtomPePacker',
        'description': 'A Highly capable Pe Packer',
        'licensing': 'open-source',
        'type': PackerType.PEProtector,
        'input': ['PE', ],
        'output': ['EXE', 'DLL'],
    }

    default_options = {
    }

    def __init__(self, logger, options):
        self.atompepacker_args = PackerAtomPePacker.default_atompepacker_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'AtomPePacker'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--atompepacker-path', metavar='PATH', dest='atompepacker_path',
                                help='Path to AtomPePacker. By default will look it up in %%PATH%%')

            parser.add_argument('--atompepacker-args', metavar='ARGS', dest='atompepacker_args',
                                help='Optional AtomPePacker-specific arguments to pass. They override default ones.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerAtomPePacker.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'atompepacker_path' in self.options.keys() and self.options['atompepacker_path'] != None and len(self.options['atompepacker_path']) > 0:
                self.options['atompepacker_path'] = configPath(
                    self.options['config'], self.options['atompepacker_path'])
            else:
                self.options['atompepacker_path'] = PackerAtomPePacker.default_options['atompepacker_path']

            if 'atompepacker_args' in self.options.keys() and self.options['atompepacker_args'] != None \
                    and len(self.options['atompepacker_args']) > 0:
                self.options['atompepacker_args'] = self.options['atompepacker_args']
                self.atompepacker_args = self.options['atompepacker_args']

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        infile2 = ''
        stub = ''
        cwd = ''
        path = self.options['atompepacker_path']

        try:
            n = 'PP64Stub.exe'
            if outfile.lower().endswith('.exe'):
                self.atompepacker_args += ' -e'

            if outfile.lower().endswith('.dll') or outfile.lower().endswith('.cpl') or outfile.lower().endswith('.xll') or outfile.lower().endswith('.wll'):
                self.atompepacker_args += ' -d'
                n = 'DllPP64Stub.dll'

            infile2 = stub = os.path.join(os.path.dirname(path), os.path.basename(infile))
            shutil.copy(infile, infile2)

            stub = os.path.join(os.path.dirname(path), n)
            if os.path.isfile(stub):
                os.remove(stub)

            cwd = os.getcwd()
            base = os.path.dirname(path)

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            cmd = IPacker.build_cmdline(
                PackerAtomPePacker.atompepacker_cmdline_template,
                os.path.basename(path),
                self.atompepacker_args,
                os.path.basename(infile),
                '',
                noQuotes=True
            )

            out = shell(self.logger, cmd,
                        output=self.options['verbose'] or self.options['debug'],
                        timeout=self.options['timeout'])

            if os.path.isfile(stub):
                shutil.move(stub, outfile)
                return self.tamper(outfile)

            else:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    outfile
                ))

                if len(out) > 0:
                    self.logger.info(f'''AtomPePacker returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from atompepacker:
----------------------------------------
{e}
----------------------------------------
''')

        except Exception as e:
            raise

        finally:
            if len(cwd) > 0:
                self.logger.dbg(
                    'reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

            if len(infile2) > 0 and os.path.isfile(infile2):
                os.remove(infile2)
            
            if len(stub) > 0 and os.path.isfile(stub):
                os.remove(stub)

        return False

    def tamper(self, outfile):
        self.logger.info(
            f'Renaming .ATOM section in output AtomPePacker artifact...')

        pe = None
        try:
            pe = pefile.PE(outfile)

            num = 0
            sectnum = 0
            newName = '.' + ''.join(random.choice(string.ascii_lowercase) for i in range(random.randint(3, 6)))

            section_table_offset = (pe.DOS_HEADER.e_lfanew + 4 +
                                    pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader)

            for sect in pe.sections:
                section_offset = section_table_offset + sectnum * 0x28
                sectnum += 1

                if sect.Name.decode().lower().startswith('.atom'):
                    newname = newName.encode(
                    ) + ((8 - len(newName)) * b'\x00')
                    self.logger.dbg('\tRenamed AtomPePacker section ({}) => ({})'.format(
                        sect.Name.decode(), newName
                    ))
                    num += 1
                    pe.set_bytes_at_offset(section_offset, newname)

            pe.parse_sections(section_table_offset)
            pe.write(outfile)

            return True

        except Exception as e:
            self.logger.err(
                f'Exception thrown while tampering with AtomPePacker artifact!\n{e}')
            return False

        finally:
            if pe:
                pe.close()
