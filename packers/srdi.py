#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re
import sys
import shutil
import tempfile


class PackersRDI(IPacker):
    default_srdi_args = ' -of raw'
    srdi_cmdline_template = f'{sys.executable} <command> <options> <infile>'

    metadata = {
        'author': 'Nick Landers, @monoxgas',
        'url': 'https://github.com/monoxgas/sRDI',
        'licensing': 'open-source',
        'description': 'Convert DLLs to position independent shellcode',
        'type': PackerType.ShellcodeEncoder,
        'input': ['DLL', ],
        'output': ['Shellcode', ],
    }

    default_options = {
        'srdi_path': '',
        'srdi_function': '',
        'srdi_data': '',
        'srdi_obfuscate_imports': True,
        'srdi_import_delay': 2,
        'srdi_clear_header': True,
        'srdi_pass_shellcode_base': True,
    }

    def __init__(self, logger, options):
        self.srdi_args = PackersRDI.default_srdi_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'sRDI'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--srdi-path', metavar='PATH', dest='srdi_path',
                                help='Path to srdi. By default will look it up in %%PATH%%')
            parser.add_argument('--srdi-args', metavar='ARGS', dest='srdi_args',
                                help='Optional srdi-specific arguments to pass. They override default ones.')

            parser.add_argument('--srdi-function', metavar='FUNCTION',
                                help='The function to call after DllMain')
            parser.add_argument('--srdi-data', metavar='DATA',
                                help='Data to pass to the target function')
            parser.add_argument('--srdi-obfuscate-imports', action='store_true',
                                help='Randomize import dependency load order')
            parser.add_argument('--srdi-import-delay', metavar='DELAY', type=int,
                                help='Number of seconds to pause between loading imports')
            parser.add_argument(
                '--srdi-clear-header', action='store_true', help='Clear the PE header on load')
            parser.add_argument('--srdi-pass-shellcode-base', action='store_true',
                                help=' Pass shellcode base address to exported function')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackersRDI.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'srdi_path' in self.options.keys() and self.options['srdi_path'] != None and len(self.options['srdi_path']) > 0 \
                    and self.options['srdi_path'] != PackersRDI.default_options['srdi_path']:
                self.options['srdi_path'] = configPath(
                    self.options['config'], self.options['srdi_path'])
            else:
                self.options['srdi_path'] = PackersRDI.default_options['srdi_path']

            if 'srdi_args' in self.options.keys() and self.options['srdi_args'] != None \
                    and len(self.options['srdi_args']) > 0:
                self.options['srdi_args'] = self.options['srdi_args']
                self.srdi_args = self.options['srdi_args']

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        cwd = ''
        temp = None
        newinfile = ''

        try:
            temp = tempfile.NamedTemporaryFile(delete=False)
            newinfile = temp.name + '.dll'
            shutil.copy(infile, newinfile)

            if not infile.lower().endswith('.dll'):
                self.logger.err(
                    'sRDI expects DLL on input, but extension doesn\'t match. Will carry on anyway.')

            if not outfile.lower().endswith('.bin'):
                self.logger.err(
                    'sRDI produces Shellcode, but extension isn\'t ".bin". Will carry on anyway.')

            if self.options['srdi_function']:
                self.srdi_args += f" -f {self.options['srdi_function']}"
            if self.options['srdi_data']:
                self.srdi_args += f" -u {self.options['srdi_data']}"
            if self.options['srdi_obfuscate_imports']:
                self.srdi_args += f" -i"
            if self.options['srdi_import_delay']:
                self.srdi_args += f" -d {self.options['srdi_import_delay']}"
            if self.options['srdi_clear_header']:
                self.srdi_args += f" -c"
            if self.options['srdi_pass_shellcode_base']:
                self.srdi_args += f" -b"

            cwd = os.getcwd()
            base = os.path.dirname(self.options['srdi_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            cmd = IPacker.build_cmdline(
                PackersRDI.srdi_cmdline_template,
                self.options['srdi_path'],
                self.srdi_args,
                newinfile,
                ''
            )

            out = shell(self.logger, cmd,
                        output=self.options['verbose'] or self.options['debug'],
                        timeout=self.options['timeout'])

            newoutfile = newinfile.replace('.dll', '.bin')

            if os.path.isfile(newoutfile):
                shutil.move(newoutfile, outfile)
                return True

            else:
                self.logger.err('Something went wrong: there is no output artifact ({})!\n'.format(
                    outfile
                ))

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                    self.logger.info(f'''{PackersRDI.get_name()} returned:
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

        finally:
            if temp:
                temp.close()

            if len(newinfile) > 0 and os.path.exists(newinfile):
                os.remove(newinfile)

            if len(cwd) > 0:
                self.logger.dbg(
                    'reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

        return False
