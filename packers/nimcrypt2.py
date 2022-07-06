#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re
import sys
import shutil

class PackerNimcrypt2(IPacker):
    default_nimcrypt2_args = ''
    nimcrypt2_cmdline_template = f'<command> <options> -f <infile> -o <outfile>'

    default_options = {
        'nimcrypt2_path' : '',
        'nimcrypt2_unhook' : True,
        'nimcrypt2_process' : '',
        'nimcrypt2_encrypt_strings' : True,
        'nimcrypt2_get_syscallstub' : False,
        'nimcrypt2_llvm_obfuscator' : False,
        'nimcrypt2_no_randomization' : False,
        'nimcrypt2_no_sandbox' : False,
        'nimcrypt2_no_ppid_spoof' : False,
    }

    def __init__(self, logger, options):
        self.nimcrypt2_args = PackerNimcrypt2.default_nimcrypt2_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'Nimcrypt2'

    @staticmethod
    def get_type():
        return PackerType.PEProtector

    @staticmethod
    def get_desc():
        return 'Generates Nim loader running input .NET, PE or Raw Shellcode. Authored by icyguider'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--nimcrypt2-path', metavar='PATH', dest='nimcrypt2_path', help = 'Path to nimcrypt2. By default will look it up in %%PATH%%')

            parser.add_argument('--nimcrypt2-unhook', action='store_true', dest='nimcrypt2_unhook', help = 'Unhook ntdll.dll')
            parser.add_argument('--nimcrypt2-process', default='', dest='nimcrypt2_process', help = 'Name of process for shellcode injection')
            parser.add_argument('--nimcrypt2-encrypt-strings', action='store_true', dest='nimcrypt2_encrypt_strings', help = 'Encrypt strings using the strenc module')
            parser.add_argument('--nimcrypt2-get-syscallstub', action='store_true', dest='nimcrypt2_get_syscallstub', help = 'Use GetSyscallStub instead of NimlineWhispers2')
            parser.add_argument('--nimcrypt2-llvm-obfuscator', action='store_true', dest='nimcrypt2_llvm_obfuscator', help = 'Use Obfuscator-LLVM to compile binary')
            parser.add_argument('--nimcrypt2-no-randomization', action='store_true', dest='nimcrypt2_no_randomization', help = 'Disable syscall name randomization')
            parser.add_argument('--nimcrypt2-no-sandbox', action='store_true', dest='nimcrypt2_no_sandbox', help = 'Disable sandbox checks')
            parser.add_argument('--nimcrypt2-no-ppid-spoof', action='store_true', dest='nimcrypt2_no_ppid_spoof', help = 'Disable PPID Spoofing')


            parser.add_argument('--nimcrypt2-args', metavar='ARGS', dest='nimcrypt2_args', help = 'Optional nimcrypt2-specific arguments to pass. They override default ones.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerNimcrypt2.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'nimcrypt2_path' in self.options.keys() and self.options['nimcrypt2_path'] != None and len(self.options['nimcrypt2_path']) > 0 \
                and self.options['nimcrypt2_path'] != PackerNimcrypt2.default_options['nimcrypt2_path']:
                self.options['nimcrypt2_path'] = configPath(self.options['config'], self.options['nimcrypt2_path'])
            else:
                self.options['nimcrypt2_path'] = PackerNimcrypt2.default_options['nimcrypt2_path']

            if 'nimcrypt2_args' in self.options.keys() and self.options['nimcrypt2_args'] != None \
                and len(self.options['nimcrypt2_args']) > 0: 
                self.options['nimcrypt2_args'] = self.options['nimcrypt2_args']
                self.nimcrypt2_args = self.options['nimcrypt2_args']

    def process(self, arch, infile, outfile):
        cwd = ''

        try:
            ver = shell(self.logger, 'nim --version').split('\n')[0].strip()

            cwd = os.getcwd()
            base = os.path.dirname(self.options['nimcrypt2_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            exemode = ''
            outformat = ''

            if isDotNetExecutable(infile):
                self.logger.info(f'{PackerNimcrypt2.get_name()} will convert input .NET executable into output {outformat}')
                exemode = 'csharp'

            elif isShellcode(infile):
                self.logger.info(f'{PackerNimcrypt2.get_name()} will convert input Shellcode into output {outformat}')
                exemode = 'raw'

            elif isValidPE(infile):
                self.logger.info(f'{PackerNimcrypt2.get_name()} will convert input PE into output {outformat}')
                exemode = 'pe'

            else:
                self.logger.fatal(f'{PackerNimcrypt2.get_name()} works only with PE executables, shellcode and .NET executables! Input file resembles something else!')

            self.nimcrypt2_args += f' -t {exemode}'

            if self.options['nimcrypt2_unhook']: self.nimcrypt2_args += ' -u'
            if len(self.options['nimcrypt2_process']) > 0: self.nimcrypt2_args += f" -p {self.options['nimcrypt2_process']}"
            if self.options['nimcrypt2_encrypt_strings']: self.nimcrypt2_args += ' -e'
            if self.options['nimcrypt2_get_syscallstub']: self.nimcrypt2_args += ' -g'
            if self.options['nimcrypt2_llvm_obfuscator']: self.nimcrypt2_args += ' -l'
            if self.options['nimcrypt2_no_randomization']: self.nimcrypt2_args += ' -n'
            if self.options['nimcrypt2_no_sandbox']: self.nimcrypt2_args += ' -s'
            if self.options['nimcrypt2_no_ppid_spoof']: self.nimcrypt2_args += ' --no-ppid-spoof'

            cmd = IPacker.build_cmdline(
                PackerNimcrypt2.nimcrypt2_cmdline_template,
                self.options['nimcrypt2_path'],
                self.nimcrypt2_args,
                infile,
                outfile
            )

            out = shell(self.logger, cmd, 
                output = self.options['verbose'] or self.options['debug'], 
                timeout = self.options['timeout'])

            if os.path.isfile(outfile):
                if exemode == 'pe':
                    changePESubsystemToGUI(outfile)

                return True

            else:
                self.logger.err('Something went wrong: there is no output artifact ({})!\n'.format(
                    outfile
                ))

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']): self.logger.info(f'''{PackerNimcrypt2.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced = True, noprefix=True)

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from packer:
----------------------------------------
{e}
----------------------------------------
''')

        except Exception as e:
            raise

        finally:
            if len(cwd) > 0:
                self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

        return False
