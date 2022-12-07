#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os


class PackerFreeze(IPacker):
    default_freeze_args = ''
    freeze_cmdline_template = '<command> <options> -I <infile> -O <outfile>'

    metadata = {
        'author': 'Matt Eidelberg (@Tyl0us)',
        'url': 'https://github.com/optiv/Freeze',
        'description': 'Takes x64 Shellcode on input and produces output EXE/DLL loader that circumvents EDR security controls like hooking or ETW',
        'licensing': 'open-source',
        'type': PackerType.ShellcodeLoader,
        'input': ['Shellcode', ],
        'output': ['PE', ],
    }

    default_options = {
        'freeze_console': False,
        'freeze_encrypt': False,
        'freeze_export': '',
        'freeze_process': '',
        'freeze_sandbox': False,
    }

    def __init__(self, logger, options):
        self.freeze_args = PackerFreeze.default_freeze_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'Freeze'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--freeze-path', metavar='PATH',
                                dest='freeze_path', help='(required) Path to Freeze executable.')
            parser.add_argument('--freeze-encrypt', action='store_true',
                                dest='freeze_console', help='Only for Binary Payloads - Generates verbose console information when the payload is executed. This will disable the hidden window feature')
            parser.add_argument('--freeze-export', metavar='ExportName', type=str,
                                dest='freeze_export', help='For DLL Loaders Only - Specify a specific Export function for a loader to have')
            parser.add_argument('--freeze-process', metavar='ProcessPath', type=str,
                                dest='freeze_process', help='The name of process to spawn. This process has to exist in C:\\Windows\\System32\\. Example \'notepad.exe\' (default "notepad.exe")')
            parser.add_argument('--freeze-sandbox', action='store_true',
                                dest='freeze_sandbox', help='Enables sandbox evasion by checking domain-joined, more than 2 CPUs, more than 4 GBs of RAM')
        else:
            self.options['freeze_path'] = os.path.abspath(configPath(
                self.options['config'], self.options['freeze_path']))

            for k, v in PackerFreeze.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if not os.path.isfile(self.options['freeze_path']):
                self.logger.fatal('--freeze-path option must be specified!')

    @ensureInputFileIsShellcode
    def process(self, arch, infile, outfile):
        args = ''

        if os.name == 'nt':
            self.logger.fatal(f'Currently Freeze doesnt work under Windows. Sorry.')

        if arch != 'x64':
            self.logger.err('WARNING! Freeze only works with input x64 Shellcode! x86 is not supported!')

        try:
            fname, ext = os.path.splitext(outfile.lower())

            if ext not in ('.exe', '.dll'):
                self.logger.fatal('Freeze expects output file to have .EXE/.DLL extension!')

            if self.options['freeze_console']: args += ' -console'
            if self.options['freeze_encrypt']: args += ' -encrypt'
            if len(self.options['freeze_export']) > 0: args += ' -export ' + self.options['freeze_export']
            if len(self.options['freeze_process']) > 0: args += ' -process ' + self.options['freeze_process']
            if self.options['freeze_sandbox']: args += ' -sandbox'

            infile2 = os.path.basename(infile)
            outfile2 = os.path.basename(outfile)

            cmd = IPacker.build_cmdline(
                PackerFreeze.freeze_cmdline_template,
                self.options['freeze_path'],
                args,
                infile2,
                outfile2
            )

            cwd = os.getcwd()
            base = os.path.dirname(infile)

            self.logger.dbg(
                'changed working directory to "{}"'.format(base))
            os.chdir(base)

            out = shell(self.logger, cmd,
                        output=self.options['verbose'] or self.options['debug'],
                        timeout=self.options['timeout'])

            status = os.path.isfile(outfile2)

            if not status:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    outfile2
                ))

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                    self.logger.info(f'''{PackerFreeze.get_name()} returned:
    ----------------------------------------
    {out}
    ----------------------------------------
    ''', forced=True, noprefix=True)

            else:
                shutil.move(outfile2, outfile)

            return os.path.isfile(outfile)

        except Exception as e:
            raise

        finally:
            if len(cwd) > 0:
                self.logger.dbg(
                    'reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

        return False