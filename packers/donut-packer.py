#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re

class PackerDonut(IPacker):
    default_donut_args = '-b 3 -e 3 -x <exit> -a <arch> -f <format>'
    donut_cmdline_template = '<command> <options> -o <outfile> <infile>'

    default_options = {
        'donut_path' : '',
        'donut_engine' : '3',
        'donut_cmdline' : '',
        'donut_thread' : False,
        'donut_cmdline_unicode' : False,
        'donut_method' : '',
        'donut_appdomain' : '',
        'donut_class' : '',
        'donut_exit' : '1',
    }

    def __init__(self, logger, options):
        self.donut_args = PackerDonut.default_donut_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'Donut'

    @staticmethod
    def get_type():
        return PackerType.ShellcodeConverter

    @staticmethod
    def get_desc():
        return 'Donut takes EXE/DLL/.NET and produces a robust PIC shellcode or Py/Ruby/Powershell/C#/Hex/Base64 array'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--donut-path', metavar='PATH', dest='donut_path',
                help = 'Path to Donut. By default will look it up in %%PATH%%')

            parser.add_argument('--donut-args', metavar='ARGS', dest='donut_args',
                help = 'Optional Donut-specific arguments to pass. They override default ones.')

            parser.add_argument('--donut-engine', metavar='ENGINE', dest='donut_engine', help = 'Donut Pack/Compress engine. Default: ' + PackerDonut.default_options['donut_engine'])
            parser.add_argument('--donut-cmdline', metavar='ENGINE', dest='donut_cmdline', help = 'Donut command line parameter for DLL method/EXE.')
            parser.add_argument('--donut-cmdline-unicode', action='store_true', dest='donut_cmdline_unicode', help = 'Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI).')
            parser.add_argument('--donut-thread', action='store_true', dest='donut_thread', help = 'Run the entrypoint of an unmanaged/native EXE as a thread and wait for thread to end.')
            parser.add_argument('--donut-method', metavar='METHOD', dest='donut_method', help = 'Optional method or function for DLL. (a method is required for .NET DLL).')
            parser.add_argument('--donut-appdomain', metavar='APPDOMAIN', dest='donut_appdomain', help = 'AppDomain name to create for .NET. If entropy is enabled, one will be generated randomly')
            parser.add_argument('--donut-class', metavar='CLASS', dest='donut_class', help = 'Optional class name. (required for .NET DLL) Can also include namespace: e.g namespace.class.')
            parser.add_argument('--donut-exit', metavar='EXIT', dest='donut_exit', default='1', help = 'Determines how the loader should exit. 1=exit thread (default), 2=exit process.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerDonut.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'donut_path' in self.options.keys() and self.options['donut_path'] != None and len(self.options['donut_path']) > 0:
                self.options['donut_path'] = configPath(self.options['config'], self.options['donut_path'])
            else:
                self.options['donut_path'] = PackerDonut.default_options['donut_path']

            if 'donut_args' in self.options.keys() and self.options['donut_args'] != None \
                and len(self.options['donut_args']) > 0: 
                self.options['donut_args'] = self.options['donut_args']
                self.donut_args = self.options['donut_args']

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        try:
            _arch = 3
            #if arch == 'x86': _arch = 1
            #elif arch == 'x64': _arch = 2

            _format = 1
            
            if outfile.lower().endswith('.b64'): _format = 2
            elif outfile.lower().endswith('.c'): _format = 3
            elif outfile.lower().endswith('.cpp'): _format = 3
            elif outfile.lower().endswith('.rb'): _format = 4
            elif outfile.lower().endswith('.py'): _format = 5
            elif outfile.lower().endswith('.ps1'): _format = 6
            elif outfile.lower().endswith('.cs'): _format = 7
            elif outfile.lower().endswith('.hex'): _format = 8

            if (_format == 1 and not outfile.lower().endswith('.bin')):
                self.logger.err('Donut produces only .bin shellcode files! Make sure your <outfile> has .bin extension or any other supported by Donut --format parameter. Carrying on anyway.')

            self.donut_args = self.donut_args.replace('<arch>', str(_arch))
            self.donut_args = self.donut_args.replace('<format>', str(_format))
            self.donut_args = self.donut_args.replace('<exit>', self.options['donut_exit'])

            if len(self.options['donut_engine']) > 0: self.donut_args += f" -z {self.options['donut_engine']}"
            if len(self.options['donut_cmdline']) > 0: self.donut_args += f" -p \"{self.options['donut_cmdline']}\""
            if self.options['donut_thread']: self.donut_args += ' -t'
            if self.options['donut_cmdline_unicode']: self.donut_args += ' -w'
            if len(self.options['donut_method']) > 0: self.donut_args += f" -m {self.options['donut_method']}"
            if len(self.options['donut_appdomain']) > 0: self.donut_args += f" -d {self.options['donut_appdomain']}"
            if len(self.options['donut_class']) > 0: self.donut_args += f" -c {self.options['donut_class']}"

            cmd = IPacker.build_cmdline(
                PackerDonut.donut_cmdline_template,
                self.options['donut_path'],
                self.donut_args,
                infile,
                outfile
            )
            
            out = shell(self.logger, cmd, 
                output = self.options['verbose'] or self.options['debug'], 
                timeout = self.options['timeout'])

            if os.path.isfile(outfile):
                return True

            else:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    outfile
                ))

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']): self.logger.info(f'''{PackerDonut.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced = True, noprefix=True)

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from {PackerDonut.get_name()}:
----------------------------------------
{e}
----------------------------------------
''')

        except Exception as e:
            raise

        return False
