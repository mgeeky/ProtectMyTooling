#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re
import sys
import shutil

class PackerNimpackt(IPacker):
    default_nimpackt_args = ''
    nimpackt_cmdline_template = f'{sys.executable} <command> <options> -i <infile> -o <outfile>'

    default_options = {
        'nimpackt_path' : '',
        'nimpackt_bake_args' : '',
        'nimpackt_nopatchamsi' : False,
        'nimpackt_nodisableetw' : False,
        'nimpackt_nounhook' : False,
        'nimpackt_nosyscalls' : False,
        'nimpackt_sleep' : False,
        'nimpackt_32bit' : False,
        'nimpackt_showconsole' : False,
        'nimpackt_inject_remote' : False,
        'nimpackt_target' : '',
        'nimpackt_existing' : False,
    }

    def __init__(self, logger, options):
        self.nimpackt_args = PackerNimpackt.default_nimpackt_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'NimPackt-v1'

    @staticmethod
    def get_type():
        return PackerType.PEProtector

    @staticmethod
    def get_desc():
        return 'Takes Shellcode or .NET Executable on input, produces EXE or DLL loader. Doesn\'t work very well with x86. Based on modified NimPackt. Brought to you by Cas van Cooten (@chvancooten)'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--nimpackt-path', metavar='PATH', dest='nimpackt_path', help = 'Path to nimpackt. By default will look it up in %%PATH%%')

            parser.add_argument('--nimpackt-bake-args', metavar='ARGS', dest='nimpackt_bake_args', help = 'Arguments to "bake into" the wrapped binary, or "PASSTHRU" to accept run-time arguments (default)')
            parser.add_argument('--nimpackt-nopatchamsi', action='store_true', dest='nimpackt_nopatchamsi', help = 'Do NOT patch (disable) the Anti-Malware Scan Interface (AMSI)')
            parser.add_argument('--nimpackt-nodisableetw', action='store_true', dest='nimpackt_nodisableetw', help = 'Do NOT disable Event Tracing for Windows (ETW)')
            parser.add_argument('--nimpackt-nounhook', action='store_true', dest='nimpackt_nounhook', help = 'Do NOT unhook user-mode API hooks in the target process by loading a fresh NTDLL.dll')
            parser.add_argument('--nimpackt-nosyscalls', action='store_true', dest='nimpackt_nosyscalls', help = 'Do NOT use direct syscalls (Windows generation 7-10) instead of high-level APIs to evade EDR')
            parser.add_argument('--nimpackt-sleep', action='store_true', dest='nimpackt_sleep', help = 'Sleep for approx. 30 seconds by calculating primes')
            parser.add_argument('--nimpackt-32bit', action='store_true', dest='nimpackt_32bit', help = 'Compile in 32-bit mode (untested)')
            parser.add_argument('--nimpackt-showconsole', action='store_true', dest='nimpackt_showconsole', help = 'Show a console window with the app\'s output when running')
            parser.add_argument('--nimpackt-remote', action='store_true', dest='nimpackt_inject_remote', help = 'Inject shellcode into remote process (default false)')
            parser.add_argument('--nimpackt-target', metavar='INJECTTARGET', dest='nimpackt_target', help = 'Remote thread targeted for remote process injection')
            parser.add_argument('--nimpackt-existing', action='store_true', dest='nimpackt_existing', help = 'Remote inject into existing process rather than a newly spawned one (defaultfalse, implies -r) (WARNING: VOLATILE)')

            parser.add_argument('--nimpackt-args', metavar='ARGS', dest='nimpackt_args', help = 'Optional nimpackt-specific arguments to pass. They override default ones.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerNimpackt.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'nimpackt_path' in self.options.keys() and self.options['nimpackt_path'] != None and len(self.options['nimpackt_path']) > 0 \
                and self.options['nimpackt_path'] != PackerNimpackt.default_options['nimpackt_path']:
                self.options['nimpackt_path'] = configPath(self.options['config'], self.options['nimpackt_path'])
            else:
                self.options['nimpackt_path'] = PackerNimpackt.default_options['nimpackt_path']

            if 'nimpackt_args' in self.options.keys() and self.options['nimpackt_args'] != None \
                and len(self.options['nimpackt_args']) > 0: 
                self.options['nimpackt_args'] = self.options['nimpackt_args']
                self.nimpackt_args = self.options['nimpackt_args']

    def process(self, arch, infile, outfile):
        cwd = ''

        try:
            ver = shell(self.logger, 'nim --version').split('\n')[0].strip()

            cwd = os.getcwd()
            base = os.path.dirname(infile)

            path, ext = os.path.splitext(outfile)
            ext = ext[1:].lower()

            if ext not in ('exe', 'dll'):
                self.logger.fatal(f'{PackerNimpackt.get_name()} must produce output EXE or DLL artifact! Make sure your <outfile> has proper extension set')

            outformat = ext
            exemode = ''

            originalInfile = os.path.basename(infile)
            normalisedInfile = re.sub('[^0-9a-zA-Z]+', '', originalInfile)

            if isDotNetExecutable(infile):
                self.logger.info(f'{PackerNimpackt.get_name()} will convert input .NET executable into output {outformat}')
                exemode = 'execute-assembly'

            elif isShellcode(infile):
                self.logger.info(f'{PackerNimpackt.get_name()} will convert input Shellcode into output {outformat}')
                exemode = 'shinject'

            else:
                self.logger.fatal(f'{PackerNimpackt.get_name()} works only with Shellcode and .NET executables! Input file resembles neither!')

            self.nimpackt_args += f' -e {exemode} -f {outformat}'

            if len(self.options['nimpackt_bake_args']) > 0: self.nimpackt_args += f" -a \"{self.options['nimpackt_bake_args']}\""
            if self.options['nimpackt_nopatchamsi']: self.nimpackt_args += ' -na'
            if self.options['nimpackt_nodisableetw']: self.nimpackt_args += ' -ne'
            if self.options['nimpackt_sleep']: self.nimpackt_args += ' -s'
            
            if self.options['nimpackt_32bit'] or arch == 'x86': 
                self.nimpackt_args += ' -32'

                if not self.options['nimpackt_nosyscalls']:
                    self.options['nimpackt_nosyscalls'] = True
                    self.logger.err('Using direct syscalls is not supported in x86. Change input to x64. Disabled use of Syscalls.')

                if not self.options['nimpackt_nounhook']:
                    self.options['nimpackt_nounhook'] = True
                    self.logger.err('Unhooking APIs is not supported in x86. Change input to x64. Disabled use of Unhooking.')
            
            if self.options['nimpackt_nosyscalls']: self.nimpackt_args += ' -ns'
            if self.options['nimpackt_nounhook']: self.nimpackt_args += ' -nu'

            if self.options['nimpackt_showconsole']: self.nimpackt_args += ' -S'
            if self.options['nimpackt_inject_remote']: self.nimpackt_args += ' -r'
            if len(self.options['nimpackt_target']) > 0: self.nimpackt_args += f" -t \"{self.options['nimpackt_target']}\""
            
            if self.options['nimpackt_existing']: self.nimpackt_args += ' -E'

            if self.options['debug']: self.nimpackt_args += ' -d'
            if self.options['verbose']: self.nimpackt_args += ' -v'

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            cmd = IPacker.build_cmdline(
                PackerNimpackt.nimpackt_cmdline_template,
                self.options['nimpackt_path'],
                self.nimpackt_args,
                infile,
                normalisedInfile
            )
            
            out = shell(self.logger, cmd, 
                output = self.options['verbose'] or self.options['debug'], 
                timeout = self.options['timeout'])

            #
            # It's a pain what NimPackt does with output file name leaving it hardly predictable...
            #
            mangledOutFileName = ''
            outDir = os.path.join(os.path.dirname(self.options['nimpackt_path']), 'output')

            if exemode == 'shinject':
                mangledOutFileName = os.path.join(outDir, normalisedInfile + f"ShinjectNimPackt.{outformat}")
            else:
                mangledOutFileName = os.path.join(outDir, normalisedInfile + f"ExecAssemblyNimPackt.{outformat}")
            
            if not os.path.isfile(mangledOutFileName):
                mangledOutFileName = os.path.join(outDir, normalisedInfile + f'.{outformat}')

            if os.path.isfile(mangledOutFileName):
                shutil.move(mangledOutFileName, outfile)

                if outformat == 'dll':
                    print(f'''

[+] {PackerNimpackt.get_name()} generated DLL loader may be executed like so:

    cmd> rundll32 {os.path.basename(outfile)},IconSrv

''')
                return True

            else:
                self.logger.err('Something went wrong: there is no output artifact ({})!\n'.format(
                    mangledOutFileName
                ))

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']): self.logger.info(f'''{PackerNimpackt.get_name()} returned:
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
