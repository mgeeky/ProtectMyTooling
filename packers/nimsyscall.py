#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re
import sys
import string
import shutil
import random

class PackerNimSyscall(IPacker):
    default_nimsyscall_args = ''
    nimsyscall_cmdline_template = f'<command> <options> --file=<infile> --output=<outfile>'

    default_options = {
        'nimsyscall_path' : '',
        'nimsyscall_noetw': False,
        'nimsyscall_noamsi': False,
        'nimsyscall_noargs': False,
        'nimsyscall_hide': True,
        'nimsyscall_reflective': False,
        'nimsyscall_debug': False,
        'nimsyscall_x86': False,
        'nimsyscall_large': False,
        'nimsyscall_comvaretw': False,
        'nimsyscall_unhook': True,
        'nimsyscall_obfuscate': False,
        'nimsyscall_sgn': True,
        'nimsyscall_replace': True,
        'nimsyscall_selfdelete': False,
        'nimsyscall_obfuscatefunctions': False,
        'nimsyscall_sign': True,
        'nimsyscall_llvm': False,
        'nimsyscall_sleepycrypt': False,
        'nimsyscall_hellsgate': False,
        'nimsyscall_syswhispers': True,
        'nimsyscall_jump': False,           # that one is causing segmentation faults, watch out
        'nimsyscall_shellcode': False,
        'nimsyscall_remoteinject': False,
        'nimsyscall_remotepatchamsi': False,
        'nimsyscall_remotepatchetw': False,
        'nimsyscall_peinject': False,       # don't use peinject/peload with shellcodes
        'nimsyscall_peload': True,
        'nimsyscall_csharp': False,
        'nimsyscall_key': ''.join(random.choice(string.ascii_letters) for i in range(10)),
        'nimsyscall_dllexportfunc': '',
        'nimsyscall_sleep': 0,
        'nimsyscall_sandbox': 'MemorySpace',
        'nimsyscall_domain': '',
        'nimsyscall_pump': '',
        'nimsyscall_signdomain': 'www.microsoft.com',
        'nimsyscall_remoteprocess': '',
    }

    def __init__(self, logger, options):
        self.nimsyscall_args = PackerNimSyscall.default_nimsyscall_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'NimSyscallPacker'

    @staticmethod
    def get_type():
        return PackerType.PEProtector

    @staticmethod
    def get_desc():
        return '(paid) Takes PE/Shellcode/.NET executable and generates robust Nim+Syscalls EXE/DLL loader. Sponsorware authored by S3cur3Th1sSh1t'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--nimsyscall-path', metavar='PATH', dest='nimsyscall_path', help = 'Path to NimSyscallWrapper.exe. By default will look it up in %%PATH%%')

            parser.add_argument('--nimsyscall-noetw', action='store_true', help="Don't use ETW Patch")
            parser.add_argument('--nimsyscall-noamsi', action='store_true', help="Don't patch AMSI")
            parser.add_argument('--nimsyscall-noargs', action='store_true', help="Don't provide any arguments to the assembly (some can only run without args)")
            #parser.add_argument('--nimsyscall-hide', action='store_true', help="Compile with --app:gui flag, so that the console won't pop up")
            parser.add_argument('--nimsyscall-reflective', action='store_true', help="Set compiler flags, so that the Loader Nim binary can be reflectively loaded")
            parser.add_argument('--nimsyscall-debug', action='store_true', help="Compiles the binary in debug mode (More DInvoke output)")
            #parser.add_argument('--nimsyscall-x86', action='store_true', help="(Compiles an x86 binary - have to cast some more function values before this works smoothly)")
            parser.add_argument('--nimsyscall-large', action='store_true', help="use this for large payloads (bigger than 5MB) as you will get an error \"interpretation requires too many iterations\" without it")
            parser.add_argument('--nimsyscall-comvaretw', action='store_true', help="Block ETW by setting COMPlus_ETWEnabled to 0")
            parser.add_argument('--nimsyscall-unhook', action='store_true', help="Unhook ntdll.dll before doing anything else for the current process")
            parser.add_argument('--nimsyscall-obfuscate', action='store_true', help="Compile the Nim binary via Denim to make use of LLVM obfuscation (not possible in combination with --reflective)")
            parser.add_argument('--nimsyscall-sgn', action='store_true', help="Encode shellcode via SGN before encrypting it´")
            parser.add_argument('--nimsyscall-replace', action='store_true', help="Replace common nim IoC's in the loader like the string 'nim'")
            parser.add_argument('--nimsyscall-selfdelete', action='store_true', help="The loader deletes it's own executable on runtime (Credit to @byt3bl33d3r and @jonasLyk)")
            parser.add_argument('--nimsyscall-obfuscatefunctions', action='store_true', help="Obfuscate some Nim specific Windows API's from the IAT via CallObfuscator (https://github.com/d35ha/CallObfuscator - only possible from a Windows OS)")
            parser.add_argument('--nimsyscall-sign', action='store_true', help="Sign the binary with a spoofed certificate")
            parser.add_argument('--nimsyscall-llvm', action='store_true', help="Add compiler flags for LLVM obfuscation, you have to set it up by yourself")
            parser.add_argument('--nimsyscall-sleepycrypt', action='store_true', help="Encrypt the memory of the loader with SleepyCrypt # experimental (Pre-Alpha, not working yet for C2-Stager)")
            parser.add_argument('--nimsyscall-hellsgate', action='store_true', help="Retrieve Syscalls via Hellsgate technique (for patching AMSI/ETW or shellcode execution/PE injection)")
            parser.add_argument('--nimsyscall-syswhispers', action='store_true', help="Embed Syscalls via Syswhispers3 (NimLineWhispers3) technique")
            parser.add_argument('--nimsyscall-jump', action='store_true', help="When using Syswhispers3, use the jumper_randomized technique")
            #parser.add_argument('--nimsyscall-shellcode', action='store_true', help="Encrypt shellcode to load it on runtime")
            parser.add_argument('--nimsyscall-remoteinject', action='store_true', help="Inject shellcode a newly spawned process (default notepad) / otherwise it's self injection")
            parser.add_argument('--nimsyscall-remotepatchamsi', action='store_true', help="Patch AMSI in the remote process before shellcode execution")
            parser.add_argument('--nimsyscall-remotepatchetw', action='store_true', help="Patch ETW in the remote process before shellcode execution")
            parser.add_argument('--nimsyscall-peinject', action='store_true', help="Encrypt a PE to decrypt and run it on runtime as shellcode via donut")
            parser.add_argument('--nimsyscall-peload', action='store_true', help="Encrypt a PE to decrypt it on runtime and execute it via a syscall variant of Run-PE")
            #parser.add_argument('--nimsyscall-csharp', action='store_true', help="Encrypt a C# assembly to load it on runtime")

            parser.add_argument('--nimsyscall-key', metavar='key', help="Key to encrypt with")
            parser.add_argument('--nimsyscall-dllexportfunc', metavar='exportfuncname', help="Comma separated names of DLL custom export functions")
            parser.add_argument('--nimsyscall-sleep', metavar='seconds', default=PackerNimSyscall.default_options['nimsyscall_sleep'], type=int, help="Sleep N seconds before decryption to evade in memory scanners. Default: " + str(PackerNimSyscall.default_options['nimsyscall_sleep']))
            parser.add_argument('--nimsyscall-sandbox', metavar='value', help="Include Sandbox Checks of your choice into the loader: Domain, DomainJoined, DiskSpace, MemorySpace")
            parser.add_argument('--nimsyscall-domain', metavar='domain', help="Specify a domain name for SandBox Evasion")
            parser.add_argument('--nimsyscall-pump', metavar='value', help="Pump the file with: words, reputation")
            parser.add_argument('--nimsyscall-signdomain', metavar='domain', default="www.microsoft.com", help="The domain to use for the certificate (default is www.microsoft.com)")
            parser.add_argument('--nimsyscall-remoteprocess', metavar='procname', help="Injects into the specified remote process name, e.g. teams.exe. Can be used for multiple process names, e.g. teams.exe,iexplore.exe,MicrosoftEdge.exe")

            parser.add_argument('--nimsyscall-args', metavar='ARGS', dest='nimsyscall_args', help = 'Optional NimSyscallPacker-specific arguments to pass. They override default ones.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerNimSyscall.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'nimsyscall_path' in self.options.keys() and self.options['nimsyscall_path'] != None and len(self.options['nimsyscall_path']) > 0 \
                and self.options['nimsyscall_path'] != PackerNimSyscall.default_options['nimsyscall_path']:
                self.options['nimsyscall_path'] = configPath(self.options['config'], self.options['nimsyscall_path'])
            else:
                self.options['nimsyscall_path'] = PackerNimSyscall.default_options['nimsyscall_path']

            if self.options['nimsyscall_obfuscate'] and self.options['nimsyscall_reflective']:
                self.logger.err('According to NimSyscallPacker help, --nimsyscall-obfuscate and --nimsyscall-reflective are mututally exclusive options!')

            if self.options['nimsyscall_hellsgate'] and self.options['nimsyscall_syswhispers']:
                self.logger.err('Use of both --hellsgate and --syswhispers doesn\'t make any sense. Will proceed though and see what happens.')

            if 'nimsyscall_args' in self.options.keys() and self.options['nimsyscall_args'] != None \
                and len(self.options['nimsyscall_args']) > 0: 
                self.options['nimsyscall_args'] = self.options['nimsyscall_args']
                self.nimsyscall_args = self.options['nimsyscall_args']


    def process(self, arch, infile, outfile):
        cwd = ''
        try:
            ver = shell(self.logger, 'nim --version').split('\n')[0].strip()

            cwd = os.getcwd()
            base = os.path.dirname(self.options['nimsyscall_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            exemode = ''
            outformat = 'exe'

            if outfile.lower().endswith('.dll'): 
                outformat = 'dll'
                self.nimsyscall_args += ' --dll'

            dotnet = isDotNetExecutable(infile)
            exe = isValidPE(infile)

            if dotnet or exe:
                if dotnet:
                    self.logger.info(f'{PackerNimSyscall.get_name()} will convert input .NET executable into output {outformat}')
                    self.options['nimsyscall_csharp'] = True
                    self.options['nimsyscall_peload'] = False
                    self.options['nimsyscall_peinject'] = False

                elif exe:
                    self.logger.info(f'{PackerNimSyscall.get_name()} will convert input PE into output {outformat}')
                    #self.options['nimsyscall_csharp'] = False
                    #self.options['nimsyscall_peload'] = True

                self.options['nimsyscall_sgn'] = False
                self.options['nimsyscall_shellcode'] = False
                self.options['nimsyscall_remoteinject'] = False
                self.options['nimsyscall_remoteprocess'] = ''
                self.options['nimsyscall_remotepatchetw'] = False
                self.options['nimsyscall_remotepatchamsi'] = False

            elif isShellcode(infile):
                self.logger.info(f'{PackerNimSyscall.get_name()} will convert input Shellcode into output {outformat}')
                self.options['nimsyscall_shellcode'] = True
                self.options['nimsyscall_csharp'] = False
                self.options['nimsyscall_peload'] = False
                self.options['nimsyscall_peinject'] = False

            self.options['nimsyscall_large'] = (os.path.getsize(infile) > 5 * 1024 * 1024)
            self.options['nimsyscall_x86'] = (arch == 'x86')

            if self.options['debug']: 
                self.options['nimsyscall_debug'] = True

            if self.options['nimsyscall_noetw']: self.nimsyscall_args += ' --noETW'
            if self.options['nimsyscall_noamsi']: self.nimsyscall_args += ' --noAMSI'
            if self.options['nimsyscall_noargs']: self.nimsyscall_args += ' --noArgs'
            if self.options['nimsyscall_hide']: self.nimsyscall_args += ' --hide'
            if self.options['nimsyscall_reflective']: self.nimsyscall_args += ' --reflective'
            if self.options['nimsyscall_debug']: self.nimsyscall_args += ' --debug'
            if self.options['nimsyscall_x86']: self.nimsyscall_args += ' --x86'
            if self.options['nimsyscall_large']: self.nimsyscall_args += ' --large'
            if self.options['nimsyscall_comvaretw']: self.nimsyscall_args += ' --COMVARETW'
            if self.options['nimsyscall_unhook']: self.nimsyscall_args += ' --unhook'
            if self.options['nimsyscall_obfuscate']: self.nimsyscall_args += ' --obfuscate'
            if self.options['nimsyscall_sgn']: self.nimsyscall_args += ' --sgn'
            if self.options['nimsyscall_replace']: self.nimsyscall_args += ' --replace'
            if self.options['nimsyscall_selfdelete']: self.nimsyscall_args += ' --self-delete'
            if self.options['nimsyscall_obfuscatefunctions']: self.nimsyscall_args += ' --obfuscatefunctions'
            if self.options['nimsyscall_sign']: self.nimsyscall_args += ' --sign'
            if self.options['nimsyscall_llvm']: self.nimsyscall_args += ' --llvm'
            if self.options['nimsyscall_sleepycrypt']: self.nimsyscall_args += ' --sleepycrypt'
            if self.options['nimsyscall_hellsgate']: self.nimsyscall_args += ' --hellsgate'
            if self.options['nimsyscall_syswhispers']: self.nimsyscall_args += ' --syswhispers'
            if self.options['nimsyscall_jump']: self.nimsyscall_args += ' --jump'
            if self.options['nimsyscall_shellcode']: self.nimsyscall_args += ' --shellcode'
            if self.options['nimsyscall_remoteinject']: self.nimsyscall_args += ' --remoteinject'
            if self.options['nimsyscall_remotepatchamsi']: self.nimsyscall_args += ' --remotepatchAMSI'
            if self.options['nimsyscall_remotepatchetw']: self.nimsyscall_args += ' --remotepatchETW'
            if self.options['nimsyscall_peinject']: self.nimsyscall_args += ' --peinject'
            if self.options['nimsyscall_peload']: self.nimsyscall_args += ' --peload'
            if self.options['nimsyscall_csharp']: self.nimsyscall_args += ' --csharp'

            if len(self.options['nimsyscall_key']) > 0: self.nimsyscall_args += f" --key={self.options['nimsyscall_key']}"
            if len(self.options['nimsyscall_dllexportfunc']) > 0: self.nimsyscall_args += f" --dllexportfunc={self.options['nimsyscall_dllexportfunc']}"
            if self.options['nimsyscall_sleep'] > 0: self.nimsyscall_args += f" --sleep={self.options['nimsyscall_sleep']}"
            if len(self.options['nimsyscall_sandbox']) > 0: self.nimsyscall_args += f" --sandbox={self.options['nimsyscall_sandbox']}"
            if len(self.options['nimsyscall_domain']) > 0: self.nimsyscall_args += f" --domain={self.options['nimsyscall_domain']}"
            if len(self.options['nimsyscall_pump']) > 0: self.nimsyscall_args += f" --pump={self.options['nimsyscall_pump']}"
            if len(self.options['nimsyscall_signdomain']) > 0: self.nimsyscall_args += f" --signdomain={self.options['nimsyscall_signdomain']}"
            if len(self.options['nimsyscall_remoteprocess']) > 0: self.nimsyscall_args += f" --remoteprocess={self.options['nimsyscall_remoteprocess']}"

            cmd = IPacker.build_cmdline(
                PackerNimSyscall.nimsyscall_cmdline_template,
                self.options['nimsyscall_path'],
                self.nimsyscall_args,
                infile,
                outfile
            )

            out = shell(self.logger, cmd, 
                output = self.options['verbose'] or self.options['debug'], 
                timeout = self.options['timeout'])

            if os.path.isfile(outfile):
                return True

            else:
                self.logger.err('Something went wrong: there is no output artifact ({})!\n'.format(
                    outfile
                ))

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']): self.logger.info(f'''{PackerNimSyscall.get_name()} returned:
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
            if len(self.options['nimsyscall_signdomain']) > 0:
                a = os.path.join(os.path.dirname(self.options['nimsyscall_path']), self.options['nimsyscall_signdomain'] + '.key')
                b = os.path.join(os.path.dirname(self.options['nimsyscall_path']), self.options['nimsyscall_signdomain'] + '.pem')
                c = os.path.join(os.path.dirname(self.options['nimsyscall_path']), self.options['nimsyscall_signdomain'] + '.pfx')

                if os.path.isfile(a): os.remove(a)
                if os.path.isfile(b): os.remove(b)
                if os.path.isfile(c): os.remove(c)

            a = os.path.join(os.path.dirname(self.options['nimsyscall_path']), 'enc.blob')
            b = os.path.join(os.path.dirname(self.options['nimsyscall_path']), 'Loader.nim')
            c = os.path.join(os.path.dirname(self.options['nimsyscall_path']), 'tmpshellcode.bin')

            if os.path.isfile(a): os.remove(a)
            if os.path.isfile(b): os.remove(b)
            if os.path.isfile(c): os.remove(c)

            if len(cwd) > 0:
                self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

        return False
