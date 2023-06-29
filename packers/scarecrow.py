#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re
import sys
import shutil


class PackerScareCrow(IPacker):
    default_scarecrow_args = ''
    scarecrow_cmdline_template = '<command> <options> -I <infile>'

    metadata = {
        'author': 'Matt Eidelberg (@Tyl0us)',
        'url': 'https://github.com/optiv/ScareCrow',
        'licensing': 'open-source',
        'description': 'Takes x64 shellcode and produces an EDR-evasive DLL (default)/JScript/CPL/XLL artifact. (works best under Linux or Win10 WSL!)',
        'type': PackerType.ShellcodeLoader,
        'input': ['Shellcode', ],
        'output': ['DLL', 'JScript', 'CPL', 'XLL'],
    }

    Run_ScareCrow_On_Windows_As_WSL = False

    default_options = {
        'scarecrow_path': '',
        'scarecrow_loader': '',
        'scarecrow_domain': '',
        'scarecrow_valid': '',
        'scarecrow_password': '',
        'scarecrow_inject': '',
        'scarecrow_sandbox': False,
        'scarecrow_sign': False,
    }

    def __init__(self, logger, options):
        self.scarecrow_args = PackerScareCrow.default_scarecrow_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'ScareCrow'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--scarecrow-path', metavar='PATH', dest='scarecrow_path',
                                help='Path to ScareCrow. By default will look it up in %%PATH%%')
            parser.add_argument('--scarecrow-args', metavar='ARGS', dest='scarecrow_args',
                                help='Optional ScareCrow-specific arguments to pass. They override default ones.')
            parser.add_argument('--scarecrow-loader', metavar='LOADER', choices=['binary', 'control', 'dll', 'excel', 'msiexec', 'wscript'], dest='scarecrow_domain',
                                help='Sets the type of process that will sideload the malicious payload. Default: binary/dll depending on outfile extension.')
            parser.add_argument('--scarecrow-domain', metavar='DOMAIN', dest='scarecrow_domain',
                                help='The domain name to use for creating a fake code signing cert. (e.g. www.acme.com). Default: ' + PackerScareCrow.default_options['scarecrow_domain'])
            parser.add_argument('--scarecrow-valid', metavar='CERT', dest='scarecrow_valid',
                                help='The path to a valid code signing cert. Used instead -domain if a valid code signing cert is desired')
            parser.add_argument('--scarecrow-password', metavar='PASS', dest='scarecrow_password',
                                help='The password for code signing cert. Required when -valid is used')
            parser.add_argument('--scarecrow-inject', metavar='PROCESS', dest='scarecrow_inject',
                                help='Enables Process Injection Mode and specify the path to the process to create/inject into (use \\ for the path)')
            parser.add_argument('--scarecrow-sandbox', action='store_true', dest='scarecrow_sandbox',
                                help='Enables sandbox evasion using IsDomainJoined calls.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerScareCrow.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'scarecrow_path' in self.options.keys() and self.options['scarecrow_path'] != None and len(self.options['scarecrow_path']) > 0:
                self.options['scarecrow_path'] = configPath(self.options['scarecrow_path'])
            else:
                self.options['scarecrow_path'] = PackerScareCrow.default_options['scarecrow_path']

            if 'scarecrow_args' in self.options.keys() and self.options['scarecrow_args'] != None \
                    and len(self.options['scarecrow_args']) > 0:
                self.options['scarecrow_args'] = self.options['scarecrow_args']
                self.scarecrow_args = self.options['scarecrow_args']

            if len(self.options['scarecrow_path']) > 0:
                scarePath = os.path.dirname(self.options['scarecrow_path'])

    @ensureInputFileIsShellcode
    def process(self, arch, infile, outfile):
        cwd = ''
        try:
            if arch != 'x64':
                self.logger.fatal(
                    'ScareCrow works only with x64 shellcodes. Make sure your shellcode file contains "64" in name or use "-a 64" parameter.')

            loader = ''

            if outfile.lower().endswith('.dll'):
                loader = 'dll'
            elif outfile.lower().endswith('.exe'):
                loader = 'binary'

            if len(self.options['scarecrow_loader']) > 0:
                loader = self.options['scarecrow_loader']

                if not outfile.lower().endswith('.js') and not outfile.lower().endswith('.hta'):
                    self.logger.fatal(
                        'When using ScareCrow -Loader different than binary/dll output file must have .js/.hta extension!')

            if self.options['scarecrow_sandbox']:
                self.scarecrow_args += ' -sandbox'
            if len(self.options['scarecrow_inject']) > 0:
                self.scarecrow_args += f' -injection "{self.options["scarecrow_inject"]}"'

            if len(self.options['scarecrow_valid']) > 0:
                self.scarecrow_args += ' -valid ' + \
                    self.options['scarecrow_valid']
                self.scarecrow_args += f' -password "{self.options["scarecrow_password"]}"'
                self.options['scarecrow_sign'] = True

            elif len(self.options['scarecrow_domain']) > 0:
                self.scarecrow_args += ' -domain ' + \
                    self.options['scarecrow_domain']
                self.options['scarecrow_sign'] = True

            if not self.options['scarecrow_sign']:
                self.scarecrow_args += ' -nosign'

            outPath = os.path.dirname(outfile)
            outName = os.path.basename(outfile)

            self.scarecrow_args += f' -O "{outName}" -outpath "{outPath}"'

            if len(loader) > 0:
                self.scarecrow_args += f' -Loader {loader}'

            cwd = os.getcwd()
            base = os.path.dirname(self.options['scarecrow_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            _infile = infile

            if os.name == 'nt' and PackerScareCrow.Run_ScareCrow_On_Windows_As_WSL:
                _infile = os.path.basename(infile)
                shutil.copy(infile, _infile)
                self.options['scarecrow_path'] = './ScareCrow'

            cmd = IPacker.build_cmdline(
                PackerScareCrow.scarecrow_cmdline_template,
                self.options['scarecrow_path'],
                self.scarecrow_args,
                _infile,
                ''
            )

            if os.name == 'nt' and PackerScareCrow.Run_ScareCrow_On_Windows_As_WSL:
                cmd = cmd.replace('"', "'")
                cmd = f"bash -c \"{cmd}\""

            os.environ['PATH'] += os.path.dirname(
                self.options['scarecrow_path'])

            out = shell(self.logger, cmd,
                        output=self.options['verbose'] or self.options['debug'],
                        timeout=self.options['timeout'])

            if os.name == 'nt' and PackerScareCrow.Run_ScareCrow_On_Windows_As_WSL:
                os.remove(_infile)

            m = re.search(r'\[\*\] ([\w\.]+) moved to ', out, re.I)
            if m:
                movedTo = m.group(1)
                shutil.move(movedTo, outfile)

            if os.path.isfile(outfile):
                return True

            else:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    outfile
                ))

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                    self.logger.info(f'''{PackerScareCrow.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from scarecrow:
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

            scarePath = os.path.dirname(self.options['scarecrow_path'])

        return False
