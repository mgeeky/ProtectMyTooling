#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import random
import string
import os
import tempfile
import shutil
import pefile

class PackerPEunion(IPacker):
    default_peunion_args = ' -s -m'
    peunion_cmdline_template = '<command> <infile> <outfile> -d'

    metadata = {
        'author': 'Martin Fischer / bytecode77 <mail@martinfischer.it>',
        'url': 'https://bytecode77.com/pe-union',
        'description': 'Encrypts executables (x86 or .NET x86/x64), which are decrypted at runtime and executed in-memory',
        'licensing': 'freeware',
        'type': PackerType.PECompressor,
        'input': ['PE', '.NET'],
        'output': ['PE', ],
    }

    default_options = {
    }

    def __init__(self, logger, options):
        self.peunion_args = PackerPEunion.default_peunion_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'PEunion'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--peunion-path', metavar='PATH',
                                dest='peunion_path', help='(required) Path to PEunion peubuild.exe executable.')

            parser.add_argument('--peunion-native86-project-path', metavar='PATH',
                                dest='peunion_native86_project_path', help='(required) Path to PEunion Native x86 (RunPE) build project (.peu).')

            parser.add_argument('--peunion-dotnet86-project-path', metavar='PATH',
                                dest='peunion_dotnet86_project_path', help='(required) Path to PEunion .NET x86 (Invoke) build project (.peu).')

            parser.add_argument('--peunion-dotnet64-project-path', metavar='PATH',
                                dest='peunion_dotnet64_project_path', help='(required) Path to PEunion .NET x64 (Invoke) build project (.peu).')

        else:
            self.options['peunion_path'] = os.path.abspath(configPath(self.options['peunion_path']))

            if not os.path.isfile(self.options['peunion_path']):
                self.logger.fatal('--peunion-path option must be specified!')

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        path, ext = os.path.splitext(infile)

        cwd = ''
        peudir = ''
        newinfile = ''

        try:
            cwd = os.getcwd()
            base = os.path.dirname(path)

            dotnet = isDotNetExecutable(infile)
            exe = isValidPE(infile)

            projectPath = ''
            if dotnet:
                if arch == 'x86': 
                    projectPath = self.options.get('peunion_dotnet86_project_path', '')
                elif arch == 'x64': 
                    projectPath = self.options.get('peunion_dotnet64_project_path', '')
            else:
                if arch == 'x86': 
                    projectPath = self.options.get('peunion_native86_project_path', '')
                elif arch == 'x64': 
                    self.logger.fatal('PEunion does not support Native x64 executables. It can only work with x86 native Executables & .NET x86/x64')

            tpl = ''
            with open(projectPath, 'r', encoding='utf8') as f:
                outlines = []
                for line in f.readlines():
                    line = line.strip()
                    if len(line) == 0 or '=' not in line:
                        outlines.append(line)

                    else:
                        parts = [x.strip() for x in line.split('=')]

                        if len(parts) > 2:
                            self.logger.fatal(f'Invalid project specification. It was supposed to contain only one "=" equal sign.')

                        if parts[0].lower() == 'path':
                            parts[1] = infile

                        outlines.append(' = '.join([x.strip() for x in parts]))

                tpl = '\n'.join(outlines)

            newinfile = ''
            peudir = os.path.join(os.path.dirname(newinfile), '.peu')

            with tempfile.NamedTemporaryFile(delete=False, suffix='.peu') as tmp:

                newinfile = tmp.name
                tmp.write(tpl.encode())

            self.logger.dbg(f'Project written to file: {newinfile}')
            self.logger.dbg(f'''
------------------------------------------------
{tpl}
------------------------------------------------
''')

            cmd = IPacker.build_cmdline(
                PackerPEunion.peunion_cmdline_template,
                self.options['peunion_path'],
                PackerPEunion.default_peunion_args,
                newinfile,
                outfile
            )

            out = shell(self.logger, cmd,
                        output=self.options['verbose'] or self.options['debug'],
                        timeout=self.options['timeout']
                        )

            tmpoutfile = os.path.join(os.path.dirname(newinfile), os.path.basename(infile))
            if os.path.isfile(tmpoutfile):
                shutil.move(tmpoutfile, outfile)

            status = os.path.isfile(outfile)

            if not status:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    outfile
                ))

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                    self.logger.info(f'''{PackerPEunion.get_name()} returned:
    ----------------------------------------
    {out}
    ----------------------------------------
    ''', forced=True, noprefix=True)

            else:
                shutil.move(newinfile, outfile)

            return os.path.isfile(outfile)

        except Exception as e:
            raise

        finally:
            if len(newinfile) > 0 and os.path.isfile(newinfile):
                os.remove(newinfile)

            if len(peudir) > 0 and os.path.isdir(peudir):
                shutil.rmtree(peudir)

            if len(cwd) > 0:
                self.logger.dbg(
                    'reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

        status = os.path.isfile(outfile)

        if not status:
            self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                outfile
            ))

            if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                self.logger.info(f'''{PackerPEunion.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        return status

