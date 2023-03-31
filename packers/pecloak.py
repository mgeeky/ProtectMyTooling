#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import re
import pefile

from IPacker import IPacker
from shutil import copyfile, move
from lib.utils import *


class PackerPeCloak(IPacker):
    default_pecloak_args = '-H 25'
    pecloak_cmdline_template = '<command> <options> <outfile>'

    metadata = {
        'author': ['Mike Czumak, @SecuritySift', 'buherator / v-p-b'],
        'url': 'https://github.com/v-p-b/peCloakCapstone/blob/master/peCloak.py',
        'licensing': 'open-source',
        'description': 'A Multi-Pass x86 PE Executables encoder. Requires Python 2.7',
        'type': PackerType.PEProtector,
        'input': ['PE', ],
        'output': ['PE', ],
    }

    def __init__(self, logger, options):
        self.pecloak_args = PackerPeCloak.default_pecloak_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'peCloak'

    @staticmethod
    def get_desc():
        return 'A Multi-Pass x86 PE Executables encoder. Requires Python 2.7'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--pecloak-python-path', metavar='PATH', dest='pecloak_python_path',
                                help='(required) Path to Python2.7 interpreter.')

            parser.add_argument('--pecloak-script-path', metavar='PATH', dest='pecloak_script_path',
                                help='(required) Path to peCloakCapstone script file.')

            parser.add_argument('--pecloak-args', metavar='ARGS', dest='pecloak_args',
                                help='Optional peCloakCapstone-specific arguments to pass during cloaking.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['pecloak_python_path'] = configPath( self.options['pecloak_python_path'])
            self.options['pecloak_script_path'] = configPath( self.options['pecloak_script_path'])

            if not os.path.isfile(self.options['pecloak_python_path']) or not os.path.isfile(self.options['pecloak_script_path']):
                self.logger.fatal(
                    'Both --pecloak-python-path and --pecloak-script-path options must be specified!')

            if 'pecloak_args' in self.options.keys() and self.options['pecloak_args'] != None \
                    and len(self.options['pecloak_args']) > 0:
                self.pecloak_args += ' ' + self.options['pecloak_args']

    def buildArgs(self, infile):
        pass

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):

        if arch != 'x86':
            #raise ArchitectureNotSupported('peCloak supports only x86 binaries!')
            self.logger.fatal('peCloak supports only x86 PE executables!')

        cwd = os.getcwd()
        base = os.path.dirname(self.options['pecloak_script_path'])

        command = '"{}" "{}"'.format(
            self.options['pecloak_python_path'],
            os.path.basename(self.options['pecloak_script_path']),
        )

        succeeded = False
        out = ''

        try:
            copyfile(infile, outfile)
            self.buildArgs(infile)

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            out = shell(self.logger, IPacker.build_cmdline(
                PackerPeCloak.pecloak_cmdline_template,
                command,
                self.pecloak_args,
                '',
                outfile,
                dontCheckExists=True
            ), output=self.options['verbose'] or self.options['debug'], timeout=self.options['timeout'])
            succeeded = True

        except ShellCommandReturnedError as e:
            foo = 'SectionDoubleP.SectionDoublePError: No more space can be added for the section header.'

            if foo in str(e):
                try:
                    self.logger.info(
                        'Re-running peCloak with option to add a new section for a code cave...')
                    out = shell(self.logger, IPacker.build_cmdline(
                        PackerPeCloak.pecloak_cmdline_template,
                        command,
                        self.pecloak_args + ' -a',
                        '',
                        outfile
                    ), output=self.options['verbose'] or self.options['debug'], timeout=self.options['timeout'])
                    succeeded = True

                except ShellCommandReturnedError as e:
                    if foo in str(e):
                        raise
            else:
                raise

        finally:
            if len(cwd) > 0:
                self.logger.dbg(
                    'reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

        if succeeded:
            pat = re.compile(r'New file saved \[([^\]]+)\]')
            m = pat.search(out)
            succeeded = False

            if m:
                tmpoutfile = m.group(1)
                self.logger.dbg(
                    'Extracted output file path: "{}"'.format(tmpoutfile))

                move(tmpoutfile, outfile)
                succeeded = True

        if not succeeded:
            self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                outfile
            ))

            if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                self.logger.info(f'''{PackerPeCloak.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        return succeeded
