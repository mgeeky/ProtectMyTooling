#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import random
import string
import os
import tempfile
import textwrap


class PackerMangle(IPacker):
    default_mangle_args = ''
    mangle_cmdline_template = '<command> <options> -I <infile> -O <outfile>'

    metadata = {
        'author': 'Matt Eidelberg (@Tyl0us)',
        'url': 'https://github.com/optiv/Mangle',
        'description': 'Takes input EXE/DLL file and produces output one with cloned certificate, removed Golang-specific IoCs and bloated size',
        'licensing': 'open-source',
        'type': PackerType.ExeSigner,
        'input': ['PE', ],
        'output': ['PE', ],
    }

    default_options = {
        'mangle_strip_go': True,
        'mangle_increase': 0,
        'mangle_certificate': 'excel',
    }

    def __init__(self, logger, options):
        self.mangle_args = PackerMangle.default_mangle_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'Mangle'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--mangle-path', metavar='PATH',
                                dest='mangle_path', help='(required) Path to Mangle executable.')
            parser.add_argument('--mangle-strip-go', action='store_true',
                                dest='mangle_path', help='Edit the PE file to strip out Go indicators')
            parser.add_argument('--mangle-increase', metavar='MBs', type=int,
                                dest='mangle_path', help='How many MBs to increase the file by')
            parser.add_argument('--mangle-certificate', metavar='executable', dest='mangle_path',
                                help='Path to the file containing the certificate you want to clone.')
        else:
            self.options['mangle_path'] = os.path.abspath(configPath( self.options['mangle_path']))

            if len(self.options['mangle_certificate']) > 0:
                self.options['mangle_certificate'] = os.path.abspath(
                    self.options['mangle_certificate'])

            for k, v in PackerMangle.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if not os.path.isfile(self.options['mangle_path']):
                self.logger.fatal('--mangle-path option must be specified!')

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):

        sigcheck = os.path.join(os.path.dirname(
            self.options['mangle_path']), 'sigcheck.exe')

        sigcheckExists = os.path.isfile(sigcheck)

        if len(self.options['mangle_certificate']) > 0:
            if os.path.isfile(self.options['mangle_certificate']):
                PackerMangle.default_mangle_args += f" -C \"{self.options['mangle_certificate']}\""
            else:
                self.logger.fatal(
                    f"Specified mangle_certificate executable does not exist:\n\t{self.options['mangle_certificate']}")

        if sigcheckExists:
            out = shell(self.logger, f"{sigcheck} -h \"{infile}\"")
            out = textwrap.indent(out, '\t')

            self.logger.info(f'''
------------
Sysinternals Sigcheck input file signature BEFORE running Mangle:

{out}
------------
''')

        if self.options['mangle_strip_go']:
            PackerMangle.default_mangle_args += ' -M'
        if self.options['mangle_increase'] > 0:
            PackerMangle.default_mangle_args += f" -S {self.options['mangle_increase']}"

        cmd = IPacker.build_cmdline(
            PackerMangle.mangle_cmdline_template,
            self.options['mangle_path'],
            PackerMangle.default_mangle_args,
            infile,
            outfile
        )

        out = shell(self.logger, cmd,
                    output=self.options['verbose'] or self.options['debug'],
                    timeout=self.options['timeout'])

        status = os.path.isfile(outfile)

        if not status:
            self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                outfile
            ))

            if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                self.logger.info(f'''{PackerMangle.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        else:
            if sigcheckExists:
                out = shell(self.logger, f"{sigcheck} -h \"{outfile}\"")
                out = textwrap.indent(out, '\t')

                self.logger.info(f'''
------------
Sysinternals Sigcheck input file signature AFTER running Mangle:

{out}
------------
''')

        return os.path.isfile(outfile)
