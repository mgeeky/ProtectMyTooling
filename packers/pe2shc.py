#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import random
import string
import os
import tempfile
import pefile


class PackerPe2shc(IPacker):
    default_pe2shc_args = ''
    pe2shc_cmdline_template = '<command> <infile> <outfile>'

    metadata = {
        'author': '@hasherezade',
        'url': 'https://github.com/hasherezade/pe_to_shellcode',
        'licensing': 'open-source',
        'description': 'takes PE EXE/DLL and produces PIC shellcode',
        'type': PackerType.ShellcodeConverter,
        'input': ['PE', ],
        'output': ['Shellcode', ],
    }

    default_options = {
    }

    def __init__(self, logger, options):
        self.pe2shc_args = PackerPe2shc.default_pe2shc_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'pe2shc'

    @staticmethod
    def get_desc():
        return 'takes PE EXE/DLL and produces PIC shellcode'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--pe2shc-path', metavar='PATH', dest='pe2shc_path',
                                help='(required) Path to Pe2shc executable.')

        else:
            self.options['pe2shc_path'] = os.path.abspath(configPath( self.options['pe2shc_path']))

            if not os.path.isfile(self.options['pe2shc_path']):
                self.logger.fatal('--pe2shc-path option must be specified!')

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        cmd = IPacker.build_cmdline(
            PackerPe2shc.pe2shc_cmdline_template,
            self.options['pe2shc_path'],
            '',
            infile,
            outfile
        )

        out = shell(self.logger, cmd,
                    output=self.options['verbose'] or self.options['debug'],
                    timeout=self.options['timeout']
                    )

        status = os.path.isfile(outfile)

        if not status:
            self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                outfile
            ))

            if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                self.logger.info(f'''{PackerPe2shc.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        return status
