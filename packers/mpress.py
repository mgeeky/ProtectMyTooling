#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import random
import string
import os
import tempfile
import pefile


class PackerMPRESS(IPacker):
    default_mpress_args = ' -s -m'
    mpress_cmdline_template = '<command> <options> <infile>'

    metadata = {
        'author': 'Vitaly Evseenko',
        'url': 'https://www.autohotkey.com/mpress/mpress_web.htm',
        'description': 'Takes input EXE/DLL/.NET/MAC-DARWIN (x86/x64) and compresses it',
        'licensing': 'freeware',
        'type': PackerType.PECompressor,
        'input': ['PE', ],
        'output': ['PE', ],
    }

    default_options = {
    }

    def __init__(self, logger, options):
        self.mpress_args = PackerMPRESS.default_mpress_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'MPRESS'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--mpress-path', metavar='PATH',
                                dest='mpress_path', help='(required) Path to MPRESS executable.')

        else:
            self.options['mpress_path'] = os.path.abspath(configPath(
                self.options['config'], self.options['mpress_path']))

            if not os.path.isfile(self.options['mpress_path']):
                self.logger.fatal('--mpress-path option must be specified!')

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        path, ext = os.path.splitext(infile)

        temp = tempfile.NamedTemporaryFile(delete=False)
        newinfile = temp.name + ext
        shutil.copy(infile, newinfile)

        cmd = IPacker.build_cmdline(
            PackerMPRESS.mpress_cmdline_template,
            self.options['mpress_path'],
            PackerMPRESS.default_mpress_args,
            newinfile,
            ''
        )

        out = shell(self.logger, cmd,
                    output=self.options['verbose'] or self.options['debug'],
                    timeout=self.options['timeout']
                    )

        status = os.path.isfile(newinfile)

        if not status:
            self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                outfile
            ))

            if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                self.logger.info(f'''{PackerMPRESS.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        else:
            shutil.move(newinfile, outfile)

        return os.path.isfile(outfile)
