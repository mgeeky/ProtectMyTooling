#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import random
import string
import os, tempfile
import pefile

#
# Name:   jadams/Packer64 
# URL:    https://github.com/jadams/Packer64
# Author: John Adams, @jadams
#

class PackerPacker64(IPacker):
    default_packer64_args = ''
    packer64_cmdline_template = '<command> <infile> <outfile>'

    default_options = {
    }

    def __init__(self, logger, options):
        self.packer64_args = PackerPacker64.default_packer64_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'packer64'

    @staticmethod
    def get_desc():
        return 'jadams/Packer64 - Packer for 64-bit PE exes'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--packer64-path', metavar='PATH', dest='packer64_path',
                help = '(required) Path to Packer64 executable.')

        else:
            self.options['packer64_path'] = os.path.abspath(configPath(self.options['config'], self.options['packer64_path']))

            if not os.path.isfile(self.options['packer64_path']):
                self.logger.fatal('--packer64-path option must be specified!')

    def process(self, arch, infile, outfile):

        if arch != 'x64':
            #raise ArchitectureNotSupported('Packer64 supports only x64 binaries!')
            self.logger.fatal('Packer64 supports only x64 PE executables!')

        path = self.options['packer64_path']

        cmd = IPacker.build_cmdline(
            PackerPacker64.packer64_cmdline_template,
            path,
            '',
            infile,
            outfile
        )

        cwd = os.getcwd()
        os.chdir(os.path.dirname(path))

        out = shell(self.logger, cmd, 
            output = self.options['verbose'] or self.options['debug'], 
            timeout = self.options['timeout']
        )

        os.chdir(cwd)

        return os.path.isfile(outfile)
