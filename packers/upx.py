#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

class PackerUpx(IPacker):
    default_upx_args = ''
    upx_cmdline_template = '<command> <options> -o <outfile> <infile>'

    default_options = {
        'upx_compress': 'best',
    }

    def __init__(self, logger, options):
        self.upx_args = PackerUpx.default_upx_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'UPX'

    @staticmethod
    def get_desc():
        return 'Universal PE Executables Compressor - highly reliable, works with x86 & x64.'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--upx-path', metavar='PATH', dest='upx_path',
                help = '(required) Path to UPX binary capable of compressing x86/x64 executables.')

            parser.add_argument('--upx-compress', metavar='LEVEL', dest='upx_compress', default = '',
                help = 'Compression level [1-9]: 1 - compress faster, 9 - compress better. Can also be "best" for greatest compression level possible.')

            parser.add_argument('--upx-args', metavar='ARGS', dest='upx_args',
                help = 'Optional UPX-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['upx_path'] = configPath(self.options['config'], self.options['upx_path'])

            if not os.path.isfile(self.options['upx_path']):
                self.logger.fatal('--upx-path option must be specified!')

            for k, v in PackerUpx.default_options.items():
                if k not in self.options.keys():
                    self.options[k] = v

            try:
                level = self.options['upx_compress']

                if level == '':
                    self.upx_args += ' '
                elif level == 'best':
                    self.upx_args += ' --best'
                else:
                    level = int(self.options['upx_compress'])

                    if level < 1 or level > 9:
                        raise ValueError

                    self.upx_args += ' -{}'.format(level)

            except ValueError:
                self.logger.fatal('--upx-compress level must be <1-9> or "best"!') 

            if 'upx_args' in self.options.keys() and self.options['upx_args'] != None \
                and len(self.options['upx_args']) > 0: 
                self.upx_args += ' ' + self.options['upx_args']

    def process(self, arch, infile, outfile):
        ver = shell(self.logger, self.options['upx_path'] + ' --version').split('\n')[0].strip()

        self.logger.info(f'Working with {ver}')

        out = shell(self.logger, IPacker.build_cmdline(
            PackerUpx.upx_cmdline_template,
            self.options['upx_path'],
            self.upx_args,
            infile,
            outfile
        ))

        return os.path.isfile(outfile)