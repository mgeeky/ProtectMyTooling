#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re
import shutil


class PackerSgn(IPacker):
    default_sgn_args = '-a <arch> -c <rounds> -max <max>'
    sgn_cmdline_template = '<command> <options> -o <outfile> <infile>'

    metadata = {
        'author': 'Ege Balci',
        'url': 'https://github.com/EgeBalci/sgn',
        'licensing': 'open-source',
        'description': 'Shikata ga nai (仕方がない) encoder ported into go with several improvements. Takes shellcode, produces encoded shellcode',
        'type': PackerType.ShellcodeEncoder,
        'input': ['Shellcode', ],
        'output': ['Shellcode', ],
    }

    default_options = {
        'sgn_path': '',
        'sgn_rounds': 1,
        'sgn_max': 20,
    }

    def __init__(self, logger, options):
        self.sgn_args = PackerSgn.default_sgn_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'sgn'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--sgn-path', metavar='PATH', dest='sgn_path',
                                help='Path to Sgn. By default will look it up in %%PATH%%')

            parser.add_argument('--sgn-args', metavar='ARGS', dest='sgn_args',
                                help='Optional Sgn-specific arguments to pass. They override default ones.')

            parser.add_argument('--sgn-rounds', metavar='NUM', type=int, dest='sgn_rounds',
                                help='Number of times to encode the binary (increases overall size) (default 1)')
            parser.add_argument('--sgn-max', metavar='NUM', type=int, dest='sgn_max',
                                help='Maximum number of bytes for obfuscation (default 20)')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerSgn.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'sgn_path' in self.options.keys() and self.options['sgn_path'] != None and len(self.options['sgn_path']) > 0:
                self.options['sgn_path'] = configPath(
                    self.options['config'], self.options['sgn_path'])
            else:
                self.options['sgn_path'] = PackerSgn.default_options['sgn_path']

            if 'sgn_args' in self.options.keys() and self.options['sgn_args'] != None \
                    and len(self.options['sgn_args']) > 0:
                self.options['sgn_args'] = self.options['sgn_args']
                self.sgn_args = self.options['sgn_args']

    @ensureInputFileIsShellcode
    def process(self, arch, infile, outfile):
        try:
            if arch == 'x86':
                _arch = 32
            elif arch == 'x64':
                _arch = 64

            self.sgn_args = self.sgn_args.replace('<arch>', str(_arch))

            if self.options['debug']:
                self.sgn_args += ' -v'

            self.sgn_args = self.sgn_args.replace(
                '<max>', str(self.options['sgn_max']))
            self.sgn_args = self.sgn_args.replace(
                '<rounds>', str(self.options['sgn_rounds']))

            cmd = IPacker.build_cmdline(
                PackerSgn.sgn_cmdline_template,
                self.options['sgn_path'],
                self.sgn_args,
                infile,
                outfile
            )

            out = shell(self.logger, cmd,
                        output=self.options['verbose'] or self.options['debug'],
                        timeout=self.options['timeout'])

            if os.path.isfile(outfile):
                return True

            else:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    outfile
                ))

                if len(out) > 0:
                    self.logger.info(f'''Sgn returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from sgn:
----------------------------------------
{e}
----------------------------------------
''')

        except Exception as e:
            raise

        return False
