#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re
import shutil


class PackerAmber(IPacker):
    default_amber_args = ''
    amber_cmdline_template = '<command> <options> -f <infile>'

    metadata = {
        'author': 'Ege Balci',
        'url': 'https://github.com/EgeBalci/amber',
        'description': 'Takes PE file on input and produces an EXE/PIC shellcode that loads it reflectively in-memory',
        'licensing': 'open-source',
        'type': PackerType.ShellcodeLoader,
        'input': ['PE', ],
        'output': ['EXE', 'Shellcode'],
    }

    default_options = {
    }

    def __init__(self, logger, options):
        self.amber_args = PackerAmber.default_amber_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'Amber'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--amber-path', metavar='PATH', dest='amber_path',
                                help='Path to Amber. By default will look it up in %%PATH%%')

            parser.add_argument('--amber-args', metavar='ARGS', dest='amber_args',
                                help='Optional Amber-specific arguments to pass. They override default ones.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerAmber.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'amber_path' in self.options.keys() and self.options['amber_path'] != None and len(self.options['amber_path']) > 0:
                self.options['amber_path'] = configPath(
                    self.options['config'], self.options['amber_path'])
            else:
                self.options['amber_path'] = PackerAmber.default_options['amber_path']

            if 'amber_args' in self.options.keys() and self.options['amber_args'] != None \
                    and len(self.options['amber_args']) > 0:
                self.options['amber_args'] = self.options['amber_args']
                self.amber_args = self.options['amber_args']

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        try:
            build = False
            if outfile.lower().endswith('.exe') or outfile.lower().endswith('.dll') or \
                    outfile.lower().endswith('.cpl') or outfile.lower().endswith('.xll') or \
                    isValidPE(infile):
                self.amber_args += '-build'
                build = True

            cmd = IPacker.build_cmdline(
                PackerAmber.amber_cmdline_template,
                self.options['amber_path'],
                self.amber_args,
                infile,
                outfile
            )

            if build:
                path, ext = os.path.splitext(infile)
                _outfile = path + '_packed.exe'
            else:
                _outfile = infile + '.bin'

            out = shell(self.logger, cmd,
                        output=self.options['verbose'] or self.options['debug'],
                        timeout=self.options['timeout'])

            if os.path.isfile(_outfile):
                if _outfile != outfile:
                    shutil.move(_outfile, outfile)
                return True

            else:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    _outfile
                ))

                if len(out) > 0:
                    self.logger.info(f'''Amber returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from amber:
----------------------------------------
{e}
----------------------------------------
''')

        except Exception as e:
            raise

        return False
