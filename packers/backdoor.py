#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import random
import string
import sys
import os
import tempfile
import pefile


class PackerBackdoor(IPacker):
    default_backdoor_options = ''
    backdoor_cmdline_template = '<command> <options> <savemode>,<runmode> <infile> <backdoor> -o <outfile>'

    metadata = {
        'author': 'Mariusz Banach, @mariuszbit',
        'url': 'https://github.com/Binary-Offensive/ProtectMyTooling',
        'description': 'Backdoors legitimate PE executable with specified shellcode',
        'licensing': 'open-source',
        'type': PackerType.ShellcodeLoader,
        'input': ['Shellcode', ],
        'output': ['PE'],
    }

    default_options = {
        'backdoor_path': f'{sys.executable} {os.path.abspath(os.path.join(os.path.dirname(__file__), "../RedBackdoorer.py"))}',
        'backdoor_args': '',
        'backdoor_save': 1,
        'backdoor_run': 1,
    }

    def __init__(self, logger, options):
        self.logger = logger
        self.backdoor_args = PackerBackdoor.default_backdoor_options
        self.options = options

    @staticmethod
    def get_name():
        return 'backdoor'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--backdoor-path', metavar='PATH', dest='backdoor_path',
                                help='(required) Path to RedBackdoorer.py script.')

            parser.add_argument('-B', '--backdoor-file', metavar='PATH', dest='backdoor_file',
                                help='(required) Legitimate PE file to backdoor.')

            parser.add_argument('--backdoor-save', metavar='MODE', dest='backdoor_save',
                                help='(required) RedBackdoorer Shellcode injection save mode.')

            parser.add_argument('--backdoor-run', metavar='MODE', dest='backdoor_run',
                                help='(required) RedBackdoorer Shellcode run mode.')

            parser.add_argument('--backdoor-args', metavar='ARGS', dest='backdoor_args',
                                help='Optional arguments to pass. They override default ones.')

        else:
            dontCheckExists = False

            if 'backdoor_path' in self.options.keys() and self.options['backdoor_path'] == '':
                self.options['backdoor_path'] = PackerBackdoor.default_options['backdoor_path']
                dontCheckExists = True
            else:
                self.options['backdoor_path'] = os.path.abspath(configPath( self.options['backdoor_path']))

            self.options['backdoor_file'] = os.path.abspath(
                self.options['backdoor_file'])

            if not dontCheckExists and not os.path.isfile(self.options['backdoor_path']):
                self.logger.fatal(
                    'Missing --backdoor-path option! It must point to RedBackdoorer.py script!')

            if not os.path.isfile(self.options['backdoor_file']):
                self.logger.fatal(
                    'Missing -B / --backdoor-file option! It must point to a legitimate PE file that you wish to backdoor.')

            for k, v in PackerBackdoor.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'backdoor_args' in self.options.keys() and self.options['backdoor_args'] != None \
                    and len(self.options['backdoor_args']) > 0:
                self.options['backdoor_args'] = self.options['backdoor_args']
                self.backdoor_args += self.options['backdoor_args']

            if len(self.options['custom_ioc']) > 0:
                self.backdoor_args += ' --ioc "' + \
                    self.options['custom_ioc'] + '"'

    @ensureInputFileIsShellcode
    def process(self, arch, infile, outfile):
        path = self.options['backdoor_path']

        if self.options['debug']:
            self.backdoor_args += ' -v'

        cmd = IPacker.build_cmdline(
            PackerBackdoor.backdoor_cmdline_template,
            path,
            self.backdoor_args,
            infile,
            outfile,
            dontCheckExists=True
        )

        cmd = cmd.replace('<backdoor>', self.options['backdoor_file'])
        cmd = cmd.replace('<savemode>', str(self.options['backdoor_save']))
        cmd = cmd.replace('<runmode>', str(self.options['backdoor_run']))

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
                self.logger.info(f'''{PackerBackdoor.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        return status
