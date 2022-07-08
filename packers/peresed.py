#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re
import sys
import pe_tools


class PackerPeresed(IPacker):
    default_peresed_args = '--clear --print-tree --print-version --ignore-trailer --remove-signature'
    peresed_cmdline_template = '<command> <options> --output <outfile> <infile>'

    metadata = {
        'author': 'Martin Vejnár, Avast',
        'url': 'https://github.com/avast/pe_tools',
        'licensing': 'open-source',
        'description': 'Removes all existing PE Resources and signature (think of Mimikatz icon)',
        'type': PackerType.PEProtector,
        'input': ['PE', ],
        'output': ['PE', ],
    }

    default_options = {
        'peresed_path': f'{sys.executable} -m pe_tools.peresed',
    }

    def __init__(self, logger, options):
        self.peresed_args = PackerPeresed.default_peresed_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'Peresed'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--peresed-path', metavar='PATH', dest='peresed_path',
                                help='Path to peresed. By default will look it up in %%PATH%%')

            parser.add_argument('--peresed-args', metavar='ARGS', dest='peresed_args',
                                help='Optional peresed-specific arguments to pass. They override default ones.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerPeresed.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'peresed_path' in self.options.keys() and self.options['peresed_path'] != None and len(self.options['peresed_path']) > 0 \
                    and self.options['peresed_path'] != PackerPeresed.default_options['peresed_path']:
                self.options['peresed_path'] = configPath(
                    self.options['config'], self.options['peresed_path'])
            else:
                self.options['peresed_path'] = PackerPeresed.default_options['peresed_path']

            if 'peresed_args' in self.options.keys() and self.options['peresed_args'] != None \
                    and len(self.options['peresed_args']) > 0:
                self.options['peresed_args'] = self.options['peresed_args']
                self.peresed_args = self.options['peresed_args']

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        cwd = ''
        try:
            cwd = os.getcwd()
            base = os.path.dirname(infile)

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            cmd = IPacker.build_cmdline(
                PackerPeresed.peresed_cmdline_template,
                self.options['peresed_path'],
                self.peresed_args,
                infile,
                outfile,
                dontCheckExists=True
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

                if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                    self.logger.info(f'''{PackerPeresed.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from packer:
----------------------------------------
{e}
----------------------------------------
''')

        except Exception as e:
            raise

        finally:
            if len(cwd) > 0:
                self.logger.dbg(
                    'reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

        return False
