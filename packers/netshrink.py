#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

class PackerNetshrink(IPacker):
    # attached .NetShrink CHM help file -> Command Line
    default_netshrink_args = '/CheckNetBoxTitle="" /CheckNetBoxMessage=""'
    netshrink_cmdline_template = '<command> <options> /InputFilePath=<infile> /OutputFilePath=<outfile>'

    default_options = {
        'netshrink_antidebug': True,
    }

    def __init__(self, logger, options):
        self.netshrink_args = PackerNetshrink.default_netshrink_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return '.Netshrink'

    @staticmethod
    def get_type():
        return PackerType.DotNetObfuscator

    @staticmethod
    def get_desc():
        return '(paid) PELock .netshrink is an .Net EXE packer with anti-cracking feautres and LZMA compression'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--netshrink-path', metavar='PATH', dest='netshrink_path',
                help = '(required) Path to netshrink executable.')

            parser.add_argument('--netshrink-detect-netversion', metavar='VER', dest='netshrink_detect_netversion',
                help = 'Enable .NET Framework installation detection (default: .NET v2.0). Example: ".NET v4.5"')

            parser.add_argument('--netshrink-antidebug', metavar='bool', type=int, choices=range(0, 2), dest='netshrink_antidebug', 
                help = 'Enable Anti-Debug checks and prevent output from running under debugger. Valid values: 0/1. Default: 1')

            parser.add_argument('--netshrink-args', metavar='ARGS', dest='netshrink_args',
                help = 'Optional netshrink-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['netshrink_path'] = configPath(self.options['config'], self.options['netshrink_path'])

            for k, v in PackerNetshrink.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if self.options['netshrink_antidebug'] not in [0, 1]:
                self.logger.fatal('The --netshrink-antidebug value must be either 0 or 1!')

            if not os.path.isfile(self.options['netshrink_path']):
                self.logger.fatal('--netshrink-path option must be specified!')

            if 'netshrink_args' in self.options.keys() and self.options['netshrink_args'] != None \
                and len(self.options['netshrink_args']) > 0: 
                self.netshrink_args += ' ' + self.options['netshrink_args']

            if self.options['netshrink_antidebug'] == 1:
                self.netshrink_args += ' /Antidebug'

    @ensureInputFileIsDotNet
    def process(self, arch, infile, outfile):

        out = shell(self.logger, IPacker.build_cmdline(
            PackerNetshrink.netshrink_cmdline_template,
            self.options['netshrink_path'],
            self.netshrink_args,
            infile,
            outfile
        ), output = self.options['verbose'] or self.options['debug'], timeout = self.options['timeout'])

        status = os.path.isfile(outfile)

        if not status:
            self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                outfile
            ))

            if len(out) > 0 and not (self.options['verbose'] or self.options['debug']): self.logger.info(f'''{PackerNetshrink.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced = True, noprefix=True)

        return status