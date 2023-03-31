#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *


class PackerLogicNet(IPacker):
    default_LogicNet_args = ''
    LogicNet_cmdline_template = '<command> <infile> <outfile>'

    metadata = {
        'author': ['AnErrupTion', 'klezVirus'],
        'url': 'https://github.com/AnErrupTion/LoGiC.NET',
        'licensing': 'open-source',
        'description': 'Free and open .NET obfuscator using dnlib',
        'type': PackerType.DotNetObfuscator,
        'input': ['.NET', ],
        'output': ['.NET', ],
    }

    def __init__(self, logger, options):
        self.LogicNet_args = PackerLogicNet.default_LogicNet_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'LoGiC.NET'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--logicnet-path', metavar='PATH', dest='logicnet_path',
                                help='(required) Path to LogicNet executable.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['logicnet_path'] = configPath( self.options['logicnet_path'])

            if not os.path.isfile(self.options['logicnet_path']):
                self.logger.fatal('--LogicNet-path option must be specified!')

    @ensureInputFileIsDotNet
    def process(self, arch, infile, outfile):
        out = ''
        cwd = ''
        try:
            cwd = os.getcwd()
            base = os.path.dirname(self.options['logicnet_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            self.logger.info("Running LogicNet protector, be patient...")

            out = shell(self.logger, IPacker.build_cmdline(
                PackerLogicNet.LogicNet_cmdline_template,
                os.path.basename(self.options['logicnet_path']),
                '',
                infile,
                outfile
            ), output=self.options['verbose'] or self.options['debug'], timeout=self.options['timeout'])

        except Exception as e:
            raise

        finally:
            if len(cwd) > 0:
                self.logger.dbg(
                    'reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

        status = os.path.isfile(outfile)

        if not status:
            self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                outfile
            ))

            if len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                self.logger.info(f'''{PackerLogicNet.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

        return status
