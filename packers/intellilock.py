#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

class PackerIntellilock(IPacker):
    # https://www.eziriz.com/intellilock_online_help/source/command_line.html
    default_intellilock_args = '-ilencryption 1 -controlflow 1 -controlflow_level 5 -unprintable_chars 1 -incremental_obfuscation 1 -include_allparameters 1 -exp_behaviour_all 0 -search_resource 0 -search_hdd 0 -dialog_nolicense 0 -dialog_date 0 -dialog_days 0 -dialog_executions 0 -dialog_runtime 0 -dialog_global 0 -dialog_instances 0 '
    intellilock_cmdline_template = '<command> <options> -file <infile> -destination <outfile>'

    def __init__(self, logger, options):
        self.intellilock_args = PackerIntellilock.default_intellilock_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'INTELLILOCK'

    @staticmethod
    def get_type():
        return PackerType.DotNetObfuscator

    @staticmethod
    def get_desc():
        return '(paid) Eziriz Intellilock is an advanced .Net (x86+x64) assemblies protector.'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--intellilock-path', metavar='PATH', dest='intellilock_path',
                help = '(required) Path to Intellilock executable.')

            parser.add_argument('--intellilock-args', metavar='ARGS', dest='intellilock_args',
                help = 'Optional Intellilock-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['intellilock_path'] = configPath(self.options['config'], self.options['intellilock_path'])

            if not os.path.isfile(self.options['intellilock_path']):
                self.logger.fatal('--intellilock-path option must be specified!')

            if 'intellilock_args' in self.options.keys() and self.options['intellilock_args'] != None \
                and len(self.options['intellilock_args']) > 0: 
                self.intellilock_args += ' ' + self.options['intellilock_args']

    @ensureInputFileIsDotNet
    def process(self, arch, infile, outfile):
        try:
            cwd = os.getcwd()
            base = os.path.dirname(self.options['intellilock_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            self.logger.info("Running Intellilock protector, be patient...")

            out = shell(self.logger, IPacker.build_cmdline(
                PackerIntellilock.intellilock_cmdline_template,
                os.path.basename(self.options['intellilock_path']),
                self.intellilock_args,
                infile,
                outfile
            ), output = self.options['verbose'] or self.options['debug'], timeout = self.options['timeout'])

        except Exception as e:
            raise

        finally:
            self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
            os.chdir(cwd)

        return os.path.isfile(outfile)