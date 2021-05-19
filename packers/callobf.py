#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import string
import os, tempfile
import pefile

class PackerCallObf(IPacker):
    default_callobf_args = ''
    callobf_cmdline_template = '<command> <infile> <outfile>'

    default_options = {
    }

    def __init__(self, logger, options):
        self.callobf_args = PackerCallObf.default_callobf_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'CallObf'

    @staticmethod
    def get_desc():
        return '(CallObfuscator) Handy tool to obscure PE imported calls by hiding dangerous calls behind innocuous ones.'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--callobf-path-x86', metavar='PATH', dest='callobf_path_x86',
                help = '(required) Path to CallObfuscator x86 executable.')

            parser.add_argument('--callobf-path-x64', metavar='PATH', dest='callobf_path_x64',
                help = '(required) Path to CallObfuscator x64 executable.')

            parser.add_argument('--callobf-config', metavar='PATH', dest='callobf_config', default = '',
                help = 'Custom config file for CallObfuscator. If "generate-automatically" is specified, a config file will be created randomly by ProtectMyTooling')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['callobf_path_x86'] = configPath(self.options['config'], self.options['callobf_path_x86'])
            self.options['callobf_path_x64'] = configPath(self.options['config'], self.options['callobf_path_x64'])

            if not os.path.isfile(self.options['callobf_path_x86']) or not os.path.isfile(self.options['callobf_path_x64']):
                self.logger.fatal('Both --callobf-path-x86 and --calobf-path-x64 option must be specified!')

            if self.options['callobf_config'] != 'generate-automatically':
                if not os.path.isfile(self.options['callobf_config']):
                    self.logger.fatal('--callobf-config option must be specified!')

                self.options['callobf_config'] = os.path.abspath(configPath(self.options['config'], self.options['callobf_config']))

    def generateConfigFile(self):
        configPath = ''
        config = ''

        dodgyFunctions = {}
        beningFunctions = {}

        #with open('')

        tmp = tempfile.NamedTemporaryFile(delete=False)

        try:
            tmp.write(config)
        finally:
            tmp.close()

        return configPath

    def process(self, arch, infile, outfile):
        configPath = self.options['callobf_config']
        autoGen = False

        if configPath == 'generate-automatically':
            autoGen = True
            configPath = self.generateConfigFile()

        path = self.options['callobf_path_x86']
        if arch == 'x64':
            path = self.options['callobf_path_x64']

        cmd = IPacker.build_cmdline(
            PackerCallObf.callobf_cmdline_template,
            path,
            '',
            infile,
            outfile
        )

        cmd += f' "{configPath}"' 

        out = shell(self.logger, cmd, 
            output = self.options['verbose'] or self.options['debug'], 
            timeout = self.options['timeout']
        )

        if(autoGen):
            os.unlink(configPath)

        return os.path.isfile(outfile)
