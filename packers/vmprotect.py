#!/usr/bin/python3
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import sys, re
import shutil

from IPacker import IPacker
from lib.utils import *

class PackerVMProtect(IPacker):
    default_vmprotect_args = ''
    vmprotect_cmdline_template = '<command> <infile> <outfile> <options>'

    def __init__(self, logger, options):
        self.vmprotect_args = PackerVMProtect.default_vmprotect_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'VMProtect'

    @staticmethod
    def get_desc():
        return '(paid) VMProtect protects x86/x64 code by virtualizing it in complex VM environments.'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--vmprotect-path', metavar='PATH', dest='vmprotect_path',
                help = '(required) Path to vmprotect executable.')

            parser.add_argument('--vmprotect-project-file', metavar='PATH', dest='vmprotect_project_file',
                help = '(required) Path to .NET Reactor .nrproj project file.')

            parser.add_argument('--vmprotect-args', metavar='ARGS', dest='vmprotect_args',
                help = 'Optional vmprotect-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['vmprotect_path'] = configPath(self.options['config'], self.options['vmprotect_path'])
            self.options['vmprotect_project_file'] = os.path.abspath(configPath(self.options['config'], self.options['vmprotect_project_file']))

            if not os.path.isfile(self.options['vmprotect_path']):
                self.logger.fatal('--vmprotect-path option must be specified!')

            if 'vmprotect_args' in self.options.keys() and self.options['vmprotect_args'] != None \
                and len(self.options['vmprotect_args']) > 0: 
                self.vmprotect_args += ' ' + self.options['vmprotect_args']

    def process(self, arch, infile, outfile):
        try:
            cwd = os.getcwd()
            base = os.path.dirname(self.options['vmprotect_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            out = shell(self.logger, IPacker.build_cmdline(
                PackerVMProtect.vmprotect_cmdline_template,
                os.path.basename(self.options['vmprotect_path']),
                self.vmprotect_args + ' -pf "{}"'.format(self.options['vmprotect_project_file']),
                infile,
                outfile
            ), output = self.options['verbose'] or self.options['debug'], timeout = self.options['timeout'])

        except Exception as e:
            raise

        finally:
            self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
            os.chdir(cwd)

        return os.path.isfile(outfile)