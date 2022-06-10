#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

class PackerThemida(IPacker):
    default_themida_args = '/shareconsole'
    themida_cmdline_template = '<command> <options> /inputfile <infile> /outputfile <outfile>'

    def __init__(self, logger, options):
        self.themida_args = PackerThemida.default_themida_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'Themida'

    @staticmethod
    def get_type():
        return PackerType.PEProtector

    @staticmethod
    def get_desc():
        return '(paid) Advanced x86/x64 PE Executables virtualizer, compressor, protector and binder.'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--themida-path-x86', metavar='PATH', dest='themida_path_x86',
                help = '(required) Path to Themida x86 executable.')

            parser.add_argument('--themida-path-x64', metavar='PATH', dest='themida_path_x64',
                help = '(required) Path to Themida x64 executable.')

            parser.add_argument('--themida-project-file', metavar='PATH', dest='themida_project_file',
                help = '(required) Path to Themida .tmd project file.')

            parser.add_argument('--themida-args', metavar='ARGS', dest='themida_args',
                help = 'Optional themida-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['themida_path_x86'] = configPath(self.options['config'], self.options['themida_path_x86'])
            self.options['themida_path_x64'] = configPath(self.options['config'], self.options['themida_path_x64'])
            self.options['themida_project_file'] = os.path.abspath(configPath(self.options['config'], self.options['themida_project_file']))

            if not os.path.isfile(self.options['themida_path_x86']) or not os.path.isfile(self.options['themida_path_x64']):
                self.logger.err('Both options --themida-path-x86 and --themida-path-x64 must be specified!')

            if not os.path.isfile(self.options['themida_project_file']):
                self.logger.fatal('You must specify existing --themida-project-file project file (.tmd) that will be reused for subsequent samples!')

            if 'themida_args' in self.options.keys() and self.options['themida_args'] != None \
                and len(self.options['themida_args']) > 0: 
                self.themida_args += ' ' + self.options['themida_args']

    @ensureInputFileIsPE
    def process(self, arch, infile, outfile):
        path = self.options['themida_path_x86']
        if arch == 'x64':
            path = self.options['themida_path_x64']

        if not path:
            self.logger.fatal('Architecture {} not supported as there was no corresponding Themida Protector path configured!\nPlease configure it using: --themida-path-{}'.format(arch, arch))

        try:
            cwd = os.getcwd()
            base = os.path.dirname(path)

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            project = self.options['themida_project_file']

            self.logger.info("Running Themida protector, heavy computations ahead, be patient...")

            out = shell(self.logger, IPacker.build_cmdline(
                PackerThemida.themida_cmdline_template,
                os.path.basename(path),
                self.themida_args + ' /protect "{}"'.format(project),
                infile,
                outfile
            ), output = self.options['verbose'] or self.options['debug'], timeout = self.options['timeout'])

        except Exception as e:
            raise

        finally:
            self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
            os.chdir(cwd)

        return os.path.isfile(outfile)