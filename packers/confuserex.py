#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import shutil

class PackerConfuserEx(IPacker):
    default_confuserex_args = '-n'
    confuserex_cmdline_template = '<command> <options> -o <outfile> <infile>'

    default_options = {
        'confuserex_plugins': ['compressor'],
    }

    def __init__(self, logger, options):
        self.confuserex_args = PackerConfuserEx.default_confuserex_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'ConfuserEx'

    @staticmethod
    def get_desc():
        return 'An open-source protector for .NET applications'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--confuserex-path', metavar='PATH', dest='confuserex_path',
                help = '(required) Path to ConfuserEx binary capable of obfuscating .NET executables.')

            parser.add_argument('--confuserex-plugins', metavar='PLUGIN', dest='confuserex_plugins', action='append',
                help = 'Specifies input plugins to use, may be repeated. Default: compressor.')

            parser.add_argument('--confuserex-args', metavar='ARGS', dest='confuserex_args',
                help = 'Optional ConfuserEx-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['confuserex_path'] = configPath(self.options['config'], self.options['confuserex_path'])

            if not os.path.isfile(self.options['confuserex_path']):
                self.logger.fatal('--confuserex-path option must be specified!')

            for k, v in PackerConfuserEx.default_options.items():
                if k not in self.options.keys():
                    self.options[k] = v

            if 'confuserex_plugins' in self.options.keys() and self.options['confuserex_plugins'] is not None \
                and len(self.options['confuserex_plugins']) > 0:
                for pl in self.options['confuserex_plugins']:
                    self.confuserex_args += ' -plugin {}'.format(pl)

            if 'confuserex_args' in self.options.keys() and self.options['confuserex_args'] != None \
                and len(self.options['confuserex_args']) > 0: 
                self.confuserex_args += ' ' + self.options['confuserex_args']

    def process(self, arch, infile, outfile):
        tmpdir = ''
        status = False

        with tempfile.TemporaryDirectory() as tmpdir:
            generatedOutFile = os.path.join(tmpdir, os.path.basename(infile))

            out = shell(self.logger, IPacker.build_cmdline(
                PackerConfuserEx.confuserex_cmdline_template,
                self.options['confuserex_path'],
                self.confuserex_args,
                infile,
                tmpdir
            ))

            if os.path.isfile(generatedOutFile):
                shutil.move(generatedOutFile, outfile)
                status = True
            else:
                self.logger.err('Something went wrong: there is no output artefact ({})!'.format(
                    generatedOutFile
                ))

        if os.path.isdir(tmpdir):
            shutil.rmtree(tmpdir)

        return status and os.path.isfile(outfile)