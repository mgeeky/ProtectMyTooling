#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

class PackerAsStrongAsFuck(IPacker):
    default_asstrongasfuck_args = ''
    asstrongasfuck_cmdline_template = '<command> -f <infile> <options>'

    default_options = {
        'asstrongasfuck_opts': '-o 235789',
    }

    def __init__(self, logger, options):
        self.asstrongasfuck_args = PackerAsStrongAsFuck.default_asstrongasfuck_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'AsStrongAsFuck'

    @staticmethod
    def get_type():
        return PackerType.DotNetObfuscator

    @staticmethod
    def get_desc():
        return 'AsStrongAsFuck - console obfuscator for .NET assemblies (modded by klezVirus)'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--asstrongasfuck-path', metavar='PATH', dest='asstrongasfuck_path',
                help = '(required) Path to asstrongasfuck executable.')

            parser.add_argument('--asstrongasfuck-opts', metavar='ARGS', dest='asstrongasfuck_opts',
                help = 'Optional AsStrongAsFuck obfuscation options. Default: 235789.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['asstrongasfuck_path'] = configPath(self.options['config'], self.options['asstrongasfuck_path'])

            if not os.path.isfile(self.options['asstrongasfuck_path']):
                self.logger.fatal('--asstrongasfuck-path option must be specified!')

            for k, v in PackerAsStrongAsFuck.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'asstrongasfuck_opts' in self.options.keys() and self.options['asstrongasfuck_opts'] != None \
                and len(self.options['asstrongasfuck_opts']) > 0: 
                self.asstrongasfuck_args += ' -o ' + self.options['asstrongasfuck_opts']

    @ensureInputFileIsDotNet
    def process(self, arch, infile, outfile):
        out = ''
        cwd = ''
        try:
            cwd = os.getcwd()
            base = os.path.dirname(self.options['asstrongasfuck_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            self.logger.info("Running AsStrongAsFuck protector, be patient...")

            out = shell(self.logger, IPacker.build_cmdline(
                PackerAsStrongAsFuck.asstrongasfuck_cmdline_template,
                os.path.basename(self.options['asstrongasfuck_path']),
                self.asstrongasfuck_args,
                infile,
                ''
            ), output = self.options['verbose'] or self.options['debug'], timeout = self.options['timeout'])

        except Exception as e:
            raise

        finally:
            if len(cwd) > 0:
                self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
                os.chdir(cwd)

        if os.path.isfile(infile + '.obfuscated'):
            shutil.move(infile + '.obfuscated', outfile)

        else:
            self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                outfile
            ))

            if len(out) > 0 and not (self.options['verbose'] or self.options['debug']): self.logger.info(f'''{PackerAsStrongAsFuck.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced = True, noprefix=True)

        return os.path.isfile(outfile)