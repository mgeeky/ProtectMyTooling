#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import xml.etree.ElementTree as ET
import shutil

class PackerConfuserEx(IPacker):
    default_confuserex_args = '-n'
    confuserex_cmdline_template = '<command> <options> <infile>'

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

            parser.add_argument('--confuserex-project-file', metavar='PATH', dest='confuserex_project_file',
                help = '(required) Path to .ConfuserEx .csproj project file.')

            parser.add_argument('--confuserex-save-generated-project-file', default=0, metavar='bool', type=int, choices=range(0, 2), dest='confuserex_save_generated_project_file', 
                help = 'Specifies whether to save newly generated project file along with the output generated executable (with .crproj extension). Valid values: 0/1. Default: 0')

            parser.add_argument('--confuserex-args', metavar='ARGS', dest='confuserex_args',
                help = 'Optional ConfuserEx-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['confuserex_path'] = configPath(self.options['config'], self.options['confuserex_path'])
            self.options['confuserex_project_file'] = os.path.abspath(configPath(self.options['config'], self.options['confuserex_project_file']))

            if not os.path.isfile(self.options['confuserex_path']):
                self.logger.fatal('--confuserex-path option must be specified!')

            for k, v in PackerConfuserEx.default_options.items():
                if k not in self.options.keys():
                    self.options[k] = v

            if 'confuserex_args' in self.options.keys() and self.options['confuserex_args'] != None \
                and len(self.options['confuserex_args']) > 0: 
                self.confuserex_args += ' ' + self.options['confuserex_args']


    def adjustProjectFile(self, projFile, arch, infile, outfile, outputDir):
        baseProject = ''

        with open(self.options['confuserex_project_file'], 'r', encoding='utf-8') as f:
            baseProject = f.read().strip()

        try:
            ET.register_namespace('', "http://confuser.codeplex.com")
            parser = ET.XMLParser()
            et = ET.fromstring(baseProject, parser=parser)

        except Exception as e:
            self.logger.fatal('The ConfuserEx input project file has corrupted structure:\n{}'.format(
                str(e)
            ))
            raise

        # ----------

        et.attrib['outputDir'] = outputDir
        et.attrib['baseDir'] = os.path.dirname(infile)

        ET.SubElement(et, 'module').attrib['path'] = os.path.basename(infile)

        # ----------

        newProject = ET.tostring(et, encoding='utf-8')
        projFile.write(newProject)

        if self.options['confuserex_save_generated_project_file']:
            self.logger.dbg('''
----------------------------------
Adjusted project file:
----------------------------------

{}
'''.format(newProject.decode()))
        
            suf = '.crproj'
            with open(outfile + suf, 'w') as foo:
                foo.write(newProject.decode())

    def process(self, arch, infile, outfile):
        tmpdir = ''
        status = False

        with tempfile.TemporaryDirectory() as tmpdir:
            generatedOutFile = os.path.join(tmpdir, os.path.basename(infile))

            tmpname = ''
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.crproj') as fp: 
                    self.adjustProjectFile(fp, arch, infile, outfile, tmpdir)
                    tmpname = fp.name

                out = shell(self.logger, IPacker.build_cmdline(
                    PackerConfuserEx.confuserex_cmdline_template,
                    self.options['confuserex_path'],
                    self.confuserex_args,
                    tmpname,
                    ''
                ), output = self.options['verbose'] or self.options['debug'])

                if os.path.isfile(generatedOutFile):
                    shutil.move(generatedOutFile, outfile)
                    status = True
                else:
                    self.logger.err('Something went wrong: there is no output artefact ({})!'.format(
                        generatedOutFile
                    ))

            except Exception as e:
                raise

            finally:
                if os.path.isfile(tmpname): 
                    os.remove(tmpname)

        if os.path.isdir(tmpdir):
            shutil.rmtree(tmpdir)

        return status and os.path.isfile(outfile)