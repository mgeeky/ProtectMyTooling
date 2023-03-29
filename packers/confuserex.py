#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import xml.etree.ElementTree as ET
import shutil

from pathlib import Path


class PackerConfuserEx(IPacker):
    default_confuserex_args = '-n'
    confuserex_cmdline_template = '<command> <options> <infile>'

    default_options = {
        'confuserex_plugins': ['compressor'],
    }

    metadata = {
        'author': 'mkaring',
        'url': 'https://github.com/mkaring/ConfuserEx',
        'description': 'An open-source protector for .NET applications',
        'licensing': 'open-source',
        'type': PackerType.DotNetObfuscator,
        'input': ['.NET', ],
        'output': ['.NET', ],
    }

    def __init__(self, logger, options):
        self.confuserex_args = PackerConfuserEx.default_confuserex_args
        self.logger = logger
        self.options = options
        self.modules = []

    @staticmethod
    def get_name():
        return 'ConfuserEx'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--confuserex-path', metavar='PATH', dest='confuserex_path',
                                help='(required) Path to ConfuserEx binary capable of obfuscating .NET executables.')

            parser.add_argument('--confuserex-project-file', metavar='PATH', dest='confuserex_project_file',
                                help='(required) Path to .ConfuserEx .csproj project file.')

            parser.add_argument('--confuserex-save-generated-project-file', default=0, metavar='bool', type=int, choices=range(0, 2), dest='confuserex_save_generated_project_file',
                                help='Specifies whether to save newly generated project file along with the output generated executable (with .crproj extension). Valid values: 0/1. Default: 0')

            parser.add_argument('--confuserex-args', metavar='ARGS', dest='confuserex_args',
                                help='Optional ConfuserEx-specific arguments to pass during compression.')

            parser.add_argument('--confuserex-module', metavar='PATH', dest='confuserex_module', nargs='+', action='append',
                                help='(Optional) Embed specified by path DLL module into final EXE. Can be repeated.')

            parser.add_argument('--confuserex-modules-in-dir', metavar='DIR', dest='confuserex_modules_in_dir', nargs='+', action='append',
                                help='(Optional) Embed all DLLs in specified DIR into final EXE. Can be repeated.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            if not os.path.isfile(self.options['confuserex_path']):
                self.logger.fatal(
                    '--confuserex-path option must be specified!')

            for k, v in PackerConfuserEx.default_options.items():
                if k not in self.options.keys() or not self.options[k]:
                    self.options[k] = v

            if 'confuserex_module' in self.options.keys() and self.options['confuserex_module'] != None \
                    and len(self.options['confuserex_module']) > 0:
                for mod in self.options['confuserex_module']:
                    self.logger.dbg(f'Will embed DLL into EXE: {mod}')
                    self.modules.append(mod)

            if 'confuserex_modules_in_dir' in self.options.keys() and self.options['confuserex_modules_in_dir'] != None \
                    and len(self.options['confuserex_modules_in_dir']) > 0:
                for d in self.options['confuserex_modules_in_dir']:
                    for path in Path(d).rglob('*.dll'):
                        self.logger.dbg(
                            f'Will embed DLL into EXE: {path.name}')
                        self.modules.append(path.name)

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

        dirA = os.path.normpath(os.path.join(os.path.dirname(infile), '..'))
        dirB = os.path.normpath(os.path.join(os.path.dirname(infile), '../..'))
        dirC = os.path.normpath(os.path.join(
            os.path.dirname(infile), '../../..'))

        if len(self.modules) > 0:
            ET.SubElement(et, 'packer').attrib['id'] = 'compressor'

        ET.SubElement(et, 'module').attrib['path'] = os.path.basename(infile)

        for mod in self.modules:
            ET.SubElement(et, 'module').attrib['path'] = mod

        ET.SubElement(et, 'probePath').text = os.path.dirname(infile)
        if os.path.isdir(dirA):
            ET.SubElement(et, 'probePath').text = dirA
        if os.path.isdir(dirB):
            ET.SubElement(et, 'probePath').text = dirB
        if os.path.isdir(dirC):
            ET.SubElement(et, 'probePath').text = dirC

        # ----------

        newProject = prettyXml(ET.tostring(et, encoding='utf-8'))

        projFile.write(newProject)

        self.logger.dbg('''
----------------------------------
Adjusted project file:
----------------------------------

{}
'''.format(newProject.decode()))

        if self.options['confuserex_save_generated_project_file']:
            suf = '.crproj'
            with open(outfile + suf, 'w') as foo:
                foo.write(newProject.decode())

    @ensureInputFileIsDotNet
    def process(self, arch, infile, outfile):
        tmpdir = ''
        status = False
        cwd = ''

        with tempfile.TemporaryDirectory() as tmpdir:
            generatedOutFile = os.path.join(tmpdir, os.path.basename(infile))

            tmpname = ''
            try:
                cwd = os.getcwd()
                base = os.path.dirname(infile)

                self.logger.dbg(
                    'changed working directory to "{}"'.format(base))
                os.chdir(base)

                with tempfile.NamedTemporaryFile(delete=False, suffix='.crproj') as fp:
                    self.adjustProjectFile(fp, arch, infile, outfile, tmpdir)
                    tmpname = fp.name

                out = shell(self.logger, IPacker.build_cmdline(
                    PackerConfuserEx.confuserex_cmdline_template,
                    self.options['confuserex_path'],
                    self.confuserex_args,
                    tmpname,
                    ''
                ), output=self.options['verbose'] or self.options['debug'], timeout=self.options['timeout'])

                if os.path.isfile(generatedOutFile):
                    shutil.move(generatedOutFile, outfile)
                    status = True

                else:
                    self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                        generatedOutFile
                    ))

                    if len(out) > 0:
                        parsedout = []
                        num = 0

                        for line in out.split('\n'):
                            line = line.strip()
                            num += 1

                            if num == 1:
                                parsedout.append(line)
                                continue

                            else:
                                if line.startswith('[INFO]') or line.startswith('[DEBUG]'):
                                    continue

                            parsedout.append(line)

                        parsedouts = '\n'.join(parsedout)

                        if(len(parsedouts)) > 0:
                            self.logger.err(f'''Error message from packer:
----------------------------------------
{parsedouts}
----------------------------------------
''')
                        elif len(out) > 0 and not (self.options['verbose'] or self.options['debug']):
                            self.logger.info(f'''{PackerConfuserEx.get_name()} returned:
----------------------------------------
{out}
----------------------------------------
''', forced=True, noprefix=True)

            except Exception as e:
                raise

            finally:
                if len(cwd) > 0:
                    self.logger.dbg(
                        'reverted to original working directory "{}"'.format(cwd))
                    os.chdir(cwd)

                if os.path.isfile(tmpname):
                    os.remove(tmpname)

        if os.path.isdir(tmpdir):
            shutil.rmtree(tmpdir)

        return status and os.path.isfile(outfile)
