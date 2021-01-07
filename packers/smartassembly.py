#!/usr/bin/python3
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import sys, re
import shutil

from IPacker import IPacker
from lib.utils import *

class PackerSmartAssembly(IPacker):
    # https://documentation.red-gate.com/sa/building-your-assembly/using-the-command-line-mode
    default_smartassembly_args = ' /log /logLevel=Verbose'

    default_options = {
        'smartassembly_tamperprotection': 1,
        'smartassembly_sealclasses': 1,
        'smartassembly_preventildasm': 1,
        'smartassembly_methodparentobfuscation': 1,
        'smartassembly_typemethodobfuscation': 3,
        'smartassembly_fieldobfuscation': 3,
        'smartassembly_cgsobfuscation': 1,
        'smartassembly_stringsencoding': 1,
        'smartassembly_compressencryptresources': 1,
        'smartassembly_controlflowobfuscate': 4,
        'smartassembly_dynamicproxy': 1,
        'smartassembly_pruning': 1,
        'smartassembly_nameobfuscate': 1,
        'smartassembly_compressassembly': 1,
        'smartassembly_encryptassembly': 1,
        'smartassembly_save_generated_project_file' : False,
    }

    smartassembly_cmdline_template = '<command> <options> /input=<infile> /output=<outfile>'

    def __init__(self, logger, options):
        self.smartassembly_args = PackerSmartAssembly.default_smartassembly_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return '.NET Reactor'

    @staticmethod
    def get_desc():
        return '(paid) A powerful code protection system for the .NET Framework including various obfuscation & anti- techniques'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--smartassembly-path', metavar='PATH', dest='smartassembly_path',
                help = '(required) Path to smartassembly executable.')

            parser.add_argument('--smartassembly-project-file', metavar='PATH', dest='smartassembly_project_file',
                help = '(required) Path to .NET Reactor .nrproj project file.')

            parser.add_argument('--smartassembly-save-generated-project-file', metavar='bool', type=bool, dest='smartassembly_save_generated_project_file',
                help = 'Specifies whether to save newly generated project file along with the output generated executable (with .nrproj extension).')

            parser.add_argument('--smartassembly-tamperprotection', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_tamperprotection', help = 'Apply tamper protection to the assembly. Valid values: 0/1. Default: 1')
        
            parser.add_argument('--smartassembly-sealclasses', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_sealclasses', help = 'Seal classes that are not inherited. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--smartassembly-preventildasm', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_preventildasm', help = 'Prevent Microsoft IL Disassembler from opening your assembly. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--smartassembly-typemethodobfuscation', metavar='bool', type=int, choices=range(1,3), dest='smartassembly_typemethodobfuscation', help = 'Apply types / methods name mangling at the specified level to assemblies with nameobfuscate:true. Valid values: 1/2/3. Default: 3')

            parser.add_argument('--smartassembly-fieldobfuscation', metavar='bool', type=int, choices=range(1,3), dest='smartassembly_fieldobfuscation', help = 'Apply fields name mangling at the specified level to assemblies with nameobfuscate:true. Valid values: 1/2/3. Default: 3')
            
            parser.add_argument('--smartassembly-methodparentobfuscation', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_methodparentobfuscation', help = 'Apply method parent obfuscation to the assembly. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--smartassembly-cgsobfuscation', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_cgsobfuscation', help = 'Obfuscate compiler-generated serializable types. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--smartassembly-stringsencoding', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_stringsencoding', help = 'Enables improved strings encoding with cache and compression enabled. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--smartassembly-controlflowobfuscate', metavar='bool', type=int, dest='smartassembly_controlflowobfuscate', choices=range(0, 4), help = 'Sets the level of control flow obfuscation to apply to the assembly: 0 - disabled obfuscation, 4 - Unverifiable. Valid values: 0-4. Default: 4')
            
            parser.add_argument('--smartassembly-compressencryptresources', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_compressencryptresources', help = 'Enable / Disable resources compression and encryption. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--smartassembly-dynamicproxy', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_dynamicproxy', help = 'Enable / Disable the references dynamic proxy. Valid values: 0/1. Default: 1')

            parser.add_argument('--smartassembly-pruning', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_pruning', help = 'Enable / Disable assembly pruning. Valid values: 0/1. Default: 1')

            parser.add_argument('--smartassembly-nameobfuscate', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_nameobfuscate', help = 'Enable / Disable types and methods obfuscation and field names obfuscation. The obfuscation is applied at the levels specified for the project. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--smartassembly-compressassembly', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_compressassembly', help = 'Enable / Disable compression when the assembly is embedded. Valid values: 0/1. Default: 1')

            parser.add_argument('--smartassembly-encryptassembly', metavar='bool', type=int, choices=range(0, 2), dest='smartassembly_encryptassembly', help = 'Enable / Disable compression when the assembly is embedded. Valid values: 0/1. Default: 1')

            parser.add_argument('--smartassembly-args', metavar='ARGS', dest='smartassembly_args',
                help = 'Optional smartassembly-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['smartassembly_path'] = configPath(self.options['config'], self.options['smartassembly_path'])
            self.options['smartassembly_project_file'] = os.path.abspath(configPath(self.options['config'], self.options['smartassembly_project_file']))

            if not os.path.isfile(self.options['smartassembly_path']):
                self.logger.fatal('--smartassembly-path option must be specified!')

            if 'smartassembly_args' in self.options.keys() and self.options['smartassembly_args'] != None \
                and len(self.options['smartassembly_args']) > 0: 
                self.smartassembly_args += ' ' + self.options['smartassembly_args']

            optionsCastToBool = {
                'smartassembly_tamperprotection' : True,
                'smartassembly_sealclasses' : True,
                'smartassembly_preventildasm' : True,
                'smartassembly_methodparentobfuscation' : True,
                'smartassembly_typemethodobfuscation' : False,
                'smartassembly_fieldobfuscation' : False,
                'smartassembly_cgsobfuscation' : True,
                'smartassembly_stringsencoding' : True,
            }

            for k, v in PackerSmartAssembly.default_options.items():
                if k not in self.options.keys():
                    self.options[k] = v

            for k, v in optionsCastToBool.items():
                if k in self.options.keys():
                    if v:
                        self.smartassembly_args += ' /{}={}'.format(
                            k.replace('smartassembly_', ''), 
                            str(bool(self.options[k])).lower())
                    else:
                        self.smartassembly_args += ' /{}={}'.format(
                            k.replace('smartassembly_', ''), 
                            str(self.options[k]))

                    if k == 'smartassembly_stringsencoding':
                        self.smartassembly_args += ';improved:true,compressencrypt:true,cache:true'


    def adjustProjectFile(self, projFile, infile, outfile):
        return
        baseProject = ''

        with open(self.options['smartassembly_project_file'], 'r', encoding='utf-8', errors='ignore') as f:
            baseProject = f.read().strip()

        try:
            parser = ET.XMLParser(encoding="utf-8")
            et = ET.fromstring(baseProject, parser=parser)

        except Exception as e:
            self.logger.fatal('RedGate SmartAssembly Protector input project file has corrupted structure:\n{}'.format(
                str(e)
            ))
            raise

        # ----------


        # ----------

        newProject = ET.tostring(et, encoding='utf-8')
        projFile.write(newProject)

        if self.options['smartassembly_save_generated_project_file']:
            self.logger.dbg('''
----------------------------------
Adjusted project file:
----------------------------------

{}
'''.format(newProject.decode()))
        
            with open(outfile + '.nrproj', 'w') as foo:
                foo.write(newProject.decode())

    def process(self, arch, infile, outfile):

        tmpname = ''
        status = False

        self.smartassembly_args += ' /assembly="{}";prune:{},nameobfuscate:{},controlflowobfuscate:{},dynamicproxy:{},compressencryptresources:{}'.format(
            os.path.basename(os.path.splitext(infile)[0]),
            str(bool(self.options['smartassembly_pruning'])).lower(),
            str(bool(self.options['smartassembly_nameobfuscate'])).lower(),
            str(self.options['smartassembly_controlflowobfuscate']),
            str(bool(self.options['smartassembly_dynamicproxy'])).lower(),
            str(bool(self.options['smartassembly_compressencryptresources'])).lower()
        )

        cmdline = ''
        try:
            cwd = os.getcwd()
            base = os.path.dirname(self.options['smartassembly_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            self.logger.info("Running RedGate SmartAssembly Protector, be patient...")

            proj = ''
            if self.options['smartassembly_project_file'] and len(self.options['smartassembly_project_file']) > 0:
                proj = ' /build "{}"'.format(self.options['smartassembly_project_file'])

            cmdline = IPacker.build_cmdline(
                PackerSmartAssembly.smartassembly_cmdline_template,
                os.path.basename(self.options['smartassembly_path']),
                proj + self.smartassembly_args,
                infile,
                outfile
            )
            out = shell(self.logger, cmdline, output = True)

            status = os.path.isfile(outfile)

        except Exception as e:
            raise

        finally:
            self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
            os.chdir(cwd)

        return status