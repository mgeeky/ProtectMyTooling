#!/usr/bin/python3
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import sys, re
import shutil

from IPacker import IPacker
from lib.utils import *

class PackerNetReactor(IPacker):
    default_netreactor_args = ''
    netreactor_cmdline_template = '<command> <options> -file <infile>'

    default_options = {
        'netreactor_merge_namespaces': 1,
        'netreactor_short_strings': 1,
        'netreactor_stealth_mode': 1,
        'netreactor_all_params': 1,
        'netreactor_public_types_internalization': 1,
        'netreactor_antitamp': 1,
        'netreactor_control_flow_obfuscation': 1,
        'netreactor_flow_level': 9,
        'netreactor_resourceencryption': 1,
        'netreactor_necrobit': 1,
        'netreactor_incremental_obfuscation': 1,
        'netreactor_unprintable_characters': 1,
        'netreactor_obfuscate_public_types': 1,
        'netreactor_anti_ildasm': 1,
        'netreactor_native_exe': 0,
        'netreactor_prejit': 0,
        'netreactor_strong_name_removal': 0,
        'netreactor_save_generated_project_file' : False,
    }

    def __init__(self, logger, options):
        self.netreactor_args = PackerNetReactor.default_netreactor_args
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
            parser.add_argument('--netreactor-path', metavar='PATH', dest='netreactor_path',
                help = '(required) Path to netreactor executable.')

            parser.add_argument('--netreactor-project-file', metavar='PATH', dest='netreactor_project_file',
                help = '(required) Path to .NET Reactor .nrproj project file.')

            parser.add_argument('--netreactor-save-generated-project-file', metavar='bool', type=bool, dest='netreactor_save_generated_project_file',
                help = 'Specifies whether to save newly generated project file along with the output generated executable (with .nrproj extension).')

            parser.add_argument('--netreactor-antitamp', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_antitamp', help = 'This option prevents your protected assembly from being tampered by hacker tools. Valid values: 0/1. Default: 1')
        
            parser.add_argument('--netreactor-control-flow-obfuscation', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_control_flow_obfuscation', help = 'Mangles program flow, making it extremely difficult for humans to follow the program logic. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--netreactor-flow-level', metavar='bool', type=int, choices=range(1,9), dest='netreactor_flow_level', help = 'Controls the level of Control Flow Obfuscation. Valid values: 1-9. Default: 9')
            
            parser.add_argument('--netreactor-resourceencryption', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_resourceencryption', help = 'Enable this option to compress and encrypt embedded resources. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--netreactor-necrobit', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_necrobit', help = 'Uses a powerful protection technology NecroBit which completely stops decompilation. It replaces the CIL code within methods with encrypted code. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--netreactor-merge-namespaces', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_merge_namespaces', help = 'Enable this option to place all obfuscated types inside a single namespace. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--netreactor-short-strings', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_short_strings', help = 'Enable to generate short strings for your obfuscated class and member names. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--netreactor-stealth-mode', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_stealth_mode', help = 'Enable this to generate random meaningful names for obfuscated classes and members. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--netreactor-all-params', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_all_params', help = 'Enable this to obfuscate all method parameters. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--netreactor-incremental-obfuscation', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_incremental_obfuscation', help = 'If you want .NET Reactor always to generate the same obfuscation strings for your type and member names, you need to enable this option. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--netreactor-unprintable-characters', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_unprintable_characters', help = 'Unprintable characters uses unprintable strings to obfuscate type and member names, but cannot be used if your assembly must run as safe code. Valid values: 0/1. Default: 1')
            
            parser.add_argument('--netreactor-obfuscate-public-types', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_obfuscate_public_types', help = 'Enable this to obfuscate all type and member names in an assembly. Valid values: 0/1. Default: 1')

            parser.add_argument('--netreactor-anti-ildasm', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_anti_ildasm', help = 'Suppres decompilation using decompilation tools such as ILDasm. Valid values: 0/1. Default: 1')

            parser.add_argument('--netreactor-native-exe', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_native_exe', help = '.NET Reactor is able to generate a native x86 EXE file stub for your app. This way its not going to be possible to directly open the app within a decompiler. Valid values: 0/1. Default: 0')

            parser.add_argument('--netreactor-prejit', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_prejit',  help = 'In combination with the Native EXE file feature and Necrobit, .NET Reactor is able to convert managed methods into REAL x86 native code. Mostly small methods (like property setters/getters) are converted into native code. Valid values: 0/1. Default: 0')

            parser.add_argument('--netreactor-public-types-internalization', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_public_types_internalization', help = 'If set to 1, .NET Reactor will convert all public types of an application into internal ones. This way the accessibility of types and members the assembly exposes will be reduced. Valid values: 0/1. Default: 0')

            parser.add_argument('--netreactor-strong-name-removal', metavar='bool', type=int, choices=range(0, 2), dest='netreactor_strong_name_removal', help = 'Enables anti Strong Name removal technique which prevents protected assemblies from being tampered by hacking tools. Warning: this option can impact the runtime performance of generated protected assembly! Valid values: 0/1. Default: 0')

            parser.add_argument('--netreactor-args', metavar='ARGS', dest='netreactor_args',
                help = 'Optional netreactor-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['netreactor_path'] = configPath(self.options['config'], self.options['netreactor_path'])
            self.options['netreactor_project_file'] = os.path.abspath(configPath(self.options['config'], self.options['netreactor_project_file']))

            if not os.path.isfile(self.options['netreactor_path']):
                self.logger.fatal('--netreactor-path option must be specified!')

            if 'netreactor_args' in self.options.keys() and self.options['netreactor_args'] != None \
                and len(self.options['netreactor_args']) > 0: 
                self.netreactor_args += ' ' + self.options['netreactor_args']

            for k, v in PackerNetReactor.default_options.items():
                if k not in self.options.keys():
                    self.options[k] = v

            optionsMap = {
                'netreactor_antitamp': 'antitamp',
                'netreactor_control_flow_obfuscation': 'control_flow_obfuscation',
                'netreactor_flow_level': 'flow_level',
                'netreactor_resourceencryption': 'resourceencryption',
                'netreactor_necrobit': 'necrobit',
                'netreactor_incremental_obfuscation': 'incremental_obfuscation',
                'netreactor_unprintable_characters': 'unprintable_characters',
                'netreactor_obfuscate_public_types': 'obfuscate_public_types',
                'netreactor_anti_ildasm': 'suppressildasm',
                'netreactor_native_exe': 'nativeexe',
                'netreactor_prejit': 'prejit',
                'netreactor_strong_name_removal': 'antistrong',
            }

            for k, v in optionsMap.items():
                if k in self.options.keys():
                    self.netreactor_args += ' -{} {}'.format(v, self.options[k])

    def adjustProjectFile(self, projFile, infile, outfile):
        baseProject = ''

        with open(self.options['netreactor_project_file'], 'r', encoding='utf-8', errors='ignore') as f:
            baseProject = f.read().strip()

        try:
            parser = ET.XMLParser(encoding="utf-8")
            et = ET.fromstring(baseProject, parser=parser)

        except Exception as e:
            self.logger.fatal('.NET Reactor input project file has corrupted structure:\n{}'.format(
                str(e)
            ))
            raise

        # ----------

        optionsNotConfigurableFromCommandLine = {
            'netreactor_merge_namespaces': './Protection_Settings/Merge_Namespaces',
            'netreactor_short_strings': './Protection_Settings/Generate_Short_Strings',
            'netreactor_stealth_mode': './Protection_Settings/Stealth_Obfuscation',
            'netreactor_all_params': './Protection_Settings/Obfuscate_All_Method_Parameters',
            'netreactor_public_types_internalization': './Protection_Settings/Public_Types_Internalization',
        }

        et.find('Main_Assembly').text = infile

        for k, v in optionsNotConfigurableFromCommandLine.items():
            et.find(v).text = str(bool(self.options[k])).lower()

        # ----------

        newProject = ET.tostring(et, encoding='utf-8')
        projFile.write(newProject)

        if self.options['netreactor_save_generated_project_file']:
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

        try:
            cwd = os.getcwd()
            base = os.path.dirname(self.options['netreactor_path'])

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            assemblyName = getClrAssemblyName(infile)
            if not assemblyName:
                self.logger.err("Could not extract assembly name from input file! Probably we won't be able to recover generated output artefact. Trying anyway...")
                assemblyName = os.path.basename(os.path.splitext(infile)[0])

            self.logger.info("Running .NET Reactor on assembly {}, be patient...".format(assemblyName))

            generatedOutfile = '{}\\{}_Secure\\{}'.format(
                os.path.dirname(infile),
                assemblyName,
                os.path.basename(infile)
            )

            with tempfile.NamedTemporaryFile(delete=False, suffix='.nrproj') as fp: 
                self.adjustProjectFile(fp, infile, outfile)
                tmpname = fp.name

            out = shell(self.logger, IPacker.build_cmdline(
                PackerNetReactor.netreactor_cmdline_template,
                os.path.basename(self.options['netreactor_path']),
                self.netreactor_args + ' -project "{}"'.format(fp.name),
                infile,
                ''
            ), output = True)

            status = (' - Successfully Protected!' in out)

            if status and os.path.isfile(generatedOutfile):
                self.logger.dbg('Moving file from auto-generated output location: "{}"'.format(generatedOutfile))
                shutil.move(generatedOutfile, outfile)
                shutil.rmtree(os.path.dirname(generatedOutfile))
            else:
                status = False
                self.logger.err('Something went wrong and we couldn\'t find generated output file ({})!'.format(generatedOutfile))

        except Exception as e:
            raise

        finally:
            self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
            os.chdir(cwd)

            if os.path.isfile(tmpname): 
                os.remove(tmpname)

        return status