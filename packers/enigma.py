#!/usr/bin/python3
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET
import sys, re

from IPacker import IPacker
from lib.utils import *

class PackerEnigma(IPacker):
    default_enigma_args = ''
    enigma_cmdline_template = '<command> <options>'

    default_options = {
        'enigma_antidebug': 1,
        'enigma_controlsum': 1,
        'enigma_antivm': 0,
        'enigma_check_processes_every': 10,
        'enigma_save_generated_project_file': False,
    }

    def __init__(self, logger, options):
        self.enigma_args = PackerEnigma.default_enigma_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'EnigmaProtector'

    @staticmethod
    def get_desc():
        return '(paid) The Engima Protector is an advanced x86/x64 PE Executables protector with many anti- features and virtualization'

    def help(self, parser):
        if parser != None:
            parser.add_argument('--enigma-path-x86', metavar='PATH', dest='enigma_path_x86',
                help = '(required) Path to The Enigma Protector x86 executable.')

            parser.add_argument('--enigma-path-x64', metavar='PATH', dest='enigma_path_x64',
                help = '(required) Path to The Enigma Protector x64 executable.')

            parser.add_argument('--enigma-project-file', metavar='PATH', dest='enigma_project_file',
                help = '(required) Path to The Enigma Protector .enigma base project file (template to work with).')

            parser.add_argument('--enigma-save-generated-project-file', metavar='bool', type=int, choices=range(0, 2), dest='enigma_save_generated_project_file', 
                help = 'Specifies whether to save newly generated project file along with the output generated executable (with .enigma extension). Valid values: 0/1. Default: 0')

            parser.add_argument('--enigma-product-name', metavar='NAME', dest='enigma_product_name',
                help = 'Product name to set in application\'s manifest.')

            parser.add_argument('--enigma-product-version', metavar='VER', dest='enigma_product_version',
                help = 'Product version to set in application\'s manifest.')

            parser.add_argument('--enigma-process-blacklist', metavar='PROCNAME', dest='enigma_processes_blacklist', action = 'append',
                help = 'Enigma will exit running if this process is found launched. May be repeated. Suitable for anti-analysis defenses.')

            parser.add_argument('--enigma-check-processes-every', metavar='SECONDS', type=int, choices=range(0, 2), dest='enigma_check_processes_every', action = 'append',
                help = 'Enigma will check processes list for blacklisted entries every N seconds. Default: 10. Use "0" to check only at startup.')

            parser.add_argument('--enigma-antidebug', metavar='bool', type=int, choices=range(0, 2), dest='enigma_antidebug', 
                help = 'Enable Anti-Debug checks and prevent output from running under debugger. Valid values: 0/1. Default: 1')

            parser.add_argument('--enigma-antivm', metavar='bool', type=int, choices=range(0, 2), dest='enigma_antivm', 
                help = 'Enable Anti-VM checks and prevent running sample in Virtual Machines such as VMWare. Valid values: 0/1. Default: 0')

            parser.add_argument('--enigma-control-sum', metavar='bool', type=int, choices=range(0, 2), dest='enigma_controlsum', 
                help = 'Enable Program control-sum / Integrity vertification. Valid values: 0/1. Default: 1')

            parser.add_argument('--enigma-protected-exe-cmdline', metavar='ARGS', dest='enigma_protected_exe_cmdline',
                help = 'Allows to use initial command line arguments for the protected executable.')

            parser.add_argument('--enigma-args', metavar='ARGS', dest='enigma_args',
                help = 'Optional enigma-specific arguments to pass during compression.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            self.options['enigma_path_x86'] = configPath(self.options['config'], self.options['enigma_path_x86'])
            self.options['enigma_path_x64'] = configPath(self.options['config'], self.options['enigma_path_x64'])
            self.options['enigma_project_file'] = os.path.abspath(configPath(self.options['config'], self.options['enigma_project_file']))

            for k, v in PackerEnigma.default_options.items():
                if k not in self.options.keys():
                    self.options[k] = v

            if not os.path.isfile(self.options['enigma_path_x86']) or not os.path.isfile(self.options['enigma_path_x64']):
                self.logger.err('Both options --enigma-path-x86 and --enigma-path-x64 must be specified!')

            if not os.path.isfile(self.options['enigma_project_file']):
                self.logger.fatal('You must specify existing --enigma-project-file project file (.tmd) that will be reused for subsequent samples!')

            if 'enigma_args' in self.options.keys() and self.options['enigma_args'] != None \
                and len(self.options['enigma_args']) > 0: 
                self.enigma_args += ' ' + self.options['enigma_args']

    def adjustProjectFile(self, projFile, arch, infile, outfile):
        baseProject = ''

        with open(self.options['enigma_project_file'], 'r', encoding='utf-8') as f:
            baseProject = f.read().strip()

        try:
            parser = ET.XMLParser(encoding="utf-8")
            et = ET.fromstring(baseProject, parser=parser)

        except Exception as e:
            self.logger.fatal('The Enigma Protector input project file has corrupted structure:\n{}'.format(
                str(e)
            ))
            raise

        # ----------

        tag = et.find('Input')
        tag.find('FileName').text = infile
        tag.find('ProductName').text = self.options['enigma_product_name']
        tag.find('VersionInfo').text = self.options['enigma_product_version']

        tag = et.find('Output')
        tag.find('FileName').text = outfile

        checks = et.find('CheckUp')

        et.find('./CheckUp/AntiDebugger/Enabled').text = str(bool(self.options['enigma_antidebug']))
        et.find('./CheckUp/ControlSum/Enabled').text = str(bool(self.options['enigma_controlsum']))
        et.find('./Protection/InlinePatching/Enabled').text = str(bool(self.options['enigma_controlsum']))
        et.find('./CheckUp/VirtualizationTools/Enabled').text = str(bool(self.options['enigma_antivm']))
        
        # Engima "Virtual Machine" Modern RISC options
        et.find('./VirtualMachine/Enabled').text = 'True'
        et.find('./VirtualMachine/FileEntryPoint/Enabled').text = 'True'
        et.find('./VirtualMachine/Common/VMType').text = '1'
        et.find('./VirtualMachine/Common/RISCVMTrashgen').text = '5'
        et.find('./VirtualMachine/Common/RISCVMObfuscation').text = '3'
        et.find('./VirtualMachine/Common/RISCVMDuplicates').text = '2'
        et.find('./VirtualMachine/Common/RISCVMEncryption').text = '3'

        if self.options['enigma_processes_blacklist'] is not None \
            and len(self.options['enigma_processes_blacklist']) > 0:
            et.find('./CheckUp/ExecutedProcesses/Enabled').text = 'True'

            if self.options['enigma_check_processes_every'] > 0:
                et.find('./CheckUp/ExecutedProcesses/CheckDelay').text = str(self.options['enigma_check_processes_every'])
                et.find('./CheckUp/ExecutedProcesses/CheckEndless').text = 'True'
            else:
                et.find('./CheckUp/ExecutedProcesses/CheckEndless').text = 'False'

            processes = et.find('./CheckUp/ExecutedProcesses/Processes')
            processes.attrib['Count'] = str(len(self.options['enigma_processes_blacklist']))

            for proc in self.options['enigma_processes_blacklist']:
                process = ET.SubElement(processes, 'Process')
                ET.SubElement(process, 'Action').text = '1'
                ET.SubElement(process, 'FileName').text = proc
                ET.SubElement(process, 'WindowText')
                ET.SubElement(process, 'WindowClass')
                ET.SubElement(process, 'FileNameCondition').text = '0'
                ET.SubElement(process, 'WindowTextCondition').text = '2'
                ET.SubElement(process, 'WindowClassCondition').text = '2'

        et.find('./Miscellaneous/CommandLine/Enabled').text = 'True'
        et.find('./Miscellaneous/CommandLine/CommandLine').text = self.options['enigma_protected_exe_cmdline']

        # ----------

        newProject = ET.tostring(et, encoding='utf-8')
        projFile.write(newProject)

        if self.options['enigma_save_generated_project_file']:
            self.logger.dbg('''
----------------------------------
Adjusted project file:
----------------------------------

{}
'''.format(newProject.decode()))
        
            suf = '.enigma'
            if arch == 'x64': suf += '64'

            with open(outfile + suf, 'w') as foo:
                foo.write(newProject.decode())

    def process(self, arch, infile, outfile):
        path = self.options['enigma_path_x86']
        if arch == 'x64':
            path = self.options['enigma_path_x64']

        if not path:
            raise ArchitectureNotSupported('Architecture {} not supported as there was no corresponding The Enigma Protector path configured!\nPlease configure it using: --enigma-path-{}'.format(arch, arch))

        tmpname = ''
        try:
            cwd = os.getcwd()
            base = os.path.dirname(path)

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)

            self.logger.info("Running Enigma protector, heavy computations ahead, be patient...")

            with tempfile.NamedTemporaryFile(delete=False, suffix='.enigma') as fp: 
                self.adjustProjectFile(fp, arch, infile, outfile)
                tmpname = fp.name

            out = shell(self.logger, IPacker.build_cmdline(
                PackerEnigma.enigma_cmdline_template,
                os.path.basename(path),
                tmpname,
                '',
                ''
            ))

        except Exception as e:
            raise

        finally:
            self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
            os.chdir(cwd)

            if os.path.isfile(tmpname): 
                os.remove(tmpname)

        return os.path.isfile(outfile)