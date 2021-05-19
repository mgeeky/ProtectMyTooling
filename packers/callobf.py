#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import random
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
        return 'CallObfuscator - An open-source, handy tool to obscure PE imported calls by hiding dangerous calls behind innocuous ones.'

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


    def generateConfigFile(self, infile):
        configPath = ''
        config = ''

        dodgyFunctions = {}
        beningFunctions = {}
        usedImports = {}

        p = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../data/dodgy-functions.txt'))
        r = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../data/all-functions.txt'))

        with open(p) as f:
            for line in f.readlines():
                line = line.strip()
                key, value = line.split(',')
                key = key.strip().lower()
                value = value.strip()

                if key not in dodgyFunctions.keys():
                    dodgyFunctions[key] = []

                dodgyFunctions[key].append(value)

        with open(r) as f:
            for line in f.readlines():
                line = line.strip()
                key, value = line.split(',')
                key = key.strip().lower()
                value = value.strip()

                if key not in beningFunctions.keys():
                    beningFunctions[key] = []

                beningFunctions[key].append(value)

        pe = pefile.PE(infile)

        self.logger.dbg('Input file PE imports:')

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()

            if dll_name not in usedImports.keys():
                usedImports[dll_name] = []

            self.logger.dbg(f'\tDLL: {dll_name}')
            for func in entry.imports:
                f = func.name.decode('utf-8')

                self.logger.dbg(f'\t\t- {f}')
                usedImports[dll_name].append(f)

        outputImports = {}

        for k, v in usedImports.items():
            k = k.lower()
            if k.endswith('.dll'):
                k = k[:-4]

            if k not in dodgyFunctions.keys():
                continue

            config += f''';
;
;
[{k}.dll]
'''
            for oldFun in v:
                randomShot = (random.randint(1, 100) % 3 == 0)

                if oldFun not in dodgyFunctions[k] and not randomShot: 
                    continue

                newFun = ''
                while newFun == '' or newFun in dodgyFunctions[k] or len(newFun) >= len(oldFun):
                    newFun = random.choice(beningFunctions[k])

                config += f'{oldFun}={newFun}\r\n'

        tmp = tempfile.NamedTemporaryFile(delete=False)

        self.logger.dbg(f'''

Resulting generated CallObfuscator config file:
------------------------------------------------------

{config}

------------------------------------------------------
''')

        try:
            tmp.write(config.encode())
            configPath = tmp.name
        finally:
            tmp.close()

        return configPath


    def process(self, arch, infile, outfile):
        configPath = self.options['callobf_config']
        autoGen = False

        pe = pefile.PE(infile)
        print('[.] Before obfuscation file\'s PE IMPHASH:\t' + pe.get_imphash())
        pe.close()

        if configPath == 'generate-automatically':
            autoGen = True
            configPath = self.generateConfigFile(infile)

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

        ret = os.path.isfile(outfile)

        if ret:
            self.renameSection(outfile)

        return ret

    def renameSection(self, outfile):
        self.logger.info(f'Renaming .cobf PE section...')

        pe = pefile.PE(outfile)

        newSectionNames = (
            '.info',
            '.meta',
            '.udata',
            '.jdata',
            '.ldata',
            '.vdata',
            '.hinfo',
            '.finfo',
            '.blob',
            '.bcert',
            '.bsec',
            '.odat',
            '.adat',
            '.edat',
            '.tdat',
            '.cdat',
        )

        section_table_offset = (pe.DOS_HEADER.e_lfanew + 4 + 
            pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader)

        sectnum = 0
        for sect in pe.sections:
            section_offset = section_table_offset + sectnum * 0x28
            sectnum += 1

            if sect.Name.decode().lower().startswith('.cobf'):
                newSectName = random.choice(newSectionNames)
                newname = newSectName.encode() + ((8 - len(newSectName)) * b'\x00')
                
                self.logger.dbg('\tRenamed CallObfuscator section ({}) => ({})'.format(
                    sect.Name.decode(), newSectName
                ))
                
                pe.set_bytes_at_offset(section_offset, newname)
                break

        pe.parse_sections(section_table_offset)
        pe.write(outfile)
        print('[.] After obfuscation file\'s PE IMPHASH:\t' + pe.get_imphash())
