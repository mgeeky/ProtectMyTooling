#!/usr/bin/python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from lib.utils import *

import sys, os
import lib.logger

class IPacker(ABC):

    def __init__(self, logger, options):
        super().__init__()

    @staticmethod
    @abstractmethod
    def get_name():
        return 'IPacker'

    @staticmethod
    @abstractmethod
    def get_type():
        return PackerType.Unsupported

    @staticmethod
    @abstractmethod
    def get_desc():
        return 'Packer class Interface'

    @staticmethod
    def validate_file_architecture():
        '''
        If this method is overloaded, will indicate that the Packer plugin does not want ProtectMyTooling
        to enforce input file being EXE/DLL. The script will handle file validation itself.
        '''
        return True

    @abstractmethod
    def help(self, parser):
        '''
        @param parser - If given, the plugin should return it's specific options using argparse
                        interface. If not given, or passed as None - the plugin should perform it's options
                        validation logic internally.
        '''
        pass

    @abstractmethod
    def process(self, arch, infile, outfile):
        return True

    @staticmethod
    def build_cmdline(template, command, options = [], infile = '', outfile = '', dontCheckExists = False):
        out = template
        out = out.replace('<command>', command)

        if len(command) == 0 or (not dontCheckExists and not os.path.isfile(command)):
            lib.logger.Logger.out(f'''
=======================================
FATAL 

build_cmdline: 
    Packer command file does not exist: "{command}"

    Cannot build shell command line to run the packer! 
    Check your YAML or ProtectMyTooling parameters

    command = "{command}"
    options = "{options}"
    infile  = "{infile}"
    outfile = "{outfile}"

    ''', sys.stdout, '[!] ', color='red')


            os._exit(1)

        if len(options) > 0: 
            if type(options) == type([]): out = out.replace('<options>', ' '.join(options))
            elif type(options) == type(''): out = out.replace('<options>', options)
        else:
            out = out.replace('<options>', '')
        if len(infile) > 0: out = out.replace('<infile>', '"{}"'.format(infile))
        else:
            out = out.replace('<infile>', '')
        if len(outfile) > 0: out = out.replace('<outfile>', '"{}"'.format(outfile))
        else:
            out = out.replace('<outfile>', '')

        out = out.replace('  ', ' ')
        return out