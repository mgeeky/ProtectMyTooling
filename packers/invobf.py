#!/usr/bin/python3
# -*- coding: utf-8 -*-

from IPacker import IPacker
from lib.utils import *

import os
import re
import pe_tools

class PackerInvObf(IPacker):

    #
    # Modify those to whatever you please.
    # Available obfuscations:
    #   
    #   [*] TOKEN       Obfuscate PowerShell command Tokens
    #   [*] AST         Obfuscate PowerShell Ast nodes (PS3.0+)
    #   [*] STRING      Obfuscate entire command as a String
    #   [*] ENCODING    Obfuscate entire command via Encoding
    #   [*] COMPRESS    Convert entire command to one-liner and Compress
    #   [*] LAUNCHER    Obfuscate command args w/Launcher techniques (run once at end)
    #   
    #   [*] TOKEN\STRING        Obfuscate String tokens (suggested to run first)
    #   [*] TOKEN\COMMAND       Obfuscate Command tokens
    #   [*] TOKEN\ARGUMENT      Obfuscate Argument tokens
    #   [*] TOKEN\MEMBER        Obfuscate Member tokens
    #   [*] TOKEN\VARIABLE      Obfuscate Variable tokens
    #   [*] TOKEN\TYPE          Obfuscate Type tokens
    #   [*] TOKEN\COMMENT       Remove all Comment tokens
    #   [*] TOKEN\WHITESPACE    Insert random Whitespace (suggested to run last)
    #   [*] TOKEN\ALL           Select All choices from above (random order)
    #   
    #   [*] AST\NamedAttributeArgumentAst    Obfuscate NamedAttributeArgumentAst nodes
    #   [*] AST\ParamBlockAst                Obfuscate ParamBlockAst nodes
    #   [*] AST\ScriptBlockAst               Obfuscate ScriptBlockAst nodes
    #   [*] AST\AttributeAst                 Obfuscate AttributeAst nodes
    #   [*] AST\BinaryExpressionAst          Obfuscate BinaryExpressionAst nodes
    #   [*] AST\HashtableAst                 Obfuscate HashtableAst nodes
    #   [*] AST\CommandAst                   Obfuscate CommandAst nodes
    #   [*] AST\AssignmentStatementAst       Obfuscate AssignmentStatementAst nodes
    #   [*] AST\TypeExpressionAst            Obfuscate TypeExpressionAst nodes
    #   [*] AST\TypeConstraintAst            Obfuscate TypeConstraintAst nodes
    #   [*] AST\ALL                          Select All choices from above
    #   
    #   [*] STRING\1            Concatenate entire command
    #   [*] STRING\2            Reorder entire command after concatenating
    #   [*] STRING\3            Reverse entire command after concatenating
    # 
    #   [*] ENCODING\1          Encode entire command as ASCII
    #   [*] ENCODING\2          Encode entire command as Hex
    #   [*] ENCODING\3          Encode entire command as Octal
    #   [*] ENCODING\4          Encode entire command as Binary
    #   [*] ENCODING\5          Encrypt entire command as SecureString (AES)
    #   [*] ENCODING\6          Encode entire command as BXOR
    #   [*] ENCODING\7          Encode entire command as Special Characters
    #   [*] ENCODING\8          Encode entire command as Whitespace
    # 
    #   [*] COMPRESS\1          Convert entire command to one-liner and compress
    #
    #   [*] LAUNCHER\PS         PowerShell
    #   [*] LAUNCHER\CMD        Cmd + PowerShell
    #   [*] LAUNCHER\WMIC       Wmic + PowerShell
    #   [*] LAUNCHER\RUNDLL     Rundll32 + PowerShell
    #   [*] LAUNCHER\VAR+       Cmd + set Var && PowerShell iex Var
    #   [*] LAUNCHER\STDIN+     Cmd + Echo | PowerShell - (stdin)
    #   [*] LAUNCHER\CLIP+      Cmd + Echo | Clip && PowerShell iex clipboard
    #   [*] LAUNCHER\VAR++      Cmd + set Var && Cmd && PowerShell iex Var
    #   [*] LAUNCHER\STDIN++    Cmd + set Var && Cmd Echo | PowerShell - (stdin)
    #   [*] LAUNCHER\CLIP++     Cmd + Echo | Clip && Cmd && PowerShell iex clipboard
    #   [*] LAUNCHER\RUNDLL++   Cmd + set Var && Rundll32 && PowerShell iex Var
    #   [*] LAUNCHER\MSHTA++    Cmd + set Var && Mshta && PowerShell iex Var
    #
    default_invobf_args = (
        r'COMPRESS\1,'
        r'TOKEN\ALL\1,'
        r'AST\ALL\1,'
        r'STRING\3,'
        r'ENCODING\5'
    )

    invobf_cmdline_template = r'<command> -c "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force ; Import-Module .\Invoke-Obfuscation.psd1 ; Invoke-Obfuscation -ScriptPath <infile> -Command \'<options>\' -Quiet | Out-File <outfile>'

    default_options = {
        'invobf_powershell' : 'powershell.exe',
    }

    def __init__(self, logger, options):
        self.invobf_args = PackerInvObf.default_invobf_args
        self.logger = logger
        self.options = options

    @staticmethod
    def get_name():
        return 'InvObf'

    @staticmethod
    def get_desc():
        return 'Obfuscates Powershell scripts with Invoke-Obfuscation (by Daniel Bohannon)'

    @staticmethod
    def validate_file_architecture():
        return False

    def help(self, parser):
        if parser != None:
            parser.add_argument('--invobf-powershell', metavar='PATH', dest='invobf_powershell',
                help = 'Path to Powershell interpreter to be used by Invoke-Obfuscation. Default: "powershell.exe"')

            parser.add_argument('--invobf-path', metavar='PATH', dest='invobf_path',
                help = 'Path to the Invoke-Obfuscation script.')

            parser.add_argument('--invobf-args', metavar='ARGS', dest='invobf_args',
                help = 'Optional Invoke-Obfuscation specific arguments to pass. They override default ones.')

        else:
            if not self.options['config']:
                self.logger.fatal('Config file not specified!')

            for k, v in PackerInvObf.default_options.items():
                if k not in self.options.keys():
                    self.options[k] = v

            if 'invobf_powershell' in self.options.keys() and self.options['invobf_powershell'] != None and len(self.options['invobf_powershell']) > 0:
                self.options['invobf_powershell'] = self.options['invobf_powershell']
            else:
                self.options['invobf_powershell'] = PackerInvObf.default_options['invobf_powershell']

            if 'invobf_path' in self.options.keys() and self.options['invobf_path'] != None and len(self.options['invobf_path']) > 0:
                self.options['invobf_path'] = configPath(self.options['config'], self.options['invobf_path'])
            else:
                self.options['invobf_path'] = PackerInvObf.default_options['invobf_path']

            if 'invobf_args' in self.options.keys() and self.options['invobf_args'] != None \
                and len(self.options['invobf_args']) > 0: 
                self.options['invobf_args'] = self.options['invobf_args']
                self.invobf_args = self.options['invobf_args']

    def process(self, arch, infile, outfile):
        try:
            if not infile.endswith('.ps1'):
                self.logger.fatal('Input file must be Powershell script ending with .ps1 extension!')

            path = self.options['invobf_path']

            cmd = IPacker.build_cmdline(
                PackerInvObf.invobf_cmdline_template,
                self.options['invobf_powershell'],
                self.invobf_args,
                infile,
                outfile
            )

            cwd = os.getcwd()
            base = os.path.dirname(path)

            self.logger.dbg('changed working directory to "{}"'.format(base))
            os.chdir(base)
            
            out = shell(self.logger, cmd, 
                output = self.options['verbose'] or self.options['debug'], 
                timeout = self.options['timeout'])

            if os.path.isfile(outfile):
                return True

            else:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    outfile
                ))

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from packer:
----------------------------------------
{e}
----------------------------------------
''')

        except Exception as e:
            raise

        finally:
            self.logger.dbg('reverted to original working directory "{}"'.format(cwd))
            os.chdir(cwd)

        return False
