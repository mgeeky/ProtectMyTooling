#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import re
import socket
import pefile
import hashlib
import tempfile
import getpass
import subprocess

from datetime import datetime
from lib.logger import Logger
from xml.dom import minidom
from enum import Enum

class ArchitectureNotSupported(Exception):
    pass

class ShellCommandReturnedError(Exception):
    pass

class PackerType(Enum):
    Unsupported          = 0
    DotNetObfuscator     = 1
    PEProtector          = 2
    ShellcodeLoader      = 3
    ShellcodeEncoder     = 4
    PowershellObfuscator = 5
    ShellcodeConverter   = 6

packerTypeNames = {
    PackerType.Unsupported          : 'Unsupported',
    PackerType.DotNetObfuscator     : '.NET Obfuscator',
    PackerType.PEProtector          : 'PE EXE/DLL Protector',
    PackerType.ShellcodeLoader      : 'Shellcode Loader',
    PackerType.ShellcodeEncoder     : 'Shellcode Encoder',
    PackerType.PowershellObfuscator : 'Powershell Obfuscator',
    PackerType.ShellcodeConverter   : 'Shellcode Converter',
}

logger = Logger()

SkipTheseModuleNames = (
    'PackerType'
)

def getClrAssemblyName(path):
    #
    # Reflectively load specified .NET assembly to extract that 
    # assembly's name. All of the magic thanks to Python.NET
    #
    try:
        ref = clr.System.Reflection.Assembly.Load(open(path, 'rb').read())
        name = ref.GetName().get_Name()
        del ref 
        return name
    except:
        return ''

def isValidPE(path):
    pe = None
    try:
        pe = pefile.PE(path)
        pe.close()
        return True
    except pefile.PEFormatError:
        return False
    finally:
        if pe:
            pe.close()

def isShellcode(path):
    if path.lower().endswith('.bin') or path.lower().endswith('.raw') or path.lower().endswith('.shc'):
        return True

    return False

def isValidPowershell(path):
    if not path.lower().endswith('.ps1') or not path.lower().endswith('.psm1') or \
        not path.lower().endswith('.psm') or not path.lower().endswith('.psd1'):
        return False

    keywords = (
        'function', 'param', 'cmdletbinding', 'parameter', 'mandatory', 'foreach', 'process', 'write-host', 
        'write-verbose', 'catch', '-not', 'new-object', 'readallbytes', '.synopsis', '.example'
    )
    with open(path, 'r') as f:
        data = f.read().lower()

        for word in keywords:
            if word.lower() in data:
                found += 1

    return found > 2

def isDotNetExecutable(path):
    if not isValidPE(path):
        return False

    pe = None
    try:
        pe = pefile.PE(path)
        idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']

        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]

        if dir_entry.VirtualAddress != 0 and dir_entry.Size > 0:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll.decode('utf-8').lower() == 'mscoree.dll':
                    for func in entry.imports:
                        if func.name.decode() == '_CorExeMain':
                            return True
    except Exception as e:
        raise
    finally:
        if pe:
            pe.close()

    return False

def ensureInputFileIsPowershell(func):
    def ensure(self, arch, infile, outfile):
        global logger
        logger = Logger(self.options)

        if not isValidPowershell(infile):
            logger.fatal('Specified input file is not a valid Powershell script as required by this packer! Make sure its extension is .ps1/.psm1 to proceed')

        return func(self, arch, infile, outfile)

    return ensure

def ensureInputFileIsShellcode(func):
    def ensure(self, arch, infile, outfile):
        global logger
        logger = Logger(self.options)

        if not isShellcode(infile):
            logger.fatal('Specified input file does not resemble a Shellcode as required by this packer! Make sure its extension is .bin to proceed.')

        return func(self, arch, infile, outfile)

    return ensure

def ensureInputFileIsDotNet(func):
    def ensure(self, arch, infile, outfile):
        global logger
        logger = Logger(self.options)

        if not isDotNetExecutable(infile):
            logger.fatal('Specified input file is not a valid .NET EXE/DLL as required by this packer!')

        return func(self, arch, infile, outfile)

    return ensure

def ensureInputFileIsPE(func):
    def ensure(self, arch, infile, outfile):
        global logger
        logger = Logger(self.options)

        if not isValidPE(infile):
            logger.fatal('Specified input file is not a valid PE executable (EXE/DLL) as required by this packer!')

        return func(self, arch, infile, outfile)

    return ensure

def prettyXml(xmlstr):
    reparsed = minidom.parseString(xmlstr)
    out = '\n'.join([line for line in reparsed.toprettyxml(indent=' '*2).split('\n') if line.strip()])
    return out.encode()

def collectIOCs(filepath, context, comment):
    iocs = {}
    iocs['filename'] = os.path.basename(filepath)
    iocs['timestamp'] = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    iocs['author'] = f'{getpass.getuser()}@{socket.gethostname()}'
    iocs['context'] = context
    iocs['comment'] = comment

    with open(filepath, 'rb') as f:
        data = f.read()

        iocs['md5'] = hashlib.md5(data).hexdigest()
        iocs['sha1'] = hashlib.sha1(data).hexdigest()
        iocs['sha256'] = hashlib.sha256(data).hexdigest()

        if isValidPE(filepath):
            pe = pefile.PE(filepath)
            iocs['imphash'] = pe.get_imphash()
            pe.close()
        else:
            iocs['imphash'] = 'N/A'

        if isDotNetExecutable(filepath):
            iocs['typeref_hash'] = 'not-yet-implemented'
        else:
            iocs['typeref_hash'] = 'N/A'

    return iocs

def shell2(cmd, alternative = False, stdErrToStdout = False, timeout = 60):
    CREATE_NO_WINDOW = 0x08000000
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    outs = ''
    errs = ''
    if not alternative:
        out = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            startupinfo=si, 
            creationflags=CREATE_NO_WINDOW,
            timeout=timeout
            )

        outs = out.stdout
        errs = out.stderr

    else:
        proc = subprocess.Popen(
            cmd,
            shell=True, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=si, 
            creationflags=CREATE_NO_WINDOW
        )
        try:
            outs, errs = proc.communicate(timeout=timeout)
            proc.wait()

        except TimeoutExpired:
            proc.kill()
            logger.err('WARNING! The command timed-out! Results may be incomplete')
            outs, errs = proc.communicate()

    status = outs.decode(errors='ignore').strip()

    if len(errs) > 0:
#        error = '''
#Running shell command ({}) failed:
#
#---------------------------------------------
#{}
#---------------------------------------------
#'''.format(cmd, errs.decode(errors='ignore'))
        error = errs.decode(errors='ignore')

        if stdErrToStdout:
            return error
            
        raise ShellCommandReturnedError(error)

    return status

def shell(logger, cmd, alternative = False, output = False, timeout = 60):
    logger.info(' Running shell (timeout: {}):\n\tcmd> {}\n'.format(timeout, cmd))
    
    out = shell2(cmd, alternative, stdErrToStdout = output, timeout = timeout)

    if not output or (type(output) == str and len(output) == 0):
        logger.dbg('Command did not produce any output.')
    else:
        logger.info('Command returned:\n------------------------------\n{}\n------------------------------\n'.format(out), forced = True)

    return out

def configPath(basepath, path):
    p = _configPath(basepath, path)

    return os.path.abspath(p)

def _configPath(basepath, path):
    if not path:
        return ''

    if os.path.isfile(path) or os.path.isdir(path):
        return path

    b = os.path.dirname(os.path.realpath(basepath))
    p = os.path.join(b, path)

    if os.path.isfile(p) or os.path.isdir(p):
        return p

    return ''

def get_tempfile_name(some_id = ''):
    return os.path.join(tempfile.gettempdir(), next(tempfile._get_candidate_names()) + some_id)

def sha1(path):
    h = hashlib.new('sha1')
    with open(path, 'rb') as f:
        h.update(f.read())

    return h.hexdigest()
