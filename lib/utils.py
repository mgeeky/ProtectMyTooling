#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import re
import hashlib
import tempfile
import subprocess

from xml.dom import minidom

class ArchitectureNotSupported(Exception):
    pass

class ShellCommandReturnedError(Exception):
    pass

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

def isDotNetExecutable(path):
    pe = pefile.PE(path)
    idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']

    dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]

    if dir_entry.VirtualAddress != 0 and dir_entry.Size > 0:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.decode('utf-8').lower() == 'mscoree.dll':
                for func in entry.imports:
                    if func.name.decode() == '_CorExeMain':
                        return True

    return False

def prettyXml(xmlstr):
    reparsed = minidom.parseString(xmlstr)
    out = '\n'.join([line for line in reparsed.toprettyxml(indent=' '*2).split('\n') if line.strip()])
    return out.encode()

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
        error = '''
Running shell command ({}) failed:

---------------------------------------------
{}
---------------------------------------------
'''.format(cmd, errs.decode(errors='ignore'))

        if stdErrToStdout:
            return error
            
        raise ShellCommandReturnedError(error)

    return status

def shell(logger, cmd, alternative = False, output = False, timeout = 60):
    logger.info(' Running shell (timeout: {}):\n\tcmd> {}'.format(timeout, cmd))
    
    out = shell2(cmd, alternative, stdErrToStdout = output, timeout = timeout)

    if not output:
        logger.dbg('shell("{}") returned:\n"{}"'.format(cmd, out))
    else:
        logger.info('shell("{}") returned:\n"{}"'.format(cmd, out), forced = True)

    return out

def configPath(basepath, path):
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