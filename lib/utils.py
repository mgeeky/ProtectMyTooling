#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import hashlib
import tempfile
import subprocess

try:
    import clr

except ImportError:
    print('[!] No clr module found. Install it using: $ pip3 install pythonnet')
    sys.exit(0)

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

def shell2(cmd, alternative = False):
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
            timeout=30
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
            outs, errs = proc.communicate(timeout=30)
            proc.wait()

        except TimeoutExpired:
            proc.kill()
            logger.err('WARNING! The command timed-out! Results may be incomplete')
            outs, errs = proc.communicate()

    status = outs.decode(errors='ignore').strip()

    if len(errs) > 0:
        raise ShellCommandReturnedError('''
Running shell command ({}) failed:

---------------------------------------------
{}
---------------------------------------------
'''.format(cmd, errs.decode(errors='ignore')))

    return status

def shell(logger, cmd, alternative = False):
    logger.info(' Running shell:\n\tcmd> {}'.format(cmd))
    
    out = shell2(cmd, alternative)

    logger.dbg('shell("{}") returned:\n"{}"'.format(cmd, out))
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