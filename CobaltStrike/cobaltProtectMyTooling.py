#!/usr/bin/python3
#
# Helper script spawning python and ProtectMyTooling.py according to settings
# received from CobaltStrike. Used by Cobalt's ProtectMyTooling.cna aggressor script.
# Do not use directly.
#
# Author:
#   Mariusz Banach / mgeeky, '20
#   <mb [at] binary-offensive.com>
#   (https://github.com/mgeeky)
#

import re
import os
import sys
#import clr
import glob
import pefile
import random
import string
import tempfile
import subprocess

settings = {
    'output' : '',
    'outputdir' : '',

    'python3_interpreter_path' : '',
    'protected_executables_cache_dir' : '',
    'default_dotnet_packers_chain' : '',
    'protect_my_tooling_dir' : '',
    'default_exe_x86_packers_chain' : '',
    'default_exe_x64_packers_chain' : '',
    'default_dll_x86_packers_chain' : '',
    'default_dll_x64_packers_chain' : '',
    'protect_my_tooling_config' : '',
    'cache_protected_executables' : ''
}

packerslist = []

def output(x):
    if settings['output'] == '':
        print(x)
        return

    with open(settings['output'], 'a+') as f:
        f.write(x + '\n')
        f.flush()


def isDotNetExecutable(path):
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

def shell(cmd):
    CREATE_NO_WINDOW = 0x08000000
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE

    out = subprocess.run(
        cmd, 
        shell=True, 
        capture_output=True, 
        startupinfo=si, 
        creationflags=CREATE_NO_WINDOW
    )
    status = out.stdout.decode(errors='ignore').strip()

    if len(out.stderr) > 0:
        raise Exception('''
Running shell command ({}) failed:

---------------------------------------------
{}
---------------------------------------------
'''.format(cmd, out.stderr.decode(errors='ignore')))

    return status

def get_tempfile_name(some_id = ''):
    return os.path.join(tempfile.gettempdir(), next(tempfile._get_candidate_names()) + some_id)

def parseOptions(config):
    global settings
    global packerslist

    data = []
    
    with open(config, 'r') as f:
        data = f.readlines()

    for line in data:
        if not line.startswith('protectmytooling.'): continue
        for k, v in settings.items():
            if k in line:
                settings[k] = line.strip().split(' = ')[1]

    if (os.path.isdir(settings['protected_executables_cache_dir'])) and (settings['cache_protected_executables'] == 'true'):
        settings['outputdir'] = settings['protected_executables_cache_dir']
    else:
        settings['outputdir'] = os.environ['temp']

    if not os.path.isdir(settings['protect_my_tooling_dir']):
        output('[!] protect_my_tooling_dir directory does not exist!')
        return False

    if not os.path.isfile(settings['protect_my_tooling_config']):
        output('[!] protect_my_tooling_config file does not exist!')
        return False

    if not os.path.isfile(settings['python3_interpreter_path']):
        output('[!] python3_interpreter_path file does not exist!')
        return False

    if not settings['default_exe_x86_packers_chain']:
        output('[!] default_exe_x86_packers_chain must be set!')
        return False

    if not settings['default_exe_x64_packers_chain']:
        output('[!] default_exe_x64_packers_chain must be set!')
        return False

    if not settings['default_dll_x86_packers_chain']:
        output('[!] default_dll_x86_packers_chain must be set!')
        return False

    if not settings['default_dll_x64_packers_chain']:
        output('[!] default_dll_x64_packers_chain must be set!')
        return False

    if not settings['default_dotnet_packers_chain']:
        output('[!] default_dotnet_packers_chain must be set!')
        return False

    packerslistoutput = shell('"{}" "{}" -L'.format(
        settings['python3_interpreter_path'],
        os.path.join(settings['protect_my_tooling_dir'], 'ProtectMyTooling.py')
    ))

    for m in re.finditer(r'\|\s*\d+\s*\|\s*([^\s]+)\s*\|', packerslistoutput):
        packerslist.append(m.group(1).lower())

    #output('[.] Packers available:')
    #for packer in packerslist:
    #    output('packer: ' + packer)

    for p in settings['default_exe_x86_packers_chain'].split(','):
        if p.lower() not in packerslist:
            output('[!] Packer: "{}" defined in default_exe_x86_packers_chain is not available!'.format(p))
            return False

    for p in settings['default_exe_x64_packers_chain'].split(','):
        if p.lower() not in packerslist:
            output('[!] Packer: "{}" defined in default_exe_x64_packers_chain is not available!'.format(p))
            return False

    for p in settings['default_dll_x86_packers_chain'].split(','):
        if p.lower() not in packerslist:
            output('[!] Packer: "{}" defined in default_dll_x86_packers_chain is not available!'.format(p))
            return False

    for p in settings['default_dll_x64_packers_chain'].split(','):
        if p.lower() not in packerslist:
            output('[!] Packer: "{}" defined in default_dll_x64_packers_chain is not available!'.format(p))
            return False

    for p in settings['default_dotnet_packers_chain'].split(','):
        if p.lower() not in packerslist:
            output('[!] Packer: "{}" defined in default_dotnet_packers_chain is not available!'.format(p))
            return False

    return True

def isPeFile(infile):
    pe = None
    try:
        pe = pefile.PE(infile)
        arch = 'x86' if (pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']) else 'x64'
        isdll = True if (pe.FILE_HEADER.Characteristics & pefile.IMAGE_CHARACTERISTICS ['IMAGE_FILE_DLL'] == pefile.IMAGE_CHARACTERISTICS ['IMAGE_FILE_DLL']) else False

        return (True, arch, isdll)

    except pefile.PEFormatError as e:
        return (False, None, None)

    finally:
        if pe:
            pe.close()

def clearCacheDir():
    if os.path.isdir(settings['protected_executables_cache_dir']):
        p = os.path.join(settings['protected_executables_cache_dir'], '*')
        output('[.] Clearing cache directory: {}'.format(p))

        for f in glob.glob(p):
            output('\tRemoving file: ' + f)
            os.remove(f)

def main(argv):
    global settings

    if len(argv) < 3:
        output('[!] Usage: cobaltProtectMyTooling.py <cobaltProtectMyTooling.conf> <infile> [logfile]')
        return False

    config = argv[1]
    infile = argv[2]
    settings['output'] = ''

    if len(argv) == 4:
        settings['output'] = argv[3]
        try:
            with open(settings['output'], 'a') as f:
                f.truncate(0)
        except Exception as e:
            output('[!] Could not create file for script\'s output.')
            return False

    if not os.path.isfile(config):
        output('[!] Input cobaltProtectMyTooling.conf file does not exist: "{}"'.format(config))
        return False

    if not parseOptions(config):
        return False

    if infile == 'clearcache':
        clearCacheDir()
        return True

    if not os.path.isfile(infile):
        output('[!] Input file does not exist: "{}"'.format(infile))
        return False

    (ret, arch, isdll) = isPeFile(infile)

    if not ret:
        output('[.] File is not a valid PE file. Returning it directly.')
        output('\nOUTPUT-FILE: "{}"'.format(infile))
        return True

    (filename, ext) = os.path.splitext(infile)
    filename = os.path.basename(filename)
    suff = '-protected.{}{}'.format(
        ''.join(random.choice(string.ascii_lowercase) for i in range(5)),
        ext
    )
    outfile = os.path.join(settings['outputdir'], filename + suff)

    packerschain = ''

    if isDotNetExecutable(infile):
        output('[.] File is a valid .NET Assembly');
        packerschain = settings['default_dotnet_packers_chain']

    else:
        if isdll:
            if arch == 'x64':
                packerschain = settings['default_dll_x64_packers_chain']
            else:
                packerschain = settings['default_dll_x86_packers_chain']
            
            output('[.] File is a native {} DLL executable.'.format(arch))
        else:
            if arch == 'x64':
                packerschain = settings['default_exe_x64_packers_chain']
            else:
                packerschain = settings['default_exe_x86_packers_chain']
            
            output('[.] File is a native {} EXE executable.'.format(arch))

    cmdline = '"{}" "{}" -c "{}" -v {} "{}" "{}"'.format(
        settings['python3_interpreter_path'],
        os.path.join(settings['protect_my_tooling_dir'], 'ProtectMyTooling.py'),
        settings['protect_my_tooling_config'],
        packerschain,
        infile,
        outfile
    )

    output('RUNNING ProtectMyTooling with command line:\n\t' + cmdline + '\n\n')
    result = shell(cmdline)

    if settings['output']:
        logfile = settings['output'] + ".tmp"
        if os.path.isfile(logfile):
            with open(logfile) as f:
                result = f.read()

    output('Result:')
    output(result)

    output('\nOUTPUT-FILE: "{}"'.format(outfile))

    return True

if __name__ == '__main__':
    main(sys.argv)