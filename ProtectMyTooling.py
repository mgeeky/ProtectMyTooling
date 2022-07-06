#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Author:
#   Mariusz Banach / mgeeky, '20-'22
#   <mb [at] binary-offensive.com>
#   (https://github.com/mgeeky)
#

VERSION = '0.14'

import os
import pefile
import shutil
import glob
import time
import pprint
import atexit
import lib.optionsparser
from lib.packersloader import PackersLoader
from lib.logger import Logger
from lib.utils import *

from RedWatermarker import PeWatermarker

options = {
    'debug': False,
    'verbose': False,
    'silent' : False,
    'colors' : True,
    'config' : '',
    'timeout' : 60,
    'arch' : '',
    'log': None,
    'packers': '',
    'packer_class_name': 'Packer\\w+',
    'watermark' : [],
    'ioc' : False,
    'custom_ioc' : '',
    'ioc_path' : '',
}

logger = None
packersloader = None
av_enable_status = -1

def init():
    global logger
    global options
    global packersloader

    logger = Logger()

    opts = lib.optionsparser.parse_options(logger, options, VERSION)
    options.update(opts)
    
    logger = Logger(options)
    packersloader = PackersLoader(logger, options)

    for name, plugin in packersloader.get_packers().items():
        plugin.logger = logger
        plugin.help(None)

    logger.dbg('Dumping all of the options specified:\n')
    logger.dbg(pprint.pformat(options))

    return True

def launchPacker(arch, packer, infile, outfile):
    keys = [x.lower() for x in lib.utils.RenamePackerNameToPackerFile.keys()]
    if packer in keys:
        packer = lib.utils.RenamePackerNameToPackerFile[packer]

    if not packer in packersloader.get_packers().keys():
        logger.fatal('Requested packer ({}) was not loaded! Fatal error.'.format(packer))

    return packersloader[packer].process(arch, infile, outfile)

def getFileArch(infile):
    pe = None
    try:
        if options['arch'] != '': 
            return options['arch']

        if lib.utils.isShellcode(infile):
            if '64' in infile:
                logger.info('Deduced from input file name x64 architecture.')
                return 'x64'

            elif '86' in infile or '32' in infile:
                logger.info('Deduced from input file name x86 architecture.')
                return 'x86'

            logger.fatal('Could not deduce shellcode architecture. Use --arch to set it up.')

        pe = pefile.PE(infile, fast_load = True)
        arch = 'x86' if (pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']) else 'x64'

    except pefile.PEFormatError as e:
        logger.fatal('Could not detect input file\'s architecture. Please specify it using --arch!')

    finally:
        if pe:
            pe.close()

    return arch

def injectWatermark(outfile):
    try:
        if len(options['watermark']) == 0:
            return False

        temp = tempfile.NamedTemporaryFile(delete=False)
        shutil.copy(outfile, temp.name)

        opts = {
            'verbose' : options['verbose'],
            'debug' : options['debug'],
            'check' : False,
        }

        for k in lib.optionsparser.AvailableWatermarkSpots:
            k = k.replace('-', '_')
            if k == 'checksum':
                opts[k] = 0
                continue

            opts[k] = ''

        for watermark in options['watermark']:
            spot, marker = watermark.split('=')
            spot = spot.replace('-', '_')

            if 'checksum' == spot:
                try:
                    marker = marker.lower()
                    base = 10

                    if marker.startswith('0x') or \
                        'a' in marker or 'b' in marker or 'c' in marker or \
                        'd' in marker or 'e' in marker or 'f' in marker:
                        base = 16

                    num = int(marker, base)

                    if num >= 2**32:
                        logger.fatal('Specified checksum number in --watermark is too large! Must be no bigger than 2^32-1 (0xffffffff)!')

                    opts[spot] = num

                except Exception as e:
                    logger.fatal('Invalid --watermark checksum=NUM value, could not be casted to integer!')
            else:
                opts[spot] = marker

        pewat = PeWatermarker(opts, logger, outfile, temp.name)
        result = pewat.watermark()

        if result:
            logger.ok('Successfully watermarked resulting artifact file.')
            shutil.copy(temp.name, outfile)
        else:
            logger.err('Could not watermark resulting artifact file.')

        return result

    except Exception as e:
        raise
        return False

    finally:
        temp.close()
        os.unlink(temp.name)

def validateOutfile(outfile):
    return os.path.isfile(outfile)

    pe = None
    try:
        pe = pefile.PE(outfile)

        logger.info('Output looks like a valid PE. Should be good to go.')
        return True

    except pefile.PEFormatError as e:
        logger.err('Output file validation failed as it has corrupted PE structure: ' + str(e))
        return False

    finally:
        if pe:
            pe.close()

def testRun(outfile):
    print('\n\nRunning application to test it...\n')
    print(shell(logger, '"{}" {}'.format(outfile, options['cmdline'])))

def processFile(singleFile, infile, _outfile):
    result = False

    iocsCollected = []

    if options['ioc']:
        iocsCollected.append(lib.utils.collectIOCs(infile, 'Input File', options['custom_ioc']))
    
    try:
        tmps = []
        checkArch = True
        packersOrder = options['packers'].split(',')

        for i in range(len(packersOrder)):
            packer = packersOrder[i].strip()
            
            if not packersloader[packer].validate_file_architecture():
                checkArch = False
                if (options['verbose'] or options['debug']):
                    logger.info(f'Packer {packer} requested not to verify file\'s architecture.')
                break

        if checkArch:
            arch = getFileArch(infile)
        else:
            arch = ''

        origFileSize = os.path.getsize(infile)

        print('[.] Processing {} file :  {}'.format(arch, infile))
        packersChain = '<file>'

        for i in range(len(packersOrder)):
            packer = packersOrder[i].strip()
            
            if i + 1 < len(packersOrder):
                outfile = get_tempfile_name('.bin')
                tmps.append(outfile)
            else:
                outfile = _outfile

            packersChain = '{}({})'.format(packersloader[packer].get_name(), packersChain)

            if (options['verbose'] or options['debug']) and singleFile:
                print('''
=================================================
[.] Generating output of {}...
=================================================
    '''.format(packersChain))
            else:
                logger.info('[>] Generating output of {}...'.format(packersChain), forced = True, noprefix=True, color = 'yellow')

            logger.dbg('\tinfile  < "{}"'.format(infile))
            logger.dbg('\toutfile > "{}"'.format(outfile))

            form = getFileFormat(infile)
            if form == '': form = 'nothing really'

            logger.info(f'Input file format resembles: {form}', color='yellow')

            if not os.path.isfile(infile):
                if singleFile:
                    logger.fatal('For some reason input file no longer exists (maybe AV kicked in?). FATAL.')
                else:
                    logger.err('For some reason input file no longer exists (maybe AV kicked in?)')
                    return

            if not launchPacker(arch, packer, infile, outfile):
                hint = ''

                if i > 0:
                    hint = ' Maybe previous packers ({}) returned a PE file that is not digestible by {}?'.format(
                        ','.join(packersOrder[:i]), packer
                    )

                if singleFile:
                    logger.fatal('Packer ({}) failed.{}'.format(packer, hint))
                else:
                    logger.err('Packer ({}) failed.{}'.format(packer, hint))
            else:
                result = True

                if options['ioc']:
                    iocsCollected.append(lib.utils.collectIOCs(outfile, 'Obfuscation artifact: ' + packersChain, options['custom_ioc']))

            if not os.path.isfile(outfile):
                if singleFile:
                    logger.fatal('Output file does not exist (maybe AV kicked in?). FATAL.')
                else:
                    logger.err('Output file does not exist (maybe AV kicked in?)')
                    return

            form = getFileFormat(outfile)
            if form == '': form = 'nothing really'
            
            logger.info(f'Output file format resembles: {form}', color='cyan')

            infile = outfile

        for t in tmps:
            logger.dbg('Removing intermediary file: {}'.format(t))
            try:
                os.remove(t)
            except Exception as e:
                logger.err(f'Could not remove intermediary file: {t}\n\tException thrown: {e}')

        if result:
            logger.info(f'''
[+] File packed. 
    Generated output : {_outfile}''', noprefix=True)

    except Exception as e:
        raise

    if len(options['watermark']) > 0:
        logger.info('Injecting watermark...')
        injectWatermark(_outfile)

    if options['ioc']:
        iocsCollected.append(lib.utils.collectIOCs(_outfile, 'Output obfuscated artifact', options['custom_ioc']))

    if result and validateOutfile(_outfile):
        newFileSize = os.path.getsize(_outfile)

        if options['ioc']:
            path, ext = os.path.splitext(outfile)
            iocName = path + '-ioc.csv'

            if len(options['ioc_path']) > 0:
                iocName = options['ioc_path']

            fileExists = os.path.isfile(iocName)

            with open(iocName, 'a') as f:
                columns = (
                    'timestamp',
                    'filename',
                    'author',
                    'context',
                    'comment',
                    'md5',
                    'sha1',
                    'sha256',
                    'imphash',
                    #'typeref_hash',
                )

                if not fileExists:
                    f.write(','.join(columns) + '\n')

                for e in iocsCollected:
                    elems = []
                    for col in columns:
                        elems.append(e[col])

                    f.write(','.join(elems) + '\n')

            logger.ok(f'IOCs written to: {iocName}')

        if (options['verbose'] or options['debug']) and singleFile:
            logger.ok('''
++++++++++++++++++++++++++++++++++++++++++++++++++++
[+] SUCCEEDED. Original file size: {} bytes, new file size {}: {}, ratio: {:.2f}%
++++++++++++++++++++++++++++++++++++++++++++++++++++
'''.format(
                origFileSize, packersChain, newFileSize,
                ((float(newFileSize) / origFileSize * 100.0))
            ), noprefix=True)

        else:
            logger.ok('\n[+] SUCCEEDED. Original file size: {} bytes, new file size {}: {}, ratio: {:.2f}%'.format(
                origFileSize, packersChain, newFileSize,
                ((float(newFileSize) / origFileSize * 100.0))
            ), noprefix=True)

        if singleFile and options['testrun']:
            testRun(outfile)

        return 0

    else:
        logger.err('\n[-] Something went wrong with ({})!'.format(
            os.path.basename(infile)
        ), noprefix=True)
        return 1

def processDir(infile, outdir):
    patterns = (
        os.path.join(infile, '*.exe'),
        os.path.join(infile, '*.dll'),
        os.path.join(infile, '*.cpl'),
        os.path.join(infile, '*.xll'),
        #os.path.join(infile, '*.scr'),
        #os.path.join(infile, '*.sys'),
    )

    outs = ()
    pref = options['packers'].replace(',', '-').lower() + '-'

    for pat in patterns:
        logger.info('Enumerating files in: {}'.format(pat))
        for file in glob.glob(pat):

            if os.path.isfile(file):
                outfile = os.path.join(outdir, pref + os.path.basename(file))

                try:
                    out = processFile(False, file, outfile)

                except Exception as e:
                    logger.err('Exception occured while processing "{}": {}'.format(
                        file, str(e)
                    ))

            #elif os.path.isdir(file):
            #    processDir(file, outdir)

def checkAv(options, logger):
    outstatus = -1

    logger.info("Checking AV status...")

    if 'check_av_command' in options.keys() and 'disable_av_command' in options.keys() \
        and 'enable_av_command' in options.keys() and options['check_av_command']:

        out = shell(logger, options['check_av_command'])
        logger.dbg('AV status before starting packers: "{}"'.format(str(out)))

        if out.lower() == 'false':
            logger.info('AV seemingly enabled.')
            outstatus = 1
        elif out.lower() == 'true':
            logger.info('AV seemingly disabled.')
            outstatus = 0
    else:
        return outstatus
    
    if outstatus == -1:
        logger.info('Unknown AV status.')

    return outstatus

def handleAv(options, logger, status):
    outstatus = -1

    if 'disable_av_command' not in options.keys() or not options['disable_av_command'] or \
        'enable_av_command' not in options.keys() or not options['enable_av_command']:
        logger.info("No Enable/Disable AV commands were specified, skipping AV orchestration.")
        return outstatus

    if status == 0:
        outstatus = checkAv(options, logger)

        if outstatus == 1:
            logger.dbg('Disabling AV...')

            out = shell(logger, options['disable_av_command'])

            logger.dbg('AV disable command returned: "{}"'.format(str(out))) 
            logger.info('AV should be disabled now. Waiting 5 seconds...')

            time.sleep(5.0)

        initialAvStatus = outstatus
        return outstatus

    elif status == 1:
        logger.dbg('Enabling AV in 5 seconds...')
        time.sleep(5.0)

        out = shell(logger, options['enable_av_command'])

        logger.dbg('AV enable command returned: "{}"'.format(str(out))) 
        logger.info('AV should be enabled now.')

    else:
        logger.info('Unknown AV handle status.')
        return -1

@atexit.register
def reEnableAvAtExit():
    try:
        handleAv(options, logger, av_enable_status)

    except lib.utils.ShellCommandReturnedError as e:
        logger.error("Error occured while trying to re-enable AV:\n{}".format(str(e)))

def main():
    global av_enable_status

    try:
        print(r'''
    ::::::::::.:::::::..      ...  :::::::::::.,::::::  .,-::::::::::::::::
     `;;;```.;;;;;;``;;;;  .;;;;;;;;;;;;;;;'''''';;;;'''''',;;;'````;;;;;;;;''''''
      `]]nnn]]' [[[,/[[[' ,[[     \[[,  [[     [[cccc [[[           [[     
       $$$""    $$$$$$c   $$$,     $$$  $$     $$"""" $$$           $$     
       888o     888b "88bo"888,_ _,88P  88,    888oo,_`88bo,__,o,   88,    
    .  YMMMb :.-:.MM   ::-. "YMMMMMP"   MMM    """"YUMMM"YUMMMMMP"  MMM    
    ;;,.    ;;;';;.   ;;;;'                                                
    [[[[, ,[[[[, '[[,[[['                                                  
    $$$$$$$$"$$$   c$$"                                                    
    888 Y88" 888o,8P"`                                                     
    ::::::::::::mM...        ...     :::    :::::.    :::. .,-:::::/       
    ;;;;;;;;''''''.;;;;;;;.  .;;;;;;;.  ;;;    ;;`;;;;,  `;;,;;-'````'        
         [[   ,[[     \[[,[[     \[[,[[[    [[[ [[[[[. '[[[[   [[[[[[/     
         $$   $$$,     $$$$$,     $$$$$'    $$$ $$$ "Y$c$"$$c.    "$$      
         88,  "888,_ _,88"888,_ _,88o88oo,._888 888    Y88`Y8bo,,,o88o     
         MMM    "YMMMMMP"  "YMMMMMP"""""YUMMMMM MMM     YM  `'YMUP"YMM   
''')
    except:
        print('''

    :: ProtectMyTooling
''')

    print(r'''    Red Team implants protection swiss knife.

    Multi-Packer wrapping around multitude of packers, protectors, shellcode loaders, encoders.
    Mariusz Banach / mgeeky '20-'22, <mb@binary-offensive.com>
    v{}
'''.format(VERSION))

    if not os.name == 'nt':
        print('[!] This script works only on Windows platforms.')

    if not init():
        return 1

    out = 0

    try:
        try:
            av_enable_status = handleAv(options, logger, 0)

        except lib.utils.ShellCommandReturnedError as e:
            logger.fatal("Error occured while trying to disable AV:\n{}".format(str(e)))

        infile = os.path.abspath(options['infile'])
        outfile = os.path.abspath(options['outfile'])

        if infile == outfile:
            logger.fatal('Input file is the same as output file!')

        if os.path.isfile(infile):
            out = processFile(True, infile, outfile)

        elif os.path.isdir(infile):
            if not os.path.isdir(outfile):
                logger.fatal('If infile points to a directory to perform recursive sweep - so should be the outfile, an output directory where to place generated artefacts!')

            logger.info('Infile is a directory. Working recursively on files stored there.')
            processDir(infile, outfile)

    except Exception as e:
        raise

    print(f'''
Friendly reminder:
    - If your produced binary crashes or doesn't run as expected - try using different packers chain.
         Packers don't guarantee stability of produced binaries, therefore ProtectMyTooling cannot as well.
    - While chaining, carefully match output->input payload formats according to what consecutive packer expects.
''')

    return out

if __name__ == '__main__':
    main()
