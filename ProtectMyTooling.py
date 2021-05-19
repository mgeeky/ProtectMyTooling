#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Author:
#   Mariusz B. / mgeeky, '20-'21
#   <mb [at] binary-offensive.com>
#   (https://github.com/mgeeky)
#

VERSION = '0.4'

import os
import pefile
import shutil
import glob
import pprint
import lib.optionsparser
from lib.packersloader import PackersLoader
from lib.logger import Logger
from lib.logger import Logger
from lib.utils import *


options = {
    'debug': False,
    'verbose': False,
    'silent' : False,
    'colors' : False,
    'config' : '',
    'timeout' : 60,
    'arch' : '',
    'log': None,
    'packers': '',
    'packer_class_name': 'Packer\\w+',
}

logger = None
packersloader = None

def init():
    global logger
    global packersloader

    logger = Logger()

    lib.optionsparser.parse_options(logger, options, VERSION)
    logger = Logger(options)
    packersloader = PackersLoader(logger, options)

    for name, plugin in packersloader.get_packers().items():
        plugin.logger = logger
        plugin.help(None)

    logger.dbg('Dumping all of the options specified:\n')
    logger.dbg(pprint.pformat(options))

    return True

def launchPacker(arch, packer, infile, outfile):
    if not packer in packersloader.get_packers().keys():
        logger.fatal('Requested packer ({}) was not loaded! Fatal error.'.format(packer))

    return packersloader[packer].process(arch, infile, outfile)

def checkAv():
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

def handleAv(status):
    outstatus = -1

    if 'disable_av_command' not in options.keys() or not options['disable_av_command'] or \
        'enable_av_command' not in options.keys() or not options['enable_av_command']:
        logger.info("No Enable/Disable AV commands were specified, skipping AV orchestration.")
        return outstatus

    if status == 0:
        outstatus = checkAv()

        if outstatus == 1:
            logger.dbg('Disabling AV...')

            out = shell(logger, options['disable_av_command'])

            logger.dbg('AV disable command returned: "{}"'.format(str(out))) 
            logger.info('AV should be disabled now.')

        return outstatus

    elif status == 1:
        logger.dbg('Enabling AV...')

        out = shell(logger, options['enable_av_command'])

        logger.dbg('AV enable command returned: "{}"'.format(str(out))) 
        logger.info('AV should be enabled now.')

    else:
        return -1

def getFileArch(infile):
    try:
        if options['arch'] != '': 
            return options['arch']

        pe = pefile.PE(infile, fast_load = True)
        arch = 'x86' if (pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']) else 'x64'

    except pefile.PEFormatError as e:
        logger.fatal('Couldn not detect input file\'s architecture. Please specify it using --arch!')

    return arch

def validateOutfile(outfile):
    return os.path.isfile(outfile)

    try:
        pe = pefile.PE(outfile)

        logger.info('Output looks like a valid PE. Should be good to go.')
        return True

    except pefile.PEFormatError as e:
        logger.err('Output file validation failed as it has corrupted PE structure: ' + str(e))
        return False

def testRun(outfile):
    print('\n\nRunning application to test it...\n')
    print(shell(logger, '"{}" {}'.format(outfile, options['cmdline'])))

def processFile(singleFile, infile, _outfile):
    result = False
    
    try:
        tmps = []
        arch = getFileArch(infile)
        origFileSize = os.path.getsize(infile)

        print('\n[.] Processing {} file: "{}"'.format(arch, infile))
        packersChain = '<file>'
        packersOrder = options['packers'].split(',')
        

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
                print('[.] Generating output of {}...'.format(packersChain))

            logger.dbg('\tinfile  < "{}"'.format(infile))
            logger.dbg('\toutfile > "{}"'.format(outfile))

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

            if not os.path.isfile(outfile):
                if singleFile:
                    logger.fatal('Output file does not exist (maybe AV kicked in?). FATAL.')
                else:
                    logger.err('Output file does not exist (maybe AV kicked in?)')
                    return

            infile = outfile

        for t in tmps:
            logger.dbg('Removing intermediary file: {}'.format(t))
            os.remove(t)

        if result:
            print('\n[.] File packed. Generated output: "{}"'.format(_outfile))

    except Exception as e:
        raise

    if result and validateOutfile(_outfile):
        newFileSize = os.path.getsize(_outfile)

        if (options['verbose'] or options['debug']) and singleFile:
            print('''
++++++++++++++++++++++++++++++++++++++++++++++++++++
[+] SUCCEEDED. Original file size: {} bytes, new file size {}: {}, ratio: {:.2f}%
++++++++++++++++++++++++++++++++++++++++++++++++++++
'''.format(
                origFileSize, packersChain, newFileSize,
                ((float(newFileSize) / origFileSize * 100.0))
            ))
        else:
            print('[+] SUCCEEDED. Original file size: {} bytes, new file size {}: {}, ratio: {:.2f}%'.format(
                origFileSize, packersChain, newFileSize,
                ((float(newFileSize) / origFileSize * 100.0))
            ))

        if singleFile and options['testrun']:
            testRun(outfile)

        return 0

    else:
        print('\n[-] Something went wrong with ({})!'.format(
            os.path.basename(infile)
        ))
        return 1

def processDir(infile, outdir):
    patterns = (
        os.path.join(infile, '*.exe'),
        os.path.join(infile, '*.dll'),
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

def main():
    print('''
        :: ProtectMyTooling - a wrapper for PE Packers & Protectors
        Script that builds around supported packers & protectors to produce complex protected binaries.
        Mariusz B. / mgeeky '20-'21, <mb@binary-offensive.com>
        v{}
'''.format(VERSION))

    if not os.name == 'nt':
        print('[!] This script works only on Windows platforms.')

    if not init():
        return 1

    status = -1
    out = 0

    try:
        try:
            status = handleAv(0)

        except lib.utils.ShellCommandReturnedError as e:
            logger.err("Error occured while trying to disable AV (Continuing anyway):\n{}".format(str(e)))

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

    finally:
        try:
            handleAv(status)
        except lib.utils.ShellCommandReturnedError as e:
            logger.error("Error occured while trying to re-enable AV (Continuing anyway):\n{}".format(str(e)))

    return out

if __name__ == '__main__':
    main()