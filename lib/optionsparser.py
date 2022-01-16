#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys, os, re
import yaml

from copy import deepcopy
from argparse import ArgumentParser

from lib.packersloader import PackersLoader
from lib.logger import Logger

OptionsDefaultValues = {
    
}

def feed_with_packer_options(logger, opts, parser):

    (packerslist, packersloader) = preload_packers(logger, opts)

    for name, packer in packersloader.get_packers().items():
        logger.dbg("Fetching packer {} options.".format(name))
        if hasattr(packer, 'help'):
            
            if parser:
                packer_options = parser.add_argument_group("Packer '{}' options".format(packer.get_name()))
                packer.help(packer_options)

    return packerslist

def preload_packers(logger, opts):
    packerslist = []
    files = sorted([f for f in os.scandir(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join('..', 'packers')))], key = lambda f: f.name)
    for _, entry in enumerate(files):
        if entry.name.endswith(".py") and entry.is_file() and entry.name.lower() not in ['ipacker.py', '__init__.py']:
            packerslist.append(entry.path)

    options = opts.copy()
    options['packerslist'] = packerslist
    options['verbose'] = True
    options['debug'] = False

    return (packerslist, PackersLoader(logger, options))

def parse_options(logger, opts, version):
    global options

    if len(sys.argv) == 2 and sys.argv[1] == '-L':
        (packerslist, packersloader) = preload_packers(logger, opts)
        num = 0
        for name, packer in packersloader.get_packers().items():
            num += 1
            print('[{0:2}] Packer: {1:14} - {2}'.format(num, name, packer.get_desc().strip()))

        sys.exit(0)

    options = opts.copy()

    usage = "Usage: %%prog [options] <packers> <infile> <outfile>"
    parser = ArgumentParser(usage=usage, prog="%prog " + version)

    parser.add_argument('packers', metavar='packers', help='Specifies packers to use and their order in a comma-delimited list. Example: "pecloak,upx" will produce upx(pecloak(original)) output.')
    parser.add_argument('infile', metavar='_input', help='Input file to be packed/protected.')
    parser.add_argument('outfile', metavar='output', help='Output file constituing generated sample.')

    defcfg = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../ProtectMyTooling.yaml'))

    parser.add_argument("-c", "--config", dest='config', default=defcfg,
        help="External configuration file. Default: ProtectMyTooling.yaml")
    parser.add_argument('-t', '--timeout', dest='timeout', default=0, type=int, 
        help = 'Command execution timeout. Default: 60 seconds.')
    parser.add_argument("-a", "--arch", dest='arch', default='',
        help="Specify file's target architecture. If input is a valid PE file, this script will try to automatically sense its arch. Otherwise (shellcode) you'll need to specify it.")

    parser.add_argument("-v", "--verbose", dest='verbose',
        help="Displays verbose output.", action="store_true")
    parser.add_argument("-d", "--debug", dest='debug',
        help="Displays debugging informations (implies verbose output).", action="store_true")
    parser.add_argument("-l", "--log", dest='log', 
        help="Specifies output log file.", metavar="PATH", type=str)
    parser.add_argument("-s", "--silent", dest='silent',
        help="Surpresses all of the output logging.", action="store_true")

    # Test it
    av = parser.add_argument_group("Test sample after generation")
    av.add_argument('-r', '--testrun', action='store_true', help = 'Launch generated sample to test it. Use --cmdline to specify execution parameters. By default output won\'t be launched.')
    av.add_argument('--cmdline', metavar='CMDLINE', dest='cmdline', default = '', type=str, help = 'Command line for the generated sample')


    # Packers handling
    av = parser.add_argument_group("Optional AV Handling hooks")
    av.add_argument('--check-av-command', default='', help = 'Command used to check status of AV solution. This command must return "True" if AV is running.')
    av.add_argument('--disable-av-command', default='', help = 'Command used to disable AV solution before processing files.')
    av.add_argument('--enable-av-command', default='', help = 'Command used to re-enable AV solution after processing files. The AV will be re-enabled only if it was enabled previously.')

    # Packers handling
    packers = parser.add_argument_group("Packers handling")
    packers.add_argument('-L', '--list-packers', action='store_true', help='List available packers.')

    opts['packerslist'] = feed_with_packer_options(logger, options, parser)
    allPackersList = opts['packerslist'].copy()

    params = parser.parse_args()

    opts['packerslist'] = params.packers.split(',')
    opts['timeout'] = int(params.timeout)

    for i in range(len(allPackersList)):
        allPackersList[i] = os.path.basename(allPackersList[i]).replace('.py', '')

    for p in opts['packerslist']:
        if p not in allPackersList:
            logger.fatal('Packer "{}" is not implemented.'.format(p))

    if not os.path.isfile(params.infile) and not os.path.isdir(params.infile):
        logger.fatal('Specified input file does not exist: "{}"'.format(params.infile))

    if os.path.isfile(params.outfile):
        logger.info('Outfile exists ("{}"). Removing it...'.format(params.outfile))
        os.remove(params.outfile)

    if hasattr(params, 'config') and len(params.config) > 0:
        try:
            fileparams = parseParametersFromConfigFile(params.config)

        except Exception as e:
            if opts['debug']: raise
            parser.error('Error occured during parsing config file: ' + str(e))

        opts.update(fileparams)

        updateParamsWithCmdAndFile(opts, vars(params), fileparams)

    else:
        opts.update(vars(params))

    if type(opts['timeout']) == str:
        if opts['timeout'] == '':
            opts['timeout'] = 60
        else:
            opts['timeout'] = int(opts['timeout'])
    elif opts['timeout'] == 0:
        opts['timeout'] = 60

    if opts['silent'] and opts['log']:
        parser.error("Options -s and -w are mutually exclusive.")

    if opts['silent']:
        opts['log'] = 'none'
    elif opts['log'] and len(opts['log']) > 0:
        try:
            with open(opts['log'], 'w') as f:
                pass
        except Exception as e:
            raise Exception('[ERROR] Failed to open log file for writing. Error: "%s"' % e)
    else:
        opts['log'] = sys.stdout

    if opts['log'] and opts['log'] != sys.stdout: opts['log'] = os.path.normpath(opts['log'])


def updateParamsWithCmdAndFile(opts, cmdlineparams, fileparams):
    def isEmpty(x):
        if x is None: return True
        if type(x) == str and x == '': return True
        if ((type(x) == list) or (type(x) == tuple) or (type(x) == dict)) and len(x) == 0: 
            return True

        return False

    allkeys = list(opts.keys()) + list(cmdlineparams.keys()) + list(fileparams.keys())

    for k in allkeys:
        if k in cmdlineparams.keys() and k in fileparams.keys():
            if cmdlineparams[k] == None: cmdlineparams[k] = ''
            if fileparams[k] == None: fileparams[k] = ''

            if isEmpty(cmdlineparams[k]) and (type(fileparams[k]) == bool or not isEmpty(fileparams[k])):
                opts[k] = fileparams[k]
            elif isEmpty(cmdlineparams[k]) and not isEmpty(fileparams[k]):
                opts[k] = fileparams[k]
            elif type(cmdlineparams[k]) == int and cmdlineparams[k] == 0 and type(fileparams[k]) == int and fileparams[k] > 0:
                opts[k] = fileparams[k]
            elif type(fileparams[k]) == int and fileparams[k] == 0 and type(cmdlineparams[k]) == int and cmdlineparams[k] > 0:
                opts[k] = cmdlineparams[k]
            else:
                opts[k] = cmdlineparams[k] 

        elif (k in cmdlineparams.keys()) and (k not in fileparams.keys()):
            opts[k] = cmdlineparams[k]

        elif (k not in cmdlineparams.keys()) and (k in fileparams.keys()):
            opts[k] = fileparams[k]

def parseParametersFromConfigFile(configFile):
    outparams = {}
    config = {}

    try:
        with open(configFile) as f:
            config = yaml.load(f, Loader=yaml.FullLoader)

        outparams.update(config)
        return outparams

    except FileNotFoundError as e:
        raise Exception(f'ProtectMyTooling config file not found: ({configFile})!')

    except Exception as e:
        raise
        raise Exception(f'Unhandled exception occured while parsing ProtectMyTooling config file: {e}')

    return outparams