#!/usr/bin/python3
# -*- coding: utf-8 -*-

import textwrap
import sys, os, re
import yaml

import lib.utils

from copy import deepcopy
from argparse import ArgumentParser

from lib.packersloader import PackersLoader
from lib.logger import Logger

OptionsDefaultValues = {
    
}

AvailableWatermarkSpots = (
    'dos-stub',
    'checksum',
    'overlay',
    'section',
)

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

    argvi = [x.lower() for x in sys.argv]

    helpRequested = ('-h' in argvi) or ('--help' in argvi)
    fullHelp = helpRequested and (('-v' in argvi or '--verbose' in argvi) or ('-d' in argvi or '--debug' in argvi))

    epilog = 'PROTIP: Use "py ProtectMyTooling.py -h -v" to see all packer-specific options.' if (helpRequested and not fullHelp) else ''

    if len(sys.argv) == 2 and sys.argv[1] == '-L':
        (packerslist, packersloader) = preload_packers(logger, opts)
        num = 0
        for name, packer in packersloader.get_packers().items():
            num += 1
            packerType = packer.get_type()
            print('[{0:2}] {1:14} -  {2:22} - {3}'.format(
                num, 
                name, 
                lib.utils.packerTypeNames[packerType], 
                packer.get_desc().strip()
            ))

        print()
        sys.exit(0)

    options = opts.copy()

    usage = "Usage: %%prog [options] <packers> <infile> <outfile>"
    parser = ArgumentParser(
        usage=usage, 
        prog="%prog " + version,
        epilog = epilog
    )

    parser.add_argument('packers', metavar='packers', help='Specifies packers to use and their order in a comma-delimited list. Example: "pecloak,upx" will produce upx(pecloak(original)) output.')
    parser.add_argument('infile', metavar='infile', help='Input file to be packed/protected.')
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
    parser.add_argument("-C", "--nocolors", dest='nocolors', action='store_true',
        help="Do not use colors in output.")
    
    ioc = parser.add_argument_group("IOCs collection")
    ioc.add_argument('-i', '--ioc', action='store_true', help = 'Collect IOCs and save them to .csv file side by side to <outfile>')
    ioc.add_argument('--ioc-path', default='', help = 'Optional. Specify a path for the IOC file. By default will place outfile-ioc.csv side by side to generated output artifact.')
    ioc.add_argument('-I', '--custom-ioc', default='', help = 'Specify a custom IOC value that is to be written into output IOCs csv file in column "comment"')

    wat = parser.add_argument_group("Artifact Watermarking")
    wat.add_argument('-w', '--watermark', metavar='WHERE=STR', default=[], nargs='+', help = 'Inject watermark to generated artifact. Syntax: where=value, example: "-w dos-stub=Foobar". Available watermark places: dos-stub,checksum,overlay,section . Section requires NAME,STR syntax where NAME denotes PE section name, e.g. "-w section=.foo,bar" will create PE section named ".foo" with contents "bar". May be repeated.')
    
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

    opts['packerslist'] = {}

    if not helpRequested or fullHelp:
        opts['packerslist'] = feed_with_packer_options(logger, options, parser)

    allPackersList = opts['packerslist'].copy()

    params = parser.parse_args()

    if ',' in params.custom_ioc:
        logger.fatal('You cannot use comma (,) in -I/--custom-ioc as that would violate CSV structure.')

    opts['packerslist'] = params.packers.split(',')
    opts['timeout'] = int(params.timeout)

    if params.nocolors:
        opts['colors'] = False

    if len(opts['arch']) > 0:
        opts['arch'] = opts['arch'].lower()
        if not opts['arch'].startswith('x'):
            opts['arch'] = 'x' + opts['arch']

        if opts['arch'] != 'x86' and opts['arch'] != 'x64':
            logger.fatal('Invalid --arch specified! Must be one of -a x86 / -a x64')

    for i in range(len(allPackersList)):
        allPackersList[i] = os.path.basename(allPackersList[i]).replace('.py', '')

    keys = [x.lower() for x in lib.utils.RenamePackerNameToPackerFile.keys()]
    
    for p in opts['packerslist']:
        if p not in allPackersList:
            if p not in keys:
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

    if len(opts['watermark']) > 0:
        for watermark in options['watermark']:
            if '=' not in watermark:
                logger.fatal(f'"--watermark {watermark}" requires syntax: WHERE=VALUE. Where denotes spot to be injected with watermark and may be one of the following: ' + ', '.join(AvailableWatermarkSpots))

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

    options = opts.copy()
    return opts

#
# Program parameters are resolved in following order (where each next phase overwrites previous values):
#
#   1. Default parameters.
#   2. Parameters from File
#   3. Parameters from Commandline
#
def updateParamsWithCmdAndFile(opts, cmdlineparams, fileparams):
    def isEmpty(x):
        if x is None: return True
        if type(x) == str and x == '': return True
        if ((type(x) == list) or (type(x) == tuple) or (type(x) == dict)) and len(x) == 0: 
            return True

        return False

    allkeys = set(list(opts.keys()) + list(cmdlineparams.keys()) + list(fileparams.keys()))

    for k in allkeys:
        if k not in opts.keys():
            opts[k] = ''

        if k in fileparams.keys() and not isEmpty(fileparams[k]):
            opts[k] = fileparams[k]

        if k in cmdlineparams.keys() and not isEmpty(cmdlineparams[k]):
            opts[k] = cmdlineparams[k]

        if opts[k] == None:
            opts[k] = ''

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