#!/usr/bin/python3
import os
import sys, re
import inspect
from io import StringIO
import csv
import lib.utils

from lib.logger import Logger

#
# Plugin that attempts to load all of the supplied plugins from 
# program launch options.
class PackersLoader:   
    class InjectedLogger(Logger):
        def __init__(self, name, options = None):
            self.name = name
            super().__init__(options)

        def _text(self, txt):
            return '[{}] {}'.format(self.name, txt)

        # Info shall be used as an ordinary logging facility, for every desired output.
        def info(self, txt, forced = False, **kwargs):
            super().info(self._text(txt), forced, **kwargs)

        # Trace by default does not uses [TRACE] prefix. Shall be used
        # for dumping packets, headers, metadata and longer technical output.
        def trace(self, txt, **kwargs):
            super().trace(self._text(txt), **kwargs)

        def dbg(self, txt, **kwargs):
            super().dbg(self._text(txt), **kwargs)

        def err(self, txt, **kwargs):
            super().err(self._text(txt), **kwargs)

        def fatal(self, txt, **kwargs):
            super().fatal(self._text(txt), **kwargs)

    def __init__(self, logger, options, instantiate = True):
        self.options = options
        self.packerslist = {}
        self.called = False
        self.logger = logger
        self.instantiate = instantiate
        plugins_count = len(self.options['packerslist'])

        if plugins_count > 0:
            self.logger.info('Loading %d packer%s...' % (plugins_count, '' if plugins_count == 1 else 's'))
            
            for packer in self.options['packerslist']:
                self.load(packer)

        self.called = True

    def __getitem__(self, key):
        keys = [x.lower() for x in lib.utils.RenamePackerNameToPackerFile.keys()]
        if key in keys:
            key = lib.utils.RenamePackerNameToPackerFile[key]

        return self.packerslist[key]

    def __setitem__(self, key, val):
        self.packerslist[key] = val
        
    # Output format:
    #   packerslist = {'packer1': instance, 'packer2': instance, ...}
    def get_packers(self):
        return self.packerslist

    #
    # Following function parses input packer path with parameters and decomposes
    # them to extract packer's arguments along with it's path.
    # For instance, having such string:
    #   -p "packers/my_packer.py",argument1="test",argument2,argument3=test2
    #
    # It will return:
    #   {'path':'packers/my_packer.py', 'argument1':'t,e,s,t', 'argument2':'', 'argument3':'test2'}
    #
    @staticmethod
    def decompose_path(p):
        decomposed = {}
        f = StringIO(p)
        rows = list(csv.reader(f, quoting=csv.QUOTE_ALL, skipinitialspace=True))

        for i in range(len(rows[0])):
            row = rows[0][i]
            if i == 0:
                decomposed['path'] = row
                continue

            if '=' in row:
                s = row.split('=')
                decomposed[s[0]] = s[1].replace('"', '')
            else:
                decomposed[row] = ''

        return decomposed

    def load(self, path):
        instance = None

        self.logger.dbg('Packer string: "%s"' % path)
        #decomposed = PackersLoader.decompose_path(path)
        #self.logger.dbg('Decomposed as: %s' % str(decomposed))
        #packer = decomposed['path'].strip()

        packer = path

        if not os.path.isfile(packer):
            _packer = os.path.normpath(os.path.join(os.path.dirname(__file__), '../packers/{}'.format(packer)))
            if os.path.isfile(_packer):
                packer = _packer
            elif os.path.isfile(_packer+'.py'):
                packer = _packer + '.py'

        name = os.path.basename(packer).lower().replace('.py', '')

        if name in self.packerslist or name in ['ipacker', '__init__']:
            # Packer already loaded.
            return

        keys = [x.lower() for x in lib.utils.RenamePackerNameToPackerFile.keys()]
        if name in keys:
            name = lib.utils.RenamePackerNameToPackerFile[name]

        self.logger.dbg('Attempting to load packer: %s ("%s")...' % (name, packer))
       
        try:
            p = os.path.dirname(packer)
            if p not in sys.path:
                sys.path.append(p)

            __import__(name)
            module = sys.modules[name]

            self.logger.dbg('Module imported.')

            try:
                handle = None
                pat = re.compile('(' + self.options['packer_class_name'] + ')')

                for attr in dir(module):
                    m = pat.match(attr)
                    if m:
                        if m.group(1) in lib.utils.SkipTheseModuleNames:
                            continue

                        handle = getattr(module, attr)
                
                if handle == None :
                    raise TypeError('Packer does not expose class of corresponding name: (' + self.options['packer_class_name'] + ')')

                found = False
                inspect.getmro(handle)
                for base in inspect.getmro(handle):
                    if base.__name__ == 'IPacker':
                        found = True
                        break

                if not found:
                    raise TypeError('Packer does not inherit from IPacker.')
                
                # Call packer's __init__ with the `logger' instance passed to it.
                if self.instantiate:
                    instance = handle(PackersLoader.InjectedLogger(name), self.options)
                else:
                    instance = handle
                
                self.logger.dbg('Found class "%s".' % self.options['packer_class_name'])

            except AttributeError as e:
                self.logger.err('Packer "%s" loading has failed: "%s".' % 
                    (name, self.options['packer_class_name']))
                self.logger.err('\tError: %s' % e)
                if self.options['debug']:
                    raise

            except TypeError as e:
                self.logger.err('Packer "{}" instantiation failed due to interface incompatibility.'.format(name))
                raise

            if not instance:
                self.logger.err('Didn\'t find supported class in module "%s"' % name)
            else:
                self[name] = instance
                self.logger.info('Packer "%s" has been installed.' % name)

        except ImportError as e:
            self.logger.err('Couldn\'t load specified packer: "%s". Error: %s' % (packer, e))
            if self.options['debug']:
                raise
