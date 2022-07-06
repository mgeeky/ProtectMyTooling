import argparse, sys, re, tempfile, os
import xml.dom, xml.dom.minidom
import grope
from .pe_parser import parse_pe, IMAGE_DIRECTORY_ENTRY_RESOURCE
from .rsrc import parse_pe_resources, pe_resources_prepack, parse_prelink_resources, KnownResourceTypes
from .version_info import parse_version_info, VersionInfo

class Version:
    def __init__(self, s):
        parts = s.split(',')
        if len(parts) == 1:
            parts = parts[0].split('.')
        self._parts = [int(part.strip()) for part in parts]
        if not self._parts or len(self._parts) > 4 or any(part < 0 or part >= 2**16 for part in self._parts):
            raise ValueError('invalid version')

        while len(self._parts) < 4:
            self._parts.append(0)

    def get_ms_ls(self):
        ms = (self._parts[0] << 16) + self._parts[1]
        ls = (self._parts[2] << 16) + self._parts[3]
        return ms, ls

    def format(self):
        return ', '.join(str(part) for part in self._parts)

class _IdentityReplace:
    def __init__(self, val):
        self._val = val

    def __call__(self, s):
        return self._val

class _ReReplace:
    def __init__(self, compiled_re, sub):
        self._compiled_re = compiled_re
        self._sub = sub

    def __call__(self, s):
        return self._compiled_re.sub(self._sub, s)

RT_VERSION = KnownResourceTypes.RT_VERSION
RT_MANIFEST = KnownResourceTypes.RT_MANIFEST

def main():
    ap = argparse.ArgumentParser(fromfile_prefix_chars='@', description="Parses and edits resources in Windows executable (PE) files.")
    ap.add_argument('--remove-signature', action='store_true', help="remove the signature. If the file contains one, editing the file will fail")
    ap.add_argument('--ignore-trailer', action='store_true', help="keep trailing data (typically in a setup program) intact, move them if necessary")
    ap.add_argument('--remove-trailer', action='store_true', help="remove any trailing data from the output")
    ap.add_argument('--update-checksum', action='store_true', help="set the correct checksum (can be slow on large files), zero it out otherwise")
    ap.add_argument('--clear', '-C', action='store_true', help="remove existing resources, except for the manifest")
    ap.add_argument('--clear-manifest', action='store_true', help="remove the manifest resource")

    gp = ap.add_argument_group('informational (applied before any edits)')
    gp.add_argument('--print-tree', '-t', action='store_true', help="prints the outline of the resource tree")
    gp.add_argument('--print-version', '-v', action='store_true', help="prints all version info structures")

    gp = ap.add_argument_group('editor commands (can be used multiple times)')
    gp.add_argument('--apply', '-A', action='append', metavar="RES", default=[], help="apply a custom .res file, overwrite any matching resource entries")
    gp.add_argument('--add-dependency', '-M', action='append', metavar="DEP", default=[], help="add dependency. DEP should be a space separated list of key=value pairs, e.g. " +
        "\"type=win32 name=Microsoft.Windows.Common-Controls version=6.0.0.0 processorArchitecture=* publicKeyToken=6595b64144ccf1df language=*\"")
    gp.add_argument('--set-version', '-V', action='append', metavar="STR", help="updates the specified version-info field, e.g. FileVersion=\"1, 2, 3, 4\"")
    gp.add_argument('--set-resource', '-R', metavar=('TYPE', 'NAME', 'LANG', 'FILE'), nargs=4, action='append', default=[], help='set a resource entry to the contents of a file, e.g. "-R RT_RCDATA prog.exe 0 prog.exe"')

    ap.add_argument('--output', '-o', help="write the edited contents to OUTPUT instead of editing the input file in-place")
    ap.add_argument('file', help="the PE file to parse and edit")

    if not sys.argv[1:]:
        ap.print_help()
        return 0

    args = ap.parse_args()

    fin = open(args.file, 'rb')
    pe = parse_pe(grope.wrap_io(fin))
    resources = pe.parse_resources()
    if args.print_tree:
        if resources is None:
            print('no resources in the PE file')
        else:
            print('resources:')
            for resource_type in resources:
                print('  {}'.format(KnownResourceTypes.get_type_name(resource_type)))
                for name in resources[resource_type]:
                    print('    {}'.format(name))
                    for lang in resources[resource_type][name]:
                        print('      {}: size={}'.format(lang, len(resources[resource_type][name][lang])))

    if resources is None:
        resources = {}

    if args.print_version:
        for name in resources[RT_VERSION]:
            for lang in resources[RT_VERSION][name]:
                print('version info: {} {}'.format(name, lang))

                vi = parse_version_info(resources[RT_VERSION][name][lang])
                fixed = vi.get_fixed_info()

                print('  file version: {}'.format(fixed.file_version))
                print('  product version: {}'.format(fixed.product_version))
                for k in fixed.descriptor.names:
                    print('  {}: 0x{:x}'.format(k, getattr(fixed, k)))

    if not args.clear and not args.apply and not args.add_dependency and not args.set_version and not args.set_resource:
        return 0

    if pe.has_trailer():
        if not args.ignore_trailer and not args.remove_trailer:
            print('error: the file contains trailing data, ignore with --ignore-trailer', file=sys.stderr)
            return 1

        if args.remove_trailer:
            pe.remove_trailer()

    if pe.has_signature():
        if not args.remove_signature and not args.remove_trailer:
            print('error: the file contains a signature', file=sys.stderr)
            return 1

        pe.remove_signature()

    if not pe.is_dir_safely_resizable(IMAGE_DIRECTORY_ENTRY_RESOURCE):
        print('error: the resource section is not resizable: {}'.format(args.file), file=sys.stderr)
        return 3

    if args.clear:
        resources = { k: v for k, v in resources.items() if k == RT_MANIFEST }

    if args.clear_manifest:
        if RT_MANIFEST in resources:
            del resources[RT_MANIFEST]

    for res_file in args.apply:
        res_fin = open(res_file, 'rb')
        # must not close res_fin until the ropes are gone

        r = parse_prelink_resources(grope.wrap_io(res_fin))
        for resource_type in r:
            for name in r[resource_type]:
                for lang in r[resource_type][name]:
                    resources.setdefault(resource_type, {}).setdefault(name, {})[lang] = r[resource_type][name][lang]

    for rtype, rname, lang, inname in args.set_resource:
        res_fin = open(inname, 'rb')
        rtype = getattr(KnownResourceTypes, rtype, rtype)
        if rname.startswith('#'):
            rname = int(rname[1:], 10)
        else:
            rname = rname.upper()
        resources.setdefault(rtype, {}).setdefault(rname, {})[int(lang)] = grope.wrap_io(res_fin)

    if args.add_dependency:
        man_data = None
        for name in resources.get(RT_MANIFEST, ()):
            for lang in resources[name]:
                if man_data is not None:
                    print('error: multiple manifest resources found', file=sys.stderr)
                    return 4
                man_data = resources[name][lang]
                man_name = name
                man_lang = lang

        if man_data is None:
            man_doc = xml.dom.minidom.getDOMImplementation().createDocument(None, 'dependency', None)
            man = man_doc.documentElement
        else:
            man_doc = xml.dom.minidom.parseString(bytes(man_data))
            man = man_doc.documentElement

        dependent_assembly = man_doc.getElementById('dependentAssembly')
        if not dependent_assembly:
            dependent_assembly = man_doc.createElement('dependentAssembly')
            man.append(dependent_assembly)

        for dep in args.add_dependency:
            dep_elem = man_doc.createElement('assemblyIdentity')
            for tok in dep.split():
                k, v = tok.split('=', 1)
                dep_elem.attrib[k] = v
            dependent_assembly.appendChild(dep_elem)

        resources[RT_MANIFEST][man_name][man_lang] = b'\xef\xbb\xbf' + man_doc.toxml(encoding='utf-8')

    if args.set_version:
        ver_data = None
        for name in resources.get(RT_VERSION, ()):
            for lang in resources[RT_VERSION][name]:
                if ver_data is not None:
                    print('error: multiple manifest resources found', file=sys.stderr)
                    return 4
                ver_data = resources[RT_VERSION][name][lang]
                ver_name = name
                ver_lang = lang

        if ver_data is None:
            ver_data = VersionInfo()

        params = {}
        for param in args.set_version:
            toks = param.split('=', 1)
            if len(toks) != 2:
                print('error: version infos must be in the form "name=value"', file=sys.stderr)
                return 2
            name, value = toks

            if value.startswith('/') and value.endswith('/'):
                pattern, sub = value[1:-1].split('/', 1)
                r = re.compile(pattern)
                params[name] = _ReReplace(r, sub)
            else:
                params[name] = _IdentityReplace(value)

        vi = parse_version_info(ver_data)

        fvi = vi.get_fixed_info()
        if 'FileVersion' in params:
            ver = Version(params['FileVersion'](None))
            fvi.dwFileVersionMS, fvi.dwFileVersionLS = ver.get_ms_ls()
        if 'ProductVersion' in params:
            ver = Version(params['ProductVersion'](None))
            fvi.dwProductVersionMS, fvi.dwProductVersionLS = ver.get_ms_ls()
        vi.set_fixed_info(fvi)

        sfi = vi.string_file_info()
        for _, strings in sfi.items():
            for k, fn in params.items():
                val = fn(strings.get(k, ''))
                if val:
                    strings[k] = val
                elif k in strings:
                    del strings[k]
        vi.set_string_file_info(sfi)
        resources[RT_VERSION][ver_name][ver_lang] = vi.pack()

    prepacked = pe_resources_prepack(resources)
    addr = pe.resize_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.size)
    pe.set_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, prepacked.pack(addr))

    if not args.output:
        fout, fout_name = tempfile.mkstemp(dir=os.path.split(args.file)[0])
        fout = os.fdopen(fout, mode='w+b')
        try:
            grope.dump(pe.to_blob(update_checksum=args.update_checksum), fout)

            fin.close()
            fout.close()
        except:
            fout.close()
            os.remove(fout_name)
            raise
        else:
            os.remove(args.file)
            os.rename(fout_name, args.file)

    else:
        with open(args.output, 'wb') as fout:
            grope.dump(pe.to_blob(), fout)

    return 0

if __name__ == '__main__':
    main()
