# pe_tools

A cross-platform toolkit for parsing/writing PE files.

Requires Python 3.6+. Install using the following command.

    pip install pe_tools

This installs the `pe_tools` module you can use in your Python scripts and
command line tools.

## Getting started

Parse a PE file by calling `parse_pe`. The resulting PeFile object then contains
information about the file and allows the file to be reserialized.

    from pe_tools import parse_pe
    import grope

    with open('file.exe', 'rb') as fin:
        pe = parse_pe(grope.wrap_io(fin))

        # use `pe` here ...

        with open('newfile.exe', 'wb') as fout:
            grope.dump(pe.to_blob(), fout)

The argument to `parse_pe` is either a bytes object or a [`grope.rope`][1].
The latter is recommended, as it allows you to parse and edit huge pe files
with little overhead. Similarly, you can either serialize to bytes with
`to_bytes()` method or to a `grope.rope` with `to_blob()`. Use `grope.dump`
to efficiently write the blob to a file.

  [1]: https://github.com/avakar/grope

## Resource editor

As an example of its usage, the package bundles a command line utility,
`peresed`, which provides means to edit resources in an existing PE file.

You can either

* apply your own resources from a `.res` file compiled by `rc.exe`,
* add manifest dependencies, and/or
* edit the version info.

    peresed [options and commands] [-o OUTPUT] FILE

By default, the tool will edit the file in-place. The `-o` option allows you to
set an alternative output file.

Pass `--clear` to remove all existing resource entries, except for the manifest,
from the file. This can be useful if you're completely rebranding the binary,
for example. This also removes the version info. To remove the manifest, use
`--clear-manifest`.

By default, the checksum in the PE file will not be updated, since you'll be
signing the file anyway. If you want it updated, pass `--update-checksum`.

### Editor commands

To apply new resource entries, use `--apply` and pass the name of the `.res`
file. You can use Visual Studio's `rc.exe` tool to create one. For each entry
in the `.res` file, the corresponding entry will be created or replaced
in the existing resources. The entries are identified by their type, name and
language. Use `--clear` if you don't want to keep any unmatched entries.

You can add a manifest dependency using `--add-dependency`. If the file already
contains a manifest, the manifest is edited. Otherwise an empty manifest
is created.

Finally, version info strings can be edited. Use `--set-version` followed by
a `key=value` pair, where `key` is the name of the version info field to change,
and `value` is either a string to replace the existing value with,
or a regex substitution of the form `/pattern/sub/`, allowing you to only
replace specific parts of the value.

Typically, the key is one of the followinig values (case matters).

* FileVersion
* ProductVersion
* FileDescription
* InternalName
* LegalCopyright
* OriginalFilename
* ProductName

The first two are treated specially and will cause the corresponding
values in the fixed version info structure to be updated too. The values
for these fields must be in the form `"1, 2, 3, 4"`.

Each command can be specified multiple times. All `--apply` commands are
performed first, then all `--add-dependency`, then all `--set-version`.

### Examples

To make an old program use the XP visual styles, add dependency on comctl32
version 6.

    peresed -M "type=win32 name=Microsoft.Windows.Common-Controls \
    version=6.0.0.0 processorArchitecture=* publicKeyToken=6595b64144ccf1df \
    language=*" file.exe

To change the version of the file, change its FileVersion member.

    peresed -V "FileVersion=1, 2, 3, 4" file.exe

To change a program's icon, compile a new resource file containig the icon
and apply it. The `new_icon.rc` file might look like this.

    100 ICON "new_icon.ico"

Compile it with `rc.exe`.

    rc.exe new_icon.rc

Apply the new resource file to your PE file.

    peresed -A new_icon.res file.exe

### All options

    usage: peresed.py [-h] [--remove-signature] [--ignore-trailer]
                      [--remove-trailer] [--update-checksum] [--clear]
                      [--clear-manifest] [--print-tree] [--print-version]
                      [--apply RES] [--add-dependency DEP] [--set-version STR]
                      [--set-resource TYPE NAME LANG FILE] [--output OUTPUT]
                      file

    Parses and edits resources in Windows executable (PE) files.

    positional arguments:
      file                  the PE file to parse and edit

    optional arguments:
      -h, --help            show this help message and exit
      --remove-signature    remove the signature. If the file contains one,
                            editing the file will fail
      --ignore-trailer      keep trailing data (typically in a setup program)
                            intact, move them if necessary
      --remove-trailer      remove any trailing data from the output
      --update-checksum     set the correct checksum (can be slow on large files),
                            zero it out otherwise
      --clear, -C           remove existing resources, except for the manifest
      --clear-manifest      remove the manifest resource
      --output OUTPUT, -o OUTPUT
                            write the edited contents to OUTPUT instead of editing
                            the input file in-place

    informational (applied before any edits):
      --print-tree, -t      prints the outline of the resource tree
      --print-version, -v   prints all version info structures

    editor commands (can be used multiple times):
      --apply RES, -A RES   apply a custom .res file, overwrite any matching
                            resource entries
      --add-dependency DEP, -M DEP
                            add dependency. DEP should be a space separated list
                            of key=value pairs, e.g. "type=win32
                            name=Microsoft.Windows.Common-Controls version=6.0.0.0
                            processorArchitecture=*
                            publicKeyToken=6595b64144ccf1df language=*"
      --set-version STR, -V STR
                            updates the specified version-info field, e.g.
                            FileVersion="1, 2, 3, 4"
      --set-resource TYPE NAME LANG FILE, -R TYPE NAME LANG FILE
                            set a resource entry to the contents of a file, e.g.
                            "-R RT_RCDATA prog.exe 0 prog.exe"
