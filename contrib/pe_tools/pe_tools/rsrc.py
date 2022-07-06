from grope import BlobIO, rope
from .utils import *
from .struct3 import Struct3, u16, u32
import time, struct


class KnownResourceTypes:
    RT_CURSOR = 1
    RT_BITMAP = 2
    RT_ICON = 3
    RT_MENU = 4
    RT_DIALOG = 5
    RT_STRING = 6
    RT_FONTDIR = 7
    RT_FONT = 8
    RT_ACCELERATOR = 9
    RT_RCDATA = 10
    RT_MESSAGETABLE = 11
    RT_GROUP_CURSOR = 12
    RT_GROUP_ICON = 14
    RT_VERSION = 16
    RT_DLGINCLUDE = 17
    RT_PLUGPLAY = 19
    RT_VXD = 20
    RT_ANICURSOR = 21
    RT_ANIICON = 22
    RT_HTML = 23
    RT_MANIFEST = 24

    @classmethod
    def get_type_name(cls, num):
        for k in dir(cls):
            if k.startswith('RT_') and getattr(cls, k, None) == num:
                return k
        return str(num)

class _RESOURCE_DIRECTORY_TABLE(Struct3):
    Characteristics: u32
    Timestamp: u32
    Major: u16
    Minor: u16
    NumberOfNameEntries: u16
    NumberOfIdEntries: u16

class _RESOURCE_DIRECTORY_ENTRY(Struct3):
    NameOrId: u32
    Offset: u32

class _RESOURCE_DATA_ENTRY(Struct3):
    DataRva: u32
    Size: u32
    Codepage: u32
    Reserved: u32

class _STRING_HEADER(Struct3):
    Length: u16

class _RES_HEADER_SIZES(Struct3):
    DataSize: u32
    HeaderSize: u32

class _RES_HEADER(Struct3):
    DataVersion: u32
    MemoryFlags: u16
    LanguageId: u16
    Version: u32
    Characteristics: u32

def _parse_prelink_name(blob):
    name, = struct.unpack('<H', bytes(blob[:2]))
    if name == 0xffff:
        name, = struct.unpack('<H', bytes(blob[2:4]))
        return name, blob[4:]
    else:
        r = []
        while True:
            ch = bytes(blob[:64])
            i = 0
            while i < 64:
                if ch[i:i+2] == b'\0\0':
                    r.append(ch[:i])
                    return b''.join(r).decode('utf-16le'), blob[i+2:]
                i += 2
            r.append(ch)
            blob = blob[64:]


def _parse_one_prelink_res(blob):
    hdr_sizes = _RES_HEADER_SIZES.unpack_from(blob)
    if hdr_sizes.HeaderSize < hdr_sizes.size:
        raise RuntimeError('corrupted header')

    full_hdr_blob = blob[hdr_sizes.size:hdr_sizes.HeaderSize]
    hdr_blob = full_hdr_blob
    data_blob = blob[hdr_sizes.HeaderSize:hdr_sizes.HeaderSize + hdr_sizes.DataSize]
    next_blob = blob[align4(hdr_sizes.HeaderSize + hdr_sizes.DataSize):]

    type, hdr_blob = _parse_prelink_name(hdr_blob)
    name, hdr_blob = _parse_prelink_name(hdr_blob)

    hdr_blob = full_hdr_blob[align4(len(full_hdr_blob) - len(hdr_blob)):]

    hdr = _RES_HEADER.unpack_from(hdr_blob)
    hdr.type = type
    hdr.name = name
    return hdr, data_blob, next_blob

def parse_prelink_resources(blob):
    r = {}
    while blob:
        hdr, data, blob = _parse_one_prelink_res(blob)
        r.setdefault(hdr.type, {}).setdefault(hdr.name, {})[hdr.LanguageId] = data

    if 0 in r:
        del r[0]
    return r

def parse_pe_resources(blob, base):
    def parse_string(offs):
        hdr = _STRING_HEADER.unpack_from(blob[offs:])
        return bytes(blob[offs+_STRING_HEADER.size:offs+_STRING_HEADER.size+hdr.Length*2]).decode('utf-16le')

    def parse_data(offs):
        entry = _RESOURCE_DATA_ENTRY.unpack_from(blob[offs:])

        if entry.DataRva < base:
            raise RuntimeError('resource is outside the resource blob')

        if entry.DataRva + entry.Size - base > len(blob):
            raise RuntimeError('resource is outside the resource blob')

        return blob[entry.DataRva - base:entry.DataRva + entry.Size - base]

    def parse_tree(offs):
        r = {}

        fin = BlobIO(blob[offs:])

        node = _RESOURCE_DIRECTORY_TABLE.unpack_from_io(fin)
        name_entries = [_RESOURCE_DIRECTORY_ENTRY.unpack_from_io(fin) for i in range(node.NumberOfNameEntries)]
        id_entries = [_RESOURCE_DIRECTORY_ENTRY.unpack_from_io(fin) for i in range(node.NumberOfIdEntries)]

        for entry in name_entries:
            name = parse_string(entry.NameOrId & ~(1<<31))
            if entry.Offset & (1<<31):
                r[name] = parse_tree(entry.Offset & ~(1<<31))
            else:
                r[name] = parse_data(entry.Offset)

        for entry in id_entries:
            if entry.Offset & (1<<31):
                r[entry.NameOrId] = parse_tree(entry.Offset & ~(1<<31))
            else:
                r[entry.NameOrId] = parse_data(entry.Offset)

        return r

    return parse_tree(0)

class _PrepackedResources:
    def __init__(self, entries, strings, blobs):
        self._entries = entries
        self._strings = strings
        self._blobs = blobs

        self.size = sum(ent.size for ent in self._entries) + len(strings) + len(blobs)

    def pack(self, base):
        def _transform(ent):
            if not isinstance(ent, _RESOURCE_DATA_ENTRY):
                return ent
            return _RESOURCE_DATA_ENTRY(ent, DataRva=ent.DataRva + base)

        ents = [_transform(ent).pack() for ent in self._entries]
        return b''.join(ents) + self._strings + bytes(self._blobs)

def _prepack(rsrc):
    if isinstance(rsrc, dict):
        name_keys = [key for key in rsrc.keys() if isinstance(key, str)]
        id_keys = [key for key in rsrc.keys() if not isinstance(key, str)]

        name_keys.sort()
        id_keys.sort()

        r = []
        children = []

        r.append(_RESOURCE_DIRECTORY_TABLE(
            Characteristics=0,
            Timestamp=0,
            Major=0,
            Minor=0,
            NumberOfNameEntries=len(name_keys),
            NumberOfIdEntries=len(id_keys),
            ))

        for keys in (name_keys, id_keys):
            for name in keys:
                items = _prepack(rsrc[name])
                children.extend(items)
                r.append(_RESOURCE_DIRECTORY_ENTRY(
                    NameOrId=name,
                    Offset=items[0]
                    ))

        r.extend(children)
        return r
    else:
        return [_RESOURCE_DATA_ENTRY(
            DataRva=rsrc,
            Size=len(rsrc),
            Codepage=0,
            Reserved=0
            )]

def pe_resources_prepack(rsrc):
    entries = _prepack(rsrc)

    strings = []
    string_map = {}
    def add_string(s):
        r = string_map.get(s)
        if r is None:
            encoded = s.encode('utf-16le')

            r = sum(len(ss) for ss in strings)
            string_map[s] = r

            strings.append(_STRING_HEADER(Length=len(encoded)//2).pack())
            strings.append(encoded)
        return r

    _entry_offsets = {}
    offs = 0
    for ent in entries:
        _entry_offsets[ent] = offs
        offs += ent.size

    table_size = offs
    for ent in entries:
        if isinstance(ent, _RESOURCE_DIRECTORY_ENTRY):
            if isinstance(ent.NameOrId, str):
                ent.NameOrId = (1<<31) | (table_size + add_string(ent.NameOrId))

    strings = b''.join(strings)
    aligned_strings_len = align16(len(strings))
    strings += b'\0' * (aligned_strings_len - len(strings))

    data_offs = table_size + len(strings)
    blobs = []

    for ent in entries:
        if isinstance(ent, _RESOURCE_DIRECTORY_ENTRY):
            if isinstance(ent.Offset, _RESOURCE_DIRECTORY_TABLE):
                ent.Offset = (1<<31) | _entry_offsets[ent.Offset]
            else:
                ent.Offset = _entry_offsets[ent.Offset]
        elif isinstance(ent, _RESOURCE_DATA_ENTRY):
            blob = ent.DataRva
            ent.DataRva = data_offs

            blobs.append(blob)
            aligned_size = align8(len(blob))
            pad = aligned_size - len(blob)
            if pad:
                blobs.append(b'\0' * pad)

            data_offs += aligned_size

    return _PrepackedResources(entries, strings, rope(*blobs))
