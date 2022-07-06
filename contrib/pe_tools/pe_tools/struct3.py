from collections import OrderedDict
import struct

class Annotation:
    def __init__(self, fmt, default):
        self._mult = 1
        self._fmt = fmt
        self.default = default

    def __getitem__(self, key):
        r = Annotation(self._fmt, self.default)
        r._mult = self._mult * key
        return r

    @property
    def fmt(self):
        if self._mult == 1:
            return self._fmt
        else:
            return '{}{}'.format(self._mult, self._fmt)

class StructDescriptor:
    def __init__(self, annotations):
        self.annotations = annotations

        fmt = ['<']
        fmt.extend(annot.fmt for annot in annotations.values())
        self.fmt = ''.join(fmt)
        self.size = struct.calcsize(self.fmt)

    @property
    def names(self):
        return self.annotations.keys()

class StructMeta(type):
    def __new__(cls, name, bases, namespace, no_struct_members=False, **kwds):
        self = super().__new__(cls, name, bases, namespace, **kwds)

        if not no_struct_members:
            self.descriptor = StructDescriptor(namespace['__annotations__'])
            for name, annot in self.descriptor.annotations.items():
                setattr(self, name, annot.default)
            self.size = self.descriptor.size

        return self

class Struct3(metaclass=StructMeta, no_struct_members=True):
    descriptor: StructDescriptor
    size: int

    def __init__(self, *args, **kw):
        annots = self.descriptor.annotations

        if len(args) > 1:
            raise TypeError('{}() takes at most a single argument'.format(type(self).__name__))

        if len(args) == 1:
            src = args[0]
            for k, v in src.__dict__.items():
                if k not in annots:
                    raise TypeError('source object contains an unexpected member {!r}'.format(k))
                setattr(self, k, v)

        for k, v in kw.items():
            if k not in annots:
                raise TypeError('{}() got an unexpected keyword argument {!r}'.format(type(self).__name__, k))
            setattr(self, k, v)

    def __repr__(self):
        return '{}({})'.format(type(self).__name__, ', '.join('{}={!r}'.format(k, getattr(self, k)) for k in self.descriptor.annotations.keys()))

    def pack(self):
        data = tuple(getattr(self, fld) for fld in self.descriptor.annotations)
        return struct.pack(self.descriptor.fmt, *data)

    @classmethod
    def calcsize(cls):
        return cls.descriptor.size

    @classmethod
    def unpack(cls, buffer):
        data = struct.unpack(cls.descriptor.fmt, bytes(buffer))

        r = cls()
        for k, v in zip(cls.descriptor.annotations, data):
            setattr(r, k, v)
        return r

    @classmethod
    def unpack_from(cls, buffer):
        desc = cls.descriptor
        data = struct.unpack(desc.fmt, bytes(buffer[:desc.size]))

        r = cls()
        for k, v in zip(desc.annotations, data):
            setattr(r, k, v)
        return r

    @classmethod
    def unpack_from_io(cls, fileobj):
        return cls.unpack_from(fileobj.read(cls.calcsize()))

u8 = Annotation('B', 0)
u16 = Annotation('H', 0)
u32 = Annotation('I', 0)
u64 = Annotation('Q', 0)
i8 = Annotation('b', 0)
i16 = Annotation('h', 0)
i32 = Annotation('i', 0)
i64 = Annotation('q', 0)
char = Annotation('s', '\0')
