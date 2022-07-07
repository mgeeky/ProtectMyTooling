
       MPRESS Version History
       ~~~~~~~~~~~~~~~~~~~~~~

v2.19
 - bugfix: support x64 on Windows 8


v2.18
 - support for .NET Framework v4.0
 - support for .NET x64
 - bugfix: possible deadlock on the overloaded computer

v2.17
 - new option -r to not compress resources
 - bugfix: in processing of relocations

v2.15
 - bugfix: compressed TYPELIB and REGISTRY resources of ActiveX components
 - bugfix: crash on empty import directory entry

v2.12
 - bugfix: crash when Open GL with some ATI adapters
 - added compression filter for 32-bit and 64-bit DLLs

v2.05
 - bugfix: wrong run-time unpacker some time selected
 - removed option -d, now default settings for the encoder are used by default
 - compression improvements (LZMA specific filters)

v2.01
 - LZMA algorithm support for Windows 64-bit (PE32+ x64) executable formats
 - new option -d to use default values for the encoder, otherwise it tries
   to find the best ones

v2.00
 - optional LZMA algorithm support for Windows 32-bit (PE32 i386) executable formats

v1.27
 - few small bugfixes

v1.25
 - bugfix: darwin-x86_64 might not work after compression
 - bugfix: floating point support on x86 and x64 applications
   might not load

v1.21
 - compression filter for darwin-x86_64
 - compression filter for darwin-i386
 - support for mac os x darwin-i386 applications
 - support for mac os x darwin-ub applications

v1.17
 - support for mac os x darwin-x86_64 applications

v1.10
 - remove public key while processing .NET applications (strong name patch)

v1.07
 - improved compression for .NET applications

v1.05
 - version identification added
 - some internal improvements
 - some small bugs fixed

v1.01
 - improved compression for x86 and x64 applications and libraries
 - bugfix: x86 applications with TLS might not run after second compression

v0.99
 - bugfix: MPRESS does not run properly on Win2k

v0.98
 - bugfix: x64 packed applications might not run on XP x64

v0.97
 - improved compression filters for x86 and x64
 - bugfix: crash on damaged x86 modules
 - bugfix: damaged .NET Assembly/Module Name
 - bugfix: corrected versions of .NET AssemblyRef

v0.95
 - added compression filter for AMD64 code
 - bugfix: Compression applications without import of kernel32 (i.e. VB)

v0.92
 - added compression filter for x86 code
 - bugfix: correct damaged PE header after compress-decompress with UPX

v0.85
 - bugfix: compression above PE32 (x86) compressed files
 - part of loader code moved into compressed block (x86)

v0.81
 - bugfix: small PE32 (x86) assembler files

v0.77b
 - bugfix: huge export directories (x86,x64),
 - bugfix: some x86 Delphi related bugs

v0.75b
 - bugfix: icons, on PE32 (XP SP2) does not understand PE32 format v8.0 ;-)

v0.72b
 - first stable version

v0.71a
 - test version
