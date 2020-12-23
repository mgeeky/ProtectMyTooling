peCloak - Capstone
==================

This is a simple fork of [SecuritySift's peCloak](http://www.securitysift.com/pecloak-py-an-experiment-in-av-evasion/) that uses [Capstone](http://www.capstone-engine.org). The intention is to provide a fork based on a well-maintained, up-to-date disassembly library and to make the script multi-platform.

Here's what I did so far:
  * Replaced pydasm with Capstone
    * Included a patched version of [SectionDoubleP](http://git.n0p.cc/?p=SectionDoubleP.git;a=summary) as it also relied on pydasm
  * Made data (un)packing platform independent by always using standard sizes

This way I managed to create obfuscated 32-bit Windows executables on 64-bit Linux which is nice :) 

Still, this is just a quick hack, bugs most probably hide here and there and I probably left some dead code too.
