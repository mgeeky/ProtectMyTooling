# Nimcrypt2
Nimcrypt2 is yet another PE packer/loader designed to bypass AV/EDR. It is an improvement on my original [Nimcrypt](https://github.com/icyguider/nimcrypt) project, with the main improvements being the use of direct syscalls and the ability to load regular PE files as well as raw shellcode.

Before going any further, I must acknowledge those who did the VAST majority of work and research that this project depends on. Firstly, I must thank [@byt3bl33d3r](https://twitter.com/byt3bl33d3r) for his [Offensive Nim repo](https://github.com/byt3bl33d3r/OffensiveNim), and [@ShitSecure](https://twitter.com/ShitSecure) for all of the code snippets he's publicly released. That is what the original version of this tool was created from, and the current version is no different. Particularly, the new PE loading functionality used in this tool is just an implementation of ShitSecure's recently released [Nim-RunPE](https://github.com/S3cur3Th1sSh1t/Nim-RunPE) code. As of 3/14/22, this code also uses his [GetSyscallStub](https://github.com/S3cur3Th1sSh1t/NimGetSyscallStub) code for dynamic syscall usage. I highly encourage sponsoring him for access to his own [Nim PE Packer](https://twitter.com/ShitSecure/status/1482428360500383755), which is no doubt a much better and more featureful version of this.

Additionally, I would like to thank [@ajpc500](https://twitter.com/ajpc500) for his [NimlineWhispers2](https://github.com/ajpc500/NimlineWhispers2) project that this tool uses for direct syscalls. I cannot stress enough how this project is simply an amalgamation of the public work of those previously mentioned, so all credit must go to them.

```
                      ___                                           
                   .-'   `'.                                        
                  /         \                                       
                  |         ;                                       
                  |         |           ___.--,                     
         _.._     |0) ~ (0) |    _.---'`__.-( (_.                   
  __.--'`_.. '.__.\    '--. \_.-' ,.--'`     `""`                   
 ( ,.--'`   ',__ /./;   ;, '.__.'`    __                            
 _`) )  .---.__.' / |   |\   \__..--""  ""'--.,_                    
`---' .'.''-._.-'`_./  /\ '.  \ _.-~~~````~~~-._`-.__.'             
      | |  .' _.-' |  |  \  \  '.               `~---`              
       \ \/ .'     \  \   '. '-._)                                  
        \/ /        \  \    `=.__`~-.   Nimcrypt v2               
   jgs  / /\         `) )    / / `"".`\                             
  , _.-'.'\ \        / /    ( (     / /  3-in-1 C#, PE, & Raw Shellcode Loader
   `--~`   ) )    .-'.'      '.'.  | (                              
          (/`    ( (`          ) )  '-;                             
           `      '-;         (-'                                   

Nimcrypt v 2.0

Usage:
  nimcrypt -f file_to_load -t csharp/raw/pe [-o <output>] [-p <process>] [-n] [-u] [-s] [-e] [-g] [-l] [-v] [--no-ppid-spoof]
  nimcrypt (-h | --help)

Options:
  -h --help     Show this screen.
  --version     Show version.
  -f --file filename     File to load
  -t --type filetype     Type of file (csharp, raw, or pe)
  -p --process process   Name of process for shellcode injection
  -o --output filename   Filename for compiled exe
  -u --unhook            Unhook ntdll.dll
  -v --verbose           Enable verbose messages during execution
  -e --encrypt-strings   Encrypt strings using the strenc module
  -g --get-syscallstub   Use GetSyscallStub instead of NimlineWhispers2
  -l --llvm-obfuscator   Use Obfuscator-LLVM to compile binary
  -n --no-randomization  Disable syscall name randomization
  -s --no-sandbox        Disable sandbox checks
  --no-ppid-spoof        Disable PPID Spoofing
```
#### Features:
* NtQueueApcThread Shellcode Execution w/ PPID Spoofing & 3rd Party DLL Blocking
* NimlineWhispers2 & GetSyscallStub for Syscall Use
* Syscall Name Randomization
* Ability to load .NET and Regular PE Files
* AES Encryption with Dynamic Key Generation
* LLVM-Obfuscator Compatibility
* String Encryption
* Sandbox Evasion

#### Tested and Confirmed Working on:
* Windows 11 (10.0.22000)
* Windows 10 21H2 (10.0.19044)
* Windows 10 21H1 (10.0.19043)
* Windows 10 20H2 (10.0.19042)
* Windows 10 19H2 (10.0.18363)
* Windows Server 2019 (10.0.17763)

#### Installation/Dependencies:
Nimcrypt2 is designed to be used on Linux systems with Nim installed. Before installing Nim, you must ensure that you have the following packages installed via your package manager:
```
sudo apt install gcc mingw-w64 xz-utils git
```
To install Nim, I prefer to use [choosenim](https://github.com/dom96/choosenim) as follows:
```
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
echo "export PATH=$HOME/.nimble/bin:$PATH" >> ~/.bashrc
export PATH=$HOME/.nimble/bin:$PATH
```

Nimcrypt2 also depends on a few packages that can be installed via Nimble. This can be done like so:
```
nimble install winim nimcrypto docopt ptr_math strenc
```

With all the dependencies now installed, Nimcrypt2 can be compiled like so:
```
nim c -d=release --cc:gcc --embedsrc=on --hints=on --app=console --cpu=amd64 --out=nimcrypt nimcrypt.nim
```

**OPTIONAL:** To use the [Obfuscator-LLVM](https://github.com/heroims/obfuscator) flag, you must have it installed on your system alongside [wclang](https://github.com/tpoechtrager/wclang). I've found this to be a bit of a pain but you should be able to do it with a little perseverance. Here's a quick step-by-step that worked on my Kali Linux system:
1. Clone desired version of Obfuscator-LLVM and build it
2. Once compiled, backup the existing version of clang and move the new Obfuscator-LLVM version of clang to /usr/bin/
3. Install wclang and add it's binaries to your PATH
4. Backup existing clang library files, copy new newly built Obfuscator-LLVM library includes to /usr/lib/clang/OLD_VERSION/

In addition, you must add the following lines to your `nim.cfg` file to point nim to your wclang binaries:
```
amd64.windows.clang.exe = "x86_64-w64-mingw32-clang"
amd64.windows.clang.linkerexe = "x86_64-w64-mingw32-clang"
amd64.windows.clang.cpp.exe = "x86_64-w64-mingw32-clang++"
amd64.windows.clang.cpp.linkerexe = "x86_64-w64-mingw32-clang++"
```

There is probably a better way to do this but this is what worked for me. If you have issues, just keep trying and ensure that you can run `x86_64-w64-mingw32-clang -v` and it shows "Obfuscator-LLVM" in the output. Also ensure MinGW is using the Obfuscator-LLVM library files: Nim will give you an error if not.

#### Known Bugs:
* As [described](https://github.com/S3cur3Th1sSh1t/Nim-RunPE/blob/a117ecec635824703047c1d850607bdf2cfa628b/README.md?plain=1#L13) by ShitSecure, if the release version of mimikatz is loaded via the PE loader, it will not accept commands for some unknown reason. Using a version of mimikatz that was compiled from source fixes this issue.

#### Greetz & Credit:
* [@byt3bl33d3r](https://twitter.com/byt3bl33d3r) for their Offensive Nim project: https://github.com/byt3bl33d3r/OffensiveNim
* [@ShitSecure](https://twitter.com/ShitSecure) for their Nim-RunPE project: https://github.com/S3cur3Th1sSh1t/Nim-RunPE
* [@ShitSecure](https://twitter.com/ShitSecure) again for their GetSyscallStub project: https://github.com/S3cur3Th1sSh1t/NimGetSyscallStub
* [@ajpc500](https://twitter.com/ajpc500) for their NimlineWhispers2 project: https://github.com/ajpc500/NimlineWhispers2
* [@Snovvcrash](https://twitter.com/snovvcrash) for their NimHollow project: https://github.com/snovvcrash/NimHollow
