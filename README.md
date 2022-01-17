# ProtectMyTooling - a wrapper around PE Packers & Protectors

Script that builds around supported packers & protectors to produce complex protected binaries.

With `ProtectMyTooling` you can quickly obfuscate your binaries without having to worry about clicking through all the Dialogs, interfaces, menus, creating projects to obfuscate a single binary, clicking through all the options available and wasting time about all that nonsense. It takes you straight to the point - to obfuscate your tool.

Aim is to offer the most convenient interface possible and allow to leverage _a chain of multiple packers_ combined on a single binary.

That's right - we can launch `ProtectMyTooling` with several packers at once:

```
C:\> py ProtectMyTooling.py hyperion,upx mimikatz.exe mimikatz-obf.exe
```

The above example will firstly pass `mimikatz.exe` to the Hyperion for obfuscation, and then the result will be provided to UPX for compression.


## Usage

Usage is very simple, all it takes is to pass the name of obfuscator to choose, input and output file paths:

```
C:\> py ProtectMyTooling.py confuserex Rubeus.exe Rubeus-obf.exe

        :: ProtectMyTooling - a wrapper for PE Packers & Protectors
        Script that builds around supported packers & protectors to produce complex protected binaries.
        Mariusz Banach / mgeeky '20-'22, <mb@binary-offensive.com>
        v0.8


[.] Processing x86 file: "d:\dev2\ProtectMyTooling\Rubeus.exe"
[.] Generating output of ConfuserEx(<file>)...

[GOOD] 10:16:48: [+] SUCCEEDED. Original file size: 417280 bytes, new file size ConfuserEx(<file>): 756224, ratio: 181.23%
```

One can also obfuscate the file and immediately attempt to launch it (also with supplied optional parameters) to ensure it runs fine with options `-r --cmdline CMDLINE`:

```
C:\> py ProtectMyTooling.py confuserex Rubeus.exe Rubeus-obf.exe -r --cmdline "hash /password:foobar"

        :: ProtectMyTooling - a wrapper for PE Packers & Protectors
        Script that builds around supported packers & protectors to produce complex protected binaries.
        Mariusz Banach / mgeeky '20-'22, <mb@binary-offensive.com>
        v0.8


[.] Processing x86 file: "d:\dev2\ProtectMyTooling\Rubeus.exe"
[.] Generating output of ConfuserEx(<file>)...

[GOOD] 10:18:10: [+] SUCCEEDED. Original file size: 417280 bytes, new file size ConfuserEx(<file>): 758272, ratio: 181.72%


Running application to test it...

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : foobar
[*]       rc4_hmac             : BAAC3929FABC9E6DCD32421BA94A84D4

[!] /user:X and /domain:Y need to be supplied to calculate AES and DES hash types!
```


Other options include:

```
C:\> py ProtectMyTooling.py --help

        :: ProtectMyTooling - a wrapper for PE Packers & Protectors
        Script that builds around supported packers & protectors to produce complex protected binaries.
        Mariusz Banach / mgeeky '20-'22, <mb@binary-offensive.com>
        v0.8

usage: Usage: %prog [options] <packers> <infile> <outfile>

positional arguments:
  packers               Specifies packers to use and their order in a comma-delimited list. Example: "pecloak,upx" will produce upx(pecloak(original)) output.
  _input                Input file to be packed/protected.
  output                Output file constituing generated sample.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        External configuration file. Default: ProtectMyTooling.yaml
  -t TIMEOUT, --timeout TIMEOUT
                        Command execution timeout. Default: 60 seconds.
  -a ARCH, --arch ARCH  Specify file's target architecture. If input is a valid PE file, this script will try to automatically sense its arch. Otherwise (shellcode) you'll need to specify it.
  -v, --verbose         Displays verbose output.
  -d, --debug           Displays debugging informations (implies verbose output).
  -l PATH, --log PATH   Specifies output log file.
  -s, --silent          Surpresses all of the output logging.

Test sample after generation:
  -r, --testrun         Launch generated sample to test it. Use --cmdline to specify execution parameters. By default output won't be launched.
  --cmdline CMDLINE     Command line for the generated sample

Optional AV Handling hooks:
  --check-av-command CHECK_AV_COMMAND
                        Command used to check status of AV solution. This command must return "True" if AV is running.
  --disable-av-command DISABLE_AV_COMMAND
                        Command used to disable AV solution before processing files.
  --enable-av-command ENABLE_AV_COMMAND
                        Command used to re-enable AV solution after processing files. The AV will be re-enabled only if it was enabled previously.

Packers handling:
  -L, --list-packers    List available packers.

[...]
```

## Cobalt Strike Integration

There is also a script that integrates `ProtectMyTooling.py` used as a wrapper around configured PE/.NET Packers/Protectors in order to easily transform input executables into their protected and compressed output forms and then upload or use them from within CobaltStrike.

The idea is to have an automated process of protecting all of the uploaded binaries or .NET assemblies used by execute-assembly and forget about protecting or obfuscating them manually before each usage. The added benefit of an automated approach to transform executables is the ability to have the same executable protected each time it's used, resulting in unique samples launched on target machines. That should nicely deceive EDR/AV enterprise-wide IOC sweeps while looking for the same artefact on different machines.

Additionally, the protected-execute-assembly command has the ability to look for assemblies of which
only name were given in a preconfigured assemblies directory (set in dotnet_assemblies_directory setting).

To use it:

1. Load `CobaltStrike/ProtectMyTooling.cna` in your Cobalt Strike.
2. Go to the menu and setup all the options

![options](images/options.png)

3. Then in your Beacon's console you'll have following commands available:

  * `protected-execute-assembly` - Executes a local, previously protected and compressed .NET program in-memory on target.
  * `protected-upload` - Takes an input file, protects it if its PE executable and then uploads that file to specified remote location.

Basically these commands will open input files, pass the firstly to the `CobaltStrike/cobaltProtectMyTooling.py` script, which in turn calls out to `ProtectMyTooling.py`. As soon as the binary gets obfuscated, it will be passed to your beacon for execution/uploading. 

### Cobalt Strike related Options

Here's a list of options required by the Cobalt Strike integrator:

* `python3_interpreter_path` - Specify a path to Python3 interpreter executable
* `protect_my_tooling_dir` - Specify a path to ProtectMyTooling main directory
* `protect_my_tooling_config` - Specify a path to ProtectMyTooling configuration file with various packers options
* `dotnet_assemblies_directory` - Specify local path .NET assemblies should be looked for if not found by execute-assembly
* `cache_protected_executables` - Enable to cache already protected executables and reuse them when needed
* `protected_executables_cache_dir` - Specify a path to a directory that should store cached protected executables
* `default_exe_x86_packers_chain` - Native x86 EXE executables protectors/packers chain
* `default_exe_x64_packers_chain` - Native x64 EXE executables protectors/packers chain
* `default_dll_x86_packers_chain` - Native x86 DLL executables protectors/packers chain
* `default_dll_x64_packers_chain` - Native x64 DLL executables protectors/packers chain
* `default_dotnet_packers_chain` - .NET executables protectors/packers chain


## Supported Packers

- [`CallObfuscator`](https://github.com/d35ha/CallObfuscator) - Obfuscates specific windows apis with different apis.
- [`ConfuserEx`](https://github.com/mkaring/ConfuserEx) - Popular .NET obfuscator, forked from [Martin Karing](https://github.com/mkaring)
- [`Enigma`](https://enigmaprotector.com/) - A powerful system designed for comprehensive protection of executable files
- [`Hyperion`](https://nullsecurity.net/tools/binary.html) - runtime encrypter for 32-bit and 64-bit portable executables. It is a reference implementation and bases on the paper "Hyperion: Implementation of a PE-Crypter"
- [`IntelliLock`](https://www.eziriz.com/intellilock.htm) - combines strong license security, highly adaptable licensing functionality/schema with reliable assembly protection
- [`NetReactor`](https://www.eziriz.com/dotnet_reactor.htm) - Unmatched .NET code protection system which completely stops anyone from decompiling your code
- [`NetShrink`](https://www.pelock.com/pl/produkty/netshrink) - an exe packer aka executable compressor, application password protector and virtual DLL binder for Windows & Linux .NET applications.
- [`Packer64`](https://github.com/jadams/Packer64) - wrapper around John Adams' `Packer64` 
- [`peresed`](https://github.com/avast/pe_tools) - Uses _"peresed"_ from **avast/pe_tools** to remove all existing PE Resources and signature _(think of Mimikatz icon)._
- [`peCloak`](https://github.com/v-p-b/peCloakCapstone/blob/master/peCloak.py) - A Multi-Pass Encoder & Heuristic Sandbox Bypass AV Evasion Tool
- [`SmartAssembly`](https://www.red-gate.com/products/dotnet-development/smartassembly/) - obfuscator that helps protect your application against reverse-engineering or modification, by making it difficult for a third-party to access your source code
- [`Themida`](https://www.oreans.com/Themida.php) - Advanced Windows software protection system
- [`UPX`](https://upx.github.io/) - a free, portable, extendable, high-performance executable packer for several executable formats.
- [`VMProtect`](https://vmpsoft.com/) - protects code by executing it on a virtual machine with non-standard architecture that makes it extremely difficult to analyze and crack the software

You can quickly list supported packers using `-L` option:

```
C:\> py ProtectMyTooling.py -L

        :: ProtectMyTooling - a wrapper for PE Packers & Protectors
        Script that builds around supported packers & protectors to produce complex protected binaries.
        Mariusz Banach / mgeeky '20-'22, <mb@binary-offensive.com>
        v0.8

[ 1] Packer: callobf        - CallObfuscator - (by Mustafa Mahmoud, @d35ha) obscures PE imports by masquerading dangerous calls as innocuous ones
[ 2] Packer: confuserex     - An open-source protector for .NET applications
[ 3] Packer: enigma         - (paid) The Engima Protector is an advanced x86/x64 PE Executables protector with many anti- features and virtualization
[ 4] Packer: hyperion       - Robust PE EXE runtime AES encrypter for x86/x64 with own-key brute-forcing logic.
[ 5] Packer: intellilock    - (paid) Eziriz Intellilock is an advanced .Net (x86+x64) assemblies protector.
[ 6] Packer: netreactor     - (paid) A powerful code protection system for the .NET Framework including various obfuscation & anti- techniques
[ 7] Packer: netshrink      - (paid) PELock .netshrink is an .Net EXE packer with anti-cracking feautres and LZMA compression
[ 8] Packer: packer64       - jadams/Packer64 - Packer for 64-bit PE exes
[ 9] Packer: pecloak        - A Multi-Pass x86 PE Executables encoder by Mike Czumak | T_V3rn1x | @SecuritySift
[10] Packer: peresed        - Uses "peresed" from avast/pe_tools to remove all existing PE Resources and signature (think of Mimikatz icon).
[11] Packer: smartassembly  - (paid) A powerful code protection system for the .NET Framework including various obfuscation & anti- techniques
[12] Packer: themida        - (paid) Advanced x86/x64 PE Executables virtualizer, compressor, protector and binder.
[13] Packer: upx            - Universal PE Executables Compressor - highly reliable, works with x86 & x64.
[14] Packer: vmprotect      - (paid) VMProtect protects x86/x64 code by virtualizing it in complex VM environments.
```

Above are the packers that are supported, but that doesn't mean that you have them configured and ready to use. 
To prepare their usage, you must first supply necessary binaries to the `contrib` directory and then configure your YAML file accordingly.

## Full Help

Full help displaying all the available options:

```
C:\> py ProtectMyTooling.py --help

        :: ProtectMyTooling - a wrapper for PE Packers & Protectors
        Script that builds around supported packers & protectors to produce complex protected binaries.
        Mariusz Banach / mgeeky '20-'22, <mb@binary-offensive.com>
        v0.8

usage: Usage: %prog [options] <packers> <infile> <outfile>

positional arguments:
  packers               Specifies packers to use and their order in a comma-delimited list. Example: "pecloak,upx" will produce upx(pecloak(original)) output.
  _input                Input file to be packed/protected.
  output                Output file constituing generated sample.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        External configuration file. Default: ProtectMyTooling.yaml
  -t TIMEOUT, --timeout TIMEOUT
                        Command execution timeout. Default: 60 seconds.
  -a ARCH, --arch ARCH  Specify file's target architecture. If input is a valid PE file, this script will try to automatically sense its arch. Otherwise (shellcode) you'll need to specify it.
  -v, --verbose         Displays verbose output.
  -d, --debug           Displays debugging informations (implies verbose output).
  -l PATH, --log PATH   Specifies output log file.
  -s, --silent          Surpresses all of the output logging.

Test sample after generation:
  -r, --testrun         Launch generated sample to test it. Use --cmdline to specify execution parameters. By default output won't be launched.
  --cmdline CMDLINE     Command line for the generated sample

Optional AV Handling hooks:
  --check-av-command CHECK_AV_COMMAND
                        Command used to check status of AV solution. This command must return "True" if AV is running.
  --disable-av-command DISABLE_AV_COMMAND
                        Command used to disable AV solution before processing files.
  --enable-av-command ENABLE_AV_COMMAND
                        Command used to re-enable AV solution after processing files. The AV will be re-enabled only if it was enabled previously.

Packers handling:
  -L, --list-packers    List available packers.

Packer 'CallObf' options:
  --callobf-path-x86 PATH
                        (required) Path to CallObfuscator x86 executable.
  --callobf-path-x64 PATH
                        (required) Path to CallObfuscator x64 executable.
  --callobf-config PATH
                        Custom config file for CallObfuscator. If "generate-automatically" is specified, a config file will be created randomly by ProtectMyTooling

Packer 'ConfuserEx' options:
  --confuserex-path PATH
                        (required) Path to ConfuserEx binary capable of obfuscating .NET executables.
  --confuserex-project-file PATH
                        (required) Path to .ConfuserEx .csproj project file.
  --confuserex-save-generated-project-file bool
                        Specifies whether to save newly generated project file along with the output generated executable (with .crproj extension). Valid values: 0/1. Default: 0
  --confuserex-args ARGS
                        Optional ConfuserEx-specific arguments to pass during compression.

Packer 'EnigmaProtector' options:
  --enigma-path-x86 PATH
                        (required) Path to The Enigma Protector x86 executable.
  --enigma-path-x64 PATH
                        (required) Path to The Enigma Protector x64 executable.
  --enigma-project-file PATH
                        (required) Path to The Enigma Protector .enigma base project file (template to work with).
  --enigma-save-generated-project-file bool
                        Specifies whether to save newly generated project file along with the output generated executable (with .enigma extension). Valid values: 0/1. Default: 0
  --enigma-product-name NAME
                        Product name to set in application's manifest.
  --enigma-product-version VER
                        Product version to set in application's manifest.
  --enigma-process-blacklist PROCNAME
                        Enigma will exit running if this process is found launched. May be repeated. Suitable for anti-analysis defenses.
  --enigma-check-processes-every SECONDS
                        Enigma will check processes list for blacklisted entries every N seconds. Default: 10. Use "0" to check only at startup.
  --enigma-antidebug bool
                        Enable Anti-Debug checks and prevent output from running under debugger. Valid values: 0/1. Default: 1
  --enigma-antivm bool  Enable Anti-VM checks and prevent running sample in Virtual Machines such as VMWare. Valid values: 0/1. Default: 0
  --enigma-control-sum bool
                        Enable Program control-sum / Integrity vertification. Valid values: 0/1. Default: 1
  --enigma-protected-exe-cmdline ARGS
                        Allows to use initial command line arguments for the protected executable.
  --enigma-args ARGS    Optional enigma-specific arguments to pass during compression.

Packer 'Hyperion' options:
  --hyperion-path PATH  (required) Path to hyperion binary capable of compressing x86/x64 executables.
  --hyperion-args ARGS  Optional hyperion-specific arguments to pass during compression.

Packer 'INTELLILOCK' options:
  --intellilock-path PATH
                        (required) Path to Intellilock executable.
  --intellilock-args ARGS
                        Optional Intellilock-specific arguments to pass during compression.

Packer '.NET Reactor' options:
  --netreactor-path PATH
                        (required) Path to netreactor executable.
  --netreactor-project-file PATH
                        (required) Path to .NET Reactor .nrproj project file.
  --netreactor-save-generated-project-file bool
                        Specifies whether to save newly generated project file along with the output generated executable (with .nrproj extension).
  --netreactor-antitamp bool
                        This option prevents your protected assembly from being tampered by hacker tools. Valid values: 0/1. Default: 1
  --netreactor-control-flow-obfuscation bool
                        Mangles program flow, making it extremely difficult for humans to follow the program logic. Valid values: 0/1. Default: 1
  --netreactor-flow-level bool
                        Controls the level of Control Flow Obfuscation. Valid values: 1-9. Default: 9
  --netreactor-resourceencryption bool
                        Enable this option to compress and encrypt embedded resources. Valid values: 0/1. Default: 1
  --netreactor-necrobit bool
                        Uses a powerful protection technology NecroBit which completely stops decompilation. It replaces the CIL code within methods with encrypted code. Valid values: 0/1. Default: 1
  --netreactor-merge-namespaces bool
                        Enable this option to place all obfuscated types inside a single namespace. Valid values: 0/1. Default: 1
  --netreactor-short-strings bool
                        Enable to generate short strings for your obfuscated class and member names. Valid values: 0/1. Default: 1
  --netreactor-stealth-mode bool
                        Enable this to generate random meaningful names for obfuscated classes and members. Valid values: 0/1. Default: 1
  --netreactor-all-params bool
                        Enable this to obfuscate all method parameters. Valid values: 0/1. Default: 1
  --netreactor-incremental-obfuscation bool
                        If you want .NET Reactor always to generate the same obfuscation strings for your type and member names, you need to enable this option. Valid values: 0/1. Default: 1
  --netreactor-unprintable-characters bool
                        Unprintable characters uses unprintable strings to obfuscate type and member names, but cannot be used if your assembly must run as safe code. Valid values: 0/1. Default: 1
  --netreactor-obfuscate-public-types bool
                        Enable this to obfuscate all type and member names in an assembly. Valid values: 0/1. Default: 1
  --netreactor-anti-ildasm bool
                        Suppres decompilation using decompilation tools such as ILDasm. Valid values: 0/1. Default: 1
  --netreactor-native-exe bool
                        .NET Reactor is able to generate a native x86 EXE file stub for your app. This way its not going to be possible to directly open the app within a decompiler. Valid values: 0/1. Default: 0
  --netreactor-prejit bool
                        In combination with the Native EXE file feature and Necrobit, .NET Reactor is able to convert managed methods into REAL x86 native code. Mostly small methods (like property setters/getters) are converted into native code. Valid values: 0/1. Default: 0
  --netreactor-public-types-internalization bool
                        If set to 1, .NET Reactor will convert all public types of an application into internal ones. This way the accessibility of types and members the assembly exposes will be reduced. Valid values: 0/1. Default: 0
  --netreactor-strong-name-removal bool
                        Enables anti Strong Name removal technique which prevents protected assemblies from being tampered by hacking tools. Warning: this option can impact the runtime performance of generated protected assembly! Valid values: 0/1. Default: 0
  --netreactor-args ARGS
                        Optional netreactor-specific arguments to pass during compression.

Packer '.Netshrink' options:
  --netshrink-path PATH
                        (required) Path to netshrink executable.
  --netshrink-detect-netversion VER
                        Enable .NET Framework installation detection (default: .NET v2.0). Example: ".NET v4.5"
  --netshrink-antidebug bool
                        Enable Anti-Debug checks and prevent output from running under debugger. Valid values: 0/1. Default: 1
  --netshrink-args ARGS
                        Optional netshrink-specific arguments to pass during compression.

Packer 'packer64' options:
  --packer64-path PATH  (required) Path to Packer64 executable.

Packer 'peCloak' options:
  --pecloak-python-path PATH
                        (required) Path to Python2.7 interpreter.
  --pecloak-script-path PATH
                        (required) Path to peCloakCapstone script file.
  --pecloak-args ARGS   Optional peCloakCapstone-specific arguments to pass during cloaking.

Packer '.NET Reactor' options:
  --smartassembly-path PATH
                        (required) Path to smartassembly executable.
  --smartassembly-project-file PATH
                        (required) Path to .NET Reactor .nrproj project file.
  --smartassembly-save-generated-project-file bool
                        Specifies whether to save newly generated project file along with the output generated executable (with .nrproj extension).
  --smartassembly-tamperprotection bool
                        Apply tamper protection to the assembly. Valid values: 0/1. Default: 1
  --smartassembly-sealclasses bool
                        Seal classes that are not inherited. Valid values: 0/1. Default: 1
  --smartassembly-preventildasm bool
                        Prevent Microsoft IL Disassembler from opening your assembly. Valid values: 0/1. Default: 1
  --smartassembly-typemethodobfuscation bool
                        Apply types / methods name mangling at the specified level to assemblies with nameobfuscate:true. Valid values: 1/2/3. Default: 3
  --smartassembly-fieldobfuscation bool
                        Apply fields name mangling at the specified level to assemblies with nameobfuscate:true. Valid values: 1/2/3. Default: 3
  --smartassembly-methodparentobfuscation bool
                        Apply method parent obfuscation to the assembly. Valid values: 0/1. Default: 1
  --smartassembly-cgsobfuscation bool
                        Obfuscate compiler-generated serializable types. Valid values: 0/1. Default: 1
  --smartassembly-stringsencoding bool
                        Enables improved strings encoding with cache and compression enabled. Valid values: 0/1. Default: 1
  --smartassembly-controlflowobfuscate bool
                        Sets the level of control flow obfuscation to apply to the assembly: 0 - disabled obfuscation, 4 - Unverifiable. Valid values: 0-4. Default: 4
  --smartassembly-compressencryptresources bool
                        Enable / Disable resources compression and encryption. Valid values: 0/1. Default: 1
  --smartassembly-dynamicproxy bool
                        Enable / Disable the references dynamic proxy. Valid values: 0/1. Default: 1
  --smartassembly-pruning bool
                        Enable / Disable assembly pruning. Valid values: 0/1. Default: 1
  --smartassembly-nameobfuscate bool
                        Enable / Disable types and methods obfuscation and field names obfuscation. The obfuscation is applied at the levels specified for the project. Valid values: 0/1. Default: 1
  --smartassembly-compressassembly bool
                        Enable / Disable compression when the assembly is embedded. Valid values: 0/1. Default: 1
  --smartassembly-encryptassembly bool
                        Enable / Disable compression when the assembly is embedded. Valid values: 0/1. Default: 1
  --smartassembly-args ARGS
                        Optional smartassembly-specific arguments to pass during compression.

Packer 'Themida' options:
  --themida-path-x86 PATH
                        (required) Path to Themida x86 executable.
  --themida-path-x64 PATH
                        (required) Path to Themida x64 executable.
  --themida-project-file PATH
                        (required) Path to Themida .tmd project file.
  --themida-args ARGS   Optional themida-specific arguments to pass during compression.

Packer 'UPX' options:
  --upx-path PATH       (required) Path to UPX binary capable of compressing x86/x64 executables.
  --upx-compress LEVEL  Compression level [1-9]: 1 - compress faster, 9 - compress better. Can also be "best" for greatest compression level possible.
  --upx-corrupt bool    If set to 1 enables UPX metadata corruption to prevent "upx -d" unpacking. This corruption won't affect executable's ability to launch. Default: enabled (1)
  --upx-args ARGS       Optional UPX-specific arguments to pass during compression.

Packer 'VMProtect' options:
  --vmprotect-path PATH
                        (required) Path to vmprotect executable.
  --vmprotect-project-file PATH
                        (required) Path to .NET Reactor .nrproj project file.
  --vmprotect-args ARGS
                        Optional vmprotect-specific arguments to pass during compression.
```

Options supplied through the command line _should_ override the ones defined in a config file.


## Adding support for a new Packer

In order to support a new packer, one has to create a plugin Python class and store it `packers` directory.

That plugin class must override `IPacker.py` interface, which pretty much boils down to necessity of overloading a few methods.

Then, your `process(...)` method could be as simple as the one visible in `packers/upx.py` implementation:

```py
  def process(self, arch, infile, outfile):
        ver = shell(self.logger, self.options['upx_path'] + ' --version').split('\n')[0].strip()
        self.logger.info(f'Working with {ver}')
        out = ''

        try:
            out = shell(self.logger, IPacker.build_cmdline(
                PackerUpx.upx_cmdline_template,
                self.options['upx_path'],
                self.upx_args,
                infile,
                outfile
            ), output = self.options['verbose'] or self.options['debug'], timeout = self.options['timeout'])

            if os.path.isfile(outfile):
                if self.options['upx_corrupt'] == 1:
                    return self.tamper(outfile)
                else:
                    return True
            else:
                self.logger.err('Something went wrong: there is no output artefact ({})!\n'.format(
                    outfile
                ))

        except ShellCommandReturnedError as e:
            self.logger.err(f'''Error message from packer:
----------------------------------------
{e}
----------------------------------------
''')

        except Exception as e:
            raise

        return False
```

All packers typically build some sort of a command line, or dynamically generate XML files and ultimately call out to `shell(...)` to execute the packer using its CLI interface (for instance _ConfuserEx_ has an executable named `ConfuserEx.CLI.exe`). 


---

### ☕ Show Support ☕

This and other projects are outcome of sleepless nights and **plenty of hard work**. If you like what I do and appreciate that I always give back to the community,
[Consider buying me a coffee](https://github.com/sponsors/mgeeky) _(or better a beer)_ just to say thank you! 💪 

---

## Author

```   
   Mariusz Banach / mgeeky, '20-'21
   <mb [at] binary-offensive.com>
   (https://github.com/mgeeky) 
```
