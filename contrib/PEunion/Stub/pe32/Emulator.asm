proc DetectEmulator
	local	Memory:DWORD
	local	String[MAX_PATH + 1]:BYTE
	local	ComputerName[MAX_PATH + 1]:BYTE
	local	ComputerNameLength:DWORD
	local	ExecutablePath[MAX_PATH + 1]:BYTE
	local	ExecutableFileName[MAX_PATH + 1]:BYTE

	; --------------------------------------------------------------------------

	; Allocating 100 MB of memory must work
	cinvoke	malloc, 100 * 1024 * 1024
	test	eax, eax
	jz		.emulator
	mov		[Memory], eax

	; Actually writing to memory is required to test the allocation
	cinvoke	memset, [Memory], 0, 100 * 1024 * 1024
	cinvoke	free, [Memory]

	; --------------------------------------------------------------------------

	; SetErrorMode return value must match previous value
	invoke	SetErrorMode, 1024
	invoke	SetErrorMode, 0
	cmp		eax, 1024
	jne		.emulator

	; --------------------------------------------------------------------------

	; VirtualAllocExNuma must work
	invoke	VirtualAllocExNuma, -1, NULL, 1000, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE, 0
	test	eax, eax
	jz		.emulator

	; --------------------------------------------------------------------------

	; Get computer name
	mov		[ComputerNameLength], MAX_PATH
	lea		eax, [ComputerName]
	lea		ebx, [ComputerNameLength]
	invoke	GetComputerNameA, eax, ebx
	test	eax, eax
	jz		@f

	; Computer name is not "NfZtFbPfH"
	lea		eax, [String]
	lodstra	'NfZtFbPfH'
	lea		ebx, [ComputerName]
	cinvoke	strcmp, eax, ebx
	test	eax, eax
	jz		.emulator

	; Computer name is not "ELICZ"
	lea		eax, [String]
	lodstra	'ELICZ'
	lea		ebx, [ComputerName]
	cinvoke	strcmp, eax, ebx
	test	eax, eax
	jz		.emulator

	; Computer name is not "tz"
	lea		eax, [String]
	lodstra	'tz'
	lea		ebx, [ComputerName]
	cinvoke	strcmp, eax, ebx
	test	eax, eax
	jz		.emulator

	; Computer name is not "MAIN"
	lea		eax, [String]
	lodstra	'MAIN'
	lea		ebx, [ComputerName]
	cinvoke	strcmp, eax, ebx
	test	eax, eax
	jz		.emulator
@@:

	; --------------------------------------------------------------------------

	; Get executable path
	lea		eax, [ExecutablePath]
	invoke	GetModuleFileNameA, NULL, eax, MAX_PATH
	cmp		eax, 0
	jle		@f

	; Get executable filename
	lea		eax, [ExecutablePath]
	invoke	PathFindFileNameA, eax
	lea		ebx, [ExecutableFileName]
	invoke	strcpy, ebx, eax

	; Executable path is not "C:\[...]\mwsmpl.exe"
	lea		eax, [String]
	lodstra	'C:\Documents and Settings\Administrator\My Documents\mwsmpl.exe'
	lea		ebx, [ExecutablePath]
	cinvoke	strcmpi, eax, ebx
	test	eax, eax
	jz		.emulator

	; Executable path is not "C:\SELF.EXE"
	lea		eax, [String]
	lodstra	'C:\SELF.EXE'
	lea		ebx, [ExecutablePath]
	cinvoke	strcmpi, eax, ebx
	test	eax, eax
	jz		.emulator

	; Executable filename is not "myapp.exe"
	lea		eax, [String]
	lodstra	'myapp.exe'
	lea		ebx, [ExecutableFileName]
	cinvoke	strcmpi, eax, ebx
	test	eax, eax
	jz		.emulator
@@:

	; --------------------------------------------------------------------------

	; No emulator detected
	xor		eax, eax
	ret

.emulator:
	; Running in emulator
	invoke	ExitProcess, 0
	ret
endp