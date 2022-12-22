proc Decompress Data:DWORD, Size:DWORD, DecompressedSize:DWORD
	local	Decompressed:DWORD
	local	FinalDecompressedSize:DWORD

	mov		[Decompressed], 0

	; Allocate decompressed data
	pebcall	PEB_Kernel32Dll, PEB_GetProcessHeap
	pebcall	PEB_NtdllDll, PEB_RtlAllocateHeap, eax, 0, [DecompressedSize]
	test	eax, eax
	jz		.ret
	mov		[Decompressed], eax

	; Decompress buffer
	lea		eax, [FinalDecompressedSize]
	pebcall	PEB_NtdllDll, PEB_RtlDecompressBuffer, COMPRESSION_FORMAT_LZNT1, [Decompressed], [DecompressedSize], [Data], [Size], eax
	test	eax, eax
	jz		.ret

	; Free buffer, if decompression failed
	pebcall	PEB_Kernel32Dll, PEB_GetProcessHeap
	pebcall	PEB_Kernel32Dll, PEB_HeapFree, eax, 0, [Decompressed]
	mov		[Decompressed], 0

.ret:
	mov		eax, [Decompressed]
	ret
endp