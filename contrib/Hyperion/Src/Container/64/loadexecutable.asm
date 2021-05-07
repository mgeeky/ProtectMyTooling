;Loads the exe which is stored in input_image
;into memory and starts its execution
proc loadExecutable input_image:QWORD

local str1[256]:BYTE, ret_val:QWORD, image_file_header:QWORD,\
loaded_file:QWORD

	mov [input_image],rcx

	;verify checksum of packed executable
	writeWithNewLine createStringVerifyChecksum, str1, le_exit_error
	fastcall verifyChecksum, [input_image], INFILE_SIZE
	test rax,rax
	jz le_exit_error

	;verify whether the content of the data section is pe
	writeWithNewLine createStringVerifyPE, str1, le_exit_error
	mov rax,[input_image]
	add rax,4
	fastcall verifyPE, rax
	test rax,rax
	mov [image_file_header],rax
	jz le_exit_error

	;copy pe header and sections into memory
	writeNewLineToLog le_exit_error
	writeWithNewLine createStringMappingFileInMemory, str1, le_exit_error
	mov rax,[input_image]
	add rax,4
	fastcall loadFile, [image_file_header], rax, INFILE_SIZE-4
	test rax,rax
	mov [loaded_file],rax
	jz le_exit_error

	;loading import table
	writeNewLineToLog le_exit_error
	writeWithNewLine createStringLoadingFilesAPIs, str1, le_exit_error
	fastcall loadImportTable, [loaded_file]
	test rax,rax
	jz le_exit_error

	;set the correct permissions for each section
	writeNewLineToLog le_exit_error
	writeWithNewLine createStringSettingPermissions, str1, le_exit_error
	mov rax,[input_image]
	add rax,4
	fastcall setPermissions, [image_file_header], rax, INFILE_SIZE-4
	test rax,rax
	jz le_exit_error

le_exit_success:
	mov rax,1
	ret

le_exit_error:
	sub rax,rax
	ret

endp

;load the APIs in the import table
proc loadImportTable uses rsi rdi rbx, image_base:QWORD

local str1[256]:BYTE, import_table:QWORD, null_directory_entry[sizeof.IMAGE_IMPORT_DESCRIPTOR]:BYTE

	mov [image_base], rcx

	;find import table in data directory
	mov rdx,[image_base]
	mov eax,[rdx+IMAGE_DOS_HEADER.e_lfanew]
	add rax,rdx
	add rax,4
	;image file header now in eax
	add rax,sizeof.IMAGE_FILE_HEADER
	lea rax,[rax+IMAGE_OPTIONAL_HEADER64.DataDirectory]
	;first data directory entry now in eax
	add rax,sizeof.IMAGE_DATA_DIRECTORY
	;import data directory entry now in eax
	mov eax,[rax+IMAGE_DATA_DIRECTORY.VirtualAddress]
	add rax,rdx
	;pointer to import table now in eax
	mov [import_table],rax
	writeWithNewLine createStringFoundImportTable, str1, le_exit_error
	writeRegisterToLog [import_table], pit_exit_error

	;init null directory entry
	lea r8,[null_directory_entry]
	mov rcx,sizeof.IMAGE_IMPORT_DESCRIPTOR
	mov al,0
pit_init_null_directory_loop:
	mov [r8],al
	inc r8
	dec rcx
	jnz pit_init_null_directory_loop

	mov rbx,[import_table]
	;iterate over the directory tables
pit_next_directory_entry:
	lea rsi,[null_directory_entry]
	mov rdi,rbx
	mov rcx,sizeof.IMAGE_IMPORT_DESCRIPTOR
	rep cmpsb
	je pit_exit_success
	;load APIs of this directory
	fastcall loadImportDirectoryTable, [image_base], rbx
	test rax,rax
	jz pit_exit_error
	;next entry
	add rbx,sizeof.IMAGE_IMPORT_DESCRIPTOR
	jmp pit_next_directory_entry

pit_exit_success:
	mov eax,1
	jmp pit_exit_ret

pit_exit_error:
	sub rax,rax

pit_exit_ret:
	ret

endp

;loads the APIs
proc loadImportDirectoryTable uses rbx r12, image_base:QWORD, directory_entry:QWORD

local str1[256]:BYTE, lookup_table:QWORD, import_address_table:QWORD, dll_image_base:QWORD

	mov [image_base],rcx
	mov [directory_entry],rdx

	;write info about data directory table to logfile
	writeNewLineToLog lidt_exit_error
	writeWithNewLine createStringProcessImportDirectory, str1, lidt_exit_error
	mov rax,[directory_entry]
	mov eax,[rax+IMAGE_IMPORT_DESCRIPTOR.Name_]
	add rax,[image_base]
	mov rbx,rax
	;pointer to dll name in ebx
	writeLog rax, lidt_exit_error
	writeNewLineToLog lidt_exit_error

	;load the corresponding dll
	invoke LoadLibrary, rbx
	test rax,rax
	jz lidt_exit_error
	mov [dll_image_base],rax

	;read pointers to the api tables
	mov rdx,[directory_entry]
	mov eax,[rdx+IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
	add rax,[image_base]
	mov [import_address_table],rax
	;check whether OriginalFirstThunk exists and can be used
	mov eax,[rdx+IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk]
	test eax,eax
	jnz lidt_use_original_first_thunk
	;in some binaries, OriginalFirstThunk table is empty
	;in this case, use FirstThunk insteadt to fetch API names or ordinals
	mov eax,[rdx+IMAGE_IMPORT_DESCRIPTOR.FirstThunk]
lidt_use_original_first_thunk:
	add rax,[image_base]
	mov [lookup_table],rax

	;index to current API
	sub r12,r12
	;iterate the lookup_table entries
lidt_next_lookup_entry:
	mov rcx,r12
	mov rax,[lookup_table]
	add rax,r12 ;counter is in r12
	mov rax,[rax] ;get entry (64 bit in PE+)
	test rax,rax
	jz lidt_exit_success
	mov rbx,rax
	mov rcx,IMAGE_ORDINAL_FLAG64
	and rax,rcx
	jnz lidt_byordinal
lidt_byname:
	createStringName str1
	writeLog rax, lidt_exit_error
	add rbx,[image_base] ;according to spec, first 32 bits are 0, therefore add is possible
	lea rbx,[rbx+IMAGE_IMPORT_BY_NAME.Name_]
	mov rax,rbx ;pointer to API name is now in rax and rbx
	writeLog rax, lidt_exit_error
	writeNewLineToLog lidt_exit_error
	;API name pointer in rbx
	invoke GetProcAddress, [dll_image_base], rbx
	test rax,rax
	jz lidt_exit_error
	mov rbx,[import_address_table]
	add rbx,r12
	mov [rbx],rax
	;fetch next API
	add r12,8 ;size of entries in import lookup table and import address table is 8 in PE+
	jmp lidt_next_lookup_entry

lidt_byordinal:
	createStringOrdinal str1
	writeLog rax, lidt_exit_error
	;remove the ordinal flag
	mov rcx,IMAGE_ORDINAL_FLAG64
	xor rbx,rcx
	mov rax,rbx
	writeRegisterToLog rax, lidt_exit_error
	;API ordinal in rbx
	invoke GetProcAddress, [dll_image_base], rbx
	test rax,rax
	jz lidt_exit_error
	mov rbx,[import_address_table]
	add rbx,r12
	mov [rbx],rax
	;fetch next API
	add r12,8
	jmp lidt_next_lookup_entry

lidt_exit_success:
	mov rax,1
	jmp lidt_exit_ret

lidt_exit_error:
	sub rax,rax

lidt_exit_ret:
	ret

endp;

;sets the memory permissions for each section
proc setPermissions uses rbx r12, image_file_header:QWORD, file_image_base:QWORD, \
file_image_size:QWORD

local number_of_sections:QWORD, image_base:QWORD, section_headers:QWORD,\
pe_header_size:QWORD, str1[256]:BYTE, vprotect_ret:QWORD

	mov [image_file_header],rcx
	mov [file_image_base],rdx
	mov [file_image_size],r8

	;find section header
	sub rax,rax
	mov rdx,[image_file_header]
	mov ax,[rdx+IMAGE_FILE_HEADER.NumberOfSections]
	mov [number_of_sections],rax
	add rdx,sizeof.IMAGE_FILE_HEADER
	mov rax,[rdx+IMAGE_OPTIONAL_HEADER64.ImageBase]
	mov [image_base],rax
	;search for section header
	lea r12,[rdx+IMAGE_OPTIONAL_HEADER64.DataDirectory]
	mov eax,[rdx+IMAGE_OPTIONAL_HEADER64.NumberOfRvaAndSizes]
	mov rdx,sizeof.IMAGE_DATA_DIRECTORY
	mul rdx
	add rax,r12
	;first section header found
	mov [section_headers],rax
	mov rax,sizeof.IMAGE_SECTION_HEADER
	mov rdx,[number_of_sections]
	mul rdx
	;end of section header sections found
	add rax,[section_headers]
	mov r12,[file_image_base]
	sub rax,r12
	;unaligned size of pe header in eax
	mov [pe_header_size],rax

	;set pe header page read-only
	lea r12,[vprotect_ret]
	invoke VirtualProtect, [image_base], [pe_header_size], PAGE_READONLY, r12
	test rax,rax
	jz sp_exit_error

	;some output for the user
	writeRegisterToLog [image_base], sp_exit_error

	;set the section page permissions
	mov r12,[number_of_sections]
	mov rbx,[section_headers]
sp_load_section_loop:
	fastcall setSection, rbx, [image_base], [file_image_base]
	test rax,rax
	jz sp_exit_error
	add rbx,sizeof.IMAGE_SECTION_HEADER
	dec r12
	jnz sp_load_section_loop

sp_exit_success:
	mov rax,1
	jmp sp_exit_ret

sp_exit_error:
	sub rax,rax

sp_exit_ret:
	ret

endp;

;sets the complete image of the decrypted file writeable so
;we can copy pe header and sections into it
proc loadFile uses rbx rdi rsi, image_file_header:QWORD, file_image_base:QWORD, \
file_image_size:QWORD

local number_of_sections:QWORD, image_base:QWORD, aux:QWORD,\
str1[256]:BYTE, vprotect_ret:QWORD, section_headers:QWORD, pe_header_size:QWORD

	mov [image_file_header],rcx
	mov [file_image_base],rdx
	mov [file_image_size],r8

	;find section header
	;mov edx,[image_file_header]
	sub rax,rax
	mov rdx,[image_file_header]
	mov ax,[rdx+IMAGE_FILE_HEADER.NumberOfSections]
	mov [number_of_sections],rax
	add rdx,sizeof.IMAGE_FILE_HEADER
	mov rax,[rdx+IMAGE_OPTIONAL_HEADER64.ImageBase]
	mov [image_base],rax
	;make the complete image writable
	mov esi,[rdx+IMAGE_OPTIONAL_HEADER64.SizeOfImage]
	mov [aux],rdx ;store edx, we need it later
	lea rbx,[vprotect_ret]
	invoke VirtualProtect, [image_base], rsi, PAGE_READWRITE, rbx
	test rax,rax
	jz lf_exit_error

	;some output for the user
	writeWithNewLine createStringLoadedPEHeader, str1, lf_exit_error
	writeRegisterToLog [image_base], lf_exit_error

	mov rdx,[aux] ;restore rdx
	;continue search for section header
	lea rbx,[rdx+IMAGE_OPTIONAL_HEADER64.DataDirectory]
	mov eax,[rdx+IMAGE_OPTIONAL_HEADER64.NumberOfRvaAndSizes]
	mov rdx,sizeof.IMAGE_DATA_DIRECTORY
	mul rdx
	add rax,rbx

	;first section header found
	mov [section_headers],rax
	mov rax,sizeof.IMAGE_SECTION_HEADER
	mov rdx,[number_of_sections]
	mul rdx
	;end of section header sections found
	add rax,[section_headers]
	mov rbx,[file_image_base]
	sub rax,rbx
	;unaligned size of pe header in eax
	mov [pe_header_size],rax

	;copy header to memory
	mov rdi,[image_base]
	mov rsi,[file_image_base]
	mov rcx,[pe_header_size]
	rep movsb

	;load the sections
	mov rsi,[number_of_sections]
	mov rbx,[section_headers]
lf_load_section_loop:
	fastcall loadSection, rbx, [image_base], [file_image_base]
	test rax,rax
	jz lf_exit_error
	add rbx,sizeof.IMAGE_SECTION_HEADER
	dec rsi
	jnz lf_load_section_loop

lf_exit_success:
	mov rax,[image_base]
	jmp lf_exit_ret

lf_exit_error:
	sub rax,rax

lf_exit_ret:
	ret
endp

;load the corresponding section into memory
proc loadSection uses rdi rsi r12, section_header:QWORD, image_base:QWORD,\
file_image_base:QWORD

local str1[256]:BYTE

	mov [section_header],rcx
	mov [image_base],rdx
	mov [file_image_base],r8

	;copy from file into memory
	mov rdx,[section_header]
	mov edi,[rdx+IMAGE_SECTION_HEADER.VirtualAddress]
	add rdi,[image_base]
	mov esi,[rdx+IMAGE_SECTION_HEADER.PointerToRawData]
	add rsi,[file_image_base]
	mov ecx,[rdx+IMAGE_SECTION_HEADER.SizeOfRawData]
	rep movsb
	writeSectionNameAndAddressToLog

ls_exit_success:
	mov rax,1
	jmp ls_exit_ret

ls_exit_error:
	sub rax,rax

ls_exit_ret:
	ret

endp

;set the memory page permission for the corresponding section
proc setSection uses rbx r12, section_header:QWORD, image_base:QWORD,\
file_image_base:QWORD

local section_flags:QWORD, vprotect_ret:QWORD, str1[256]:BYTE

	mov [section_header],rcx
	mov [image_base],rdx
	mov [file_image_base],r8

	;section execute/read/write?
	mov rdx,[section_header]
	mov ebx,[rdx+IMAGE_SECTION_HEADER.Characteristics]
	and ebx,IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
	cmp ebx,IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
	jne ssn_no_execute_read_write
	mov rax,PAGE_EXECUTE_READWRITE
	mov [section_flags],rax
	jmp ssn_set_memory
ssn_no_execute_read_write:
	;section execute/read?
	mov ebx,[rdx+IMAGE_SECTION_HEADER.Characteristics]
	and ebx,IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ
	cmp ebx,IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ
	jne ssn_no_execute_read
	mov rax,PAGE_EXECUTE_READ
	mov [section_flags],rax
	jmp ssn_set_memory
ssn_no_execute_read:
	;section read/write?
	mov ebx,[rdx+IMAGE_SECTION_HEADER.Characteristics]
	and ebx,IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
	cmp ebx,IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE
	jne ssn_no_read_write
	mov rax,PAGE_READWRITE
	mov [section_flags],rax
	jmp ssn_set_memory
ssn_no_read_write:
	;section read?
	mov ebx,[rdx+IMAGE_SECTION_HEADER.Characteristics]
	and ebx,IMAGE_SCN_MEM_READ
	cmp ebx,IMAGE_SCN_MEM_READ
	jne ssn_no_read
	mov rax,PAGE_READONLY
	mov [section_flags],rax
	jmp ssn_set_memory
ssn_no_read:
	mov rax,PAGE_NOACCESS
	mov [section_flags],rax

	;set section permissions
ssn_set_memory:
	mov eax,[rdx+IMAGE_SECTION_HEADER.VirtualAddress]
	add rax,[image_base]
	mov ebx,[rdx+IMAGE_SECTION_HEADER.VirtualSize]
	lea r12,[vprotect_ret]
	invoke VirtualProtect,rax,rbx,[section_flags], r12
	test rax,rax
	jz ssn_exit_error

	;some output for the user
	mov rdx,[section_header]
	mov eax,[rdx+IMAGE_SECTION_HEADER.VirtualAddress]
	add rax,[image_base]
	writeRegisterToLog rax, ssn_exit_error

ssn_exit_success:
	mov rax,1
	jmp ssn_exit_ret

ssn_exit_error:
	sub rax,rax

ssn_exit_ret:
	ret

endp;

;check MZ und PE signature and return start of the image file header
proc verifyPE, image_base:QWORD

	mov [image_base], rcx

	mov rcx,[image_base]
	mov ax,[rcx+IMAGE_DOS_HEADER.e_magic]
	cmp ax,IMAGE_DOS_SIGNATURE
	jne vpe_exit_error
	mov eax,[rcx+IMAGE_DOS_HEADER.e_lfanew]
	add rcx,rax
	mov eax,dword [rcx]
	cmp eax,IMAGE_NT_SIGNATURE
	jne vpe_exit_error
	add rcx,4

vpe_exit_success:
	mov rax,rcx
	ret

vpe_exit_error:
	sub rax,rax
	ret

endp

;First 4 bytes of data seciton contain a checksum
;Verify that the checksum is correct
;TODO: CHECKSUM SIZE is atm hardcoded
proc verifyChecksum uses rbx rdi, section_address:QWORD, section_size:QWORD

	mov [section_address],rcx
	mov [section_size],rdx

	mov rbx,[section_address]
	mov eax,[rbx]
	add rbx,4
	mov rcx,[section_size]
	sub rcx,4
	;checksum is in eax
	;pointer to file in ebx
	;size of file in ecx
	sub rdi,rdi
vs_calc_cs:
	sub rdx,rdx
	mov dl,byte [rbx]
	add edi,edx
	inc rbx
	dec rcx
	jnz vs_calc_cs
	;calculated checksum is in edi
	cmp edi,eax
	jne vs_exit_error

vs_exit_success:
	mov eax,1
	jmp vs_exit_ret

vs_exit_error:
	sub eax,eax

vs_exit_ret:
	ret

endp
