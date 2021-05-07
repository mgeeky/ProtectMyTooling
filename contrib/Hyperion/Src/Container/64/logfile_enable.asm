;-------------------------------------------
;the content of this file is excluded,	    |
;when the user disables logging features    |
;in hyperion command line. pls keep in mind |
;and dont rely on its existence.	    |
;-------------------------------------------  

;--- Begin Macro Section ---

macro createStringBruteforcing location
{
	 mov [location+0],'B'
	 mov [location+1],'r'
	 mov [location+2],'u'
	 mov [location+3],'t'
	 mov [location+4],'e'
	 mov [location+5],'f'
	 mov [location+6],'o'
	 mov [location+7],'r'
	 mov [location+8],'c'
	 mov [location+9],'i'
	 mov [location+10],'n'
	 mov [location+11],'g'
	 mov [location+12],' '
	 mov [location+13],'K'
	 mov [location+14],'e'
	 mov [location+15],'y'
	 mov [location+16],0
	 lea rax,[location]
}

macro createStringSettingPermissions location
{
	 mov [location+0],'S'
	 mov [location+1],'e'
	 mov [location+2],'t'
	 mov [location+3],'t'
	 mov [location+4],'i'
	 mov [location+5],'n'
	 mov [location+6],'g'
	 mov [location+7],' '
	 mov [location+8],'S'
	 mov [location+9],'e'
	 mov [location+10],'c'
	 mov [location+11],'t'
	 mov [location+12],'i'
	 mov [location+13],'o'
	 mov [location+14],'n'
	 mov [location+15],' '
	 mov [location+16],'P'
	 mov [location+17],'e'
	 mov [location+18],'r'
	 mov [location+19],'m'
	 mov [location+20],'i'
	 mov [location+21],'s'
	 mov [location+22],'s'
	 mov [location+23],'i'
	 mov [location+24],'o'
	 mov [location+25],'n'
	 mov [location+26],'s'
	 mov [location+27],0
	 lea rax,[location]
}

macro createStringOrdinal location
{
	 mov [location+0],'O'
	 mov [location+1],'r'
	 mov [location+2],'d'
	 mov [location+3],'i'
	 mov [location+4],'n'
	 mov [location+5],'a'
	 mov [location+6],'l'
	 mov [location+7],':'
	 mov [location+8],' '
	 mov [location+9],0
	 lea rax,[location]
}

macro createStringName location
{
	 mov [location+0],'N'
	 mov [location+1],'a'
	 mov [location+2],'m'
	 mov [location+3],'e'
	 mov [location+4],':'
	 mov [location+5],' '
	 mov [location+6],0
	 lea rax,[location]
}

macro createStringProcessImportDirectory location
{
	 mov [location+0],'P'
	 mov [location+1],'r'
	 mov [location+2],'o'
	 mov [location+3],'c'
	 mov [location+4],'e'
	 mov [location+5],'s'
	 mov [location+6],'s'
	 mov [location+7],'i'
	 mov [location+8],'n'
	 mov [location+9],'g'
	 mov [location+10],' '
	 mov [location+11],'I'
	 mov [location+12],'m'
	 mov [location+13],'p'
	 mov [location+14],'o'
	 mov [location+15],'r'
	 mov [location+16],'t'
	 mov [location+17],' '
	 mov [location+18],'D'
	 mov [location+19],'i'
	 mov [location+20],'r'
	 mov [location+21],'e'
	 mov [location+22],'c'
	 mov [location+23],'t'
	 mov [location+24],'o'
	 mov [location+25],'r'
	 mov [location+26],'y'
	 mov [location+27],':'
	 mov [location+28],0
	 lea rax,[location]
}

macro createStringFoundImportTable location
{
	 mov [location+0],'I'
	 mov [location+1],'m'
	 mov [location+2],'p'
	 mov [location+3],'o'
	 mov [location+4],'r'
	 mov [location+5],'t'
	 mov [location+6],' '
	 mov [location+7],'T'
	 mov [location+8],'a'
	 mov [location+9],'b'
	 mov [location+10],'l'
	 mov [location+11],'e'
	 mov [location+12],':'
	 mov [location+13],0
	 lea rax,[location]
}

macro createStringLoadingFilesAPIs location
{
	 mov [location+0],'L'
	 mov [location+1],'o'
	 mov [location+2],'a'
	 mov [location+3],'d'
	 mov [location+4],'i'
	 mov [location+5],'n'
	 mov [location+6],'g'
	 mov [location+7],' '
	 mov [location+8],'A'
	 mov [location+9],'P'
	 mov [location+10],'I'
	 mov [location+11],'s'
	 mov [location+12],0
	 lea rax,[location]
}

macro createStringMappingFileInMemory location
{
	 mov [location+0],'M'
	 mov [location+1],'a'
	 mov [location+2],'p'
	 mov [location+3],'p'
	 mov [location+4],'i'
	 mov [location+5],'n'
	 mov [location+6],'g'
	 mov [location+7],' '
	 mov [location+8],'F'
	 mov [location+9],'i'
	 mov [location+10],'l'
	 mov [location+11],'e'
	 mov [location+12],' '
	 mov [location+13],'i'
	 mov [location+14],'n'
	 mov [location+15],'t'
	 mov [location+16],'o'
	 mov [location+17],' '
	 mov [location+18],'M'
	 mov [location+19],'e'
	 mov [location+20],'m'
	 mov [location+21],'o'
	 mov [location+22],'r'
	 mov [location+23],'y'
	 mov [location+24],0
	 lea rax,[location]
}

macro createStringLoaded location
{
	 mov [location+0],'L'
	 mov [location+1],'o'
	 mov [location+2],'a'
	 mov [location+3],'d'
	 mov [location+4],'e'
	 mov [location+5],'d'
	 mov [location+6],' '
	 mov [location+7],0
	 lea rax,[location]
}

macro createStringLoadedPEHeader location
{
	 mov [location+0],'S'
	 mov [location+1],'e'
	 mov [location+2],'t'
	 mov [location+3],' '
	 mov [location+4],'I'
	 mov [location+5],'m'
	 mov [location+6],'a'
	 mov [location+7],'g'
	 mov [location+8],'e'
	 mov [location+9],' '
	 mov [location+10],'w'
	 mov [location+11],'r'
	 mov [location+12],'i'
	 mov [location+13],'t'
	 mov [location+14],'a'
	 mov [location+15],'b'
	 mov [location+16],'l'
	 mov [location+17],'e'
	 mov [location+18],':'
	 mov [location+19],0
	 lea rax,[location]
}

macro createStringVerifyPE location
{
	 mov [location+0],'V'
	 mov [location+1],'e'
	 mov [location+2],'r'
	 mov [location+3],'i'
	 mov [location+4],'f'
	 mov [location+5],'y'
	 mov [location+6],'i'
	 mov [location+7],'n'
	 mov [location+8],'g'
	 mov [location+9],' '
	 mov [location+10],'P'
	 mov [location+11],'E'
	 mov [location+12],0
	 lea rax,[location]
}

macro createStringVerifyChecksum location
{
	 mov [location+0],'V'
	 mov [location+1],'e'
	 mov [location+2],'r'
	 mov [location+3],'i'
	 mov [location+4],'f'
	 mov [location+5],'y'
	 mov [location+6],'i'
	 mov [location+7],'n'
	 mov [location+8],'g'
	 mov [location+9],' '
	 mov [location+10],'C'
	 mov [location+11],'h'
	 mov [location+12],'e'
	 mov [location+13],'c'
	 mov [location+14],'k'
	 mov [location+15],'s'
	 mov [location+16],'u'
	 mov [location+17],'m'
	 mov [location+18],0
	 lea rax,[location]
}

macro createStringDone location
{
	 mov [location+0],'D'
	 mov [location+1],'o'
	 mov [location+2],'n'
	 mov [location+3],'e'
	 mov [location+4],0
	 lea rax,[location]
}

macro createStringError location
{
	 mov [location+0],'E'
	 mov [location+1],'r'
	 mov [location+2],'r'
	 mov [location+3],'o'
	 mov [location+4],'r'
	 mov [location+5],0
	 lea rax,[location]
}

macro createStringStartingHyperion location
{
	 mov [location+00],'H'
	 mov [location+01],'y'
	 mov [location+02],'p'
	 mov [location+03],'e'
	 mov [location+04],'r'
	 mov [location+05],'i'
	 mov [location+06],'o'
	 mov [location+07],'n'
	 mov [location+08],' '
	 mov [location+09],'L'
	 mov [location+10],'o'
	 mov [location+11],'g'
	 mov [location+12],'f'
	 mov [location+13],'i'
	 mov [location+14],'l'
	 mov [location+15],'e'
	 mov [location+16],13
	 mov [location+17],10
	 mov [location+18],0
	 lea rax,[location]
}

macro createStringStartingHyperionLines location
{
	 mov [location+00],'-'
	 mov [location+01],'-'
	 mov [location+02],'-'
	 mov [location+03],'-'
	 mov [location+04],'-'
	 mov [location+05],'-'
	 mov [location+06],'-'
	 mov [location+07],'-'
	 mov [location+08],'-'
	 mov [location+09],'-'
	 mov [location+10],'-'
	 mov [location+11],'-'
	 mov [location+12],'-'
	 mov [location+13],'-'
	 mov [location+14],'-'
	 mov [location+15],'-'
	 mov [location+16],13
	 mov [location+17],10
	 mov [location+18],0
	 lea rax,[location]
}

macro createStringLogTxt location
{
	 mov [location+0],'l'
	 mov [location+1],'o'
	 mov [location+2],'g'
	 mov [location+3],'.'
	 mov [location+4],'t'
	 mov [location+5],'x'
	 mov [location+6],'t'
	 mov [location+7],0
	 lea rax,[location]
}

;writes a string and a newline to the logfile
macro writeWithNewLine char_sequence, char_buffer, error_exit{
	char_sequence char_buffer
	lea rax,[str1]
	fastcall writeLog_, rax
	test rax,rax
	jz error_exit
	fastcall writeNewLineToLog_
	test rax,rax
	jz error_exit
}

;write a string to the logfile
macro writeLog content, error_exit{
	fastcall writeLog_, content
	test rax,rax
	jz error_exit
}

;delete old log file and create a new one
macro initLogFile error_exit{
	fastcall initLogFile_, error_exit
	test rax,rax
	jz error_exit
}

;write a newline into logfile
macro writeNewLineToLog error_exit{
	fastcall writeNewLineToLog_
	test rax,rax
	jz error_exit
}

;write a register value into logile
macro writeRegisterToLog value, error_exit{
	fastcall writeRegisterToLog_, value
	test rax,rax
	jz error_exit
}

;TODO: Does not really fit into architecture
macro writeSectionNameAndAddressToLog{
	lea rdi,[str1]
	mov byte [rdi+8],0
	mov rdx,[section_header]
	lea rsi,[rdx+IMAGE_SECTION_HEADER._Name]
	mov rcx,8
	mov r12, rdi
	rep movsb
	mov rdi, r12
	writeLog rdi, ls_exit_error
	writeNewLineToLog ls_exit_error
	mov rdx,[section_header]
	mov eax,[rdx+IMAGE_SECTION_HEADER.VirtualAddress]
	add rax,[image_base]
	writeRegisterToLog rax, ls_exit_error
}

;--- End Macro Section ---

;get the length of a string
proc strlen_ uses rdi rcx, string_ptr:QWORD

	 mov [string_ptr],rcx

	 mov rdi,[string_ptr]
	 sub rcx, rcx
	 sub al, al
	 not rcx
	 cld
	 repne scasb
	 not rcx
	 dec rcx
	 mov rax,rcx

	 ret

endp

;write <content> into log.txt
;returns false if an eerror occurs
proc writeLog_ content:QWORD

local str1[256]:BYTE, oldlogsize:QWORD, newlogsize:QWORD, contentsize:QWORD,\
      filehandle:QWORD, filemappingobject:QWORD, mapaddress:QWORD, retval:QWORD

	 mov [content],rcx

	 ;open file
	 createStringLogTxt str1
	 sub r11,r11
	 invoke CreateFile, rax, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, r11, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, r11
	 mov [retval],rax
	 test rax,rax
	 jz wl_logexit
	 mov [filehandle],rax

	 ;get logfile size
	 invoke GetFileSize, qword [filehandle], 0
	 mov [oldlogsize],rax

	 ;get size of string for logfile for concatenation
	 fastcall strlen_, qword [content]
	 mov [contentsize], rax
	 add rax,qword [oldlogsize]
	 mov [newlogsize], rax

	 ;create the file mapping
	 sub r10,r10
	 invoke CreateFileMapping, qword [filehandle], r10, PAGE_READWRITE, r10, rax, r10
	 mov [retval],rax
	 test rax, rax
	 jz wl_closelogfile
	 mov [filemappingobject],rax

	 sub r10,r10
	 invoke MapViewOfFile, rax, FILE_MAP_ALL_ACCESS, r10, r10, qword [newlogsize]
	 mov [retval],rax
	 test rax, rax
	 jz wl_closemaphandle
	 mov [mapaddress],rax

	 ;copy string into map
	 add rax,[oldlogsize]
	 mov rdi,rax
	 mov rsi,[content]
	 mov rcx,[contentsize]
	 repz movsb
	 mov [retval],1

wl_unmapfile:
	 invoke UnmapViewOfFile, qword [mapaddress]

wl_closemaphandle:
	 invoke CloseHandle, qword [filemappingobject]

wl_closelogfile:
	 invoke CloseHandle, qword [filehandle]

wl_logexit:
	 mov rax,[retval]
	 ret;

endp

;adds a <newline> to the logfile
;returns false if an error occurs
proc writeNewLineToLog_

local str1[3]:BYTE

	 lea rax,[str1]
	 mov byte [rax+0],13
	 mov byte [rax+1],10
	 mov byte [rax+2],0
	 fastcall writeLog_, rax
	 ret

endp

;returns false if an error occurs
proc writeRegisterToLog_ Value:QWORD

local str1[18]:BYTE, retval:QWORD
	 mov [Value],rcx

	 lea rax,[str1]
	 fastcall binToString_, rax, [Value]
	 fastcall writeLog_, rax
	 mov [retval],rax
	 test rax,rax
	 jz wrtl_exit
	 fastcall writeNewLineToLog_
	 mov [retval],rax
	 test rax,rax
	 jz wrtl_exit

wrtl_exit:
	 mov rax,[retval]
	 ret

endp

;converts <bin> into an 8 byte string and stores it <buffer>
proc binToString_ buffer:QWORD, bin:QWORD
	 mov [buffer],rcx
	 mov [bin], rdx

	 mov r10,[bin]
	 mov rcx,16
bts_next_byte:
	 mov rax,r10
	 and rax,0000000fh
	 cmp rax,9
	 jg bts_add_55
bts_add_48:
	 add rax,48
	 jmp bts_store_bin
bts_add_55:
	 add rax,55
bts_store_bin:
	 dec rcx
	 mov rdx,[buffer]
	 mov byte [rcx+rdx],al
	 test rcx,rcx
	 jz bts_finished_conversion
	 shr r10,4
	 jmp bts_next_byte

bts_finished_conversion:
	 mov rax,[buffer]
	 mov byte [rax+16],0
	 ret
endp

;Write initial message into logfile
proc initLogFile_

local str1[256]:BYTE

	createStringLogTxt str1
	invoke DeleteFile, rax

	createStringStartingHyperionLines str1
	fastcall writeLog_, rax
	test rax,rax
	jz ilf_exit_error

	createStringStartingHyperion str1
	fastcall writeLog_, rax
	test rax,rax
	jz ilf_exit_error

	createStringStartingHyperionLines str1
	fastcall writeLog_, rax
	test rax,rax
	jz ilf_exit_error

	fastcall writeNewLineToLog_
	test rax,rax
	jz ilf_exit_error

ilf_exit_success:
	mov rax,1
	ret

ilf_exit_error:
	sub rax,rax
	ret

endp