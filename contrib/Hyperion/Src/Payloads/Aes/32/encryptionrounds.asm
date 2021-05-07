;uses the generated round keys to encrypt an aes block
proc encryptionRounds encryption_ptr:DWORD,\
     roundkeys_ptr:DWORD, sbox_ptr:DWORD, mul2_table_ptr:DWORD, \
     mul3_table_ptr:DWORD
    pushad

    ;roundkey and encryption in eax and ebx
    mov eax,[roundkeys_ptr]
    mov ebx,[encryption_ptr]

    ;initial round
    stdcall addRoundKey, ebx, eax

    ;main round
    add eax,BLOCK_SIZE
    mov ecx,ENCRYPTION_ROUNDS - 1
er_main:
    stdcall subBlockBytes, ebx, [sbox_ptr]
    stdcall shiftRows, ebx
    stdcall mixColumns23, ebx, [mul2_table_ptr], [mul3_table_ptr]
    stdcall addRoundKey, ebx, eax

    add eax,BLOCK_SIZE
    dec ecx
    jnz er_main

    ;final round
    stdcall subBlockBytes, ebx, [sbox_ptr]
    stdcall shiftRows, ebx
    stdcall addRoundKey, ebx, eax

    popad
    ret
endp

;mix columns operation is a column matrix
;multiplication
proc mixColumns23, data_ptr:DWORD, mul2_table_ptr:DWORD,\
     mul3_table_ptr:DWORD

     local current_column:DWORD

    push edx
    push eax
    push ebx
    push ecx
    mov edx, [data_ptr]

    rept 4{
    ;element 3
    mov eax, [edx]
    bswap eax
    mov cl, al
    shr eax,8
    xor cl, al
    shr eax,8
    mov ebx, [mul3_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov ebx, [mul2_table_ptr]
    xlatb
    xor cl, al
    mov [current_column], ecx
    ;element 2
    mov eax, [edx]
    bswap eax
    mov cl, al
    shr eax, 8
    mov ebx, [mul3_table_ptr]
    xlatb
    xor cl, al
    shr eax, 8
    mov ebx, [mul2_table_ptr]
    xlatb
    xor cl, al
    shr eax, 8
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 1
    mov eax, [edx]
    bswap eax
    mov ebx, [mul3_table_ptr]
    xlatb
    mov cl, al
    shr eax, 8
    mov ebx, [mul2_table_ptr]
    xlatb
    xor cl, al
    shr eax, 8
    xor cl, al
    shr eax, 8
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 0
    mov eax, [edx]
    bswap eax
    mov ebx, [mul2_table_ptr]
    xlatb
    mov cl, al
    shr eax, 8
    xor cl, al
    shr eax, 8
    xor cl, al
    shr eax, 8
    mov ebx, [mul3_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    ;finished, store it
    bswap eax
    mov [edx], eax
    add edx, COLUMN_SIZE
    }

    pop ecx
    pop ebx
    pop eax
    pop edx
    ret

endp

proc shiftRows, data_ptr:DWORD

    push eax
    push ebx
    mov ebx,[data_ptr]

    inc ebx
    stdcall loadRow, ebx
    rol eax,8
    stdcall storeRow, eax, ebx
    inc ebx
    stdcall loadRow, ebx
    rol eax,16
    stdcall storeRow, eax, ebx
    inc ebx
    stdcall loadRow, ebx
    rol eax,24
    stdcall storeRow, eax, ebx

    pop ebx
    pop eax
    ret

endp

proc loadRow, data_ptr:DWORD

   push esi
   mov esi,[data_ptr]

   lodsb
   shl eax,8
   add esi,3
   lodsb
   shl eax,8
   add esi,3
   lodsb
   shl eax,8
   add esi,3
   lodsb

   pop esi
   ret

endp

proc storeRow, row:DWORD, data_ptr:DWORD

   push edi
   mov edi,[data_ptr]
   mov eax,[row]
   rol eax,8

   stosb
   rol eax,8
   add edi,3
   stosb
   rol eax,8
   add edi,3
   stosb
   rol eax,8
   add edi,3
   stosb

   pop edi
   ret

endp

;xors the data with the round key and stores result
;in data
proc addRoundKey data_ptr:DWORD, round_key_ptr:DWORD

    push eax
    push ebx
    push edx

    mov eax,[data_ptr]
    mov ebx,[round_key_ptr]
    rept 4{
	 mov edx,[ebx]
	 xor edx,[eax]
	 mov [eax],edx
	 add eax,COLUMN_SIZE
	 add ebx,COLUMN_SIZE
    }

    pop edx
    pop ebx
    pop eax
    ret

endp

;substitute aes block with s-box
proc subBlockBytes data_ptr:DWORD, sbox_ptr:DWORD

    push eax
    push ebx
    push edx
    mov ebx, [sbox_ptr]
    mov edx, [data_ptr]

    rept 4{
	 mov eax, [edx]
	 xlatb
	 ror eax, 8
	 xlatb
	 ror eax, 8
	 xlatb
	 ror eax, 8
	 xlatb
	 ror eax, 8
	 mov [edx], eax
	 add edx, COLUMN_SIZE
    }

    pop edx
    pop ebx
    pop eax
    ret

endp