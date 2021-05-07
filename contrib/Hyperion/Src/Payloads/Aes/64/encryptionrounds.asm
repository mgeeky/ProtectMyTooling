;uses the generated round keys to encrypt an aes block
proc encryptionRounds uses rbx r12 r13, encryption_ptr:QWORD,\
     roundkeys_ptr:QWORD, sbox_ptr:QWORD, mul2_table_ptr:QWORD, \
     mul3_table_ptr:QWORD

    mov [encryption_ptr],rcx
    mov [roundkeys_ptr],rdx
    mov [sbox_ptr],r8
    mov [mul2_table_ptr],r9

    ;roundkey and encryption in eax and ebx
    mov r12,[roundkeys_ptr]
    mov rbx,[encryption_ptr]

    ;initial round
    fastcall addRoundKey, rbx, r12

    ;main round
    add r12,BLOCK_SIZE
    mov r13,ENCRYPTION_ROUNDS - 1
er_main:
    fastcall subBlockBytes, rbx, [sbox_ptr]
    fastcall shiftRows, rbx
    fastcall mixColumns23, rbx, [mul2_table_ptr], [mul3_table_ptr]
    fastcall addRoundKey, rbx, r12

    add r12,BLOCK_SIZE
    dec r13
    jnz er_main

    ;final round
    fastcall subBlockBytes, rbx, [sbox_ptr]
    fastcall shiftRows, rbx
    fastcall addRoundKey, rbx, r12

    ret
endp

;mix columns operation is a column matrix
;multiplication
proc mixColumns23 uses rbx r12, data_ptr:QWORD, mul2_table_ptr:QWORD,\
     mul3_table_ptr:QWORD

    local current_column:DWORD
    mov [data_ptr],rcx
    mov [mul2_table_ptr],rdx
    mov [mul3_table_ptr],r8
	
    mov rdx, [data_ptr]
    mov r12,4
mixColumns23_loop:
    ;element 3
    mov eax, [rdx]
    bswap eax
    mov cl, al
    shr eax,8
    xor cl, al
    shr eax,8
    mov rbx, [mul3_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul2_table_ptr]
    xlatb
    xor cl, al
    mov [current_column], ecx
    ;element 2
    mov eax, [rdx]
    bswap eax
    mov cl, al
    shr eax, 8
    mov rbx, [mul3_table_ptr]
    xlatb
    xor cl, al
    shr eax, 8
    mov rbx, [mul2_table_ptr]
    xlatb
    xor cl, al
    shr eax, 8
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 1
    mov eax, [rdx]
    bswap eax
    mov rbx, [mul3_table_ptr]
    xlatb
    mov cl, al
    shr eax, 8
    mov rbx, [mul2_table_ptr]
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
    mov eax, [rdx]
    bswap eax
    mov rbx, [mul2_table_ptr]
    xlatb
    mov cl, al
    shr eax, 8
    xor cl, al
    shr eax, 8
    xor cl, al
    shr eax, 8
    mov rbx, [mul3_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    ;finished, store it
    bswap eax
    mov [rdx], eax
    add rdx, COLUMN_SIZE

    dec r12
    jnz mixColumns23_loop

    ret

endp

proc loadRow uses rsi, data_ptr:QWORD

   mov [data_ptr], rcx

   mov rsi, [data_ptr]
   xor rax, rax
   lodsb
   shl eax, 8
   add rsi, 3
   lodsb
   shl eax, 8
   add rsi, 3
   lodsb
   shl eax, 8
   add rsi, 3
   lodsb

   ret

endp

proc storeRow uses rdi, row:QWORD, data_ptr:QWORD

   mov [row], rcx
   mov [data_ptr], rdx

   mov rdi, [data_ptr]
   mov rcx, [row]
   mov eax, ecx
   rol eax, 8

   stosb
   rol eax, 8
   add rdi, 3
   stosb
   rol eax, 8
   add rdi, 3
   stosb
   rol eax, 8
   add rdi, 3
   stosb

   ret

endp

proc shiftRows uses rbx, data_ptr:DWORD

    mov [data_ptr], rcx

    mov rbx, [data_ptr]
    inc rbx
    fastcall loadRow, rbx
    rol eax, 8
    fastcall storeRow, rax, rbx
    inc rbx
    fastcall loadRow, rbx
    rol eax, 16
    fastcall storeRow, rax, rbx
    inc rbx
    fastcall loadRow, rbx
    rol eax, 24
    fastcall storeRow, rax, rbx

    ret

endp

;xors the data with the round key and stores result
;in data
proc addRoundKey data_ptr:QWORD, round_key_ptr:QWORD

	mov [data_ptr], rcx
	mov [round_key_ptr], rdx

	mov rcx, [data_ptr]
	mov rdx, [round_key_ptr]
    mov r8, [rcx]
    xor r8, [rdx]
    mov [rcx], r8
    add rcx, COLUMN_SIZE*2
    add rdx, COLUMN_SIZE*2
    mov r8, [rcx]
    xor r8, [rdx]
    mov [rcx], r8
    ret

endp

;substitute aes block with s-box
proc subBlockBytes uses rbx r12, data_ptr:QWORD, sbox_ptr:QWORD

	mov [data_ptr], rcx
	mov [sbox_ptr], rdx 

    mov rbx, [sbox_ptr]
	mov rcx, [data_ptr]
    mov r12, 2
subBlockBytes_loop:
    mov rax, [rcx] ;data_ptr
    xlatb
    ror rax, 8
    xlatb
    ror rax, 8
    xlatb
    ror rax, 8
    xlatb
    ror rax, 8
    xlatb
    ror rax, 8
    xlatb
    ror rax, 8
    xlatb
    ror rax, 8
    xlatb
    ror rax, 8
    mov [rcx], rax
    add rcx, COLUMN_SIZE*2

    dec r12
    jnz subBlockBytes_loop

    ret

endp
