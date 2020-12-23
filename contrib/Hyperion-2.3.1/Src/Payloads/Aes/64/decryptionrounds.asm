;uses the generated round keys to decrypt an aes block
proc decryptionRounds uses rbx r12, decryption_ptr:QWORD,\
     roundkeys_ptr:QWORD, inverse_sbox_ptr:QWORD, mul9_table_ptr:QWORD, \
     mul11_table_ptr:QWORD, mul13_table_ptr:QWORD,\
     mul14_table_ptr:QWORD

    mov [decryption_ptr], rcx
    mov [roundkeys_ptr], rdx
    mov [inverse_sbox_ptr], r8
    mov [mul9_table_ptr], r9

    ;roundkey and decryption in eax and ebx
    mov r12, [roundkeys_ptr]
    add r12, BLOCK_SIZE*ENCRYPTION_ROUNDS
    mov rbx, [decryption_ptr]

    ;final round
    fastcall addRoundKey, rbx, r12
    fastcall inverseShiftRows, rbx
    fastcall subBlockBytes, rbx, [inverse_sbox_ptr]
    sub r12,BLOCK_SIZE

    ;main round
dr_main:
    fastcall addRoundKey, rbx, r12
    fastcall mixColumns9111314, rbx, [mul9_table_ptr], [mul11_table_ptr],\
	    [mul13_table_ptr], [mul14_table_ptr]
    fastcall inverseShiftRows, rbx
    fastcall subBlockBytes, rbx, [inverse_sbox_ptr]
    sub r12, BLOCK_SIZE
    cmp r12, [roundkeys_ptr]
    jne dr_main

    ;initial_round
    fastcall addRoundKey, rbx, r12
    ret
endp

;mix columns operation is a column matrix
;multiplication
proc mixColumns9111314 uses r12 rbx, data_ptr:QWORD, mul9_table_ptr:QWORD,\
     mul11_table_ptr:QWORD, mul13_table_ptr:QWORD, mul14_table_ptr:QWORD

     local current_column:DWORD

    mov [data_ptr],rcx
    mov [mul9_table_ptr], rdx
    mov [mul11_table_ptr], r8
    mov [mul13_table_ptr], r9

    mov rdx, [data_ptr]
    mov r12,4

mixColumns9111314_loop:
    ;element 3
    mov eax, [rdx]
    bswap eax
    mov rbx, [mul9_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov rbx, [mul13_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul11_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul14_table_ptr]
    xlatb
    xor cl, al
    mov [current_column], ecx
    ;element 2
    mov eax, [rdx]
    bswap eax
    mov rbx, [mul13_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov rbx, [mul11_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul14_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul9_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 1
    mov eax, [rdx]
    bswap eax
    mov rbx, [mul11_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov rbx, [mul14_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul9_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul13_table_ptr]
    xlatb
    xor cl, al
    mov eax, [current_column]
    shl eax, 8
    mov al, cl
    mov [current_column], eax
    ;element 0
    mov eax, [rdx]
    bswap eax
    mov rbx, [mul14_table_ptr]
    xlatb
    mov cl, al
    shr eax,8
    mov rbx, [mul9_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul13_table_ptr]
    xlatb
    xor cl, al
    shr eax,8
    mov rbx, [mul11_table_ptr]
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
    jnz mixColumns9111314_loop

    ret
endp

;reverse shift operation for decryption
proc inverseShiftRows uses rbx, data_ptr:QWORD

    mov [data_ptr], rcx

    mov rbx, [data_ptr]
    inc rbx
    fastcall loadRow, rbx
    rol eax, 24
    fastcall storeRow, rax, rbx
    inc rbx
    fastcall loadRow, rbx
    rol eax, 16
    fastcall storeRow, rax, rbx
    inc rbx
    fastcall loadRow, rbx
    rol eax, 8
    fastcall storeRow, rax, rbx

    ret

endp
