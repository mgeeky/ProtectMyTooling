include 'sbox.asm'
include 'rcon.asm'
include 'keychain.asm'
include 'encryptionrounds.asm'
include 'decryptionrounds.asm'
include 'galois.asm'

;encrypts cleartext and stores the result at enctext
proc encAES uses rbx rsi rdi,\
     size:QWORD, cleartext_ptr:QWORD, enctext_ptr:QWORD, aeskey_ptr:QWORD

local keychain[(ENCRYPTION_ROUNDS+1)*BLOCK_SIZE]:BYTE, sbox[SBOX_SIZE]:BYTE,\
      rcon[RCON_SIZE]:BYTE, galois_mul2[GALOIS_SIZE]:BYTE,\
      galois_mul3[GALOIS_SIZE]:BYTE, mul2_table_ptr:QWORD,\
      mul3_table_ptr:QWORD, sbox_ptr:QWORD, keychain_ptr:QWORD,\
      rcon_ptr:QWORD

    mov [size],rcx
    mov [cleartext_ptr],rdx
    mov [enctext_ptr],r8
    mov [aeskey_ptr],r9
	
    ;sbox and rcon are created in memory
    ;galois lookup tables too
    lea rax,[sbox]
    mov [sbox_ptr], rax
    fastcall createSBox, rax
    lea rax,[rcon]
    mov [rcon_ptr], rax
    fastcall createRcon, rax
    lea rax,[galois_mul2]
    mov [mul2_table_ptr], rax
    lea rbx,[galois_mul3]
    mov [mul3_table_ptr], rbx
    fastcall createGaloisEncryption, rax, rbx

    ;copy the key into the round key buffer
    mov rcx, KEY_SIZE
    mov rsi, [aeskey_ptr]
    lea rdi, [keychain]
    mov [keychain_ptr], rdi
    rep movsb

    ;create the round keys
    fastcall createKeyChain, [keychain_ptr], [sbox_ptr],\
	    [rcon_ptr]

    ;copy clear text to encryption buffer
    mov rcx, [size]
    mov rsi, [cleartext_ptr]
    mov rdi, [enctext_ptr]
    rep movsb

    ;rsi == current to be encrypted block
    ;ebx == end of cleartext
    mov rsi,[enctext_ptr]
    mov rbx,rsi
    add rbx,[size]
eaes_block_loop:
    fastcall encryptionRounds, rsi, [keychain_ptr], \
	    [sbox_ptr], [mul2_table_ptr], [mul3_table_ptr]

    add rsi,BLOCK_SIZE
    cmp rsi,rbx
    jnge eaes_block_loop

    mov rax,1
    ret

endp

;decrypts cleartext and stores the result at enctext
proc decAES uses rbx rsi rdi,\
     size:QWORD, enctext_ptr:QWORD, cleartext_ptr:QWORD, aeskey_ptr:QWORD

local keychain[(ENCRYPTION_ROUNDS+1)*BLOCK_SIZE]:BYTE,\
      sbox[SBOX_SIZE]:BYTE, invert_sbox[SBOX_SIZE]:BYTE,\
      rcon[RCON_SIZE]:BYTE,\
      galois_mul9[GALOIS_SIZE]:BYTE, galois_mul11[GALOIS_SIZE]:BYTE, \
      galois_mul13[GALOIS_SIZE]:BYTE, galois_mul14[GALOIS_SIZE]:BYTE,\
      mul9_table_ptr:QWORD, mul11_table_ptr:QWORD, mul13_table_ptr:QWORD,\
      mul14_table_ptr:QWORD, sbox_ptr:QWORD, invert_sbox_ptr:QWORD,\
      keychain_ptr:QWORD, rcon_ptr:QWORD

    mov [size],rcx
    mov [enctext_ptr],rdx
    mov [cleartext_ptr],r8
    mov [aeskey_ptr],r9
	
    ;sbox, invert sbox
    ;and rcon are created in memory
    lea rax,[sbox]
    mov [sbox_ptr], rax
    fastcall createSBox, rax
    lea rax,[rcon]
    mov [rcon_ptr], rax
    fastcall createRcon, rax
    lea rax, [invert_sbox]
    mov [invert_sbox_ptr], rax
    fastcall createInvertSBox, rax

    ;create galois lookup tables for
    ;9, 11, 13 and 14
    lea rax,[galois_mul9]
    mov [mul9_table_ptr], rax
    lea rax,[galois_mul11]
    mov [mul11_table_ptr], rax
    lea rax,[galois_mul13]
    mov [mul13_table_ptr], rax
    lea rax,[galois_mul14]
    mov [mul14_table_ptr], rax
    fastcall createGaloisDecryption, [mul9_table_ptr],\
	[mul11_table_ptr], [mul13_table_ptr], [mul14_table_ptr]

    ;copy the key into the round key buffer
    mov rcx, KEY_SIZE
    mov rsi, [aeskey_ptr]
    lea rdi, [keychain]
    mov [keychain_ptr], rdi
    rep movsb

    ;create the round keys
    fastcall createKeyChain, [keychain_ptr], [sbox_ptr],\
	    [rcon_ptr]

    ;copy encrypted text to decryption buffer
    mov rcx, [size]
    mov rsi, [enctext_ptr]
    mov rdi, [cleartext_ptr]
    rep movsb

    ;rsi == current to be decrypted block
    ;ebx == end of cleartext
    mov rsi,[cleartext_ptr]
    mov rbx,rsi
    add rbx,[size]
daes_block_loop:
    fastcall decryptionRounds, rsi, [keychain_ptr],\
	    [invert_sbox_ptr], [mul9_table_ptr], [mul11_table_ptr],\
	    [mul13_table_ptr], [mul14_table_ptr]

    add rsi,BLOCK_SIZE
    cmp rsi,rbx
    jnge daes_block_loop

    mov rax,1
    ret

endp
