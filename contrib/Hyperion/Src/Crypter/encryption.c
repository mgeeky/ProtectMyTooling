#include "hyperion.h"

#define CBC 0
#define CTR 0
#define ECB 1
#include <aes.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Create a simple checksum from a file which adds each of its bytes
 */
uint32_t getChecksum(unsigned char* data, unsigned int size){
        uint32_t ret = 0;
        for(unsigned int i=0; i<size; i++) {
                uint8_t current = (uint8_t) data[i];
                ret+=(uint32_t) current;
        }
        return ret;
}

/**
 * Generates a random key and encrypts the file
 */
BOOL encryptFile(uint8_t* input_file, unsigned int file_size,
                 unsigned int key_length, unsigned int key_space){
        //generate a random encryption key
        srand ( time(NULL) );
        uint8_t key[AES_KEY_SIZE];
        for(unsigned int i=0; i<AES_KEY_SIZE; i++) {
                if(i<key_length) {
                        key[i] = rand() % key_space;
                }
                else{
                        key[i] = 0;
                }
        }

        //print key to console
        verbose("Generated Encryption Key: ");
        for(int i=0; i<AES_KEY_SIZE; i++) {
                if(i==6) verbose("\n ");
                else verbose(" ");
                verbose("0x%x", (uint32_t) key[i]);
        }
        verbose("\n");

        return encryptAES(input_file, file_size, key);
}

/**
 * Encrypts the file with AES. Returns false if an error occured
 * (e.g. if the AES APIs could not been loaded).
 */
BOOL encryptAES(uint8_t* input, unsigned int size, uint8_t* key){
		int i;
		struct AES_ctx ctx;
		AES_init_ctx(&ctx, key);

		for (i = 0; i < size; i+=AES_BLOCKLEN)
		{
			AES_ECB_encrypt(&ctx, input + i);
		}
        return TRUE;
}
