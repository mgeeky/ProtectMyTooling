#include "hyperion.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

/**
 * Calculates the checksum of input_file, encrypts checksum+input_file,
 * converts checksum+input_file to a FASM byte array and writes it to filename.
 * Furthermore, a FASM include is generated which contains the previously
 * calculated file size.
 */
BOOL fasmEncryptOutput(const char* output_dir, struct OpenFile* input_file,
                       unsigned int key_length, unsigned int key_space){
        //calculate size the size of encrypted input file and create a FASM include
        unsigned int encrypted_size = input_file->size + CHECKSUM_SIZE;
        encrypted_size+=AES_BLOCK_SIZE - (encrypted_size%AES_BLOCK_SIZE);
        verbose("Input file size + Checksum: 0x%x\n", input_file->size + CHECKSUM_SIZE);
        verbose("Rounded up to a multiple of key size: 0x%x\n", encrypted_size);
        if(!fasmDefine(output_dir, INFILE_SIZE_FILENAME, INFILE_SIZE_LABEL,
                       encrypted_size, FALSE)) {
                return FALSE;
        }

        //allocate memory for checksum+input_file
        uint8_t* encrypted_input = calloc(encrypted_size, sizeof(uint8_t));
        if(!encrypted_input) {
                fprintf(stderr, "Could not allocate memory for encrypted input file\n");
                return FALSE;
        }
        memcpy(&(encrypted_input[CHECKSUM_SIZE]), input_file->file, input_file->size);
        uint32_t checksum = getChecksum(input_file->file, input_file->size);
        verbose("Generated checksum: 0x%x\n", checksum);
        *((uint32_t*) encrypted_input) = checksum;

        //encrypt checksum+input_file
        if(!encryptFile(encrypted_input, encrypted_size, key_length, key_space)) {
                return FALSE;
        }

        /*
         * fasm byte array which contains the encrypted file. Size is calculated:
         * 3 for initial "db ", 61 per 10 encrypted bytes, 2 additional lines
         * just to be save ;)
         */
        unsigned int fasm_output_size = 3 + (encrypted_size/10)*63 + 2*63;
        char* fasm_output = calloc(fasm_output_size, sizeof(char));
        if(!fasm_output) {
                fprintf(stderr, "Could not allocate memory for encrypted fasm array\n");
                free(encrypted_input);
                return FALSE;
        }

        strlcat(fasm_output, "db ", fasm_output_size);
        unsigned int fasm_output_pointer = strlen(fasm_output);
        for(unsigned int i=0; i<encrypted_size; i++) {
                char sin[MAX_CHAR_SIZE];
                sin[0] = 0;
                sprintf(sin, "0x%x", encrypted_input[i]);

                if(i!=(encrypted_size-1)){
                        strlcat(sin, ", ", sizeof(sin));
                }
                if(i!=0 && i%10==0){
                        strlcat(sin, "\\\r\n", sizeof(sin));
                }

                //strcat(fasm_output, sin);
                memcpy(&(fasm_output[fasm_output_pointer]), sin, strlen(sin)+1);
                fasm_output_pointer+=strlen(sin);
        }
        free(encrypted_input);

        char infile_array_filename[MAX_CHAR_SIZE];
        infile_array_filename[0] = 0;
        strlcat(infile_array_filename, output_dir, MAX_CHAR_SIZE);
        strlcat(infile_array_filename, INFILE_ARRAY_FILENAME, MAX_CHAR_SIZE);
        if(!memToFile(infile_array_filename, fasm_output, strlen(fasm_output),
                      FALSE)) {
                fprintf(stderr, "Could not write into %s\n", infile_array_filename);
                free(fasm_output);
                return FALSE;
        }
        else{
                verbose("Written encrypted input file as FASM array to:\n %s\n",
                        infile_array_filename);
                free(fasm_output);
                return TRUE;
        }
}

/**
 * Declares a FASM constant "<label> equ <value>" and stores the result
 * in an output file
 */
BOOL fasmDefine(const char* output_dir, const char* file_name,
                const char* label, uint64_t value, BOOL append){
        //create output
        char output_buffer[MAX_CHAR_SIZE];
        output_buffer[0] = 0;
        strlcat(output_buffer, label, MAX_CHAR_SIZE);
        strlcat(output_buffer, " equ 0x", MAX_CHAR_SIZE);
        char hex_value[MAX_CHAR_SIZE];
        hex_value[0] = 0;
        snprintf(hex_value, MAX_CHAR_SIZE, "%I64x", value);
        strlcat(output_buffer, hex_value, MAX_CHAR_SIZE);
        strlcat(output_buffer, "\r\n", MAX_CHAR_SIZE);

        //write output to file
        char full_output_name[MAX_CHAR_SIZE];
        full_output_name[0] = 0;
        strlcat(full_output_name, output_dir, MAX_CHAR_SIZE);
        strlcat(full_output_name, file_name, MAX_CHAR_SIZE);
        if(!memToFile(full_output_name, output_buffer, strlen(output_buffer),
                      append)) {
                fprintf(stderr, "Could not write include file %s\n",
                        full_output_name, append);
                return FALSE;
        }
        else{
                verbose("%s written to %s\n", output_buffer, full_output_name);
                return TRUE;
        }
}

/**
 * Declares a FASM include "include <label>" and stores the result
 * in an output file
 */
BOOL fasmInclude(const char* output_dir, const char* file_name,
                 const char* label, BOOL append){
        //create output
        char output_buffer[MAX_CHAR_SIZE];
        output_buffer[0] = 0;
        strlcat(output_buffer, "include '", MAX_CHAR_SIZE);
        strlcat(output_buffer, label, MAX_CHAR_SIZE);
        strlcat(output_buffer, "'\r\n", MAX_CHAR_SIZE);

        //write output to file
        char full_output_name[MAX_CHAR_SIZE];
        full_output_name[0] = 0;
        strlcat(full_output_name, output_dir, MAX_CHAR_SIZE);
        strlcat(full_output_name, file_name, MAX_CHAR_SIZE);
        if(!memToFile(full_output_name, output_buffer, strlen(output_buffer),
                      append)) {
                fprintf(stderr, "Could not write include file %s\n",
                        full_output_name, append);
                return FALSE;
        }
        else{
                verbose("%s written to %s\n", output_buffer, full_output_name);
                return TRUE;
        }
}

BOOL fasmHeader(BOOL guiApp, BOOL pe32plus){
        //create output
        char output_buffer[MAX_CHAR_SIZE];
        output_buffer[0] = 0;
        if(pe32plus){
            strlcat(output_buffer, "format PE64 ", MAX_CHAR_SIZE);
        }
        else{
            strlcat(output_buffer, "format PE ", MAX_CHAR_SIZE);
        }

        if(guiApp){
            strlcat(output_buffer, "GUI ", MAX_CHAR_SIZE);
        }
        else{
            strlcat(output_buffer, "console ", MAX_CHAR_SIZE);
        }

        if(pe32plus){
            strlcat(output_buffer, "5.0 at IMAGE_BASE", MAX_CHAR_SIZE);
        }
        else{
            strlcat(output_buffer, "4.0 at IMAGE_BASE", MAX_CHAR_SIZE);
        }

        //write output to file
        char full_output_name[MAX_CHAR_SIZE];
        full_output_name[0] = 0;
        strlcat(full_output_name, (pe32plus ? CONTAINER64_DIR : CONTAINER32_DIR), 
                MAX_CHAR_SIZE);
        strlcat(full_output_name, MAIN_PROLOG_FILENAME, MAX_CHAR_SIZE);
        if(!memToFile(full_output_name, output_buffer, strlen(output_buffer),
                      FALSE)) {
                fprintf(stderr, "Could not write include file %s\n",
                        full_output_name);
                return FALSE;
        }
        else{
                verbose("%s written to %s\n", output_buffer, full_output_name);
                return TRUE;
        }
}
