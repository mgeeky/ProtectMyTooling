#include "hyperion.h"

#include <stdio.h>
#include <stdlib.h>

BOOL fileToMem(const char* file_name, struct OpenFile* open_file){
        //open input file
        verbose("Opening %s\n", file_name);

        FILE* f1 = fopen(file_name,"rb");
        if(f1 == NULL) {
                fprintf(stderr, "Could not open %s\n", file_name);
                return FALSE;
        }

        /* obtain file size: */
        fseek (f1, 0, SEEK_END);
        int f1_size = ftell (f1);
        rewind (f1);

        /* copy file to memory */
        unsigned char* file1 = (unsigned char*) malloc(f1_size);
        if(file1 == NULL) {
                fprintf(stderr, "Could not allocate memory for input file size %d\n", f1_size);
                return FALSE;
        }
        size_t read_bytes = fread((void*) file1, 1, f1_size, f1);
        if(read_bytes != f1_size) {
                fprintf(stderr, "Could not copy input file into memory: %d %d\n",
                        read_bytes, f1_size);
                fclose(f1);
                return FALSE;
        }

        /* close input files */
        fclose(f1);

        //file opened successfully
        open_file->file = file1;
        open_file->size = f1_size;
        verbose("Successfully copied file to memory location: 0x%x\n",
                (unsigned long int) open_file->file);
        return TRUE;
}

BOOL memToFile(const char* file_name, char* content, unsigned long size,
               BOOL append){
        FILE* f1 = NULL;
        if(!append) {
                f1 = fopen(file_name,"wb");
        }
        else{
                f1 = fopen(file_name,"ab");
        }

        if(f1 == NULL) {
                fprintf(stderr, "Could not open %s\n", file_name);
                return FALSE;
        }

        size_t bytes_written = fwrite(content, sizeof(char), size, f1);
        if(bytes_written != size) {
                fclose(f1);
                fprintf(stderr, "Could not copy memory to output file: %d %d\n",
                        bytes_written, size);
                return FALSE;
        }

        /* close input files */
        fclose(f1);
        return TRUE;
}
