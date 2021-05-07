#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "hyperion.h"

BOOL isGuiApplication(uint16_t subsystem){
    switch(subsystem){
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: 
            verbose("Found gui flag in binary\n");
            return TRUE;
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: 
            verbose("Found commandline flag in binary\n");
            return FALSE;
            break;
        default:
            printf("Unknown subsystem 0x%x, handling binary as gui application\n");
            return TRUE;
            break;
    }
}

BOOL isExecutable(struct CoffHeader* coff_header){
        if (coff_header==0) {
                return FALSE;
        }
        if (!(coff_header->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
                fprintf(stderr, "File is not an executable image, aborting...\n");
                return FALSE;
        }
        if (coff_header->Characteristics & IMAGE_FILE_DLL) {
                fprintf(stderr, "File is a dll, aborting...\n");
                return FALSE;
        }
        return TRUE;
}

BOOL isPE32(struct CoffHeader* coff_header){
        struct OptionalStandardHeader32* ret
                = (struct OptionalStandardHeader32*)
                  ((char*) coff_header + sizeof(struct CoffHeader));
        if (ret->Magic == OPTIONAL_HEADER_MAGIC_PE32) {
                return TRUE;
        }
        else{
                return FALSE;
        }
}

/**
 * Checks whether file has a correct MZ and PE signature.
 * Returns the offset to the coff file header if signatures
 * are correct, otherwise a null pointer.
 */
struct CoffHeader* getCoffHeader(struct OpenFile* input_file){
        if(sizeof(struct MZHeader) > input_file->size) {
                fprintf(stderr, "No valid executable\n");
                return NULL;
        }

        //check MZ signature
        struct MZHeader* mz = (struct MZHeader*) input_file->file;
        if(memcmp(mz->signature, MZ_SIGNATURE, MZ_SIGNATURE_SIZE != 0)) {
                fprintf(stderr, "No valid MZ Signature\n");
                return NULL;
        }
        verbose("Found valid MZ signature\n");

        //get PE header
        verbose("Found pointer to PE Header: 0x%x\n", mz->ptrPE);
        //ptrPe out of bounds?
        if(input_file->file + mz->ptrPE >= input_file->file + input_file->size) {
                fprintf(stderr, "Pointer to PE in MZ header points to nowhere\n");
                return NULL;
        }
        //no ptrPE?
        if (!(mz->ptrPE)) {
                fprintf(stderr, "Pointer to PE in MZ header is a null pointer\n");
                return NULL;
        }

        uint8_t* pe_sig = mz->ptrPE + (uint8_t*) input_file->file;
        if(memcmp(pe_sig, PE_SIGNATURE, PE_SIGNATURE_SIZE) != 0) {
                fprintf(stderr, "No valid PE signature found\n");
                return NULL;
        }
        verbose("Found valid PE signature\n");

        return (struct CoffHeader*) (input_file->file + mz->ptrPE + PE_SIGNATURE_SIZE);
}
