#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <inttypes.h>

#include "hyperion.h"

extern BOOL display_verbose;

int main(int argc, char *argv[]){
        if(argc<3) {
                printf("Hyperion PE-Crypter\n");
                printf("Version 2.3.1 by Christian Ammann\n");
                printf("Http://www.phobosys.de/hyperion\n");
                printf("\n");
                printf("Usage: hyperion.exe <options> <infile> <outfile>\n");
                printf("List of available options:\n");
                printf("  -k <size> \t Length of random AES key in bytes.\n");
                printf("            \t Default value is 6.\n");
                printf("  -s <size> \t Each byte of the key has a range between\n");
                printf("            \t 0 and <size-1>. Default value is 4.\n");
                printf("  -l, --logile \t The packed executable generates a log.txt\n");
                printf("          \t on startup for debugging purpose\n");
                printf("  -v, --verbose\t Print verbose informations while running.\n");
                return EXIT_SUCCESS;
        }

        //command line options
        unsigned int key_length = 6;
        unsigned int key_space = 4;
        BOOL create_log = FALSE;

        char* infile_name = 0;
        char* output_name = 0;

        //parse commandline parameters
        for(int i=1; i<argc; i++) {
                if(i==argc-2) {
                        infile_name = argv[i];
                }
                else if(i==argc-1) {
                        output_name = argv[i];
                }
                else if(!strcmp(argv[i], "-k")) {
                        i++;
                        key_length = (unsigned int) strtol(argv[i], NULL, 10);
                }
                else if(!strcmp(argv[i], "-s")) {
                        i++;
                        key_space = (unsigned int) strtol(argv[i], NULL, 10);
                }
                else if(!strcmp(argv[i], "-l") || !strcmp(argv[i], "--logfile")) {
                        create_log = TRUE;
                }
                else if(!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
                        display_verbose = TRUE;
                }
                else{
                        fprintf(stderr, "Error: Invalid parameter");
                        return EXIT_FAILURE;
                }
        }

        //check whether specified parameters are valid
        if(key_length > 16 || key_length<1) {
                fprintf(stderr, "Key length has to be a value between 1 and 16\n");
                return EXIT_FAILURE;
        }
        if(key_space > 255 || key_space<2) {
                fprintf(stderr, "Key space has to be a value between 2 and 255\n");
                return EXIT_FAILURE;
        }

        //open input file
        verbose("\n");
        verbose(" -------------------------------\n");
        verbose("| Stage 1: Analyzing input file |\n");
        verbose(" -------------------------------\n");
        verbose("\n");
        struct OpenFile open_file;
        if(!fileToMem(infile_name, &open_file)) {
                return EXIT_FAILURE;
        }

        //check whether it's a valid executable and collect data
        struct CoffHeader* coff_header = getCoffHeader(&open_file);
        if(!coff_header) {
                goto error;
        }
        if(!isExecutable(coff_header)) {
                goto error;
        }

        //we need these later when we generate the asm code
        struct PEData pe_data;
        pe_data.ImageBase32 = 0;
        pe_data.ImageBase64 = 0;
        const char* container_directory;

        BOOL pe32 = isPE32(coff_header);
        int idd_size = 0;
        struct ImageDataDirectory* idd = NULL;
        if(pe32) {
                verbose("Found 32 bit binary\n");
                struct OptionalStandardHeader32* osh32 = getOSH32(coff_header);
                struct OptionalWindowsHeader32* owh32 = getOWH32(osh32);
                verbose("Image base is 0x%x\n", owh32->ImageBase);
                verbose("Image size is 0x%x\n", owh32->SizeOfImage);
                pe_data.ImageBase32 = owh32->ImageBase;
                pe_data.SizeOfImage = owh32->SizeOfImage;
                container_directory = CONTAINER32_DIR;
                pe_data.GuiApplication = isGuiApplication(owh32->Subsystem);
                idd = getIDD32(owh32);
                idd_size = owh32->NumberOfRvaAndSizes;
        }
        else{
                verbose("Found 64 bit binary\n");
                struct OptionalStandardHeader64* osh64 = getOSH64(coff_header);
                struct OptionalWindowsHeader64* owh64 = getOWH64(osh64);
                verbose("Image base is 0x%" PRIx64 "\n", owh64->ImageBase);
                verbose("Image size is 0x%" PRIx64 "\n", owh64->SizeOfImage);
                pe_data.ImageBase64 = owh64->ImageBase;
                pe_data.SizeOfImage = owh64->SizeOfImage;
                container_directory = CONTAINER64_DIR;
                pe_data.GuiApplication = isGuiApplication(owh64->Subsystem);
                idd = getIDD64(owh64);
                idd_size = owh64->NumberOfRvaAndSizes;
        }

        //abort if input is a .NET executable
        if(idd_size >= CLR_RUNTIME_HEADER_INDEX){
            uint32_t va = idd[CLR_RUNTIME_HEADER_INDEX].VirtualAddress;
            uint32_t size= idd[CLR_RUNTIME_HEADER_INDEX].Size;

            if(va != 0 && size != 0){
                fprintf(stderr, "Aborting because input file seems to be a .NET executable\n");
                fprintf(stderr, "See \"Encryption of .NET Executables\" on nullsecurity.net for details\n");
                goto error;
            }
        }

        //create decryption stub
        verbose("\n");
        verbose(" -------------------------------\n");
        verbose("| Stage 2: Generating ASM files |\n");
        verbose(" -------------------------------\n");
        verbose("\n");

        //generates something like: format PE console 4.0 at IMAGE_BASE
        if(!fasmHeader(pe_data.GuiApplication, !pe32))
        {
                goto error;
        }

        //encrypt input file and create fasm array
        if(!fasmEncryptOutput(container_directory, &open_file, key_length,
                              key_space))
        {
                goto error;
        }

        //create image base asm representation and write it to IMAGE_BASE_INC
        if(!fasmDefine(container_directory, IMAGE_BASE_FILENAME,
                       IMAGE_BASE_LABEL,
                       pe32 ? pe_data.ImageBase32 : pe_data.ImageBase64,
                       FALSE))
        {
                goto error;
        }
        //create image size asm representation and write it to IMAGE_SIZE_INC
        if(!fasmDefine(container_directory, IMAGE_SIZE_FILENAME,
                       IMAGE_SIZE_LABEL, pe_data.SizeOfImage, FALSE))
        {
                goto error;
        }

        //store aes key length and space in include file
        if(!fasmDefine(container_directory, KEY_SIZE_FILENAME,
                       REAL_KEY_SIZE_LABEL, key_length, FALSE))
        {
                goto error;
        }
        if(!fasmDefine(container_directory, KEY_SIZE_FILENAME,
                       REAL_KEY_RANGE_LABEL, key_space, TRUE))
        {
                goto error;
        }

        //enable/disable crypter log meachanism
        if(create_log && !fasmInclude(container_directory, LOGFILE_SELECT_FILENAME,
                                      LOG_ENABLE_FILENAME, FALSE)) {
                goto error;
        }
        else if(!create_log && !fasmInclude(container_directory,
                                            LOGFILE_SELECT_FILENAME,
                                            LOG_DISABLE_FILENAME, FALSE)) {
                goto error;
        }

        //activate aes decryption payload
        decryptAES(pe32);

        //get current directory
        char current_directory[MAX_CHAR_SIZE];
        if(!GetCurrentDirectory(MAX_CHAR_SIZE, current_directory)) {
                fprintf(stderr, "Could not receive current directory\n");
                goto error;
        }

        //start fasm to generate a packed executable
        verbose("\n");
        verbose(" --------------------------------\n");
        verbose("| Stage 3: Generating Executable |\n");
        verbose(" --------------------------------\n");
        verbose("\n");
        char cmd_line[MAX_CHAR_SIZE];
        cmd_line[0] = 0;
        strlcat(cmd_line, FASM_EXECUTABLE_FILENAME, MAX_CHAR_SIZE);
        strlcat(cmd_line, " ", MAX_CHAR_SIZE);
        strlcat(cmd_line, (pe32 ? CONTAINER32_DIR : CONTAINER64_DIR), MAX_CHAR_SIZE);
        strlcat(cmd_line, CONTAINER_MAIN_FILENAME, MAX_CHAR_SIZE);
        strlcat(cmd_line, " ", MAX_CHAR_SIZE);
        strlcat(cmd_line, output_name, MAX_CHAR_SIZE);

        //init necessary structs for createprocess
        PROCESS_INFORMATION process_info;
        STARTUPINFO startup_info;
        ZeroMemory( &startup_info, sizeof(startup_info) );
        startup_info.cb = sizeof(startup_info);

        //redirect stdin to somewhere else
        if(!display_verbose) {
                HANDLE g_hChildStd_OUT_Rd = NULL;
                HANDLE g_hChildStd_OUT_Wr = NULL;
                SECURITY_ATTRIBUTES saAttr;
                saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
                saAttr.bInheritHandle = TRUE;
                saAttr.lpSecurityDescriptor = NULL;

                BOOL cp_ret = CreatePipe(&g_hChildStd_OUT_Rd,
                                         &g_hChildStd_OUT_Wr, &saAttr, 0);
                BOOL shi_ret = SetHandleInformation(g_hChildStd_OUT_Rd,
                                                    HANDLE_FLAG_INHERIT, 0);
                if ( !cp_ret || !shi_ret ) {
                        fprintf(stderr, "Warning: Couldn't create pipe for FASM output\n");
                }
                else{
                        startup_info.hStdError = g_hChildStd_OUT_Wr;
                        startup_info.hStdOutput = g_hChildStd_OUT_Wr;
                        startup_info.dwFlags |= STARTF_USESTDHANDLES;
                }
        }

        verbose("Starting FASM with the following parameters:\n");
        verbose("Commandline: %s\n", cmd_line);
        verbose("FASM Working Directory: %s\n", current_directory);
        if(!CreateProcess(FASM_EXECUTABLE_FILENAME, cmd_line, 0, 0,
                          FALSE, 0, 0, current_directory, &startup_info,
                          &process_info)) {
                fprintf(stderr, "Could not start fasm.exe\n");
                fprintf(stderr, "Error Code: 0x%x\n", GetLastError());
                goto error;
        }

        //wait for process to terminate
        WaitForSingleObject( process_info.hProcess, INFINITE );

        // Get the exit code
        DWORD exitCode = 0;
        GetExitCodeProcess(process_info.hProcess, &exitCode);
        if(exitCode!=0 && !display_verbose){
            fprintf(stderr, "FASM returned an error, see --verbose for details\n");
        }
        else if(exitCode==0 && display_verbose){
            printf("\nDone :-)\n");
        }

        //warning for deprecation
        if(pe32) {
            printf("############################################\n");
            printf("# Warning: You encrypted a 32 bit PE file. #\n");
            printf("# 32 bit support is not maintained anymore #\n");
            printf("# since release 2.3                        #\n");
            printf("############################################\n");
        }

        // Close the handles.
        CloseHandle( process_info.hProcess );
        CloseHandle( process_info.hThread );

        free(open_file.file);
        return EXIT_SUCCESS;

error:
        free(open_file.file);
        return EXIT_FAILURE;
}
