#ifndef __HYPERION_H__
#define __HYPERION_H__

#include <windows.h>
#include <stdint.h>
#include "pe.h"
#include "fasmoutput.h"

#define TRUE 1
#define FALSE 0
#define MAX_CHAR_SIZE 1024

#define CHECKSUM_SIZE 4
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define AES_ENCRYPT_API "aesEncrypt"
#define AES_DLL "Src\\Payloads\\Aes\\bin\\aes10.dll"

struct OpenFile {
        unsigned char* file;
        int size;
};

struct PEData {
        uint32_t ImageBase32;
        uint64_t ImageBase64;
        uint32_t SizeOfImage;
        BOOL GuiApplication;
};

//verbose api
void verbose(const char *format, ...);

//file api
BOOL fileToMem(const char* file_name, struct OpenFile* open_file);
BOOL memToFile(const char* file_name, char* content, unsigned long size,
               BOOL append);

//pe api
struct CoffHeader* getCoffHeader(struct OpenFile* input_file);
BOOL isExecutable(struct CoffHeader* coff_header);
BOOL isPE32(struct CoffHeader* coff_header);
BOOL isGuiApplication(uint16_t subsystem);
struct OptionalStandardHeader32* getOSH32(struct CoffHeader* coff_ptr);
struct OptionalStandardHeader64* getOSH64(struct CoffHeader* coff_ptr);
struct OptionalWindowsHeader32* getOWH32(struct OptionalStandardHeader32* os_ptr);
struct OptionalWindowsHeader64* getOWH64(struct OptionalStandardHeader64* os_ptr);
struct ImageDataDirectory* getIDD32(struct OptionalWindowsHeader32* owh_ptr);
struct ImageDataDirectory* getIDD64(struct OptionalWindowsHeader64* owh_ptr);

//fasm api
BOOL fasmDefine(const char* output_dir, const char* filename,
                const char* label, uint64_t value, BOOL append);
BOOL fasmInclude(const char* output_dir, const char* filename,
                const char* label, BOOL append);
BOOL fasmEncryptOutput(const char* output_dir, struct OpenFile* input_file,
                       unsigned int key_length, unsigned int key_space);
BOOL fasmHeader(BOOL guiApp, BOOL pe32plus);

//encryption api
uint32_t getChecksum(unsigned char* data, unsigned int size);
BOOL encryptFile(uint8_t* input_file, unsigned int file_size,
                 unsigned int key_length, unsigned int key_space);
BOOL encryptAES(uint8_t* input, unsigned int size, uint8_t* key);

//decryption api
BOOL decryptAES(BOOL pe32);

//secure string
size_t strlcat(char *dst, const char *src, size_t size);
size_t strlcpy(char *dst, const char *src, size_t size);

#endif
