#include "hyperion.h"
#include "fasmoutput.h"

//include '..\..\Payloads\Aes\32\aes.inc'
//include '..\..\Payloads\Aes\32\aes.asm'
//include '..\..\Payloads\Aes\32\decryptexecutable.asm'

BOOL decryptAES(BOOL pe32){
  const char* payload_directory;
  const char* container_directory;
  
  //select destination paths
  if(pe32){
    payload_directory = PAYLOAD32_AES_DIR;
    container_directory = CONTAINER32_DIR;
  }
  else{
    payload_directory = PAYLOAD64_AES_DIR;
    container_directory = CONTAINER64_DIR;
  }

  //create file names
  char aes_inc[MAX_CHAR_SIZE];
  aes_inc[0] = 0;
  strlcat(aes_inc, payload_directory, MAX_CHAR_SIZE);
  strlcat(aes_inc, AES_INC_FILENAME, MAX_CHAR_SIZE);
  
  char aes_asm[MAX_CHAR_SIZE];
  aes_asm[0] = 0;
  strlcat(aes_asm, payload_directory, MAX_CHAR_SIZE);
  strlcat(aes_asm, AES_ASM_FILENAME, MAX_CHAR_SIZE);
  
  char decrypter_asm[MAX_CHAR_SIZE];
  decrypter_asm[0] = 0;
  strlcat(decrypter_asm, payload_directory, MAX_CHAR_SIZE);
  strlcat(decrypter_asm, AES_DECRYPTION_FILENAME, MAX_CHAR_SIZE);
  
  //create include file to use aes algorithm
  if(!fasmInclude(container_directory, DECRYPTION_PAYLOAD_FILENAME, aes_inc, FALSE))
  {
          return FALSE;
  }
  if(!fasmInclude(container_directory, DECRYPTION_PAYLOAD_FILENAME, aes_asm, TRUE))
  {
          return FALSE;
  }
  if(!fasmInclude(container_directory, DECRYPTION_PAYLOAD_FILENAME, decrypter_asm, TRUE))
  {
          return FALSE;
  }
  
  return TRUE;
}
