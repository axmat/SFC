#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <bearssl.h>


#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"

#define MIN_PASS_LENGTH 8
#define CHUNK_SIZE 4096
#define AES_KEY_SIZE 16
#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16
#define SHA_256_SIZE 32



const char salt[] = "FakcYGOSsWBOtmKbbj33YQnEAxrvsnQycjUz6YVa";

char * aes_key = NULL;
char * aes_iv = NULL;
br_aes_ct_ctr_keys * ctrctx = NULL;
br_gcm_context * gcmctx = NULL;

#define err(msg)\
  printf("%s[x] %s.\n", KRED, msg); exit(1);

#define errerrno(msg)\
  printf("%s[x] %s: %s.\n", KRED, msg, strerror(errno)); exit(1);

#define info(msg)\
  printf("%s[*] %s.\n", KGRN, msg);

#define warn(msg)\
  printf("%s[*] %s.\n", KYEL, msg);

#define usage()\
  printf("[x] Invalid command line is selected.\n\
Example usage: SimpleFileCrypter -d <fileToDecrypt>\n\
               SimpleFileCrypter -e <fileToEncrypt>\n");\
  exit(1);


void checkSecret(const char * secret){
  size_t len = strlen(secret);
  int hasUpper = 0;
  int hasLower = 0;
  int hasDigit = 0;

  if(len < MIN_PASS_LENGTH){
    err("Password length is too short");    
  }

  for(int i = 0; i < len; i++){
    if(isupper(secret[i])){
      hasUpper = 1;
    }
    if(islower(secret[i])){
      hasLower = 1;
    }
    if(isdigit(secret[i])){
      hasDigit = 1;
    }
    if(hasDigit && hasLower && hasUpper){
      return;
    }
  }

  err("Password must have uppercases, lowercases and digits");
  
}

void initCrypt(const char * secret){

  // Initialze the SHA256 context used as our PRF
  br_sha256_context shactx;
  br_sha256_init(&shactx);

  // Initialze the HMAC key context
  br_hmac_key_context hmackeyctx;
  br_hmac_key_init(&hmackeyctx, shactx.vtable, secret, strlen(secret));

  // Initialze the HMAC context
  br_hmac_context hmacctx;
  br_hmac_init(&hmacctx, &hmackeyctx, 0);  

  // Generate key material over the salt as input
  br_hmac_update(&hmacctx, salt, 40);
  char keyMaterial[SHA_256_SIZE];
  br_hmac_out(&hmacctx, keyMaterial);

  // clear the context for the KDF related structures
  memset(&shactx, 0, sizeof(br_sha256_context));
  memset(&hmackeyctx, 0, sizeof(br_hmac_key_context));
  memset(&hmacctx, 0, sizeof(br_hmac_context));


  // Use the first 16 bytes of key material as AES key
  aes_key = (char *) malloc(AES_KEY_SIZE);
  memcpy(aes_key, keyMaterial, AES_KEY_SIZE);

  // Use the next 12 bytes for the AES IV 
  aes_iv = (char *) malloc(AES_IV_SIZE);
  memcpy(aes_iv, keyMaterial+AES_KEY_SIZE, AES_IV_SIZE);


  // Initialze the AES-GCM constant-time context with the Key and IV 
  ctrctx = (br_aes_ct_ctr_keys *) malloc(sizeof(br_aes_ct_ctr_keys));
  gcmctx = (br_gcm_context *) malloc(sizeof(br_gcm_context));
  br_aes_ct_ctr_init(ctrctx, aes_key, AES_KEY_SIZE);
  br_gcm_init(gcmctx, &(ctrctx->vtable), br_ghash_ctmul);
  br_gcm_reset(gcmctx, aes_iv, AES_IV_SIZE);    
}

void releaseCrypt(){
  // Release AES and IV memory
  memset(aes_key, 0, AES_KEY_SIZE);
  memset(aes_iv, 0, AES_KEY_SIZE);
  free(aes_key);
  free(aes_iv);

  // Release the GCM context memory 
  memset(ctrctx, 0, sizeof(br_aes_ct_ctr_keys));
  memset(gcmctx, 0, sizeof(br_gcm_context));
  free(ctrctx);
  free(gcmctx);
}

void crypt(const char * src, int mode, char * dst, char * tagPath){
  const char * srcPath = src;
  char * dstPath = dst;

  // If no destination file is provided, create one using the source path
  if(dst == NULL){
    size_t srcPathLen = strlen(srcPath);
    dstPath = (char *) malloc(srcPathLen+7);
    if(dstPath == NULL){
      err("Memory allocation failed");
    }
    memset(dstPath, 0, srcPathLen+7);
    strncpy(dstPath, srcPath, srcPathLen);

    // default extension for the new file 
    if(mode == 1){
      strcat(dstPath, ".crypt");
    }
    else{
      strcat(dstPath, ".clear");
    }    
  }

  // Open the source and destination file
  FILE * fSource = fopen(srcPath, "r"); 
  FILE * fDestination = fopen(dstPath, "w+"); 

  if(fSource == NULL){    
    errerrno("Source file could not be accessed");
  }
  
  if(fDestination == NULL){    
    errerrno("Destination file could not be accessed");    
  }


  // Transform the data from plain/cipher to cipher/plain one chunk at a time
  char buff[CHUNK_SIZE];  
  size_t szRead = CHUNK_SIZE;
  while(szRead == CHUNK_SIZE){
    szRead = fread(buff, 1, CHUNK_SIZE, fSource);    
    br_gcm_flip(gcmctx);
    br_gcm_run(gcmctx, mode, buff, szRead);
    size_t szWrite = fwrite(buff, 1, szRead, fDestination);    
    if(szWrite != szRead){             
       errerrno("Encrypted data could not be written");
    }
  }
  fclose(fDestination);
  fclose(fSource);


  if(mode == 1){
    info("File is encrypted")
  }
  if(mode == 0){
    info("File is decrypted") 
  }

  if(tagPath != NULL){
    char tag[AES_TAG_SIZE];
    FILE * fTag;

    // Get the authnetication tag and write it out to the tag file
    if(mode == 1){
      fTag = fopen(tagPath, "w+"); 
      if(fTag == NULL){        
        errerrno("Tag file could not be accessed");        
      }
      br_gcm_get_tag(gcmctx, tag);
      size_t szWrite = fwrite(tag, 1, AES_TAG_SIZE, fTag);    
      if(szWrite != AES_TAG_SIZE){        
        err("Tag could not be written");         
      }
      info("Tag is generated");
      
    }
    // Check the authnetication tag
    else{
      fTag = fopen(tagPath, "r"); 
      if(fTag == NULL){
        errerrno("Tag file could not be accessed");
      }
      size_t szRead = fread(tag, 1, AES_TAG_SIZE, fTag);      
      if(szRead != AES_TAG_SIZE){                
        errerrno("Tag file could not be read");
      }
      if(br_gcm_check_tag(gcmctx, tag) != 1){        
        warn("Tag is invalid: Encrypted data have been modified or the password is incorrect");        
      }
      else{
        info("The integrity of the decrypted file is valid");
      }
    }    
    fclose(fTag);
  }
}

int main(int argc, char *argv[]){
  int c;
  int mode = -1;
  char * secret = NULL;
  char * srcPath = NULL;
  char * dstPath = NULL;
  char * tagPath = NULL;

  while ((c = getopt (argc, argv, "t:e:d:o:")) != -1)
  {
    switch (c)
    {
      case 'e':
        mode = 1;
        srcPath = optarg;
        break;
      case 'd':
        mode = 0;
        srcPath = optarg;
        break;
      case 'o':
        dstPath = optarg;
        break;      
      case 't':
        tagPath = optarg;
        break;      
    }
  }
  
  // File encryption or decryption? 
  if (mode == 1){
    info("Encryption");
  }
  else if(mode == 0){
    info("Decryption");
  }
  else{
    usage();
  }

  // check/generate GCM authentication tag is enabled
  if(tagPath != NULL){
    info("Integrity check"); 
  }

  // Get the password from the user without showing it on the terminal
  secret = getpass("Please enter the password to proceed: ");

  // Check the password strength: length and quality of material 
  checkSecret(secret);

  // Initialze the crypto context, Derive AES IV and Key
  initCrypt(secret);

  // Perform encryption or decryption, and check the auhtentication tag if provided
  crypt(srcPath, mode, dstPath, tagPath);

  // Clear the crypto context and key/iv buffers from memory
  releaseCrypt();
}