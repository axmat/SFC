# Simple File Crypter

This application is made to **encrypt/decrypt** large files with **integirity check** on Linux OS. The encryption/decryption mechanism and choices of cryptography primitives and libraries have been explained below.
# Interface
Simple File Crypter (SFC) accepts 4 options as follow:
 - -e \<fileToEncrpt>: Encrpytion mode of operation which accepts a source file to encrypt
 - -d \<fileToDecrpt>: Decryption modeo f operation which accept a source file already encrypted with SFC to decrypt
 - -o \<destination>: The destination ciphertext (in encryption mode) or plaintext (in decryption mode) file to be generated. If it's not provided, SFC will generate a new file by appending \".crypt" or \".clear" to the current source file. 
 - -t \<tag file>: An optional GCM tag that will be generated in encryption mode and will be checked in decrpytion mode. 

# Description
## Key Generation
Upon each encrpytion/decryption command, SFC asks the user to provide a password with enough complexity. SFC uses **hmac_sha256** to derive a 128 bit encrpytion key and 96 bit IV for the counter mode **AES**. Additionally a **salt** has been used to create the key material to make bruteforce attack on **sha256** harder in case an adversary could recover the key material from the memory.

## Encryption
SFC uses a **aes_gcm** with 128 bit keys to perform encryption of data. The encryption has been performed on every 4 kilobyte chunk of data at a time to allow the user to encrypt larger files without loading the entire file in memory. 

## Implementation
SFC uses [bearssl](https://www.bearssl.org) to perform the key derivation and encrpytion. 


# Argument

 1. **Password choice**:  The password provided by the user needs to be at least 8 character including uppercase, lowercase and numeric values. Although the complexity of the minimum requirement for the password can be higher, this depends on the application. We make sure the password is never visible in clear text in terminal 
 2. **KDF**: To generate enough key material from a user friendly password, we used a **hmac_sha256** key derivation function as our **PRF** which is suggested by various standards. **sha256** and **hmac** are standard schemes that does not suffer from any known weakness. 
 3. **Salt**: We use a 320 bit salt to make sure if someone recovered a key material, it would not be possible to recover the password easily. a good **kdf**  function and **salt** makes computation of dictionary attacks harder. However, in long term the value of salt need to be generated again.
 4. **AES-GCM**: AES GCM mode is stream cipher mode that provides confidentially and integrity. GCM does not leak any information even on a large file and is a secure mode for AES.  It can be implemented efficiently with some current hardware support. Note that, AES-GCM is secure if the IV is also chosen randomly. We generate both Key and IV using the KDF function. 128-bit keys are also suffice for file encrpytion. 
 5. **BearSSL**: BearSSL is a lightweght and simple to use library. One reason that using this library is preferred over other choices such as Openssl is that **BearSSL** follow constant-time coding techniques which remove weakness due to side-channel attacks. 

