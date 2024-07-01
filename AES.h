//#pragma once
#ifndef AES_H
#define AES_H

#include <stdint.h>// for uint32_t
#include <stdbool.h>//for bool

#define KeySize 16
typedef enum {
    ECB,  // cipher Electronic Codebook Mode
    CBC,  // cipher Block Chaining Mode
    CFB,  // cipher feedback Mode
    OFB,  // cipher output feedback Mode
    GCM   // cipher Galois/Counter Mode 2^(128)
} AES_Mode;


/*Round Key manipulation*/
unsigned char sbox_Lookup(unsigned char input);
unsigned char inv_sbox_Lookup(unsigned char input);
uint32_t rotate_8(uint32_t w3);
void rotate_10(uint32_t *x);
void rotate_16(uint32_t *x);
void rotate_5(uint32_t *x);
uint32_t byteSub(uint32_t w3);
uint32_t invByteSub(uint32_t w3);
uint32_t g(uint32_t w3, uint32_t Rcon);
void incrementRcon(uint32_t *pRcon);
void makeRoundKeys(char *initkey, uint32_t keyarr[][4]);
void generateRandomKey(char* str, int length);
void extractFromInit(char *initKey, uint32_t *posOne);
void stateRowShift(uint32_t *state);
void invstateRowShift(uint32_t *state);
uint8_t gmul(uint8_t a, uint8_t b);
void mixColumns(uint32_t *state);
void invMixColumns(uint32_t *state);

/*General logic functions*/
uint32_t *encryptAes(char *input, char *key, char **output,AES_Mode mode); 
void decryptAes(char *input, char *key,char **output,AES_Mode mode, uint32_t *LenTag); 
void gcmExtractFromInit(uint32_t *posOne,char *initKey);
void gcmSplitLens(int lenpt, int lenhead, uint32_t *length);
int countBits(uint32_t x);
void swapBits(uint32_t *num, int x, int y);
void cpystates(uint32_t *state, uint32_t *priorstate);
void ivInit(uint32_t *iv);
void tostr(uint32_t *state, char **output, bool lastround, int pos);
void addcipher(char **output, bool lastround, int pos, char cipher);
void fillWithOnes(uint32_t *array);
void xWithPt(uint32_t *state, uint32_t *once);
void ivCfbInc(uint32_t *iv, char cipher);

/*GCM functions*/
void gcmIvInit(uint32_t *ivCounter, char *initKey);
void gcmIncIv(uint32_t* iv);
void gcmMultiply(uint32_t* X, uint32_t* Y, uint32_t* Z);
void gcmAddToTag(uint32_t *H, uint32_t *LenTAg);
bool checkTagSig(uint32_t *H,uint32_t *LenTag);

/*Modes of operation functions*/
void ecbCipher(char *input, char *key, char **output, uint32_t roundKeys[][4]);
void ecbDecipher(char *input, char *key, char **output, uint32_t roundKeys[][4], uint32_t cipherlen);
void cbccipher(char *input, char *key, char **output, uint32_t roundKeys[][4]);
void cbcDecipher(char *input, char *key, char **output, uint32_t roundKeys[][4], uint32_t cipherlen);
void cfbcipher(char *input, char *key, char **output, uint32_t roundKeys[][4]);
void cfbDecipher(char *input, char *key, char **output, uint32_t roundKeys[][4], uint32_t cipherlen);
void ofbcipher(char *input, char *key, char **output, uint32_t roundKeys[][4]);
void ofbDecipher(char *input, char *key, char **output, uint32_t roundKeys[][4], uint32_t cipherlen);
void gcmCipher(char *input, char *key, char **output, uint32_t roundKeys[][4], uint32_t *lenTag);
void gcmDecipher(char *input, char *key, char **output, uint32_t roundKeys[][4], uint32_t *lenTag);
void aesBasic(uint32_t *toencrypt, uint32_t *res, uint32_t roundKeys[][4]);

/*Helper log Functions*/
void proundkeys(uint32_t keyarr[][4]);
void pstring(char *str);
void pkey(uint32_t *key);
void phexstring(char *str);
void takesubstr(char *dst, char *src, int start, int len);
void phexstrsize(char *str, int size);
void bin(unsigned n);
void perror(const char *message);

/*free Dynmaic Data*/
void freebuffs(char **buf1, char **buf2);
/*-----------------------------------------------------------------------*/
/*----------!---------------NOTICE--------------------!------------------*/
    /*Header will not be encrypted, only GCM multiplied and added the chained
    authenticated tag as Additional data Header that stayes the same every
    call for the purpose of using this code modify the dummy header to take
    as to suit your needs.*/
/*----------!--------------------!--------------------!------------------*/
#endif