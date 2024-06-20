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
    GCM   // cipher Galois/Counter Mode
} AES_Mode;


/*Round Key manipulation*/
unsigned char sbox_Lookup(unsigned char input);
unsigned char inv_sbox_Lookup(unsigned char input);
uint32_t rotate_8(uint32_t w3);
void rotate_10(uint32_t *x);
void rotate_16(uint32_t *x);
uint32_t byteSub(uint32_t w3);
uint32_t invByteSub(uint32_t w3);
uint32_t g(uint32_t w3, uint32_t Rcon);
void incrementRcon(uint32_t *pRcon);
void makeRoundKeys(char *initkey, uint32_t keyarr[][4]);
void generateRandomKey(char* str, int length);
void extractFromInit(char *initKey, uint32_t *posOne);
int encryptAes(char *input, char *key, char **output,AES_Mode mode); 
void decryptAes(char *input, char *key,char **output,AES_Mode mode, int cyphlen); 
void stateRowShift(uint32_t *state);
void invstateRowShift(uint32_t *state);
uint8_t gmul(uint8_t a, uint8_t b);
void mixColumns(uint32_t *state);
void invMixColumns(uint32_t *state);
int countBits(uint32_t x);
void swapBits(uint32_t *num, int x, int y);
void cpystates(uint32_t *state, uint32_t *priorstate);
void ivInit(uint32_t *iv);
void tostr(uint32_t *state, char **output, bool lastround, int pos);
void addCypher(char **output, bool lastround, int pos, char cypher);
void fillWithOnes(uint32_t *array);
void xWithPt(uint32_t *state, uint32_t *once);


/*Modes of operation functions*/
void ecbCypher(char *input, char *key, char **output, uint32_t roundKeys[][4]);
void ecbDeCypher(char *input, char *key, char **output, uint32_t roundKeys[][4], int cypherlen);
void cbcCypher(char *input, char *key, char **output, uint32_t roundKeys[][4]);
void cbcDeCypher(char *input, char *key, char **output, uint32_t roundKeys[][4], int cypherlen);
void cfbCypher(char *input, char *key, char **output, uint32_t roundKeys[][4]);
void cfbDeCypher(char *input, char *key, char **output, uint32_t roundKeys[][4], int cypherlen);
void ofbCypher(char *input, char *key, char **output, uint32_t roundKeys[][4]);
void ofbDeCypher(char *input, char *key, char **output, uint32_t roundKeys[][4], int cypherlen);
void ivCfbInc(uint32_t *iv, char cypher);

/*Helper log Functions*/
void proundkeys(uint32_t keyarr[][4]);
void pstring(char *str);
void pkey(uint32_t *key);
void phexstring(char *str);
void takesubstr(char *dst, char *src, int start, int len);
void phexstrsize(char *str, int size);
void bin(unsigned n);

/*free Dynmaic Data*/
void freebuffs(char **buf1, char **buf2);

#endif