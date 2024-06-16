#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "AES.h"

unsigned char aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

unsigned char aes_inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

unsigned char sbox_Lookup(unsigned char input){
    return aes_sbox[input];
}

unsigned char inv_sbox_Lookup(unsigned char input){
    return aes_inv_sbox[input];
}

uint32_t rotate_8(uint32_t w3){
    return (w3 << 8) | (w3 >> (sizeof(w3) * 8 - 8));
}

uint32_t byteSub(uint32_t w3){
    uint32_t f = 0xff000000,res = 0; 
    char c;
    int shift = 24;
     
    for(int i = 0 ; i < 4; i++){
       c = (w3 & f) >> shift;
       res += (uint32_t)sbox_Lookup(c) << shift;
       f = f >> 8;
       shift -= 8;
    }
    return res;
}

uint32_t invByteSub(uint32_t w3){
    uint32_t f = 0xff000000, res = 0; 
    char c;
    int shift = 24;
    for(int i = 0 ; i < 4; i++){
       c = (w3 & f) >> shift;
       res += (uint32_t)inv_sbox_Lookup(c) << shift;
       f = f >> 8;
       shift -= 8;
    }
    return res;
}

void makeRoundKeys(char *initkey, uint32_t keyarr[][4]){
    uint32_t Rcon = 0x01000000;
    uint32_t *Rconptr = &Rcon,w3;
    extractFromInit(initkey, keyarr[0]);

    for(int i = 1; i < 11; i++){
        w3 = keyarr[i-1][3];
        keyarr[i][0] = keyarr[i-1][0] ^ g(w3,Rcon);
        keyarr[i][1] = keyarr[i][0] ^ keyarr[i-1][1];
        keyarr[i][2] = keyarr[i][1] ^ keyarr[i-1][2];
        keyarr[i][3] = keyarr[i][2] ^ keyarr[i-1][3];
        incrementRcon(Rconptr);
    }
}

void generateRandomKey(char* str, int length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz "
                           "0123456789!@#$%^&*()_+-{}|"
                           "[]~=/`. ";

    // Seed the random number generator with the current time
    srand((unsigned int)time(NULL));

    size_t charset_size = sizeof(charset) - 1;
    //printf("Charset size: %zu\n", charset_size);

    // Generate random characters
    for (int i = 0; i < length; i++) {
        int key = rand() % charset_size;
        str[i] = charset[key];
        //printf("Character %d: %c (key: %d)\n", i, str[i], key);
    }

    str[length] = '\0'; // Null-terminate the string
}

void extractFromInit(char *initKey, uint32_t *posOne){
    uint32_t f = 0xff000000;
    int shift, pos = 0,j;

    for(int i  = 0 ; i < 4 ; i++){
        shift = 24;
        f = 0xff000000;
        for(j = 0 ; j < 4 ; j++){
            posOne[i] += ((uint32_t)initKey[pos] << shift) & f;
            pos++;
            shift -= 8;
            f = f >> 8;
        }
    }
}

uint32_t g(uint32_t w3, uint32_t Rcon){
     return byteSub(rotate_8(w3)) ^ Rcon ;
}

void incrementRcon(uint32_t *pRcon){
    uint32_t leftmost_bit = *pRcon & 0x80000000;
        // Left shift the constant
        *pRcon <<= 1;
        // If leftmost bit is set, perform XOR with Rcon
        if (leftmost_bit) {
            *pRcon ^= 0x1B000000;
        }
}

int encryptAes(char *input, char *key, char **output,AES_Mode mode){
    uint32_t roundKeys[11][4]= {0};
    makeRoundKeys(key,roundKeys);

    switch (mode){
        case ECB:
            ecbCypher(input,key,&*output,roundKeys);
            break;
        case CBC:
            cbcCypher(input,key,&*output,roundKeys);
            break;    
        default:
            break;
    }

    return strlen(input);
} 

void decryptAes(char *input, char *key,char **output,AES_Mode mode, int cyphlen){
    uint32_t roundKeys[11][4]= {0};
    makeRoundKeys(key,roundKeys);
    
    printf("here in decryptAEs");

    switch (mode){
        case ECB:
            ecbDeCypher(input,key,&*output,roundKeys,cyphlen);
            break;
        case CBC:
            cbcDeCypher(input,key,&*output,roundKeys,cyphlen);
            break;    
        default:
            break;
    }
}

void proundkeys(uint32_t keyarr[][4]){
    int shift;
    for (size_t i = 0; i < 11; i++)
    {
        for (size_t k = 0; k < 4; k++){
            shift = 24;
            for (size_t j = 0; j < 4; j++){
                printf("%02x", keyarr[i][k] >> shift & 0x000000ff);
                shift -= 8;
            }    
        }
        printf("\n");
    }  
}

void pstring(char *str){
    printf("%s\n",str);
}

void pkey(uint32_t *key){
    int shift;
    for (size_t k = 0; k < 4; k++){
            shift = 24;
            for (size_t j = 0; j < 4; j++){
                printf("%02x", key[k] >> shift & 0x000000ff);
                shift -= 8;
            }    
        }
        printf("\n");
}

void stateRowShift(uint32_t *state){
    uint32_t temp[4];
    // Extract bytes from state columns and rearrange them
    // First row (no shift)
    temp[0] = (state[0] & 0xFF000000) |
              (state[1] & 0x00FF0000) |
              (state[2] & 0x0000FF00) |
              (state[3] & 0x000000FF);

    // Second row (shift left by 1 byte)
    temp[1] = (state[1] & 0xFF000000) |
              (state[2] & 0x00FF0000) |
              (state[3] & 0x0000FF00) |
              (state[0] & 0x000000FF);

    // Third row (shift left by 2 bytes)
    temp[2] = (state[2] & 0xFF000000) |
              (state[3] & 0x00FF0000) |
              (state[0] & 0x0000FF00) |
              (state[1] & 0x000000FF);

    // Fourth row (shift left by 3 bytes)
    temp[3] = (state[3] & 0xFF000000) |
              (state[0] & 0x00FF0000) |
              (state[1] & 0x0000FF00) |
              (state[2] & 0x000000FF);

    // Copy the shifted values back into state
    for (int i = 0; i < 4; i++) {
        state[i] = temp[i];
    }
}

void invstateRowShift(uint32_t *state){
    uint32_t temp[4];
    // Inverse row shifts
    temp[0] = (state[0] & 0xFF000000) |
              (state[3] & 0x00FF0000) |
              (state[2] & 0x0000FF00) |
              (state[1] & 0x000000FF);

    temp[1] = (state[1] & 0xFF000000) |
              (state[0] & 0x00FF0000) |
              (state[3] & 0x0000FF00) |
              (state[2] & 0x000000FF);

    temp[2] = (state[2] & 0xFF000000) |
              (state[1] & 0x00FF0000) |
              (state[0] & 0x0000FF00) |
              (state[3] & 0x000000FF);

    temp[3] = (state[3] & 0xFF000000) |
              (state[2] & 0x00FF0000) |
              (state[1] & 0x0000FF00) |
              (state[0] & 0x000000FF);

    // Copy the shifted values back into state
    for (int i = 0; i < 4; i++) {
        state[i] = temp[i];
    }
}

uint8_t gmul(uint8_t a, uint8_t b){
    uint8_t p = 0;
    uint8_t hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return p;
}

void mixColumns(uint32_t *state){
    uint8_t matrix[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    }, s0, s1, s2, s3, new_s0, new_s1, new_s2, new_s3;
    uint32_t col;

    for (int i = 0; i < 4; i++) {
        col = state[i];
        s0 = (col >> 24) & 0xFF;
        s1 = (col >> 16) & 0xFF;
        s2 = (col >> 8) & 0xFF;
        s3 = col & 0xFF;

        new_s0 = gmul(matrix[0][0], s0) ^ gmul(matrix[0][1], s1) ^ gmul(matrix[0][2], s2) ^ gmul(matrix[0][3], s3);
        new_s1 = gmul(matrix[1][0], s0) ^ gmul(matrix[1][1], s1) ^ gmul(matrix[1][2], s2) ^ gmul(matrix[1][3], s3);
        new_s2 = gmul(matrix[2][0], s0) ^ gmul(matrix[2][1], s1) ^ gmul(matrix[2][2], s2) ^ gmul(matrix[2][3], s3);
        new_s3 = gmul(matrix[3][0], s0) ^ gmul(matrix[3][1], s1) ^ gmul(matrix[3][2], s2) ^ gmul(matrix[3][3], s3);

        state[i] = (new_s0 << 24) | (new_s1 << 16) | (new_s2 << 8) | new_s3;
    }
}

void invMixColumns(uint32_t *state){
    uint8_t matrix[4][4] = {
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
    }, s0, s1, s2, s3, new_s0, new_s1, new_s2, new_s3;
    uint32_t col;

    for (int i = 0; i < 4; i++) {
        col = state[i];
        s0 = (col >> 24) & 0xFF;
        s1 = (col >> 16) & 0xFF;
        s2 = (col >> 8) & 0xFF;
        s3 = col & 0xFF;

        new_s0 = gmul(matrix[0][0], s0) ^ gmul(matrix[0][1], s1) ^ gmul(matrix[0][2], s2) ^ gmul(matrix[0][3], s3);
        new_s1 = gmul(matrix[1][0], s0) ^ gmul(matrix[1][1], s1) ^ gmul(matrix[1][2], s2) ^ gmul(matrix[1][3], s3);
        new_s2 = gmul(matrix[2][0], s0) ^ gmul(matrix[2][1], s1) ^ gmul(matrix[2][2], s2) ^ gmul(matrix[2][3], s3);
        new_s3 = gmul(matrix[3][0], s0) ^ gmul(matrix[3][1], s1) ^ gmul(matrix[3][2], s2) ^ gmul(matrix[3][3], s3);

        state[i] = (new_s0 << 24) | (new_s1 << 16) | (new_s2 << 8) | new_s3;
    }
}

void tostr(uint32_t *state, char **output, bool lastround, int pos){
    int shift;
    int nchunk = lastround ? 17 : 16;
    uint32_t dig8 = 0x000000ff;

    *output = realloc( *output , pos + nchunk);
    if (*output == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
    }

    for (size_t i = 0; i < 4; i++){
        shift = 24;
        for (size_t j = 0; j < 4; j++){
            //printf("char is: %02x\n",(state[i] >> shift) & dig8);
             (*output)[pos] = (state[i] >> shift) & dig8;
            shift -= 8;
            //printf("char is: %c\n",(*output)[pos]);
            pos++;
        }
    }

    if(lastround)
        (*output)[pos] = '\0';
}

void takesubstr(char *dst, char *src, int start, int len){
    int count = 0;
    
    while(count < len){
        dst[count] = src[start + count];
        count++;
    }
}

void ecbCypher(char *input, char *key, char **output, uint32_t roundKeys[][4]){
    uint32_t state[4] = {0};
    int start  = 0, len = 16,inputlen = strlen(input);
    char buffer[17] = {0};
    bool lastround = false;

    printf("input len is : %ld\n", strlen(input));
    while(start < inputlen){
       printf("size of buffer %ld",sizeof(buffer));
       memset(buffer, 0, sizeof(buffer));
       takesubstr(buffer,input,start,len);
       memset(state, 0, sizeof(state));
       extractFromInit(buffer, state);
       
       for (size_t i = 0; i < 11; i++) {
            if(i == 0){
                for (size_t j = 0; j < 4; j++){
                    state[j] = state[j] ^ roundKeys[i][j];
                }
            }
            else{
                for (size_t j = 0; j < 4; j++){
                    state[j] = byteSub(state[j]);
                }
            stateRowShift(state);
            if(i != 10)
                mixColumns(state);
            for (size_t j = 0; j < 4; j++){
                state[j] = state[j] ^ roundKeys[i][j];
            }    
        }
        }
        if((start + 16) >= inputlen)
            lastround = !lastround;
       tostr(state,output,lastround,start);
       start += 16;
    }
}

void ecbDeCypher(char *input, char *key, char **output, uint32_t roundKeys[][4], int cypherlen){
    uint32_t state[4] = {1};
    int start  = 0 , len = 16;
    char buffer[17] = {0};
    bool lastround = false;
    
    //printf("cypher len is : %ld\n", strlen(input));

    while(start < cypherlen){
       memset(buffer, 0, sizeof(buffer));
       takesubstr(buffer,input,start,len);
       memset(state, 0, sizeof(state));
       extractFromInit(buffer, state);

       for(int i = 10; i >= 0; i--){
            if( i != 0){
               for (size_t j = 0; j < 4; j++){
                    state[j] = state[j] ^ roundKeys[i][j];
                }
                if (i != 10) 
                    invMixColumns(state); 
                invstateRowShift(state);
                for(size_t j = 0; j < 4; j++) {
                    state[j] = invByteSub(state[j]);
                }
            }
            else{
                for (size_t j = 0; j < 4; j++){
                    state[j] = state[j] ^ roundKeys[i][j];
                }
        }
        }
       if((start + 16) >= cypherlen)
            lastround = !lastround;
       tostr(state,output,lastround,start);
       start += 16;
    }
    
}

void phexstrsize(char *str, int size){
    for (int i = 0; i < size; i++){
        printf("%02x",(uint8_t)str[i]);
    }
    printf("\n");
}

void phexstring(char *str){
    int i = 0;
    while(str[i] != '\0'){
        printf("%02x",(uint8_t)str[i]);
        i++;
    }
    printf("\n");
}

void freebuffs(char **buf1, char **buf2){
    free(*buf1);
    free(*buf2);
}

void cbcCypher(char *input, char *key, char **output, uint32_t roundKeys[][4]){
    uint32_t state[4] = {0}, iv[4] = {0}, priorstate[4] = {0};
    int start  = 0, len = 16,inputlen = strlen(input);
    char buffer[17] = {0};
    bool lastround = false;
    
    extractFromInit(key,iv);
    ivInit(iv);
    while(start < inputlen){
       printf("size of buffer %ld",sizeof(buffer));
       memset(buffer, 0, sizeof(buffer));
       takesubstr(buffer,input,start,len);
       memset(state, 0, sizeof(state));
       extractFromInit(buffer, state);

       if(start == 0){
           for (size_t i = 0; i < 4; i++){
                state[i] ^= iv[i];
           }
       }
       else{
           for (size_t i = 0; i < 4; i++){
                state[i] ^= priorstate[i];
           }
       }
       for (size_t i = 0; i < 11; i++) {
            if(i == 0){
                for (size_t j = 0; j < 4; j++){
                    state[j] = state[j] ^ roundKeys[i][j];
                }
            }
            else{
                for (size_t j = 0; j < 4; j++){
                    state[j] = byteSub(state[j]);
                }
            stateRowShift(state);
            if(i != 10)
                mixColumns(state);
            for (size_t j = 0; j < 4; j++){
                state[j] = state[j] ^ roundKeys[i][j];
            }    
        }
        }
        if((start + 16) >= inputlen)
            lastround = !lastround;
        else
            cpystates(state, priorstate);    
       tostr(state,output,lastround,start);
       start += 16;
    }
}

void cbcDeCypher(char *input, char *key, char **output, uint32_t roundKeys[][4], int cypherlen){
    uint32_t state[4] = {0}, iv[4] = {0}, priorstate[4] = {0};
    int start  = 0 , len = 16;
    char buffer[17] = {0};
    bool lastround = false;
    
    extractFromInit(key,iv);
    ivInit(iv);
    printf("cypher len is : %ld\n", strlen(input));

    while(start < cypherlen){
       memset(buffer, 0, sizeof(buffer));
       takesubstr(buffer,input,start,len);
       memset(state, 0, sizeof(state));
       extractFromInit(buffer, state);
       if(start != 0)
            cpystates(state, priorstate);
       for(int i = 10; i >= 0; i--){
            if( i != 0){
               for (size_t j = 0; j < 4; j++){
                    state[j] = state[j] ^ roundKeys[i][j];
                }
                if (i != 10) 
                    invMixColumns(state); 
                invstateRowShift(state);
                for(size_t j = 0; j < 4; j++) {
                    state[j] = invByteSub(state[j]);
                }
            }
            else{
                for (size_t j = 0; j < 4; j++){
                    state[j] = state[j] ^ roundKeys[i][j];
                }
        }
        }
       if((start + 16) >= cypherlen)
            lastround = !lastround;
       if(start == 0){
           for (size_t i = 0; i < 4; i++){
                state[i] ^= iv[i];
           }
       }
       else{
           for (size_t i = 0; i < 4; i++){
                state[i] ^= priorstate[i];
           }
       }     
       tostr(state,output,lastround,start);
       start += 16;
    }
    
}

void ivInit(uint32_t *iv){
    int m = 0;

    for (size_t i = 0; i < 4; i++){
        bin(iv[i]);
        m = countBits(iv[i]) % 7;
        for (size_t j = 0; (j + m) < 31; j++){
            swapBits(&iv[i], j, j + m);
            bin(iv[i]);
        }
        rotate_10(&iv[i]);
        bin(iv[i]);
        rotate_16(&iv[i]);
        bin(iv[i]);
    }
}

void bin(unsigned n)
{
    unsigned i = 1;
    for ( i = i << 31; i > 0; i = i / 2) {
        ((n & i) != 0)? printf("1"):printf("0");
    }
    printf("\n");
}

int countBits(uint32_t x){
    unsigned i = 1;
    int counter = 0;

    for ( i = i << 31; i > 0; i = i / 2){
        if((x & i) != 0)
            counter++;
    }

    return counter;
}

void swapBits(uint32_t *num, int x, int y) {
    uint32_t bit_x = (*num >> x) & 1;
    uint32_t bit_y = (*num >> y) & 1;

    if (bit_x != bit_y) {
        *num ^= (1U << x) | (1U << y);
    }
}

void rotate_10(uint32_t *x){
   *x =  (*x << 10) | (*x >> (sizeof(*x) * 8 - 10));
}

void rotate_16(uint32_t *x){
   *x =  (*x << 16) | (*x >> (sizeof(*x) * 8 - 16));
}

void cpystates(uint32_t *state, uint32_t *priorstate){
    for (size_t i = 0; i < 4; i++){
        priorstate = state;
    }
}