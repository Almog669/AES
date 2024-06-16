#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "AES.h"

void checks(char **s){
    *s = (char*)malloc((sizeof(char)) * 4);
    //strcpy(s, "1234ssh");
    char *s1 ="abcd";
    for (size_t i = 0; i < 4; i++)
    {
       (*s)[i] = s1[i];
    }
    (*s)[4] = '\0';
    printf("sizeof s is : %lu\n", strlen(*s));
    //pstring(s);
    //free(s);
}

int f(char *input, char *key, char **output,AES_Mode mode){
    return encryptAes(input,key,&*output,mode);
}

void f1(char *input, char *key, char **output,AES_Mode mode, int len){
    decryptAes(input,key,&*output,mode,len);
}

int main(){
    char *input = "abcdef0123456789abcdef0123456789";
    char *cypher = NULL;
    char *text = NULL;
    char key[17];
    int len;
    generateRandomKey(key, KeySize);
    
    len = encryptAes(input,key,&cypher,CBC);
    phexstrsize(cypher,64);
    decryptAes(cypher,key,&text,CBC,len);
    pstring(text);
    freebuffs(&cypher,&text);
    

    // uint32_t x = 127;
    // uint32_t *ptr = &x;
    // bin(x);
    // swapBits(ptr, 5,28);
    // bin(x);
    // printf("counter is for x: %d\n", countBits(x));
    // printf("size of int: %ld\n", sizeof(uint32_t));
    return 0;
}

