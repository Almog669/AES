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
    char *input = "this is an encrypted message ! try to reverse";
    char *cypher = NULL;
    char *text = NULL;
    char key[17];
    int len;
    generateRandomKey(key, KeySize);
    
    len = encryptAes(input,key,&cypher,OFB);
    //printf("len of cypher : %d\n",len);
    //printf("len for phexsize : %d\n",len + (16 - (len % 16)));
    phexstrsize(cypher,len + (16 - (len % 16)));
    //phexstrsize(cypher,len);
    decryptAes(cypher,key,&text,OFB,len);
    pstring(text);
    freebuffs(&cypher,&text);
    
    return 0;
}

