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

int main(){
    char *input = "this is an encrypted text try to reverse !";
    char *cipher = NULL;
    char *text = NULL;
    char key[17];
    uint32_t *len_Tag;
    generateRandomKey(key, KeySize);
    len_Tag = encryptAes(input,key,&cipher,GCM);
    //printf("len of cipher : %d\n",len);
    //printf("len for phexsize : %d\n",len + (16 - (len % 16)));
    phexstrsize(cipher,len_Tag[0] + (16 - (len_Tag[0] % 16)));
    //phexstrsize(cipher,len_Tag[0]);
    decryptAes(cipher,key,&text,GCM,len_Tag);
    pstring(text);
    freebuffs(&cipher,&text);
    return 0;
}

