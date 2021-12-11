#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <wchar.h>

const char *ASCII= "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890!@#$%^&*()_-+=;:<>,./ |[]{}'\\`~";
const char *HEX_CHARS="0123456789abcdef";

char *get_str() {
    char buf[81] = {0};
    char *res = NULL;
    int len = 0;
    int n = 0;
    do {
        n = scanf("%80[^\n]", buf);
        if (n < 0) {
            if (!res) {
                return NULL;
            }
        } else if (n > 0) {
            int chunk_len = strlen(buf);
            int str_len = len + chunk_len;
            res = (char *) realloc(res, (str_len + 1)*sizeof(char));
            memcpy(res + len, buf, chunk_len);
            len = str_len;
        } else {
            scanf("%*c");
        }
    } while (n > 0);

    if (len > 0) {
        res[len] = '\0';
    } else {
        res = calloc(1, sizeof(char));
    }

    return res;
}

char *get_str_file(FILE *f) {
    char buf[81] = {0};
    char *res = NULL;
    int len=0;
    int n = 0;
    n = fscanf(f, "%80[^\n]\012", buf);
    if (n < 0) {
        if (!res) {
            return NULL;
        }
    } else if (n > 0) {
        int chunk_len = strlen(buf);
        int str_len = len + chunk_len;
        res = (char *) calloc(chunk_len+1, sizeof(char));
        memcpy(res, buf, chunk_len);
        len = str_len;
    } else {
        fscanf(f , "%*c");
    }

    if (len > 0) {
        res[len] = '\0';
    } else {
        res = calloc(1, sizeof(char));
    }

    return res;
}

int Check_ASCII(char s){
    if (strchr(ASCII, s))
        return 1;
    else
        return 0;
}

char *Make_Mask(char *s){
    int len = strlen(s);
    char *mask=calloc(len+1,sizeof (char));
    for (int i = 0; i < len; i++){
        if (Check_ASCII(s[i]))
            mask[i] = '1';
        else
            mask[i] = '0';
    }
    return mask;
}

int bitsToInt(char *c){
    int res=0;
    if (c) {
        int l = strlen(c);
        for (int i=0; i<l; i++){
            res=res*2;
            if (c[i]=='1')
                res++;
        }
    }
    return res;
}

int calcIntLenHex(int n){
    if (n<0)
        return -1;
    if (n==0)
        return 1;
    int res=0;
    while (n>0){
        res++;
        n=n/16;
    }
    return res;
}

char *intToHex(int n){
    char *res=NULL;
    int len=calcIntLenHex(n);
    if (len>0){
        res=(char *) calloc(len+1, sizeof (char));
        for (int i=0; i<len; i++){
            res[len-i-1]=HEX_CHARS[n % 16];
            n=n/16;
        }
    }
    return res;
}

int hexToInt(char *sHex){
    if (!(sHex))
        return -1;
    int l=strlen(sHex);
    if (l<1)
        return -1;
    int res=0;
    for (int i=0; i<l; i++){
        char *c=strchr(HEX_CHARS,sHex[i]);
        if (c) {
            res=res*16+(c-HEX_CHARS);
        } else
            return -1;
    }
    return res;
}

char *encodeMask(char *mask){
    char *res=NULL;
    if (mask){
        char* hex_mask=intToHex(bitsToInt(mask));
        if (hex_mask){
            char* hex_len=intToHex(strlen(mask));
            int l1=strlen(hex_len);
            int l2=strlen(hex_mask);
            res=(char *) calloc(l1+l2+1+1, sizeof (char));
            memcpy(res,hex_len,l1);
            res[l1]='_';
            memcpy(res+l1+1,hex_mask,l2);
            free(hex_len);
            free(hex_mask);
        }
    }
    return res;
}

int main() {
    printf("Input file name\n");
    char *name = get_str();
    FILE *f_in;
    FILE *f_out;
    char *s;
    f_in = fopen(name, "r");
    f_out = fopen("Masks.txt", "w");
    if (f_in == NULL){
        printf("Invalid file name\n");
        return 0;
    }
    while (1){
        s = get_str_file(f_in);
        if (s == NULL)
            break;
        char *mask = Make_Mask(s);
        mask = encodeMask(mask);
        fprintf(f_out, "%s\012", mask);
        //printf("Mask '%s'\n", mask);

    }
    //char *mask = Make_Mask(s);
    //printf("Mask '%s'\n", mask);
    fclose(f_in);
    fclose(f_out);
    free(name);
    free(s);
    //processMask(mask);
    return 0;
}

