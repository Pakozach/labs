#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    int len = 0;
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

int nextSet(int *set, int k, int n){
    for (int i=0; i<k; i++){
        (set[i])++;
        if (set[i]<n)
            return 1;
        set[i]=0;
    }
    return 0;
}

void printSet(int *set, int k){
    for (int i=0; i<k; i++){
        printf("%d ",set[i]);
    }
    printf("\n");
}

void placeSet(char *mask, int *set, int *pos, int k){
    for (int i=0;i<k;i++){
        mask[pos[i]]=ASCII[set[k-i-1]];
    }
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


char *decodeMask(char *e_mask){
    char *res=NULL;
    if (e_mask){
        char *c=strchr(e_mask,'_');
        if (c) {
            int l1=c-e_mask;
            int l2=strlen(e_mask)-l1-1;
            if ((l1>0) && (l2>0)) {
                char *hex_len=(char *) calloc(l1+1,sizeof (char ));
                memcpy(hex_len,e_mask,l1);
                int len=hexToInt(hex_len);
                if (len>0){
                    char *hex_mask=(char *) calloc(l2+1,sizeof (char ));
                    memcpy(hex_mask,e_mask+l1+1,l2);
                    int n=hexToInt(hex_mask);
                    if (n>=0){
                        res=(char *) calloc(len+1, sizeof (char));
                        int i=len-1;
                        while (n>0){
                            if ((n % 2)==1)
                                res[i]='1';
                            else
                                res[i]='0';
                            n=n/2;
                            i--;
                        }
                        while (i>=0) {
                            res[i]='0';
                            i--;
                        }
                    }
                    free(hex_mask);
                }
                free(hex_len);
            }
        }
    }
    return res;
}

void processMask(char *mask){
    // размер таблицы символов
    int n=strlen(ASCII);

    // считаем количество единиц
    int len=strlen(mask);
    int k=0;
    for (int i=0;i<len;i++){
        if (mask[i]=='1') k++;
    }

    // выделяем массив и заполняем его позициями подстановок в маске (там, где '1')
    int *pos=(int *) calloc(k,sizeof (int));
    int j=0;
    for (int i=0;i<len;i++){
        if (mask[i]=='1') {
            pos[j]=i;
            j++;
        }
    }

    // выделяем массив для перебора наборов подстановок
    int *set=(int *) calloc(k,sizeof (int));
    do {
        // замена в маске '0' символами из набора set
        placeSet(mask, set, pos, k);
        printf("%s\n", mask);
    } while (nextSet(set, k, n));

    free(pos);
    free(set);
}

int main() {
    printf("Input file name\n");
    char *name = get_str();
    FILE *f;
    char *s;
    f = fopen(name, "r");
    if (f == NULL){
        printf("Invalid file name\n");
        return 0;
    }
    while (1){
        s = get_str_file(f);
        if (s == NULL)
            break;
	s = decodeMask(s);
        processMask(s);
    }
    fclose(f);
    free(name);
    free(s);
    return 0;
}
