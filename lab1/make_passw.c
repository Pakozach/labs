#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *ASCII= "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890!@#$%^&*()_-+=;:<>,./ |[]{}'\\`~";

char *get_str() {
    char buf[81] = {0};
    char *res = NULL;
    int len;
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
    int len;
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


void Process_Mask(char *mask){
    // размер таблицы символов
    int n=strlen(ASCII);

    // считаем количество нулей
    int len=strlen(mask);
    int k=0;
    for (int i=0;i<len;i++){
        if (mask[i]=='0') k++;
    }

    // выделяем массив и заполняем его позициями подстановок в маске (там, где '0')
    int *pos=(int *) calloc(k,sizeof (int));
    int j=0;
    for (int i=0;i<len;i++){
        if (mask[i]=='0') {
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
        Process_Mask(s);
    }
    fclose(f);
    free(name);
    free(s);
    return 0;
}
