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
        fprintf(f_out, "%s\012", mask);
        //printf("Mask '%s'\n", mask);
    }
    //char *mask = Make_Mask(s);
    //printf("Mask '%s'\n", mask);
    fclose(f_out);
    fclose(f_in);
    free(name);
    free(s);
   // processMask(mask);
    return 0;
}
