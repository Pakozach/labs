#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

typedef unsigned char byte;

byte *reg_create(int len){
    return (byte *) calloc(len, sizeof (byte)+1);
};

byte r1_next(byte *r){
    byte res = r[0];
    for (int i=0; i<6; i++)
        r[i]=r[i+1];
    //r[6] = (res + r[2] + r[4] + 1) % 256;
    r[6] = res ^ r[2] ^ r[4] ^ 0x1;
    return res;
};

byte r2_next(byte *r){
    byte res = r[0];
    for (int i=0; i<8; i++)
        r[i]=r[i+1];
    //r[8] = (byte) (r[2] + r[4] + r[6] + 1) % 256;
    r[8] = r[2] ^ r[4] ^ r[6] ^ 0x1;
    return res;
};

byte r3_next(byte *r){
    byte res = r[0];
    for (int i=0; i<10; i++)
        r[i]=r[i+1];
    //r[10] = (byte) (r[4] + r[6] + r[8] + 1) % 256;
    r[10] = r[4] ^ r[6] ^ r[8] ^ 0x1;
    return res;
};

byte gamma_next(byte *r1, byte *r2, byte *r3){
    byte a=r1_next(r1);
    byte b=r2_next(r2);
    byte c=r3_next(r3);
    return (a*b*c + a*b + a*c + 1) % 256;
}

byte Ek(byte P, byte *r1, byte *r2, byte *r3){
    return P ^ gamma_next(r1, r2, r3);
}

int read_byte(FILE *f, byte *b) {
     unsigned int hex;
    int n = fscanf(f, "%2x", &hex);
    if (n == EOF)
        return 0;
    if (n == 0) {
        printf("Incorrect input data\n");
        return 0;
    }
    *b = (byte) hex % 256;
    return 1;
}

int read_register(FILE *f, byte *r, int len){
    for (int i=0; i<len; i++) {
        if (!(read_byte(f, r+i)))
            return 0;
    }
    return 1;
}

int gamma_init (const char *path, byte *r1, byte *r2, byte *r3){
    FILE *f = fopen(path, "r");
    if (f == NULL){
        printf("Invalid file name %s\n", path);
        return 0;
    }
    int res=0;
    if (read_register(f, r1, 7)) {
        if (read_register(f, r2, 9)){
            if (read_register(f, r3, 11))
                res=1;
        }
    }
    fclose(f);
    return res;
}

int open_in_out (const char *path_in, const char *path_out, FILE **f_in, FILE **f_out){
    *f_in=NULL;
    *f_out=NULL;
    // открываем входной файл
    *f_in = fopen(path_in, "r");
    if (*f_in == NULL){
        printf("Invalid file name %s\n", path_in);
        return 0;
    }

    // открываем выходной файл для записи результатов
    if (path_out){
        *f_out = fopen(path_out, "w");
        if (*f_out == NULL){
            printf("Invalid file name %s\n", path_out);
            fclose(*f_in);
            return 0;
        }
    }

    return 1;
}

void encode_F(FILE *f_in, FILE *f_out, byte * r1, byte * r2, byte * r3){
    byte b, c;
    while (read_byte(f_in, &b)){
        c = Ek(b, r1, r2, r3);
        fprintf(f_out,"%02x", c);
    }
}

int encode(const char *path_key, const char *path_in, const char *path_out){
    int res=0;
    byte *r1=reg_create(7);
    byte *r2=reg_create(9);
    byte *r3=reg_create(11);
    if (gamma_init(path_key, r1, r2, r3)){

        // открываем файл для шифрования
        FILE *f_in, *f_out;
        if (!(open_in_out(path_in, path_out, &f_in, &f_out)))
            return 0;

        // выполняем шифрование
        if (f_out) {
            encode_F(f_in, f_out, r1, r2, r3);
            fclose(f_out);
            printf("Encoded file %s\n", path_out);
        } else{
            encode_F(f_in, stdout, r1, r2, r3);
        }

        res=1;
        fclose(f_in);
    }
    free(r3);
    free(r2);
    free(r1);
    return res;
};




void test(){
    char *path_key="d:\\dbo\\r.txt";
    char *path_in="d:\\dbo\\1.txt";
    char *path_out_e="d:\\dbo\\1_e.txt";
    char *path_out_d="d:\\dbo\\1_d.txt";
    //encode(path_key, path_in, NULL);
    encode(path_key, path_in, path_out_e);
    encode(path_key, path_out_e, path_out_d);
};

int main(int argc, char *argv[]){
    //test1();
    const char* short_options = "k:";

    const struct option long_options[] = {
            { "key", required_argument, NULL, 'k' },
            { NULL, 0, NULL, 0 }
    };

    int rez;
    int option_index;

    char *path_key = NULL;
    char *path_in = NULL;
    while ((rez=getopt_long(argc,argv,short_options,
                            long_options,&option_index))!=-1){

        switch(rez){
            case 'k': {
                path_key = optarg;
                path_in = argv[argc-1];
                break;
            };
            case '?': default: {
                printf("found unknown option\n");
                break;
            };
        };
    };
    if (path_key){
        if (path_in){
            printf("%s %s \n", path_key, path_in);
            encode(path_key, path_in, NULL);
        } else
            printf("No file in \n");
    } else
        printf("No file key \n");
    return 0;
}
