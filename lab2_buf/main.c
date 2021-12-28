#include <stdio.h>
#include <getopt.h>
#include <string.h>

#define MODE_EBC 1
#define MODE_CBC 2
#define MODE_OFB 3

typedef unsigned int block;
typedef unsigned char byte;
typedef int sbox [16][16];

sbox S=
        {
                {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
                {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
                {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
                {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
                {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
                {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
                {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
                {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
                {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
                {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
                {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
                {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
                {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
                {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
                {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
                {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };

sbox SI=
        {
                {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
                {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
                {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
                {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
                {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
                {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
                {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
                {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
                {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
                {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
                {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
                {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
                {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
                {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
                {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
        };

void block_to_bytes(block A, byte *a00, byte *a01, byte *a10, byte *a11){
    block X = A;
    *a11 = X % 256; X = X / 256;
    *a10 = X % 256; X = X / 256;
    *a01 = X % 256; X = X / 256;
    *a00 = X % 256;
}

block bytes_to_block(byte a00, byte a01, byte a10, byte a11){
    return 256*(256*(256*a00 + a01) + a10) + a11;
}

byte make_S(sbox *sb, byte a){
    byte i = a / 16;
    byte j = a % 16;
  return (*sb)[i][j];
}

// выполнение одного раунда шифрования AES
void turn_AES(byte *a00, byte *a01, byte *a10, byte *a11, block K){
    // подстановка S с циклическим сдвигом xor K
    byte k00, k01, k10, k11;
    block_to_bytes(K, &k00, &k01, &k10, &k11);

    byte a = *a00;
    *a00 = make_S(&S, *a01) ^ k00;
    *a01 = make_S(&S, *a10) ^ k01;
    *a10 = make_S(&S, *a11) ^ k10;
    *a11 = make_S(&S, a) ^ k11;
}

void turn_AES_I(byte *a00, byte *a01, byte *a10, byte *a11, block K){
    // подстановка S с циклическим сдвигом xor K
    byte k00, k01, k10, k11;
    block_to_bytes(K, &k00, &k01, &k10, &k11);

    byte a = *a00;
    *a00 = make_S(&SI, (*a11 ^ k11));
    *a11 = make_S(&SI, (*a10 ^ k10));
    *a10 = make_S(&SI, (*a01 ^ k01));
    *a01 = make_S(&SI, a ^ k00);
}

block inverse(block K){
    block X=0, Y=K;
    block n=128;
    for (int i=0; i<8; i++){
        X = X + n*(Y % 2);
        n=n/2; Y=Y/2;
    }
    return X;
}

// генерация раундовых ключей
void get_keys(block K, block *K0, block *K1, block *K2){
    *K0 = K;
    *K1 = inverse(K);
    *K2 = (*K0) ^ (*K1);
}

block Ek(block P, block K){
    // генерация раундовых ключей
    block K0, K1, K2;
    get_keys(K, &K0, &K1, &K2);

    // предварительная обработка открытого текста P, получаем информационный блок C0
    block C0 = K0 ^ P;

    // выполняем раунды
    byte a00, a01, a10, a11;
    block_to_bytes(C0, &a00, &a01, &a10, &a11);
    // первый
    turn_AES(&a00, &a01, &a10, &a11, K1);
    // второй
    turn_AES(&a00, &a01, &a10, &a11, K2);
    // результат
    return bytes_to_block(a00, a01, a10, a11);
}

block Dk(block C, block K){
    // генерация раундовых ключей
    block K0, K1, K2;
    get_keys(K, &K0, &K1, &K2);

    // выполняем раунды
    byte a00, a01, a10, a11;
    block_to_bytes(C, &a00, &a01, &a10, &a11);
    // первый
    turn_AES_I(&a00, &a01, &a10, &a11, K2);
    // второй
    turn_AES_I(&a00, &a01, &a10, &a11, K1);
    // результат
    return K0 ^  bytes_to_block(a00, a01, a10, a11);
}

// Ci = Ek(Pi, K)
block E_ECB(block P, block K){
    return Ek(P, K);
}

// Pi = Dk(Ci, K)
block D_ECB(block C, block K){
    return Dk(C, K);
}

// Ci = Ek(Pi + Ci-1, K), С0=IV
block E_CBC(block P, block C_prior, block K){
    return Ek(P ^ C_prior, K);
}

// Pi = Ci-1 + Dk(Ci, K), С0=IV
block D_CBC(block C_prior, block C, block K){
    return C_prior ^ Dk(C, K);
}

int read_block(FILE *f, block *b) {
    int n = fscanf(f, "%8x", b);
    if (n == EOF)
        return 0;
    if (n == 0) {
        printf("Incorrect input data\n");
        return 0;
    }
    return 1;
}

void encode_ECB_F(FILE *f_in, FILE *f_out, block K){
    block b, c;
    while (read_block(f_in, &b)){
        c = E_ECB(b, K);
        fprintf(f_out,"%08x", c);
    }
};

void decode_ECB_F(FILE *f_in, FILE *f_out, block K){
    block b, c;
    while (read_block(f_in, &b)){
        c = D_ECB(b, K);
        fprintf(f_out, "%08x", c);
    }
};

void encode_CBC_F(FILE *f_in, FILE *f_out, block K, block IV){
    block C=IV;
    block b;
    while (read_block(f_in, &b)){
        C = E_CBC(b, C, K);
        fprintf(f_out,"%08x", C);
    }
};

void decode_CBC_F(FILE *f_in, FILE *f_out, block K, block IV){
    block C=IV;
    block b;
    while (read_block(f_in, &b)){
        C = D_CBC(C, b, K);
        fprintf(f_out, "%08x", C);
    }
};

void encode_OFB_F(FILE *f_in, FILE *f_out, block K, block IV){
    block K_prior=IV;
    block b, C;
    while (read_block(f_in, &b)){
        K_prior = Ek(K_prior, K);
        C = K_prior ^ b;
        fprintf(f_out,"%08x", C);
    }
};

void decode_OFB_F(FILE *f_in, FILE *f_out, block K, block IV){
    encode_OFB_F(f_in, f_out, K, IV);
};

int open_in_out (char *path_in, char *path_out, FILE **f_in, FILE **f_out){
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

int encode_ECB(char *path_in, char *path_out, block K){
    // открываем файл для шифрования
    FILE *f_in, *f_out;
    if (!(open_in_out(path_in, path_out, &f_in, &f_out)))
        return 0;

    // выполняем шифрование
    if (f_out) {
        encode_ECB_F(f_in, f_out, K);
        fclose(f_out);
        printf("Encoded file %s\n", path_out);
    } else
        encode_ECB_F(f_in, stdout, K);
    fclose(f_in);
};

int decode_ECB(char *path_in, char *path_out, block K){
    // открываем файл для шифрования
    FILE *f_in, *f_out;
    if (!(open_in_out(path_in, path_out, &f_in, &f_out)))
        return 0;

    // выполняем расшифрование
    if (f_out) {
        decode_ECB_F(f_in, f_out, K);
        fclose(f_out);
        printf("Decoded file %s\n", path_out);
    } else
        decode_ECB_F(f_in, stdout, K);
    fclose(f_in);
};

int encode_CBC(char *path_in, char *path_out, block K, block IV){
    // открываем файл для шифрования
    FILE *f_in, *f_out;
    if (!(open_in_out(path_in, path_out, &f_in, &f_out)))
        return 0;

    // выполняем шифрование
    if (f_out) {
        encode_CBC_F(f_in, f_out, K, IV);
        fclose(f_out);
        printf("Encoded file %s\n", path_out);
    } else
        encode_CBC_F(f_in, stdout, K, IV);
    fclose(f_in);
};

int decode_CBC(char *path_in, char *path_out, block K, block IV){
    // открываем файл для шифрования
    FILE *f_in, *f_out;
    if (!(open_in_out(path_in, path_out, &f_in, &f_out)))
        return 0;

    // выполняем расшифрование
    if (f_out) {
        decode_CBC_F(f_in, f_out, K, IV);
        fclose(f_out);
        printf("Decoded file %s\n", path_out);
    } else
        decode_CBC_F(f_in, stdout, K, IV);
    fclose(f_in);
};

int encode_OFB(char *path_in, char *path_out, block K, block IV){
    // открываем файл для шифрования
    FILE *f_in, *f_out;
    if (!(open_in_out(path_in, path_out, &f_in, &f_out)))
        return 0;

    // выполняем шифрование
    if (f_out) {
        encode_OFB_F(f_in, f_out, K, IV);
        fclose(f_out);
        printf("Encoded file %s\n", path_out);
    } else
        encode_OFB_F(f_in, stdout, K, IV);
    fclose(f_in);
};

int decode_OFB(char *path_in, char *path_out, block K, block IV){
    // открываем файл для шифрования
    FILE *f_in, *f_out;
    if (!(open_in_out(path_in, path_out, &f_in, &f_out)))
        return 0;

    // выполняем расшифрование
    if (f_out) {
        decode_OFB_F(f_in, f_out, K, IV);
        fclose(f_out);
        printf("Decoded file %s\n", path_out);
    } else
        decode_OFB_F(f_in, stdout, K, IV);
    fclose(f_in);
};

int str_to_mode(char *s){
    if (strcmp(s, "ebc"))
        return MODE_EBC;
    if (strcmp(s, "CBC"))
        return MODE_CBC;
    if (strcmp(s, "OFB"))
        return MODE_OFB;
    return 0;
}

block str_to_block(char *s){
    block res=0;
    int hex;
    if (sscanf(s, "%08x", &hex))
        res = (block) hex;
    return res;
}

int test(){
    block IV = 0x12345678;
    block K = 0xabcdef01;
    encode_OFB("d:\\dbo\\1.txt", "d:\\dbo\\1_e.txt", K, IV);
    printf("\n");
    decode_OFB("d:\\dbo\\1_e.txt", "d:\\dbo\\1_d.txt", K, IV);
    /*encode_CBC("d:\\dbo\\1.txt", "d:\\dbo\\1_e.txt", K, IV);
    printf("\n");
    decode_CBC("d:\\dbo\\1_e.txt", "d:\\dbo\\1_d.txt", K, IV);*/


    //byte a=0xaf;
    //printf("0x%08x\n",make_S(&SI, make_S(&S, a)));
/*
    block P, K, C;
    P = 0x12345678;
    K = 0xabcdef01;
    C = Ek(P, K);
    printf("0x%08x\n",P);
    printf("0x%08x\n",C);
    printf("0x%08x\n",Dk(C, K));
    return 0;
*/

}

int main(int argc, char *argv[]){
    const char* short_options = "k:hm:edi:";

    const struct option long_options[] = {
            { "key", required_argument, NULL, 'k' },
            { "help", no_argument, NULL, 'h' },
            { "mode", required_argument, NULL, 'm' },
            { "enc", no_argument, NULL, 'e' },
            { "dec", no_argument, NULL, 'd' },
            { "iv", required_argument, NULL, 'i' },
          //  { "debug", no_argument, NULL, 'g' },
            { NULL, 0, NULL, 0 }
    };

    int rez;
    int option_index;
    block K = 0;
    block IV = 0;
    int enc_mode = 0;
    int mode = 0;
    //int is_debug = 0;
    while ((rez=getopt_long(argc,argv,short_options,long_options,&option_index))!=-1){
        switch(rez){
            case 'k': {
                K = str_to_block(optarg);
                break;
            };
            case 'h': {
                printf("-m, --mode=[value]: set encode mode (ecb, cbc, ofb)\n");
                printf("-e, --enc: set encode data\n");
                printf("-d, --dec: set decode data\n");
                printf("-k, --key=[value]: key in hex\n");
                printf("-i, --iv=[value]: Initialization Vector in hex\n");
                return 0;
            };
            case 'e': {
                mode += 1;
                break;
            };
            case 'd': {
                mode += 2;
                break;
            };
            case 'i': {
                IV = str_to_block(optarg);
                break;
            };
            case 'm': {
                enc_mode = str_to_mode(optarg);
                break;
            };
            /*case 'g': {
                is_debug += 1;
                break;
            };*/
            case '?': default: {
                printf("found unknown option\n");
                break;
            };
        };
    };
    char *file_in = argv[argc - 1];
    if ((!K) || (!file_in) || (mode < 1) || (mode > 2) || (!enc_mode)) {
        printf("Incorrect parameters\n");
        return 0;
    }
    if (((enc_mode == MODE_CBC) || (enc_mode == MODE_OFB)) && (!IV)){
        printf("No IV");
        return 0;
    }
    if (enc_mode == MODE_EBC){
        if (mode == 1)
            encode_ECB(file_in, NULL, K);
        else
            decode_ECB(file_in, NULL, K);
    }
    if (enc_mode == MODE_CBC){
        if (mode == 1)
            encode_CBC(file_in, NULL, K, IV);
        else
            decode_CBC(file_in, NULL, K, IV);
    }
    if (enc_mode == MODE_OFB){
        if (mode == 1)
            encode_OFB(file_in, NULL, K, IV);
        else
            decode_OFB(file_in, NULL, K, IV);
    }
    return 0;
}
