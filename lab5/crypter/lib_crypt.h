#ifndef LIB_CRYPT_H
#define LIB_CRYPT_H
# pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>



#define MAX_MESSAGE_SIZE 4096
#define MAX_BUFFER_SIZE MAX_MESSAGE_SIZE+8

//#define DIGEST_LENGTH_MD5 MD5_DIGEST_LENGTH  //16
//#define DIGEST_LENGTH_SHA1 SHA_DIGEST_LENGTH //20
#define DIGEST_LENGTH_MD5 16
#define DIGEST_LENGTH_SHA1 20

#define PASSWORD_LENGTH 4
#define NONCE_LENGTH 64

#define KEY_LENGTH_AES128 16
#define KEY_LENGTH_AES192 24
#define KEY_LENGTH_AES256 32
#define ZERO_HEAD_LENGTH 8

// типы хэш
#define HASH_TYPE_NONE  -1
#define HASH_TYPE_MD5  0
#define HASH_TYPE_SHA1 1

// типы шифров
#define ENC_TYPE_NONE   -1
#define ENC_TYPE_3DES   0
#define ENC_TYPE_AES128 1
#define ENC_TYPE_AES192 2
#define ENC_TYPE_AES256 3

typedef unsigned char byte;
typedef byte t_digest_md5[DIGEST_LENGTH_MD5];
typedef byte t_digest_sha1[DIGEST_LENGTH_SHA1];
typedef byte t_password[PASSWORD_LENGTH];
typedef byte t_nonce[NONCE_LENGTH];

typedef struct t_buffer{
    int len;
    byte data[MAX_BUFFER_SIZE];
} t_buffer;

char *get_enc_file_path(char *dir_out, t_password psw, int hash_type, int enc_type);
void do_generate(t_password psw, int hash_type, int enc_type, char *dir_out);
void do_verify(char *file_path);
void crack(char *file_path, int is_show);
void init_rand();
int str_to_hash_type(char *s, int len, int *p_type);
int str_to_enc_type(char *s, int len, int *p_type);
int str_to_psw(char *s, int len, t_password psw);
int encode_file (char *path_in, char *path_out, t_password psw, int hash_type, int enc_type, t_nonce nonce, byte *iv, int block_size);
int decode_file (char *path_in, char *path_out, t_password psw);
int str_to_nonce (char *s, t_nonce nonce);
void gen_nonce(t_nonce nonce);
byte *str_to_iv (char *s, int enc_type, int *block_size);
byte *gen_iv (int enc_type, int *block_size);
#endif //LIB_CRYPT_H
