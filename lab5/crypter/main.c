#include <stdio.h>
#include <getopt.h>
#include "lib_crypt.h"

#define EXEC_RES_OK 1
#define EXEC_RES_ERROR 0
#define EXEC_RES_BAD_PARAMS 2

typedef struct t_params {
    int is_encode;
    int is_decode;
    char *psw_str;
    char *path_in;
    char *path_out;
    char *hash_str;
    char *enc_str;
    char *nonce_str;
    char *iv_str;
} t_params;

t_params *params_create(){
    t_params *params=calloc(1, sizeof (t_params));
    params->is_encode = 0;
    params->is_decode = 0;
}

void params_free(t_params **params){
    if (*params){
        if ((*params)->psw_str)
            free((*params)->psw_str);
        if ((*params)->path_in)
            free((*params)->path_in);
        if ((*params)->path_out)
            free((*params)->path_out);
        if ((*params)->hash_str)
            free((*params)->hash_str);
        if ((*params)->enc_str)
            free((*params)->enc_str);
        if ((*params)->nonce_str)
            free((*params)->nonce_str);
        if ((*params)->iv_str)
            free((*params)->iv_str);
        free(*params);
        *params=NULL;
    }
}

char *str_clone(char *s){
    char *res=NULL;
    if (s) {
        res = calloc(1, (strlen(s) + 1) * sizeof (char));
        strcpy(res, s);
    }
    return res;
}

int set_param(char **p, char short_name, char *str_value){
    if (*p){
        printf("Parameter '%c' is already set\n", short_name);
        return 0;
    }
    *p = str_clone(str_value);
    return 1;
}

int read_params(int argc, char *argv[], t_params *params){
    int res = 1;
    const char* short_options = "edp:i:o:h:a:n:v:";

    const struct option long_options[] = {
            { "enc", no_argument, NULL, 'e' },
            { "dec", no_argument, NULL, 'd' },
            { "pass", required_argument, NULL, 'p' },
            { "input", required_argument, NULL, 'p' },
            { "output", required_argument, NULL, 'o' },
            { "hmac", required_argument, NULL, 'h' },
            { "alg", required_argument, NULL, 'a' },
            { "nonce", required_argument, NULL, 'n' },
            { "iv", required_argument, NULL, 'v' },
            //  { "debug", no_argument, NULL, 'g' },
            { NULL, 0, NULL, 0 }
    };

    char rez;
    int option_index;
    while ((rez=getopt_long(argc, argv, short_options, long_options, &option_index))!=-1){
        switch(rez){
            case 'e': {
                params->is_encode = 1;
                break;
            };
            case 'd': {
                params->is_decode = 1;
                break;
            };
            case 'p': {
                if (!set_param(&(params->psw_str), rez, optarg))
                    res = 0;
                break;
            };
            case 'i': {
                if (!set_param(&(params->path_in), rez, optarg))
                    res = 0;
                break;
            };
            case 'o': {
                if (!set_param(&(params->path_out), rez, optarg))
                    res = 0;
                break;
            };
            case 'h': {
                if (!set_param(&(params->hash_str), rez, optarg))
                    res = 0;
                break;
            };
            case 'a': {
                if (!set_param(&(params->enc_str), rez, optarg))
                    res = 0;
                break;
            };
            case 'n': {
                if (!set_param(&(params->nonce_str), rez, optarg))
                    res = 0;
                break;
            };
            case 'v': {
                if (!set_param(&(params->iv_str), rez, optarg))
                    res = 0;
                break;
            };
            case '?': default: {
                res = 0;
                printf("found unknown option\n");
                break;
            };
        };
    };
    return res;
}

int check_params(t_params *params){
    if (params->is_encode==params->is_decode){
        printf("Set parameter encode (-e) or decode (-d)\n");
        return 0;
    }
    if (params->psw_str==NULL){
        printf("Set password (-p)\n");
        return 0;
    }
    if (params->path_in==NULL){
        printf("Set input file (-i)\n");
        return 0;
    }
    if (params->path_out==NULL){
        printf("Set output file (-o)\n");
        return 0;
    }
    if (params->is_decode){
        if ((params->enc_str) || (params->hash_str) || (params->nonce_str) || (params->iv_str)) {
            printf("--hmac, --alg, --nonce, --iv must be empty when decode\n");
            return 0;
        }
    }
    return 1;
}

int execute_encode(t_params *params){
    t_password psw;
    int hash_type;
    int enc_type;
    t_nonce nonce;
    byte *iv;
    int block_size;

    // password
    if (!str_to_psw(params->psw_str, strlen(params->psw_str), psw)){
        printf("Bad password\n");
        return EXEC_RES_BAD_PARAMS;
    }

    // HMAC
    if (params->hash_str) {
        if (!str_to_hash_type(params->hash_str, strlen(params->hash_str), &hash_type)) {
            printf("Bad hmac\n");
            return EXEC_RES_BAD_PARAMS;
        }
    } else
        hash_type = HASH_TYPE_SHA1;

    // ALG
    if (params->enc_str) {
        if (!str_to_enc_type(params->enc_str, strlen(params->enc_str), &enc_type)) {
            printf("Bad alg\n");
            return EXEC_RES_BAD_PARAMS;
        }
    } else
        enc_type = ENC_TYPE_AES128;

    // NONCE
    if (params->nonce_str){
        if (!(str_to_nonce(params->nonce_str, nonce))){
            printf("Bad nonce\n");
            return EXEC_RES_BAD_PARAMS;
        }
    }
    else
        gen_nonce(nonce);

    // IV
    if (params->iv_str)
        iv = str_to_iv (params->iv_str, enc_type, &block_size);
    else
        iv = gen_iv(enc_type, &block_size);
    if (!iv){
        printf("Bad iv\n");
        return EXEC_RES_BAD_PARAMS;
    }

    if (encode_file (params->path_in, params->path_out,  psw, hash_type, enc_type, nonce, iv, block_size))
        return EXEC_RES_OK;
    else
        return EXEC_RES_ERROR;
}

int execute_decode(t_params *params){
    t_password psw;

    // password
    if (!str_to_psw(params->psw_str, strlen(params->psw_str), psw)){
        printf("Bad password\n");
        return EXEC_RES_BAD_PARAMS;
    }

    if (decode_file (params->path_in, params->path_out,  psw))
        return EXEC_RES_OK;
    else
        return EXEC_RES_ERROR;
}

void print_help(){
    printf("Use options:\n");
    printf("  -e (--enc) or -d (--dec) (encode or decode)\n");
    printf("  -p (--pass) 4 bytes password (-p 1f1d0012)\n");
    printf("  -i (--input) input file path\n");
    printf("  -o (--output) output file path\n");
    printf("  -h (--hmac) (md5 or sha1). If not set - use default sha1.\n");
    printf("  -a (--alg) (aes128, aes192 or aes256). If not set - use default aes128.\n");
    printf("  -n (--nonce) (hex-value Nonce)\n");
    printf("  -v (--iv) (hex-value IV)\n");
}

int execute_action(t_params *params){
    init_rand();
    if (params->is_encode)
        return execute_encode(params);
    else
        return execute_decode(params);
}

int main(int argc, char *argv[]){
    t_params *params = params_create();

    if (read_params(argc, argv, params))
        if (check_params(params)) {
            int res = execute_action(params);
            if (res == EXEC_RES_BAD_PARAMS)
                print_help();
        } else
            print_help();
    else
        print_help();

    params_free(&params);
    return 0;
}
