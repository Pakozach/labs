#define USE_OPENSSL
#include "lib_crypt.h"
#ifdef USE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#endif

// 8 нулевых байт
const byte ZERO_HEAD [ZERO_HEAD_LENGTH]={0};
// заголовок в файле ENC
const char *HEADER_ENC="ENC";

const char *HEX_CHARS="0123456789abcdef";

int is_debug=0;

void print_buf1(const char *msg, byte *b, int len){
    if (msg)
        printf(msg);
    if (b){
        int h;
        for(int i=0; i<len; i++){
            h = b[i];
            printf("%02x", h);
        }
    }
}

void print_buf(const char *msg, byte *b, int len){
    print_buf1(msg, b, len);
    printf("\n");
}

void debug(const char *msg, byte *b, int len){
    if (is_debug)
        print_buf(msg, b, len);
}

int test_chiper(t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv, int key_len){
    byte b = key_len;
    //debug("test_chiper len: 0x", &b, 1);
    //debug("test_chiper k: ", k, key_len);
    int j = 0;
    for (int i=0; i<buf_in->len; i++){
        if (j>=key_len)
            j=0;
        (buf_out->data)[i] = (buf_in->data)[i] ^ k[j];
        j++;
    }
    return 1;
}

void test_hash(byte *text, int n, byte *hash, int len){
    //if (is_debug)
    //    printf("test_hash len: %d\n", len);
    debug("test_hash text: ", text, n);
    int j = 0;
    for (int i=0; i<n; i++) j = (j + text[i]) % len;
    for (int i=0; i<len; i++) hash[i] = (i + j) % 256;
    for (int i=0; i<n; i++) {
        if (j>=len)
            j=0;
        hash[j] = hash[j] ^ text[i];
        j++;
    }
    debug("test_hash hash: ", hash, len);
}


void calc_md5(byte *text, int n, t_digest_md5 hash) {
    // из openssl/md5.h:
#ifdef USE_OPENSSL
    MD5(text, n, hash);
#else
    test_hash(text, n, hash, DIGEST_LENGTH_MD5);
#endif
}

void calc_sha1(byte *text, int n, t_digest_sha1 hash) {
    // из openssl/sha.h:
#ifdef USE_OPENSSL
    SHA1(text, n, hash);
#else
    test_hash(text, n, hash, DIGEST_LENGTH_SHA1);
#endif
}

int encode_buf_3DES (t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv){
    return 0;
}

int decode_buf_3DES (t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv){
    return 0;
}

int encode_buf_AES(t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv, int key_len){
    // из openssl/aes.h:
    int res = 1;
#ifdef USE_OPENSSL
    AES_KEY enc_key;
    AES_set_encrypt_key(k, key_len*8, &enc_key); // длина в битах!
    AES_cbc_encrypt(buf_in->data, buf_out->data, buf_in->len, &enc_key, iv, AES_ENCRYPT);
#else
    res = test_chiper(buf_in, buf_out, k, iv, key_len);
#endif
    buf_out->len = buf_in->len;
    return res;
}

int decode_buf_AES(t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv, int key_len){
    // из openssl/aes.h:
    int res = 1;
#ifdef USE_OPENSSL
    AES_KEY dec_key;
    AES_set_decrypt_key(k, key_len*8, &dec_key); // длина в битах!
    AES_cbc_encrypt(buf_in->data, buf_out->data, buf_in->len, &dec_key, iv, AES_DECRYPT);
#else
    res = test_chiper(buf_in, buf_out, k, iv, key_len);
#endif
    buf_out->len = buf_in->len;
    return res;
}

int encode_buf_AES128 (t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv){
    return encode_buf_AES(buf_in, buf_out, k, iv, KEY_LENGTH_AES128);
}

int encode_buf_AES192 (t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv){
    return encode_buf_AES(buf_in, buf_out, k, iv, KEY_LENGTH_AES192);
}

int encode_buf_AES256 (t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv){
    return encode_buf_AES(buf_in, buf_out, k, iv, KEY_LENGTH_AES256);
}

int decode_buf_AES128 (t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv){
    return decode_buf_AES(buf_in, buf_out, k, iv, KEY_LENGTH_AES128);
}

int decode_buf_AES192 (t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv){
    return decode_buf_AES(buf_in, buf_out, k, iv, KEY_LENGTH_AES192);
}

int decode_buf_AES256 (t_buffer *buf_in, t_buffer *buf_out, byte *k, byte *iv){
    return decode_buf_AES(buf_in, buf_out, k, iv, KEY_LENGTH_AES256);
}

t_buffer *buffer_create(){
    return calloc(1,sizeof (t_buffer));
};

void buffer_clear(t_buffer *buf){
    buf->len = 0;
}

void buffer_free(t_buffer **p_buf){
    if (*p_buf){
        free(*p_buf);
        *p_buf=NULL;
    };
}

int buffer_write(t_buffer *buf, const byte *data, int size){
    int res = size;
    if (res + buf->len > MAX_BUFFER_SIZE)
        res = MAX_BUFFER_SIZE - buf->len;
    if (res>0) {
        memcpy(buf->data + buf->len, data, res);
        buf->len = buf->len + res;

    }
    return res;
}

byte *concat(byte *b1, int l1, byte *b2, int l2){
    if (l1 + l2 == 0)
        return NULL;
    byte *res=malloc(l1 + l2);
    if (b1)
        memcpy(res,b1,l1);
    if (b2)
        memcpy(res+l1,b2,l2);
    //debug("concat res: ", res, l1+l2);
    return res;
}

byte *pad(byte *k0, int block_size, byte c){
    byte *res = calloc(block_size, sizeof (byte));
    for (int i=0; i<block_size; i++)
        res[i] = k0[i] ^ c;
    return res;
}

byte *i_pad(byte *k0, int block_size){
    return pad(k0, block_size, 0x36);
}

byte *o_pad(byte *k0, int block_size){
    return pad(k0, block_size, 0x5c);
}

void hash_concat_md5 (byte *b1, int l1, byte *b2, int l2, t_digest_md5 hash){
    byte *b=concat(b1, l1, b2, l2);
    calc_md5(b, l1 + l2, hash);
    free(b);
}

byte *get_key0_md5(t_password k, int block_size){
    // получаем k0 из k, равный размеру блока block_size
    byte *k0 = NULL;
    if (PASSWORD_LENGTH == block_size){
        // если длина k = размеру блока block_size, то k0=k
        k0 = concat(k, block_size, NULL, 0);
    } else {
        if (PASSWORD_LENGTH < block_size) {
            // если длина ключа k < размеру блока block_size, то k0 - это дополнение k справа нулями
            int l = block_size - PASSWORD_LENGTH;
            byte *z = calloc(l, sizeof(byte));
            k0 = concat(k, PASSWORD_LENGTH, z, l);
            free(z);
        } else {
            // если длина ключа k > размера блока block_size, то k0 - это hash от k + дополнение справа нулями
            t_digest_md5 hash1;
            calc_md5(k, PASSWORD_LENGTH, hash1);
            byte *z = NULL;
            int l = block_size - DIGEST_LENGTH_MD5;
            if (l>0)
                z = calloc(l, sizeof(byte));
            else
                l=0;
            int l1 = block_size - l;
            k0 = concat(hash1, l1, z, l);
            if (z) free(z);
        }
    }
    //debug("get_key0_md5 k0: ", k0, block_size);
    return k0;
}

int hmac_md5(byte *text, int n, t_password k, int block_size, t_digest_md5 hash){
    // получаем k0 из k, равный размеру блока block_size
    byte *k0 = get_key0_md5(k, block_size);
    if (k0==NULL)
        return 0;
    //debug("hmac_md5 k0: ", k0, block_size);

    // HMAC_k (text)= H ( (K0 ^ opad) || H( (K0 ^ ipad) || text ) )
    t_digest_md5 hash1;
    byte *pad;

    // выражение hash1 = H( (K0 ^ ipad) || text )
    pad = i_pad(k0, block_size);
    hash_concat_md5(pad, block_size, text, n, hash1);
    //debug("hmac_md5 hash1: ", hash1, DIGEST_LENGTH_MD5);
    free(pad);

    // выражение HMAC = H( (K0 ^ opad) || hash1 )
    pad = o_pad(k0, block_size);
    hash_concat_md5(pad, block_size, hash1, DIGEST_LENGTH_MD5, hash);
    //debug("hmac_md5 hash: ", hash, DIGEST_LENGTH_MD5);
    free(pad);

    return 1;
}

void hash_concat_sha1 (byte *b1, int l1, byte *b2, int l2, t_digest_sha1 hash){
    byte *b=concat(b1, l1, b2, l2);
    calc_sha1(b, l1 + l2, hash);
    free(b);
}

byte *get_key0_sha1(t_password k, int block_size){
    // получаем k0 из k, равный размеру блока block_size
    byte *k0 = NULL;
    if (PASSWORD_LENGTH == block_size){
        // если длина k = размеру блока block_size, то k0=k
        k0 = concat(k, block_size, NULL, 0);
    } else {
        if (PASSWORD_LENGTH < block_size) {
            // если длина ключа k < размеру блока block_size, то k0 - это дополнение k справа нулями
            int l = block_size - PASSWORD_LENGTH;
            byte *z = calloc(l, sizeof(byte));
            k0 = concat(k, PASSWORD_LENGTH, z, l);
            free(z);
        } else {
            // если длина ключа k > размера блока block_size, то k0 - это hash от k + дополнение справа нулями
            t_digest_sha1 hash1;
            calc_sha1(k, PASSWORD_LENGTH, hash1);
            byte *z = NULL;
            int l = block_size - DIGEST_LENGTH_SHA1;
            if (l>0)
                z = calloc(l, sizeof(byte));
            else
                l=0;
            int l1 = block_size - l;
            k0 = concat(hash1, l1, z, l);
            if (z) free(z);
        }
    }
    return k0;
}

int hmac_sha1(byte *text, int n, t_password k, int block_size, t_digest_sha1 hash){
    // получаем k0 из k, равный размеру блока block_size
    byte *k0 = get_key0_sha1(k, block_size);
    if (k0==NULL)
        return 0;

    // HMAC_k (text)= H ( (K0 ^ opad) || H( (K0 ^ ipad) || text ) )
    t_digest_sha1 hash1;
    byte *pad;

    // выражение hash1 = H( (K0 ^ ipad) || text )
    pad = i_pad(k0, block_size);
    hash_concat_sha1(pad, block_size, text, n, hash1);
    free(pad);

    // выражение HMAC = H( (K0 ^ opad) || hash1 )
    pad = o_pad(k0, block_size);
    hash_concat_sha1(pad, block_size, hash1, DIGEST_LENGTH_SHA1, hash);
    free(pad);

    return 1;
}

byte *get_key_hmac_md5(t_password k, t_nonce nonce, int block_size){
    int hmac_len=DIGEST_LENGTH_MD5;
    if (block_size>2*hmac_len){
        printf("can not create key: block size %d is greater then %d", block_size, 2*hmac_len);
        return NULL;
    }

    byte *res=NULL;
    t_digest_md5 hmac1;
    hmac_md5(nonce, NONCE_LENGTH, k, block_size, hmac1);
    if (block_size<=hmac_len){
        res=concat(hmac1, block_size,NULL,0);
    } else
    {
        t_digest_md5 hmac2;
        hmac_md5(hmac1, hmac_len, k, block_size, hmac2);
        res=concat(hmac1, hmac_len, hmac2,block_size - hmac_len);
    }
    //debug("get_key_hmac_md5 k: ", res, block_size);
    return res;
}

byte *get_key_hmac_sha1(t_password k, t_nonce nonce, int block_size){
    int hmac_len=DIGEST_LENGTH_SHA1;
    if (block_size>2*hmac_len){
        printf("can not create key: block size %d is greater then %d", block_size, 2*hmac_len);
        return NULL;
    }

    byte *res=NULL;
    t_digest_sha1 hmac1;
    hmac_sha1(nonce, NONCE_LENGTH, k, block_size, hmac1);
    if (block_size<=hmac_len){
        res=concat(hmac1, block_size,NULL,0);
    } else
    {
        t_digest_sha1 hmac2;
        hmac_sha1(hmac1, hmac_len, k, block_size, hmac2);
        res=concat(hmac1, hmac_len, hmac2,block_size - hmac_len);
    }
    //debug("get_key_hmac_sha1 k: ", res, block_size);
    return res;
}

byte *get_key_hmac (int hash_type, t_password psw, t_nonce nonce, int block_size) {
    debug("get_key_hmac psw: ", psw, PASSWORD_LENGTH);
    debug("get_key_hmac nonce: ", nonce, NONCE_LENGTH);
    if (is_debug)
      printf("get_key_hmac hash_type=%d, block_size=%d\n", hash_type, block_size);
    byte *res=NULL;
    if (hash_type==HASH_TYPE_MD5)
        res = get_key_hmac_md5(psw, nonce, block_size);
    else
    if (hash_type==HASH_TYPE_SHA1)
        res = get_key_hmac_sha1(psw, nonce, block_size);
    else
        printf("Unknown hash type %d\n", hash_type);
    debug("get_key_hmac k: ", res, block_size);
    return res;
}

void gen_rand_bytes (byte *b, int size){
    for (int i=0; i < size; i++)
        b[i] = rand() % 256;
}

byte *create_rand_bytes (int size){
    byte *b = calloc(size, sizeof (byte));
    gen_rand_bytes (b, size);
    return b;
}

void gen_nonce(t_nonce nonce){
    gen_rand_bytes(nonce, NONCE_LENGTH);
}

int get_block_size(int enc_type){
    //if (enc_type==ENC_TYPE_3DES)
    //    return KEY_LENGTH_3DES;
    if (enc_type==ENC_TYPE_AES128)
        return KEY_LENGTH_AES128;
    if (enc_type==ENC_TYPE_AES192)
        return  KEY_LENGTH_AES192;
    if (enc_type==ENC_TYPE_AES256)
        return  KEY_LENGTH_AES256;
    printf("Unknown encode type %d\n", enc_type);
    return 0;
}

byte *gen_iv (int enc_type, int *block_size){
    *block_size = get_block_size(enc_type);
    if (*block_size > 0)
        return create_rand_bytes(*block_size);
    printf("Can not generate ini vector\n");
    return NULL;
}

int encode_buf (t_buffer *buf_in, t_buffer *buf_out, int enc_type, byte *k, byte *iv){
    if (enc_type==ENC_TYPE_3DES)
        return encode_buf_3DES(buf_in, buf_out, k, iv);
    if (enc_type==ENC_TYPE_AES128)
        return encode_buf_AES128(buf_in, buf_out, k, iv);
    if (enc_type==ENC_TYPE_AES192)
        return encode_buf_AES192(buf_in, buf_out, k, iv);
    if (enc_type==ENC_TYPE_AES256)
        return encode_buf_AES256(buf_in, buf_out, k, iv);
    printf("Error on encode_buf: unknown encode type %d\n", enc_type);
    return 0;
};

int decode_buf (t_buffer *buf_in, t_buffer *buf_out, int enc_type, byte *k, byte *iv){
    if (enc_type==ENC_TYPE_3DES)
        return decode_buf_3DES(buf_in, buf_out, k, iv);
    if (enc_type==ENC_TYPE_AES128)
        return decode_buf_AES128(buf_in, buf_out, k, iv);
    if (enc_type==ENC_TYPE_AES192)
        return decode_buf_AES192(buf_in, buf_out, k, iv);
    if (enc_type==ENC_TYPE_AES256)
        return decode_buf_AES256(buf_in, buf_out, k, iv);
    return 0;
};

int encode_f (byte *text, int n, t_password psw, int hash_type, int enc_type, FILE *f_out){
    int res = 0;
    fwrite(HEADER_ENC, strlen(HEADER_ENC), 1, f_out);
    byte b;
    b = hash_type;
    fwrite(&b, sizeof (byte), 1, f_out);
    b = enc_type;
    fwrite(&b, sizeof (byte), 1, f_out);

    // NONCE
    t_nonce nonce;
    gen_nonce(nonce);
    fwrite(nonce, NONCE_LENGTH, 1, f_out);

    // IV
    int block_size;
    byte *iv = gen_iv(enc_type, &block_size);
    if (!(iv==NULL)){
        fwrite(iv, block_size, 1, f_out);

        // ключ шифрования
        byte *k = get_key_hmac(hash_type, psw, nonce, block_size);
        if (!(k==NULL)) {
            // Буфер: 8 нулей + текст
            t_buffer *buf_in = buffer_create();
            buffer_write(buf_in, ZERO_HEAD, ZERO_HEAD_LENGTH);
            buffer_write(buf_in, text, n);

            // шифруем буфер
            t_buffer *buf_out = buffer_create();
            res = encode_buf(buf_in, buf_out, enc_type, k, iv);
            if (res)
                fwrite(buf_out->data, buf_out->len, 1, f_out);
            else
                printf("Error on encode_f: can not encode buffer\n");

            buffer_free(&buf_out);
            buffer_free(&buf_in);
            free(k);
        }
        free(iv);
    }
    return res;
}

char *psw_to_hex(t_password psw){
    char *hex = calloc(PASSWORD_LENGTH*2+1, sizeof (char));
    for(int i=0; i < PASSWORD_LENGTH; i++){
        hex[2*i+1] = HEX_CHARS[psw[i] % 16];
        hex[2*i] = HEX_CHARS[(psw[i] / 16) % 16];
    }
    return hex;
}

char *get_enc_file_name(t_password psw, int hash_type, int enc_type){
    // возьмем имя файла с запасом
    char *name = calloc(40, sizeof (char));

    if (hash_type==HASH_TYPE_MD5)
        strcat(name, "md5_");
    if (hash_type==HASH_TYPE_SHA1)
        strcat(name, "sha1_");

    if (enc_type==ENC_TYPE_3DES)
        strcat(name, "3des_");
    if (enc_type==ENC_TYPE_AES128)
        strcat(name, "aes128_");
    if (enc_type==ENC_TYPE_AES192)
        strcat(name, "aes192_");
    if (enc_type==ENC_TYPE_AES256)
        strcat(name, "aes256_");

    char *hex = psw_to_hex(psw);
    strcat(name, hex);
    free(hex);
    strcat(name, ".enc");
    return name;
}

char *get_enc_file_path(char *dir_out, t_password psw, int hash_type, int enc_type){
    char *file_name = get_enc_file_name(psw, hash_type, enc_type);
    char *file_path;
    if (dir_out){
        file_path = calloc(strlen(file_name) + strlen(dir_out) + 2, sizeof (char));
        strcat(file_path, dir_out);
        if ((!(file_path[strlen(file_path)-1]=='/')) && (!(file_path[strlen(file_path)-1]=='\\')))
            strcat(file_path, "/");
    } else {
        file_path = calloc(strlen(file_name) + 1, sizeof (char));
    }
    strcat(file_path, file_name);
    free(file_name);
    return  file_path;
}


int encode (byte *text, int n, t_password psw, int hash_type, int enc_type, char *dir_out){
    int res = 0;

    char *file_path = get_enc_file_path(dir_out, psw, hash_type, enc_type);
    FILE *f_out = fopen(file_path,"wb+");
    if (f_out) {
        res = encode_f(text, n, psw, hash_type, enc_type, f_out);
        fclose(f_out);
    } else {
        printf("Can not open file %s\n",file_path);
    }

    free(file_path);
    return res;
}

void do_generate(t_password psw, int hash_type, int enc_type, char *dir_out){
    byte *text="test1234567890";
    encode(text, strlen(text), psw, hash_type, enc_type, dir_out);
}

char *extract_file_name(const char *file_path){
    if (!file_path)
        return NULL;
    // ищем с конца разделитель
    int i=strlen(file_path);
    if (i==0)
        return NULL;
    while (i>=0){
        if (file_path[i]=='/')
            break;
        if (file_path[i]=='\\')
            break;
        i--;
    }
    if (i<0)
        i = 0;
    else
        i++;                ;
    int len = strlen(file_path) - i;
    if (len==0)
        return NULL;
    char *file_name=calloc(len+1, sizeof(char));
    memcpy(file_name, file_path+i, len);
    return file_name;
}

char *str_shift_to(char *s, char c){
    if (s) {
        int len = strlen(s);
        for (int i=0; i<len; i++)
            if (s[i]==c)
                return s+i+1;
    }
    return NULL;
}

int str_is(char *s, int len, const char *tpl){
    if (len == strlen(tpl)){
        for(int i=0; i<len; i++)
            if (s[i] != tpl[i])
                return 0;
        return 1;
    } else
        return 0;

}

int str_to_hash_type(char *s, int len, int *p_type){
    int res = 1;
    if (str_is(s, len, "md5"))
        *p_type = HASH_TYPE_MD5;
    else
    if (str_is(s, len, "sha1"))
        *p_type = HASH_TYPE_SHA1;
    else
        res = 0;
    return res;
}

int str_to_enc_type(char *s, int len, int *p_type){
    int res = 1;
    if (str_is(s, len, "3des"))
        *p_type = ENC_TYPE_3DES;
    else
    if (str_is(s, len, "aes128"))
        *p_type = ENC_TYPE_AES128;
    else
    if (str_is(s, len, "aes192"))
        *p_type = ENC_TYPE_AES192;
    else
    if (str_is(s, len, "aes256"))
        *p_type = ENC_TYPE_AES256;
    else
        res = 0;
    return res;
}

int str_to_psw(char *s, int len, t_password psw){
    if (!(len==PASSWORD_LENGTH*2))
        return 0;
    for (int i=0; i<PASSWORD_LENGTH; i++){
        char *c1=strchr(HEX_CHARS,s[2*i]);
        char *c2=strchr(HEX_CHARS,s[2*i+1]);
        if ((c1 != NULL) && (c2 != NULL))
            psw[i] = (c1-HEX_CHARS)*16 + (c2-HEX_CHARS);
        else
            return 0;
    }
    return 1;
}

int parse_file_name(char *file_path, int *p_hash_type, int *p_enc_type, t_password psw){
    char *file_name = extract_file_name(file_path);
    if (!file_name)
        return 0;
    char *c_hash = file_name;                   // начало типа хэша
    char *c_enc = str_shift_to(c_hash, '_'); // начало типа шифра
    char *c_psw = str_shift_to(c_enc, '_');  // начало пароля
    char *c_ext = str_shift_to(c_psw, '.');  // начало расширения
    int res=0;
    if ((c_hash != NULL) && (c_enc != NULL) && (c_psw != NULL) && (c_ext != NULL)) {
        if (str_to_hash_type(c_hash, c_enc-c_hash-1, p_hash_type))
            if (str_to_enc_type(c_enc, c_psw-c_enc-1, p_enc_type))
                if (str_to_psw(c_psw, c_ext-c_psw-1, psw))
                    if (str_is(c_ext, strlen(file_name) - (c_ext - file_name),"enc"))
                        res = 1;
    }
    free(file_name);
    return res;
}

int read_enc_file_data(FILE *f_in, t_buffer *buf_in){
    int res = 1;
    byte b;
    while(fread(&b, sizeof(byte), 1, f_in)) {
        if (!buffer_write(buf_in, &b, 1)){
            res = 0;
            break;
        }
    }
    return res;
}

int read_enc_file(FILE *f_in, int *p_hash_type, int *p_enc_type, t_nonce nonce, byte **iv, int *p_block_size, t_buffer *buf_in){
    int res = 0;
    *iv = NULL;
    char buf[strlen(HEADER_ENC)];
    if (fread(buf, strlen(HEADER_ENC), 1, f_in)){
        if (strcmp(buf, HEADER_ENC)==0){
            byte b;
            if (fread(&b, sizeof(byte), 1, f_in)){
                *p_hash_type = b;
                if ((*p_hash_type == HASH_TYPE_MD5) || (*p_hash_type == HASH_TYPE_SHA1)) {
                    if (fread(&b, sizeof(byte), 1, f_in)){
                        *p_enc_type = b;
                        *p_block_size = get_block_size(*p_enc_type);
                        if ((*p_block_size>0)) {
                            if (fread(nonce, NONCE_LENGTH, 1, f_in)){
                                *iv = calloc(*p_block_size, 1);
                                if (fread(*iv, *p_block_size, 1, f_in)){
                                    res = read_enc_file_data(f_in, buf_in);
                                } else
                                    printf("Can not read ini vector\n");
                            } else
                                printf("Can not read nonce\n");
                        } else
                            printf("Invalid block size for enc_type %d\n", *p_enc_type);
                    } else
                        printf("Can not read enc_type\n");
                } else
                    printf("Unknown hash_type %d\n", *p_hash_type);
            } else
                printf("Can not read hash_type\n");
        } else
            printf("Invalid header %s\n", buf);
    }
    return res;
}

int buf_have_zero8(t_buffer *buf){
    for (int i=0; (i<ZERO_HEAD_LENGTH) && (i<buf->len); i++) {
        if (!(ZERO_HEAD[i] == (buf->data)[i]))
            return 0;
    }
    return 1;
}

int verify_f(FILE *f_in, t_password psw, int hash_type, int enc_type){
    int res = 0;
    t_buffer *buf_in=buffer_create();
    t_buffer *buf_out=buffer_create();
    int hash_type1;
    int enc_type1;
    t_nonce nonce;
    byte *iv = NULL;
    int block_size;
    if (read_enc_file(f_in, &hash_type1, &enc_type1, nonce, &iv, &block_size, buf_in)){
        if ((hash_type1==hash_type) && (enc_type1==enc_type)){
            byte *k = get_key_hmac(hash_type, psw, nonce, block_size);
            if (!(k==NULL)) {
                if (decode_buf(buf_in, buf_out, enc_type, k, iv)) {
                    res = buf_have_zero8(buf_out);
                } else
                    printf("Can not decode file data\n");
                free(k);
            }
        } else
            printf("File name and file data have different hash or encode types: hash %d =? %d,  enc %d =? %d\n", hash_type1, hash_type, enc_type1, enc_type);
    }
    if (iv)
        free(iv);
    buffer_free(&buf_out);
    buffer_free(&buf_in);
    return res;
}

int verify(char *file_path){
    t_password psw;
    int hash_type;
    int enc_type;
    if (!parse_file_name(file_path , &hash_type, &enc_type, psw))
        return 0;
    int res = 0;
    FILE *f_in = fopen(file_path,"rb+");
    if (f_in) {
        res = verify_f(f_in, psw, hash_type, enc_type);
        fclose(f_in);
    } else {
        printf("Can not open file %s\n",file_path);
    }
    return res;
}

void do_verify(char *file_path){
    if (verify(file_path))
        printf("True\n");
    else
        printf("False\n");
}

void init_rand(){
    srand(time(NULL));
}

void psw_copy(t_password psw, t_password psw0){
    for (int i=0; i<PASSWORD_LENGTH; i++)
        psw[i]=psw0[i];
}

int get_next_psw(t_password psw){
    int i=PASSWORD_LENGTH-1;
    while (1) {
        psw[i] = psw[i] + 1;
        if (psw[i]==0){
            if (i==0)
                return 0;
            else
                i--;
        } else
            return 1;
    }
}

void print_hash_enc_type(int hash_type, int enc_type){
    if (hash_type==HASH_TYPE_MD5)
        printf("HMAC_MD5");
    if (hash_type==HASH_TYPE_SHA1)
        printf("HMAC_SHA1");

    printf(", ");

    if (enc_type==ENC_TYPE_3DES)
        printf("3DES");
    if (enc_type==ENC_TYPE_AES128)
        printf("AES128");
    if (enc_type==ENC_TYPE_AES192)
        printf("AES192");
    if (enc_type==ENC_TYPE_AES256)
        printf("AES256");

    printf("\n");
}

void print_current_speed(t_password psw0, t_password psw, double speed){
    print_buf1("Current: ", psw0, PASSWORD_LENGTH);
    print_buf1("-", psw, PASSWORD_LENGTH);
    printf(" | Speed: %.0f c/s\n", speed);
}

int crack_f(FILE *f_in, t_password psw, int *count, int is_show){
    int res = 0;
    int step = 0xffff;
    *count = 1;
    t_buffer *buf_in=buffer_create();
    t_buffer *buf_out=buffer_create();
    int hash_type;
    int enc_type;
    t_nonce nonce;
    byte *iv = NULL;
    int block_size;
    if (read_enc_file(f_in, &hash_type, &enc_type, nonce, &iv, &block_size, buf_in)){
        if (is_show){
            printf("Valid file!\n");
            print_hash_enc_type(hash_type, enc_type);
            print_buf("NONCE: ", nonce, NONCE_LENGTH);
            print_buf("IV: ", iv, block_size);
            print_buf("CT: ", buf_in->data, buf_in->len);
        }
        t_password psw0={0};
        psw_copy(psw, psw0);
        clock_t time_start = clock();
        do {
            byte *k = get_key_hmac(hash_type, psw, nonce, block_size);
            if (!(k==NULL)) {
                if (decode_buf(buf_in, buf_out, enc_type, k, iv)) {
                    res = buf_have_zero8(buf_out);
                    if (res){
                        free(k);
                        break;
                    }
                } else{
                    printf("Can not decode file data\n");
                    free(k);
                    break;
                }
                free(k);
            } else {
                printf("Can not get HMAC KEY\n");
                break;
            }
            if ((*count % step)==0){
                double dt = (double)(clock()-time_start)/CLOCKS_PER_SEC;
                print_current_speed(psw0, psw, step/dt);
                time_start = clock();
                psw_copy(psw0, psw);
            }
            *count = *count + 1;
        } while (get_next_psw(psw));
    } else
        printf("File incorrect\n");
    if (iv)
        free(iv);
    buffer_free(&buf_out);
    buffer_free(&buf_in);
    return res;
}

void crack(char *file_path, int is_show){
    FILE *f_in = fopen(file_path,"rb+");
    if (f_in) {
        t_password psw;
        clock_t time_start = clock();
        int count;
        if (crack_f(f_in, psw, &count, is_show)){
            double dt = (double)(clock()-time_start)/CLOCKS_PER_SEC;
            char *hex = psw_to_hex(psw);
            printf("Found: %s | Speed: %.0f c/s\n", hex, count/dt);
            free(hex);
        }
        fclose(f_in);
    } else {
        printf("Can not open file %s\n",file_path);
    }
}
