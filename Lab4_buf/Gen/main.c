#include "lib_crypt.h"

int main(int argc, char *argv[]) {
    if (argc<4) {
        printf("Incorrect number of parameters");
        return 0;
    }
    init_rand();
    int res=0;
    int hash_type, enc_type;
    t_password psw;
    if (str_to_hash_type(argv[2], strlen(argv[2]), &hash_type))
        if (str_to_enc_type(argv[3], strlen(argv[3]), &enc_type))
            if (str_to_psw(argv[1], strlen(argv[1]), psw)){
                do_generate(psw, hash_type, enc_type, NULL);
                res = 1;
            }
    if (!res)
        printf("Incorrect parameters");

    return 0;
}
