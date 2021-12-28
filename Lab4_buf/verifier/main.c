#include "lib_crypt.h"

int main(int argc, char *argv[]) {
    if (argc<2) {
        printf("Incorrect number of parameters");
        return 0;
    }
    init_rand();
    do_verify(argv[1]);
    return 0;
}
