#include "lib_crypt.h"

int main(int argc, char *argv[]) {
    if ((argc<2) || (argc>3)) {
        printf("Incorrect number of parameters");
        return 0;
    }
    int is_show = 0;
    char *file_path;
    if (argc==2){
        file_path = argv[1];
    } else {
        if( (strcmp(argv[1], "-v") !=0 ) && (strcmp(argv[1], "--verbose") !=0 )){
            printf("Incorrect parameters");
            return 0;
        }
        is_show = 1;
        file_path = argv[2];
    }
    crack(file_path, is_show);
    return 0;
}
