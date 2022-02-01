#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>

#define MAX_TASK_COUNT 32
#define JOB_ID_MD5 1
#define JOB_ID_SHA 2
#define JOB_ID_AES128 3
#define JOB_ID_AES256 4

#define KEY_LENGTH_AES128 16
#define KEY_LENGTH_AES256 32
#define MAX_KEY_LENGTH KEY_LENGTH_AES256
#define MAX_WORD_SIZE 80


// параметры запуска
typedef struct run_params_t{
    int task_count;
    char *data_file_path;
    char *out_file_path;
    char *alg_str;
    char *task_count_str;
} run_params_t;

// дескрипторы ввода/вывода для главного процесса
int task_f_in[MAX_TASK_COUNT];  // дескриптор для записи сообщений для дочернего процесса
int task_f_out[MAX_TASK_COUNT]; // дескриптор для чтения сообщений от дочернего процесса
pid_t task_pid[MAX_TASK_COUNT]; // идентификатор дочернего процесса
int task_count=0; // количество дочерних процессов

// дескрипторы ввода/вывода для дочерних процессов
int f_in;
int f_out;

// параметры текущей задачи
FILE *file_in=NULL;   // файл с входными данными
FILE *file_out=NULL;  // файл с результатом работы
int main_job_id; // текущее задание

// параметры шифрования AES
char sec_key[MAX_KEY_LENGTH]; // буфер для секретного ключа (генерирует главный поток один на все дочерние)
int sec_key_length;           // реальная длина ключа

AES_KEY enc_key; // контекст ключа шифрования в терминах openssl


void task_init_job_AES(){
    AES_set_encrypt_key(sec_key, sec_key_length*8, &enc_key); // длина в битах!
    /*for (int i = 0; i < sec_key_length; i++){
        printf("%02x", sec_key[i]);
    }
    printf("\n");*/
}

void task_init_job(){
    switch (main_job_id) {
        case JOB_ID_AES128:
        case JOB_ID_AES256:
            task_init_job_AES();
            break;
        default:{
        }
    }
}

char *task_read_data(int max_size){
    char *data= calloc(1, (max_size)*sizeof(char));
    ssize_t n = read(f_out, data, max_size);
    if (n < 0) {
        free(data);
        data = NULL;
        printf("Task %d: read pipe error\n", getpid());
    }
    return data;
}

int task_write_answer(char *buf, int len){
    if (write(f_in, buf, len) != len) {
        close(f_in);
        return 0;
    }
    return 1;
}

int task_make_job_MD5(){
    int res=0;
    char *word=task_read_data(MAX_WORD_SIZE + 1);
    if (word){
        char hash[MD5_DIGEST_LENGTH];
        MD5(word, strlen(word), hash);
        res=task_write_answer(hash, MD5_DIGEST_LENGTH);
        free(word);
    }
    return res;
}

int task_make_job_SHA(){
    int res=0;
    char *word=task_read_data(MAX_WORD_SIZE + 1);
    if (word){
        char hash[SHA_DIGEST_LENGTH];
        SHA1(word, strlen(word), hash);
        res=task_write_answer(hash, SHA_DIGEST_LENGTH);
        free(word);
    }
    return res;
}

int task_make_job_AES(){
    int res=0;
    char *buf=task_read_data(AES_BLOCK_SIZE);
    if (buf){
        char buf_out[AES_BLOCK_SIZE];
        AES_ecb_encrypt(buf, buf_out, &enc_key, AES_ENCRYPT);
        res=task_write_answer(buf_out, AES_BLOCK_SIZE);
        free(buf);
    }
    return res;
}

int task_make_job(){
    switch (main_job_id) {
        case JOB_ID_MD5:
            return task_make_job_MD5();
            break;
        case JOB_ID_SHA:
            return task_make_job_SHA();
            break;
        case JOB_ID_AES128:
        case JOB_ID_AES256:
            return task_make_job_AES();
            break;
        default:{
            printf("unknown job %d\n", main_job_id);
        }
    }
}

// основная процедура работы задачи (процесса)
void run_task(){
    pid_t pid=getpid();
    printf("run_task %d f_in=%d, f_out=%d\n", pid, f_in, f_out);
    int flag;
    ssize_t n;
    task_init_job();
    while (1){
        // читаем флаг: 1 - выполнить работу, 0 - завершить работу
        if ((n = read(f_out, &flag, sizeof (int))) < 0) {
            close(f_in);
            printf("Task %d: read pipe error\n", pid);
            exit(1);
        }
        else
            if (n){
                if (flag == 0){
                    // флаг 0 - завершить работу
                    printf("Exit task %d\n", pid);
                    close(f_in);
                    exit(0);
                } else {
                    // флаг 1 - выполнить работу
                    if (!task_make_job()){
                        close(f_in);
                        exit(1);
                    }
                }
            }
    }
}

int run_proc(){
    int res = 0;
    int fd_out[2];
    int fd_in[2];
    if (pipe(fd_in) == 0){
        if (pipe(fd_out) == 0){
            pid_t pid;
            if ((pid = fork()) < 0)
                printf("Cannot start thread\n");
            else
                if (pid > 0){
                    //Родительский процесс
                    int task_num = task_count;
                    task_pid[task_num] = pid;
                    close(fd_in[0]);
                    task_f_in[task_num] = fd_in[1];
                    close(fd_out[1]);
                    task_f_out[task_num] = fd_out[0];
                    res = 1;
                    task_count++;
                } else {
                    //Дочерний процесс
                    close(fd_in[1]);
                    f_out = fd_in[0];
                    close(fd_out[0]);
                    f_in = fd_out[1];
                    run_task();
                }
        } else {
            printf("Cannot open pipe out\n");
        }
    } else {
        printf("Cannot open pipe in\n");
    }
    return res;
}

char *read_file_data(size_t block_size){
    char *res= calloc(1, (block_size + 1)*sizeof(char));
    if (! fread(res, 1, block_size, file_in)){
        // конец файла
        // printf("End of file\n");
        free(res);
        res = NULL;
    }
    return res;
}

char *read_file_word(){
    char *word= calloc(1, (MAX_WORD_SIZE + 1)*sizeof(char));
    int len=0;
    char c;
    while (len<MAX_WORD_SIZE){
        if (! fread(&c, 1, 1, file_in))
            break;
        if (ispunct(c) || isspace(c)){
            if (len)
                break;
        } else {
            word[len] = c;
            len++;
        }
    }
    if (len==0){
        free(word);
        word = NULL;
    }
    return word;
}

int send_job_flag(int task_num, int flag){
    if (write(task_f_in[task_num], &flag, sizeof(int)) == sizeof(int))
        return 1;
    else
        return 0;
}

int send_flag_work(int task_num){
    return send_job_flag(task_num ,1);
}

int send_flag_stop(int task_num){
    return send_job_flag(task_num ,0);
}

int send_job_hash_word(int task_num){
    int res=0;
    char *buf=read_file_word();
    if (buf){
        int len=strlen(buf);
        if (send_flag_work(task_num)) {
            if (write(task_f_in[task_num], buf, len) == len) {
                res=1;
            }
        }
        free(buf);
    }
    return res;
}

int send_job_MD5(int task_num){
    return send_job_hash_word(task_num);
}

int send_job_SHA(int task_num){
    return send_job_hash_word(task_num);
}

int send_job_AES(int task_num){
    int res=0;
    char *buf=read_file_data(AES_BLOCK_SIZE);
    if (buf){
        if (send_flag_work(task_num)) {
            if (write(task_f_in[task_num], buf, AES_BLOCK_SIZE) == AES_BLOCK_SIZE) {
                res=1;
            }
        }
        free(buf);
    }
    return res;
}

int send_job(int task_num){
    switch (main_job_id) {
        case JOB_ID_MD5:
            return send_job_MD5(task_num);
        case JOB_ID_SHA:
            return send_job_SHA(task_num);
        case JOB_ID_AES128:
        case JOB_ID_AES256:
            return send_job_AES(task_num);
        default:{
            printf("unknown job %d\n", main_job_id);
            return 0;
        }
    }
}

int open_in_out_files(run_params_t *params){
    file_in = fopen(params->data_file_path,"rb");
    if (file_in) {
        file_out = fopen(params->out_file_path,"wb");
        if (file_out) {
        } else {
            fclose(file_in);
            printf("Can not open out file %s\n", params->out_file_path);
            return 0;
        }
    } else {
        printf("Can not open in file %s\n", params->data_file_path);
        return 0;
    }
    return 1;
}

void gen_rand_bytes (char *b, int size){
    for (int i=0; i < size; i++)
        b[i] = rand() % 256;
}

int init_job_MD5(){
    return 1;
}

int init_job_SHA(){
    return 1;
}

int init_job_AES(int key_length){
    sec_key_length = key_length;
    gen_rand_bytes(sec_key, sec_key_length);
    return 1;
}

void init_rand(){
    srand(time(NULL));
}

int init_job(run_params_t *params){
    if (! open_in_out_files(params))
        return 0;
    init_rand();
    switch (main_job_id) {
        case JOB_ID_MD5:
            return init_job_MD5();
        case JOB_ID_SHA:
            return init_job_SHA();
        case JOB_ID_AES128:
            return init_job_AES(KEY_LENGTH_AES128);
        case JOB_ID_AES256:
            return init_job_AES(KEY_LENGTH_AES256);
        default:{
            printf("unknown job %d\n", main_job_id);
            return 0;
        }
    }
}

void done_job(){
    if (file_in)
        fclose(file_in);
    if (file_out)
        fclose(file_out);
}

int send_job_for_tasks(){
  int job_count=0;
  for (int i=0; i<task_count; i++)
      if (send_job(i))
          job_count++;
      else
          break;
    return job_count;
}

char *read_job_answer(int task_num, int max_size){
    char *buf= calloc(1, (max_size)*sizeof(char));
    ssize_t n = read(task_f_out[task_num], buf, max_size);
    if (n < 0) {
        close(f_in);
        printf("Read answer pipe error\n");
        free(buf);
        buf=NULL;
    }
    return buf;
}

int write_job_answer(int task_num, int  size){
    int res=0;
    char *buf = read_job_answer(task_num, size);
    if (buf){
        if (!fwrite(buf, size, 1, file_out))
            printf("can not write out file\n");
        else
            res=1;
        free(buf);
    }
    return res;
}

int verify_job_MD5(int task_num){
    return write_job_answer(task_num, MD5_DIGEST_LENGTH);
}

int verify_job_SHA(int task_num){
    return write_job_answer(task_num, SHA_DIGEST_LENGTH);
}

int verify_job_AES(int task_num){
    return write_job_answer(task_num, AES_BLOCK_SIZE);
}

int verify_job(int task_num){

    switch (main_job_id) {
        case JOB_ID_MD5:
            return verify_job_MD5(task_num);
        case JOB_ID_SHA:
            return verify_job_SHA(task_num);
        case JOB_ID_AES128:
        case JOB_ID_AES256:
            return verify_job_AES(task_num);
        default:{
            printf("unknown job %d\n", main_job_id);
            return 0;
        }
    }
}

int verify_tasks_job(int job_count){
    for (int i=0; i<job_count; i++)
        if (!verify_job(i))
            return 0;
    return 1;
}

void run_main(double *dt){
    int job_count;
    clock_t time_start = clock();
    while (1) {
        job_count = send_job_for_tasks();
        if (job_count)
            verify_tasks_job(job_count);
        else {
            printf("Main exit\n");
            break;
        }

    }
    *dt = (double)(clock()-time_start)/CLOCKS_PER_SEC;
}

int str_to_job_id(char *s, int *id){
    int res = 1;
    if (strcmp(s, "md5"))
        *id = JOB_ID_MD5;
    else
    if (strcmp(s, "sha"))
        *id = JOB_ID_SHA;
    else
    if (strcmp(s, "aes128"))
        *id = JOB_ID_AES128;
    else
    if (strcmp(s, "aes256"))
        *id = JOB_ID_AES256;
    else
        res = 0;
    return res;
}

int check_params(run_params_t *params){
    // alg
    if (params->alg_str) {
        if (!str_to_job_id(params->alg_str, &main_job_id)) {
            printf("Bad alg %s\n", params->alg_str);
            return 0;
        }
    } else
        main_job_id = JOB_ID_AES128;

    // task_count
    if (params->task_count_str)
        params->task_count=atoi(params->task_count_str);
    else
        params->task_count=4;
    if (params->task_count>MAX_TASK_COUNT){
        printf("Task count %d mustn't be great then %d\n", params->task_count, MAX_TASK_COUNT);
        return 0;
    }
    if (params->task_count<1){
        printf("Task count %d mustn't be less then 1\n", params->task_count);
        return 0;
    }

    if (params->data_file_path == NULL)
        params->data_file_path="in.txt";
    if (params->out_file_path == NULL)
        params->out_file_path="out.txt";

    return 1;
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

int read_params(int argc, char *argv[], run_params_t *params){
    params->data_file_path=NULL;
    params->out_file_path=NULL;
    params->alg_str=NULL;
    params->task_count_str=NULL;

    int is_help=0;
    const char* short_options = "i:o:a:t:h";

    const struct option long_options[] = {
            { "input", required_argument, NULL, 'i' },
            { "output", required_argument, NULL, 'o' },
            { "alg", required_argument, NULL, 'a' },
            { "tasks", required_argument, NULL, 't' },
            { "help", no_argument, NULL, 'h' },
            { NULL, 0, NULL, 0 }
    };

    char rez;
    int option_index;
    while ((rez=getopt_long(argc, argv, short_options, long_options, &option_index))!=-1){
        switch(rez){
            case 'h': {
                is_help = 1;
                break;
            };
            case 'i': {
                if (!set_param(&(params->data_file_path), rez, optarg))
                    is_help = 1;
                break;
            };
            case 'o': {
                if (!set_param(&(params->out_file_path), rez, optarg))
                    is_help = 1;
                break;
            };
            case 'a': {
                if (!set_param(&(params->alg_str), rez, optarg))
                    is_help = 1;
                break;
            };
            case 't': {
                if (!set_param(&(params->task_count_str), rez, optarg))
                    is_help = 1;
                break;
            };
            case '?': default: {
                is_help = 1;
                printf("found unknown option\n");
                break;
            };
        };
    };
    if (is_help)
        return 0;
    else
        return check_params(params);
}

void print_help(){
    printf("Use options:\n");
    printf("  -h (--help) print this help.\n");
    printf("  -i (--input) input file path (default \"in.txt\")\n");
    printf("  -o (--output) output file path (default \"out.txt\")\n");
    printf("  -a (--alg) md5, sha, aes128, aes256 (if not set - use default aes128)\n");
    printf("  -t (--tasks) tasks count (child processes count, default 4)\n");
}

int start_tasks(int count){
    printf("Total tasks %d\n", count);
    for (int i=0; i<count; i++)
        if (!run_proc()) {
            printf("Can not start all processes\n");
            return 0;
        }
    return 1;
}

void stop_task(int task_num){
    if (!send_flag_stop(task_num)) {
        printf("Can not send break flag for task %d (pid=%d)\n", task_num, task_pid[task_num]);
    } else {
        waitpid(task_pid[task_num], NULL, 0);
        printf("Finished task %d (pid=%d)\n", task_num, task_pid[task_num]);
    }
}

void stop_tasks(){
    for (int i=0; i<task_count; i++)
        stop_task(i);
}

int main(int argc, char *argv[]) {
    run_params_t params;
    if (read_params(argc, argv, &params)){
        if (init_job(&params)){
            double dt;
            int ok=0;
            if (start_tasks(params.task_count)){
                run_main(&dt);
                ok=1;
            }
            stop_tasks();
            done_job();
            if (ok)
                printf("Total time: %.8f s\n", dt);
        }
    } else
        print_help();
    exit(0);
}