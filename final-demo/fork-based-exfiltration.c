#include<stdio.h>
#include<stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char* argv[]) {

    if(argc != 3) {
        printf("Usage: ./output_file_name <in_file> <out_file>\n");
        return EXIT_FAILURE;
    }

    FILE *f = fopen(argv[1], "r");

    char read_buffer[1024];

    if(f) {
        fgets(read_buffer, 1024, f);
    }
    else {
        printf("Unable to open %s.\n", argv[1]);
    }

    pid_t pid = fork();

    if(pid < 0) {
        printf("Fork failed. Aborting.\n");
        exit(1);
    }
    else if(pid == 0) {
        printf("In the child process. Child PID: %d\n", getpid());

        FILE *fout = fopen(argv[2], "w");

        if(fout) {
            fputs(read_buffer, fout);
            fclose(fout);
            printf("File %s was created and written to successfully\n", argv[2]);
        } 
        else {
            printf("Unable to create file %s\n", argv[2]);
        }
    }
    else {
        printf("This is the parent with PID %d\n", getpid());
        fclose(f);
    }

    return EXIT_SUCCESS;
}