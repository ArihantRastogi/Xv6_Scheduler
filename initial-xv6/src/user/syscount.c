// In user/syscount.c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/syscall.h"

int
main(int argc, char *argv[])
{
    if(argc < 3){
        fprintf(2, "Usage: syscount <mask> <command> [args...]\n");
        exit(1);
    }
    int mask = atoi(argv[1]);  // Convert the mask argument to an integer
    if(getsyscount(mask) < 0){
        fprintf(2, "getsyscount failed\n");
        exit(1);
    }
    exec(argv[2], &argv[2]);
    return 0;
}
