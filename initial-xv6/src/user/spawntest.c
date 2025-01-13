#include "kernel/types.h"
#include "kernel/stat.h"
#include "user.h"

int main(void) {
    int pid = fork(); // Create a new process
    int status;
    
    if(pid < 0) {
        // Fork failed
        printf("Fork failed!\n");
    } else if(pid == 0) {
        // Child process
        int gpid = fork();
        int gstatus;
        if(gpid<0){
            printf("Fork Failed\n");
        }
        else if(gpid==0){
            printf("Grand Child process. PID: %d\n", getpid());
        }
        else{
            wait(&gstatus);
            printf("Child process. PID: %d\n", getpid());
        }
    } else {
        // Parent process
        wait(&status); // Wait for the child process to finish
        printf("Parent process. PID: %d\n", getpid());
    }
    exit(0); // Exit the process
}
