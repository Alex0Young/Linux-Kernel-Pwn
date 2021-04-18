from pwn import *

vmlinux = ELF("./vmlinux")

base = 0xffffffff81000000
commit_creds_offset = vmlinux.symbols["commit_creds"] - base
print hex(commit_creds_offset) #0x9c8e0

prepare_kernel_cred = vmlinux.symbols["prepare_kernel_cred"] - base
print hex(prepare_kernel_cred) #0x9cce0

'''
ubuntu@ubuntu:~/Desktop$ checksec vmlinux
[*] '/home/ubuntu/Desktop/vmlinux'
    Arch:     amd64-64-little
    Version:  4.15.8
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0xffffffff81000000)
    RWX:      Has RWX segments
0x9c8e0
0x9cce0
'''