#define _GNU_SOURCE
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include "include/config.h"
#include "include/queue.h"
#include "include/container.h"
#include "include/debug.h"


/*    __________  ___                                 */ 
/*   / __/ __/  |/  /                                 */
/*  / _// _// /|_/ /                                  */
/* /___/_/ /_/  /_/  Extreme Fuzzing Machine (2022)   */

/* Questions or anything? Contact: Joshua Williamson <1joshua.williamson@gmail.com> */

/* Welcome to EFM: most of this code is borrowed directly from the following chain of other borrows!*/
/*  \/  */
/* Program-smoothing: https://github.com/PoShaung/program-smoothing-fuzzing, credits to Po Shaung */
/*  \/  */
/* Neuzz: https://github.com/Dongdongshe/neuzz, credits to Dong Dong She */
/*  \/  */
/* AFL :(https://github.com/mirrorer/afl), credits to Michal Zalewski */

/* Terrible code warning: As I am a novice in C, I am forewarning that I have introduced some pretty hideous crimes to */
/*                        programming here. So if you spot any mistakes please tell me, I'd like to improve them. Also */
/*                        there are some very silly and unsafe things I've here that I aim to fix soon. Most notably   */
/*                        fixing buffer size allocations that will very very easily overflow with any larger file input*/ 
/*                        and making an area of shared memory that is pretty badly insucure. I will aim to make this   */
/*                        safer. So I reccomend you run this in a burner VM. Also as you probably know, fuzzing is     */
/*                        terrible for your hard drive, so please make the output diectory on a ram disk if you're     */
/*                        fuzzing on your own beloved hardware.                                                        */                           

/* Fork server init timeout multiplier: we'll wait the user-selected timeout plus this much for the fork server to spin up. */
#define FORK_WAIT_MULT      10
/* Environment variable used to pass SHM ID to the called program. */
#define SHM_ENV_VAR "__AFL_SHM_ID"
/* Local port to communicate with python module. */
#define PORT                12012
/* Maximum line length passed from GCC to 'as' and used for parsing configuration files. */
#define MAX_LINE            8192
/* Designated file descriptors for forkserver commands (the application will use FORKSRV_FD and FORKSRV_FD + 1). */
#define FORKSRV_FD          198
/* Distinctive bitmap signature used to indicate failed execution. */
#define EXEC_FAIL_SIG       0xfee1dead
/* Smoothing divisor for CPU load and exec speed stats (1 - no smoothing). */
#define AVG_SMOOTHING       16

/* Havoc stuff: */
/* Caps on block sizes for inserion and deletion operations. The set of numbers are adaptive to file length and the defalut max file length is 10000. */
/* default setting, will be changed later accroding to file len */

int havoc_blk_small = 2048;
int havoc_blk_medium = 4096;
int havoc_blk_large = 8192;

#define HAVOC_BLK_SMALL     32
#define HAVOC_BLK_MEDIUM    128
#define HAVOC_BLK_LARGE     1500
#define HAVOC_BLK_XL        32768

#define MEM_BARRIER() \
    asm volatile("" ::: "memory")
/* Map size for the traced binary. */
#define MAP_SIZE            2<<18
#define NN_MAP_SIZE         1024
 
#define R(x) (random() % (x))
#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)
#define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
 
/* Error-checking versions of read() and write() that call RPFATAL() as appropriate. */
#define ck_write(fd, buf, len, fn)                         \
  do {                                                     \
    u32 _len = (len);                                      \
    int _res = write(fd, buf, _len);                       \
    if (_res != _len)                                      \
      WARNFLOG("Short write to %d %s", _res, fn); \
  } while (0)

#define ck_read(fd, buf, len, fn)                           \
  do {                                                      \
    u32 _len = (len);                                       \
    int _res = read(fd, buf, _len);                         \
    if (_res != _len)                                       \
      WARNFLOG("Short read from %d %s", _res, fn); \
  } while (0)

/* User-facing macro to sprintf() to a dynamically allocated buffer. */
#define alloc_printf(_str...) ({          \
  char *_tmp;                             \
  int _len = snprintf(NULL, 0, _str);     \
  if (_len < 0)                           \
    WARNFLOG("Whoa, snprintf() fails?!");   \
  _tmp = malloc(_len + 1);                \
  snprintf((char *)_tmp, _len + 1, _str); \
  _tmp;                                   \
})

#define FLIP_BIT(_ar, _b)                     \
  do {                                        \
    u8* _arf = (u8*)(_ar);                    \
    u32 _bf = (_b);                           \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

#define SWAP16(_x) ({                 \
    u16 _ret = (_x);                  \
    (u16)((_ret << 8) | (_ret >> 8)); \
  })

#define SWAP32(_x) ({                   \
    u32 _ret = (_x);                    \
    (u32)((_ret << 24) | (_ret >> 24) | \
          ((_ret << 8) & 0x00FF0000) |  \
          ((_ret >> 8) & 0x0000FF00));  \
  })

/* Types */

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif /* ^__x86_64__ */

unsigned long execs_per_line=0;         /* Number of execs per line of gradient file explored*/

int write_nocov,                        /* Bool to write or not to write a nocov                            */
    nocov_statistic,                    /* Threshold for a number to be under for a nocov case to be written*/
    stage_cnt = 0,                      /* Operation counter for stats                                      */
    stage_tot = 200,                    /* Total operations in stage for stats                              */
    round_cnt = 0,                      /* Round number counter                                             */
    edge_gain = 0,                      /* If there is new edge gain                                        */
    exec_tmout = 1000,                  /* Exec timeout (ms)                                                */
    unique_crashes = 0,                 /* Amount of unique crashes found                                   */
    total_crashes = 0,                  /* Total crashes found                                              */
    unique_tmout = 0,                   /* Amount of unique tmout found                                     */
    total_tmout = 0,                    /* Total tmout found                                                */
    old = 0,                            /* Counting amount of old nocov files                               */
    now = 0,                            /* Amount of nocov files now                                        */
    log_warn = 0,                       /* Number of warnings in the log                                    */
    log_fatal = 0,                      /* Any fatal log entries                                            */
    kill_signal,                        /* Signal that killed the child                                     */
    loc[10000],                         /* Array to store critical bytes locations                          */
    sign[10000],                        /* Array to store sign of critical bytes                            */
    num_index[14] = {0, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192};
                                        /* Default setting, will change according to different file length  */


static int out_fd,                      /* Persistent fd for out_file       */
           dev_urandom_fd = -1,         /* Persistent fd for /dev/urandom   */
           dev_null_fd = -1,            /* Persistent fd for /dev/null      */
           fsrv_ctl_fd,                 /* Fork server control pipe (write) */
           fsrv_st_fd,                  /* Fork server status pipe (read)   */
           forksrv_pid,                 /* PID of the fork server           */
           child_pid = -1,              /* PID of the fuzzed program        */
           out_dir_fd = -1,             /* FD of the lock file              */
           nnforkexec_pid,              /* PID of fork executing python mod */
           start_nn = 1,                /* Arg to launch python mod or not  */
           shm_id,                      /* ID of the SHM region             */
           nn_shm_id,                   /* Shared memory with NN for stats  */
           mem_limit = 1024,            /* Maximum memory limit for target  */
           cpu_aff = -1,                /* Selected CPU core                */
           cpu_core_count,              /* CPU core count                   */
           mut_cnt = 0,                 /* Total mutation counter           */
           havoc_cnt = 0;               /* Total mutation counter by havoc  */

char *target_path,                      /* Path to target binary            */
     *trace_bits,                       /* SHM with instrumentation bitmap  */
     *nn_stats,                         /* Pointer to NN shared memory stats*/
     *fn = "-",                         /* Current file                     */
     *in_dir,                           /* Input directory with test cases  */
     *out_file,                         /* File to fuzz, if any             */
     *out_dir,                          /* Working & output directory       */
     *log_pth,                          /* Path for log file                */
     *nn_arr[9],                        /* Points shared mem stats segments */
     **nn_args,                        /* Array of args to pass to nn mod  */
     *out_buf,                          /* Bufs for mutation operations     */ 
     *out_buf1,                         /* Bufs for mutation operations     */
     *out_buf2,                         /* Bufs for mutation operations     */
     *out_buf3;                         /* Bufs for mutation operations     */

char virgin_bits[MAP_SIZE],             /* Regions yet untouched by fuzzing */
     crash_bits[MAP_SIZE],              /* Regions yet untouched by crashing*/
     tmout_bits[MAP_SIZE];              /* Regions yet untouched by tmouting*/

static u64 total_bitmap_size    = 0,    /* Total bit count for all bitmaps  */
           total_bitmap_entries = 0,    /* Number of bitmaps counted        */
           total_cal_cycles     = 0,    /* Total calibration cycles         */
           cur_depth            = 0,    /* Entry depth in queue             */
           start_time,                  /* Start time of fuzz               */
           grads_last,                  /* Time sinmce we last got gradients*/
           total_cal_us = 0,            /* Total calibration time (us)      */
           total_execs;                 /* Total number of execs            */

static volatile u8 stop_soon,           /* Ctrl-C pressed?                  */
                   child_timed_out,     /* Traced process timed out?        */
                   clear_screen = 1;    /* Window resized?                  */

static u8 log_msg_buf[2048],            /* Buffer for log information       */
          not_on_tty,                   /* Stdout is not tty                */
          term_too_small;               /* Is the terminal too small?       */

static u8 *use_banner,                  /* Display banner                   */
          *stage_name = "init";         /* Name of the current fuzz stage   */

static u32 queue_cycle = 0,             /* Counting fuzzed cycles           */
           stats_update_freq = 1,       /* Stats update frequency (execs)   */
           rand_cnt;                    /* Random number counter            */

size_t len=0;                           /* Maximum file length for every mutation */

static struct queue *queue_havoc;       /* Queue for muation in havoc stage */

struct file_container *file_container;  /* Store file list of Fuzz          */

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};

/*Logging*/

#define log(...)                                            \
  do {                                                      \
    sprintf(log_msg_buf, __VA_ARGS__);                      \
    time_t rawtime = time(NULL);                            \
    char strTime[100];                                      \
    strftime(strTime, sizeof(strTime), "%Y-%m-%d %H:%M:%S", \
             localtime(&rawtime));                          \
    FILE *f = fopen(log_pth,"a+");          \
    char log_buf[2048];                                     \
    sprintf(log_buf, "%s: %s \n", strTime, log_msg_buf);    \
    fputs(log_buf, f);                                      \
    fclose(f);                                              \
  } while (0)

/* Spin up fork server (instrumented mode only). The idea is explained here:
   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html
   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */

void setup_stdio_file(void) {

  char* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) WARNF("Unable to create .cur_input");

  free(fn);

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

#define FF(_b)  (0xff << ((_b) << 3))

static u32 count_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;

  }

  return ret;

}

/* Same as above but used for virgin bitmap */

static u32 count_non_255_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;

  }

  return ret;

}

/* Keep the compiler happpy */

static void show_stots(void);

/* Get time */

static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 

  if (child_pid > 0) kill(child_pid, SIGKILL);
  if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);
  if ((start_nn) || (nnforkexec_pid > 0)) kill(nnforkexec_pid, SIGKILL);
  OKF("total execs %ld edge coverage %d.", total_execs,(int)(count_non_255_bytes(virgin_bits)));
  SAYF(bSTOP CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  free(out_buf);
  free(out_buf1);
  free(out_buf2);
  free(out_buf3);
  exit(0);
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0.
   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

static inline char has_new_bits(char* virgin_map) {

#ifdef __x86_64__

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  u8   ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef __x86_64__

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^__x86_64__ */

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  return ret;

}


/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig) {

  if (child_pid > 0) {

    child_timed_out = 1;
    kill(child_pid, SIGKILL);

  } else if (child_pid == -1 && forksrv_pid > 0) {

    child_timed_out = 1;
    kill(forksrv_pid, SIGKILL);

  }

}

/* Clears screen if terminal moves */

static void handle_resize(int sig) {
  clear_screen = 1;
}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  
  /*Window Resize*/
  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}

/* Fork server that we'll be executing everything on */

void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  int rlen;
  char* cwd = getcwd(NULL, 0);
  out_file = alloc_printf("%s/.cur_input",cwd);
  OKF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) WARNF("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) WARNF("fork() failed");

  if (!forksrv_pid) {

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) WARNF("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) WARNF("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);


    execv(target_path, argv);
    
    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */
    *(int *)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    WARNF("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    WARNF("waitpid() failed");

  if (WIFSIGNALED(status)) {

    WARNF("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(int*)trace_bits == EXEC_FAIL_SIG)
    WARNF("Unable to execute target application ('%s')", argv[0]);

  WARNF("Fork server handshake failed");
  
}

/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);
  shmctl(nn_shm_id, IPC_RMID, NULL);

}

/* Configure shared memory and virgin_bits. This is called at startup. */
/* Also configures a shared memory region to the python mopdule so we can share stats eaily */

void setup_shm(void) {

  ACTF("Setting up shared memory buffers");

  char* shm_str;

  memset(virgin_bits, 255, MAP_SIZE);
  memset(crash_bits, 255, MAP_SIZE);
  memset(tmout_bits, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  /*I know this is dumb, but I cant think of a better way*/

#define GETEKYDIR ("/tmp")
#define PROJECTID  (6667)

  key_t unsafe_key = ftok(GETEKYDIR, PROJECTID);
  if ( unsafe_key < 0 ){
      WARNF("ftok error");
      exit(1);
  }
  nn_shm_id = shmget(unsafe_key, NN_MAP_SIZE, IPC_CREAT | IPC_EXCL | 0666);

  if (shm_id < 0) WARNF("Fork server shmget() failed");
  if (nn_shm_id < 0) WARNF("Python module shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  setenv(SHM_ENV_VAR, shm_str, 1);

  free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  nn_stats = shmat(nn_shm_id, 0, 0);

  if ((!trace_bits) || (!nn_stats)) WARNF("shmat() failed");

}

/* Starts nn server */

void start_nn_mod(char** argv){

  char python[7]="python";
  char nn_path[14]="./utils/nn.py";
  char quiet[3]="-q";
  char out[3]="-o";

  nn_args[0]=&python;
  nn_args[1]=&nn_path;
  nn_args[2]=&quiet;
  nn_args[3]=&out;
  nn_args[4]=out_dir;
  nn_args[5]=target_path;

  ACTF("Spinning up neural network server");

  if (!start_nn) return;

  nnforkexec_pid = fork();

  if (nnforkexec_pid == 0){
      execvp(&python,nn_args);
      exit(127);

  }
}

/* Checks server is still alive every now and then */

void check_nn_alive(void){

  if (!start_nn) return;

  int status = waitpid(nnforkexec_pid, NULL, WNOHANG);

  if (status < 0)
    WARNF("waitpid() failed");

  if (status != 0) {
    FATAL("Neural Net python module died, add the debug flag -d to the args and launch\n" 
          "the python module seperately with a debugger.");
  }
}

/* Helper to remove the working directory at start up */

int remove_directory(const char *path) {
   DIR *d = opendir(path);
   size_t path_len = strlen(path);
   int r = -1;

   if (d) {
      struct dirent *p;

      r = 0;
      while (!r && (p=readdir(d))) {
          int r2 = -1;
          char *buf;
          size_t len;

          /* Skip the names "." and ".." as we don't want to recurse on them. */
          if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
             continue;

          len = path_len + strlen(p->d_name) + 2; 
          buf = malloc(len);

          if (buf) {
             struct stat statbuf;

             snprintf(buf, len, "%s/%s", path, p->d_name);
             if (!stat(buf, &statbuf)) {
                if (S_ISDIR(statbuf.st_mode))
                   r2 = remove_directory(buf);
                else
                   r2 = unlink(buf);
             }
             free(buf);
          }
          r = r2;
      }
      closedir(d);
   }

   if (!r)
      r = rmdir(path);

   return r;
}

/* Sets up file descriptors to send stuff to the void, makes dirs in working dir */

void setup_dirs_fds(void) {

  char* tmp;
  int fd;

  ACTF("Setting up output directories...");

  remove_directory(out_dir);

  if (mkdir(out_dir, 0700)) {

    if (errno != EEXIST) WARNF("Unable to create %s", out_dir);

  }
  
  tmp = alloc_printf("%s/seeds", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  free(tmp);

  tmp = alloc_printf("%s/vari_seeds", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  free(tmp);

  tmp = alloc_printf("%s/havoc_seeds", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  free(tmp);

  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  free(tmp);

  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  free(tmp);

  tmp = alloc_printf("%s/nocov", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  free(tmp);

  /* Generally useful file descriptors. */

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) WARNF("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) WARNF("Unable to open /dev/urandom");

}

/* Very very important, makes sure that crashes dont get interpreted at timeouts */

static void check_crash_handling(void) {

  /* This is Linux specific, but I don't think there's anything equivalent on
     *BSD, so we can just let it slide for now. */

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8  fchar;

  if (fd < 0) return;

  ACTF("Checking core_pattern...");

  if (read(fd, &fchar, 1) == 1 && fchar == '|') {

    WARNF("\n \n" cRST 
         "Hmm, your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues: there will be an extended delay\n"
         "    between stumbling upon a crash and having this information relayed to the\n"
         "    fuzzer via the standard waitpid() API.\n\n"

         "    To avoid having crashes misinterpreted as timeouts, please log in as root\n" 
         "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core >/proc/sys/kernel/core_pattern\n \n" "\033[0m");
    exit(1);
  }
 
  close(fd);

}

/* Size of file */

int fsize(FILE *fp){
    int prev=ftell(fp);
    fseek(fp, 0L, SEEK_END);
    int sz=ftell(fp);
    fseek(fp,prev,SEEK_SET); //go back to where we were
    return sz;
}

/* Sets granularity of mutations as well as havoc index's */

int set_havoc_template(char *dir){
  DIR *dp;
  struct dirent *entry;
  int tmp;
  if ((dp = opendir(dir)) == NULL) {
    WARNF("cannot open directory: %s", dir);
    return;
  }

  while ((entry = readdir(dp)) != NULL) {
    if (entry->d_type == DT_REG){
      char* init_seed = alloc_printf("%s/%s", dir, entry->d_name);
      FILE *fl=fopen(init_seed,"r");
      free(init_seed);
      tmp = fsize(fl);
      if (tmp > len) len=tmp;
    }
  }
  closedir(dp);
  /* change num_index and havoc_blk_* according to file len */
  if (len > 7000) {
    num_index[13] = (len - 1);
    havoc_blk_large = (len - 1);
  }
  else if (len > 4000) {
    num_index[13] = (len - 1);
    num_index[12] = 3072;
    havoc_blk_large = (len - 1);
    havoc_blk_medium = 2048;
    havoc_blk_small = 1024;
  }
  OKF("Setting up mutation templates, max file size: %ld", len);
}

/* Detect @@ in args. */

void detect_file_args(int argc, char** argv) {

  int i = 0;
  char* cwd = getcwd(NULL, 0);
  nn_args = malloc(20*(argc + 7));

  if (!cwd) WARNF("getcwd() failed");

  while (argv[i]) {

    char* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      char *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file)
        out_file = alloc_printf("%s/.cur_input", out_dir);

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/') aa_subst = out_file;
      else aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/') free(aa_subst);
      nn_args[i+6]=0x0;

    }
    else{
      nn_args[i+6]=argv[i];
    }

    i++;

  }

  free(cwd);

}

/* set up target path */ 

void setup_targetpath(char * argvs){
    char* cwd = getcwd(NULL, 0);
    log_pth = alloc_printf("%s/%s/%s", cwd, out_dir, "log_fuzz");
    target_path = alloc_printf("%s/%s", cwd, argvs);
    argvs = target_path;
}

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */
static const u8 count_class_lookup8[256] = {

  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};

static u16 count_class_lookup16[65536];


void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++)
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] =
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];
}


#ifdef __x86_64__

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];
    }
    mem++;
  }
}

#else

static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    mem++;

  }

}

#endif /* ^__x86_64__ */


/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void) {

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f) return 0;

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) val += atoi(tmp + 14);

  }
 
  fclose(f);

  if (!res) {
    res = val;
  } else {
    res = res * (1.0 - 1.0 / AVG_SMOOTHING) + ((double)val) * (1.0 / AVG_SMOOTHING);
  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;

}


/* Count the number of logical CPU cores. */

static void get_core_count(void) {

  u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) return;

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

#else

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) cpu_core_count++;

  fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0) {

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    ACTF("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cpu_core_count > 1 ? "s" : "",
        cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1) {

      if (cur_runnable > cpu_core_count * 1.5) {
        WARNF("System under apparent load, performance may be spotty.");
      }
    }

  } else {
    cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");
  }

}

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */
static void bind_to_free_cpu(void) {

  DIR* d;
  struct dirent* de;
  cpu_set_t c;

  u8 cpu_used[4096] = { 0 };
  u32 i;

  if (cpu_core_count < 2) return;

  if (getenv("AFL_NO_AFFINITY")) {
    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;
  }

  d = opendir("/proc");

  if (!d) {
    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;
  }

  ACTF("Checking CPU core loadout...");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d))) {

    u8* fn;
    FILE* f;
    u8 tmp[MAX_LINE];
    u8 has_vmsize = 0;

    if (!isdigit(de->d_name[0])) continue;

    fn = alloc_printf("/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) {
      free(fn);
      continue;
    }

    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) has_vmsize = 1;

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
          !strchr(tmp, '-') && !strchr(tmp, ',') &&
          sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
          has_vmsize) {

        cpu_used[hval] = 1;
        break;

      }

    }

    free(fn);
    fclose(f);

  }

  closedir(d);

  for (i = 0; i < cpu_core_count; i++) if (!cpu_used[i]) break;

  if (i == cpu_core_count) {
    WARNF("No more free CPU cores");
  }

  ACTF("Found a free CPU core, binding to #%u.", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c))
    WARNF("sched_setaffinity failed");

}

 /* Get unix time in microseconds */
 
 static u64 get_cur_time_us(void) {
 
   struct timeval tv;
   struct timezone tz;
 
   gettimeofday(&tv, &tz);
 
   return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
 
 }


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(int timeout) {

  show_stots();

  static struct itimerval it;
  static u32 prev_timed_out = 0;

  int status = 0;

  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

    int res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (stop_soon) return 0;
      WARNFLOG("err%d: Unable to request new process from fork server (OOM?)", res);

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      WARNFLOG("err%d: Unable to request new process from fork server (OOM?)",res);

    }
    if (child_pid <= 0) WARNFLOG("Fork server is misbehaving (OOM?)");


  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */
    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
      if (stop_soon) return 0;
      WARNFLOG("err%d: Unable to communicate with fork server (OOM?)",res);
    }


  if (!WIFSTOPPED(status)) child_pid = 0;

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();


#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */

  if (WIFSIGNALED(status) && !stop_soon) {

    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

    return FAULT_CRASH;

  }
  return FAULT_NONE;

}

/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  int fd = out_fd;

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) WARNFLOG("Unable to create file");

  ck_write(fd, mem, len, out_file);

  close(fd);

}

/*Will count number of no coverage files*/
int count_seeds(char * in_dir, char * filter_str){
    int file_count = 0;
    DIR * dirp;
    struct dirent * entry;

    dirp = opendir(in_dir);
    
    if (!dirp) {
      WARNFLOG("Cannot open directory");
      return;
    }
    if (strcmp(filter_str,"")==1){
      while ((entry = readdir(dirp)) != NULL) {
        if (entry->d_type == DT_REG) file_count++;
      }
    }
    else{
      while ((entry = readdir(dirp)) != NULL) {
          if (entry->d_type == DT_REG  && strstr(entry->d_name,filter_str) != NULL ) { /* If the entry is a regular file and has prefix*/
              file_count++;
          }
      }
    }
    closedir(dirp);
    return file_count;
}

/* Check CPU governor. */

static void check_cpu_governor(void) {

  FILE* f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ")) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) return;

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f)) WARNF("fgets() failed");

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &min) != 1) min = 0;
    fclose(f);
  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &max) != 1) max = 0;
    fclose(f);
  }

  if (min == max) return;

  ACTF("Err: Suboptimal CPU scaling governor");

}

/* parse one line of gradient string into array */
void parse_array(char * str, int * array){
    
    int i=0;
    
    char* token = strtok(str,",");
    
    while(token != NULL){
        array[i]=atoi(token);
        i++;
        token = strtok(NULL, ",");
    }

    return;
}

/* So theres around 1024 bytes to write messages in the shared memory between the nn module */
/* each message is a 40 byte region */
/* status = nn_arrp[0] */
/* last accuracy = nn_arrp[1] */
/* bitmap size = nn_arrp[2] */
/* corpus size = nn_arrp[3] */
/* nocov size = nn_arrp[4] */
/* last mapping time = nn_arrp[5] */
/* last reducing time = nn_arrp[6] */
/* last training time = nn_arrp[7] */
/* num grad = nn_arrp[8] */

void set_up_nn_pointers(char * str, char ** array){
    
    int addr_shift=0;
    
    for (int i=0; i < 9; i++){
        array[i]=str + addr_shift;
        addr_shift=addr_shift+39;
    }

    return;
}

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */
static inline u32 UR(u32 limit) {
  if (unlikely(!rand_cnt--)) {
    u32 seed[2];
    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");
    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);
  }
  return random() % limit;
}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */
static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;

  switch (UR(3)) {
    case 0:  min_value = 1;
             max_value = havoc_blk_small;
             break;

    case 1:  min_value = havoc_blk_small;
             max_value = havoc_blk_medium;
             break;

    case 2:  min_value = havoc_blk_medium;
             max_value = havoc_blk_large;
  }
  if (min_value >= limit) min_value = 1;

  return min_value + (UR(MIN(max_value, limit) - min_value + 1));
}

static u32 calculate_score(struct queue_entry* q) {

	u32 avg_exec_us = total_cal_us / total_cal_cycles;
	u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
	u32 perf_score = 100;

	if      (q->exec_us * 0.1  > avg_exec_us) perf_score = 10;
	else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
	else if (q->exec_us * 0.5  > avg_exec_us) perf_score = 50;
	else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
	else if (q->exec_us * 4    < avg_exec_us) perf_score = 300;
	else if (q->exec_us * 3    < avg_exec_us) perf_score = 200;
	else if (q->exec_us * 2    < avg_exec_us) perf_score = 150;

	if      (q->bitmap_size * 0.3  > avg_bitmap_size) perf_score *= 3;
	else if (q->bitmap_size * 0.5  > avg_bitmap_size) perf_score *= 2;
	else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
	else if (q->bitmap_size * 3    < avg_bitmap_size) perf_score *= 0.25;
	else if (q->bitmap_size * 2    < avg_bitmap_size) perf_score *= 0.5;
	else if (q->bitmap_size * 1.5  < avg_bitmap_size) perf_score *= 0.75;

	if (q->handicap >= 4) {
		perf_score *= 4;
		q->handicap -= 4;
	} else if (q->handicap) {
		perf_score *= 2;
		q->handicap--;
	}

	switch (q->depth) {
		case 0 ... 3:   break;
		case 4 ... 7:   perf_score *= 2; break;
		case 8 ... 13:  perf_score *= 3; break;
		case 14 ... 25: perf_score *= 4; break;
		default:        perf_score *= 5;
	}

	if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

	return perf_score;
}

static u32 cal_havoc_div(struct queue_entry* q) {
	u32 havoc_div;
	u64 avg_us = total_cal_us / total_cal_cycles;

	if      (avg_us > 50000) havoc_div = 10; /* 0-19 execs/sec   */
	else if (avg_us > 20000) havoc_div = 5;  /* 20-49 execs/sec  */
	else if (avg_us > 10000) havoc_div = 2;  /* 50-100 execs/sec */

	return havoc_div;
}

struct queue_entry* construct_queue_entry(char* fname) {

  u8* fn = (u8*)malloc(strlen(fname) + 1);
  memset(fn, 0, strlen(fname) + 1);
  strncpy(fn, fname, strlen(fname));

  struct queue_entry* q = (struct queue_entry*)malloc(sizeof(struct queue_entry));

  s32 fd = open(fn, O_RDONLY);
  struct stat st;
  fstat(fd, &st);

  q->len = st.st_size;

  u8* use_mem;
  use_mem = malloc(q->len);
  memset(use_mem, 0, q->len);
  ck_read(fd, use_mem, q->len, fn);

  u64 start_us = get_cur_time_us();

  s32 stage_max = 8, stage_cur;
  for(stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    write_to_testcase(use_mem, q->len);
		run_target(exec_tmout);
  }

  u64 end_us = get_cur_time_us();

  total_cal_us     += end_us - start_us;
  total_cal_cycles += stage_max;

  q->exec_us     = (end_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = queue_cycle;
  q->fname       = fn;
  q->depth       = cur_depth + 1;

  total_bitmap_size += q->bitmap_size;
	total_bitmap_entries++;

  free(use_mem);
  close(fd);
  return q;
}

void container_to_queue() {
    struct file_node* file = file_container->head->next;
    stage_name="Havoc seed analysis";
    stage_tot=file_container->size;
    stage_cnt=0;
    while (file) {
      fn=file->fname;
      struct queue_entry* entry = construct_queue_entry(file->fname);
      add_entry_to_queue(queue_havoc, entry);
      file = file->next;
      stage_cnt++;
   }
   fn="";
}

void container_to_queue_mut() {
    struct file_node* file = file_container->head->next;
    while (file) {
      struct queue_entry* entry = construct_queue_entry(file->fname);
      add_entry_to_queue(queue_havoc, entry);
      file = file->next;
   }
}


u8* load_entry(struct queue_entry* q) {
  s32 fd;
  fd = open(q->fname, O_RDONLY);
	u8* use_mem = malloc(q->len);
  memset(use_mem, 0, q->len); 
  ck_read(fd, use_mem, q->len, q->fname);
	close(fd);
	return use_mem;
}

void execute_target_program(char* out_buf, size_t length, char* out_dir) {
  write_to_testcase(out_buf, length);
  int fault = run_target(exec_tmout);
  if (fault != 0 && fault == FAULT_CRASH) {
    if (has_new_bits(crash_bits)){
      char *mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes", round_cnt, mut_cnt++);
      int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
      ck_write(mut_fd, out_buf, length, mut_fn);
      free(mut_fn);
      close(mut_fd);
      unique_crashes++;
      total_crashes++;
    }
    else total_crashes++;
  }

  if (fault != 0 && fault == FAULT_TMOUT) {
    if (has_new_bits(tmout_bits)){
      char *mut_fn = alloc_printf("%s/hangs_%d_%06d", "./hangs", round_cnt, mut_cnt++);
      int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
      ck_write(mut_fd, out_buf, length, mut_fn);
      free(mut_fn);
      close(mut_fd);
      unique_tmout++;
      total_tmout++;
    }
    else total_tmout++;
  }

  /* save mutations that find new edges. */
  int ret = has_new_bits(virgin_bits);
  if (ret == 2) {
    char *mut_fn = alloc_printf("%s/id_%d_%06d_cov", out_dir, round_cnt, mut_cnt++);
    add_file_to_container(file_container, mut_fn);
    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    ck_write(mut_fd, out_buf, length, mut_fn);
    free(mut_fn);
    close(mut_fd);
  }
  else if (ret == 1) {
    char *mut_fn = alloc_printf("%s/id_%d_%06d", out_dir, round_cnt, mut_cnt++);
    add_file_to_container(file_container, mut_fn);
    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    ck_write(mut_fd, out_buf, length, mut_fn);
    free(mut_fn);
    close(mut_fd);
  }
  else if (write_nocov && rand() % 1000000 < nocov_statistic) {
    char *mut_fn = alloc_printf("%s/id_%d_%06d_+nocov", "nocov", round_cnt, mut_cnt++);
    /*add_file_to_container(file_container, mut_fn); <--- do i want this?*/
    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    ck_write(mut_fd, out_buf, length, mut_fn);
    free(mut_fn);
    close(mut_fd);
  }
}

void execute_target_program_vari(char* out_buf, size_t length, char* out_dir) {
  write_to_testcase(out_buf, length);
  int fault = run_target(exec_tmout);
  if (fault != 0 && fault == FAULT_CRASH) {
    if (has_new_bits(crash_bits)){
      char *mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes", round_cnt, mut_cnt++);
      int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
      ck_write(mut_fd, out_buf, length, mut_fn);
      free(mut_fn);
      close(mut_fd);
      unique_crashes++;
      total_crashes++;
    }
    else total_crashes++;
  }

  if (fault != 0 && fault == FAULT_TMOUT) {
    if (has_new_bits(tmout_bits)){
      char *mut_fn = alloc_printf("%s/hangs_%d_%06d", "./hangs", round_cnt, mut_cnt++);
      int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
      ck_write(mut_fd, out_buf, length, mut_fn);
      free(mut_fn);
      close(mut_fd);
      unique_tmout++;
      total_tmout++;
    }
    else total_tmout++;
  }

  /* save mutations that find new edges. */
  int ret = has_new_bits(virgin_bits);
  if (ret == 2) {
    char *mut_fn = alloc_printf("%s/id_%d_%06d_cov", out_dir, round_cnt, mut_cnt++);
    add_file_to_container(file_container, mut_fn);
    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    ck_write(mut_fd, out_buf, length, mut_fn);
    free(mut_fn);
    close(mut_fd);
  }
  else if (ret == 1) {
    char *mut_fn = alloc_printf("%s/id_%d_%06d", out_dir, round_cnt, mut_cnt++);
    add_file_to_container(file_container, mut_fn);
    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    ck_write(mut_fd, out_buf, length, mut_fn);
    free(mut_fn);
    close(mut_fd);
  }
}

/* gradient guided mutation */
void gen_mutate() {
  stage_name = "gradient (mutation)";
  stage_tot = atoi(nn_arr[8]);
  file_container = create_file_container();
  /* flip interesting locations within 14 iterations */
  for (int iter = 0; iter < 13; iter = iter + 1) {
    memcpy(out_buf1, out_buf, len);
    memcpy(out_buf2, out_buf, len);

    /* find mutation range for every iteration */
    int low_index = num_index[iter];
    int up_index = num_index[iter + 1];
    u8 up_step = 0;
    u8 low_step = 0;
    for (int index = low_index; index < up_index; index = index + 1) {
      int cur_up_step = 0;
      int cur_low_step = 0;
      if (sign[index] == 1) {
        cur_up_step = (255 - (u8)out_buf[loc[index]]);
        if (cur_up_step > up_step)
          up_step = cur_up_step;
        cur_low_step = (u8)(out_buf[loc[index]]);
        if (cur_low_step > low_step)
          low_step = cur_low_step;
      }
      else {
        cur_up_step = (u8)out_buf[loc[index]];
        if (cur_up_step > up_step)
          up_step = cur_up_step;
        cur_low_step = (255 - (u8)out_buf[loc[index]]);
        if (cur_low_step > low_step)
          low_step = cur_low_step;
      }
    }

    /* up direction mutation(up to 255) */
    for (int step = 0; step < up_step; step = step + 1) {
      int mut_val;
      for (int index = low_index; index < up_index; index = index + 1) {
        mut_val = ((u8)out_buf1[loc[index]] + sign[index]);
        if (mut_val < 0)
          out_buf1[loc[index]] = 0;
        else if (mut_val > 255)
          out_buf1[loc[index]] = 255;
        else
          out_buf1[loc[index]] = mut_val;
      }
      execute_target_program(out_buf1, len, "seeds");
    }

    /* low direction mutation(up to 255) */
    for (int step = 0; step < low_step; step = step + 1) {
      for (int index = low_index; index < up_index; index = index + 1) {
        int mut_val = ((u8)out_buf2[loc[index]] - sign[index]);
        if (mut_val < 0)
          out_buf2[loc[index]] = 0;
        else if (mut_val > 255)
          out_buf2[loc[index]] = 255;
        else
          out_buf2[loc[index]] = mut_val;
      }
      execute_target_program(out_buf2, len, "seeds");
    }
  }

  stage_name = "gradient (random ins/del)";

  /* random insertion/deletion */
  int cut_len = 0;
  int del_loc = 0;
  int rand_loc = 0;
  for (int del_count = 0; del_count < 1024; del_count = del_count + 1) {
    del_loc = loc[del_count];
    if ((len - del_loc) <= 2)
      continue;
    
    /* random deletion at a critical offset */
    cut_len = choose_block_len(len - 1 - del_loc);
    memcpy(out_buf1, out_buf, del_loc);
    memcpy(out_buf1 + del_loc, out_buf + del_loc + cut_len, len - del_loc - cut_len);
    execute_target_program(out_buf1, len - cut_len, "seeds");

    /* random insertion at a critical offset */
    cut_len = choose_block_len(len - 1);
    rand_loc = UR(cut_len);
  
    memcpy(out_buf3, out_buf, del_loc);
    memcpy(out_buf3 + del_loc, out_buf + rand_loc, cut_len);
    memcpy(out_buf3 + del_loc + cut_len, out_buf + del_loc, len - del_loc);
    execute_target_program_vari(out_buf3, len + cut_len, "vari_seeds");
  }
  container_to_queue_mut();
  free_file_container(file_container);
}

/* afl havoc stage mutation */
void afl_havoc_stage(struct queue_entry* q) {

  stage_name = "havoc";

  u8* havoc_in_buf = load_entry(q);

  u32 perf_score = calculate_score(q);
  u32 havoc_div  = cal_havoc_div(q);

  s32 stage_cur, idx, temp_len;
  s32 stage_max = 256 * perf_score / havoc_div / 100;
  if(stage_max < 16) stage_max = 16;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    u32 use_stacking = 1 << (2 + UR(HAVOC_STACK_POW2));

    u8* havoc_out_buf = malloc(q->len);
    memcpy(havoc_out_buf, havoc_in_buf, q->len);
    temp_len = q->len;

    for (idx = 0; idx < use_stacking; idx++) {
      switch (UR(15)) {
        case 0:
          /* Flip a single bit somewhere. Spooky! */
          FLIP_BIT(havoc_out_buf, UR(temp_len << 3));
          break;

        case 1:
          /* Set byte to interesting value. */
          havoc_out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:
          /* Set word to interesting value, randomly choosing endian. */
          if (temp_len < 2) break;
          if (UR(2)) {
            *(u16*)(havoc_out_buf + UR(temp_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];
          } else {
            *(u16*)(havoc_out_buf + UR(temp_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);
          }
          break;

        case 3:
          /* Set dword to interesting value, randomly choosing endian. */
          if (temp_len < 4) break;
          if (UR(2)) {
            *(u32*)(havoc_out_buf + UR(temp_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];
          } else {
            *(u32*)(havoc_out_buf + UR(temp_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);
          }
          break;
        
        case 4:
          /* Randomly subtract from byte. */
          havoc_out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:
          /* Randomly add to byte. */
          havoc_out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;
        
        case 6:
          /* Randomly subtract from word, random endian. */
          if (temp_len < 2) break;
          if (UR(2)) {
            u32 pos = UR(temp_len - 1);
            *(u16*)(havoc_out_buf + pos) -= 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(havoc_out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(havoc_out_buf + pos)) - num);
          }
          break;
        
        case 7:
          /* Randomly add to word, random endian. */
          if (temp_len < 2) break;
          if (UR(2)) {
            u32 pos = UR(temp_len - 1);
            *(u16*)(havoc_out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);
            *(u16*)(havoc_out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(havoc_out_buf + pos)) + num);
          }
          break;

        case 8:
         /* Randomly subtract from dword, random endian. */
         if (temp_len < 4) break;
         if (UR(2)) {
           u32 pos = UR(temp_len - 3);
           *(u32*)(havoc_out_buf + pos) -= 1 + UR(ARITH_MAX);
         } else {
           u32 pos = UR(temp_len - 3);
           u32 num = 1 + UR(ARITH_MAX);
           *(u32*)(havoc_out_buf + pos) =
             SWAP32(SWAP32(*(u32*)(havoc_out_buf + pos)) - num);
         }
         break;

        case 9:
          /* Randomly add to dword, random endian. */
          if (temp_len < 4) break;
          if (UR(2)) {
            u32 pos = UR(temp_len - 3);
            *(u32*)(havoc_out_buf + pos) += 1 + UR(ARITH_MAX);
          } else {
            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);
            *(u32*)(havoc_out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(havoc_out_buf + pos)) + num);
          }
          break;

        case 10:
          /* Just set a random byte to a random value. */
          havoc_out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;
        
        case 11 ... 12: {
            /* Delete bytes. */
            u32 del_from, del_len;
            if (temp_len < 2) break;

            del_len = choose_block_len(temp_len - 1);
            del_from = UR(temp_len - del_len + 1);
            memmove(havoc_out_buf + del_from, havoc_out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;
            break;
          }
        
        case 13: {
            if (temp_len + HAVOC_BLK_XL < MAX_FILE) {
              /* Clone bytes (75%) or insert a block of constant bytes (25%). */
              u8  actually_clone = UR(4);
              u32 clone_from, clone_to, clone_len;
              u8* new_buf;

              if (actually_clone) {
                clone_len  = choose_block_len(temp_len);
                clone_from = UR(temp_len - clone_len + 1);
              } else {
                clone_len = choose_block_len(HAVOC_BLK_XL);
                clone_from = 0;
              }

              clone_to = UR(temp_len);
              if (temp_len + clone_len >= 10000)
                  break;
              new_buf = malloc(temp_len + clone_len);
              /* Head */
              memcpy(new_buf, havoc_out_buf, clone_to);

              /* Inserted part */
              if (actually_clone)
                memcpy(new_buf + clone_to, havoc_out_buf + clone_from, clone_len); 
              else
                memset(new_buf + clone_to, UR(2) ? UR(256) : havoc_out_buf[UR(temp_len)], clone_len); 

              /* Tail */
              memcpy(new_buf + clone_to + clone_len, havoc_out_buf + clone_to,
                     temp_len - clone_to);

              free(havoc_out_buf);
              havoc_out_buf = new_buf;
              temp_len += clone_len;
            }
            break;
          }

        case 14: {
            /* Overwrite bytes with a randomly selected chunk (75%) or fixed bytes (25%). */
            u32 copy_from, copy_to, copy_len;
            if (temp_len < 2) break;

            copy_len  = choose_block_len(temp_len - 1);
            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);

            if (UR(4)) {
              if (copy_from != copy_to)
                memmove(havoc_out_buf + copy_to, havoc_out_buf + copy_from, copy_len);
            } else memset(havoc_out_buf + copy_to,
                          UR(2) ? UR(256) : havoc_out_buf[UR(temp_len)], copy_len);
            break;
          }
      }
    }
    /* run target program */
    write_to_testcase(havoc_out_buf, temp_len);
    int fault = run_target(exec_tmout);
    int ret = has_new_bits(virgin_bits);

    if (fault != 0) {
      if(fault == FAULT_CRASH) {
        if (has_new_bits(crash_bits)){
          char *mut_fn = alloc_printf("%s/crash_%d_%06d_havoc", "./crashes", round_cnt, havoc_cnt++);
          int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
          ck_write(mut_fd, havoc_out_buf, len, mut_fn);
          free(mut_fn);
          close(mut_fd);
          unique_crashes++;
          total_crashes++;
        }
        else total_crashes++;
      }
      if(fault == FAULT_TMOUT) {
        if (has_new_bits(tmout_bits)){
          char *mut_fn = alloc_printf("%s/hangs_%d_%06d_havoc", "./hangs", round_cnt, havoc_cnt++);
          int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
          ck_write(mut_fd, havoc_out_buf, len, mut_fn);
          free(mut_fn);
          close(mut_fd);
          unique_tmout++;
          total_tmout++;
        }
      else total_tmout++;
      }
    }

    if (ret) {
      u8* m_fn;
      if (temp_len > len)
        m_fn = alloc_printf("%s/id_%d_%06d_havoc", "./havoc_seeds", round_cnt, havoc_cnt++);
      else
        m_fn = alloc_printf("%s/id_%d_%06d_havoc", "seeds", round_cnt, havoc_cnt++);

      int m_fd = open(m_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
      ck_write(m_fd, havoc_out_buf, temp_len, m_fn);
      close(m_fd);

      struct queue_entry* entry = construct_queue_entry(m_fn);
      add_entry_to_queue(queue_havoc, entry);
      free(m_fn);
    }
    free(havoc_out_buf);
  }
  free(havoc_in_buf);
}

void dry_run(char *dir) {
  stage_name="Dry running";
  stage_tot=count_seeds(dir,"");
  stage_cnt=0;
  DIR *dp;
  struct dirent *entry;
  struct stat statbuf;
  file_container = create_file_container();
  if ((dp = opendir(dir)) == NULL) {
    WARNF("cannot open directory: %s", dir);
    return;
  }
  if (chdir(dir) == -1)
    WARNF("chdir failed");
  int cnt = 0;
  u64 start_us, stop_us;
  while ((entry = readdir(dp)) != NULL) {
    if (stat(entry->d_name, &statbuf) == -1)
      continue;
    if (S_ISREG(statbuf.st_mode)) {
      char *tmp = NULL;
      tmp = strstr(entry->d_name, ".");
      if (tmp != entry->d_name) {
        fn = entry->d_name;
        /* add dry run seeds to file container */
        char* init_seed = alloc_printf("%s/%s", "seeds", entry->d_name);
        add_file_to_container(file_container, init_seed);
        free(init_seed);

        int fd_tmp = open(entry->d_name, O_RDONLY);
        if (fd_tmp == -1)
          WARNFLOG("open failed");
        int file_len = statbuf.st_size;
        memset(out_buf1, 0, len);
        ck_read(fd_tmp, out_buf1, file_len, entry->d_name);

        start_us = get_cur_time_us();

        write_to_testcase(out_buf1, file_len);
        int fault = run_target(exec_tmout);
        int ret = has_new_bits(virgin_bits);
        if (fault != 0 && fault == FAULT_CRASH) {
          if (has_new_bits(crash_bits)){
            char *mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes", round_cnt, mut_cnt++);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, file_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            unique_crashes++;
            total_crashes++;
          }
          else total_crashes++;
        }

        if (fault != 0 && fault == FAULT_TMOUT) {
          if (has_new_bits(tmout_bits)){
            char *mut_fn = alloc_printf("%s/hangs_%d_%06d", "./hangs", round_cnt, mut_cnt++);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, file_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            unique_tmout++;
            total_tmout++;
          }
          else total_tmout++;
        }

        stop_us = get_cur_time_us();
        total_cal_us = total_cal_us - start_us + stop_us;
        cnt = cnt + 1;
        close(fd_tmp);
        stage_cnt++;
      }
    }
  }
  if (chdir("..") == -1)
    WARNFLOG("chdir failed");
  closedir(dp);

  /* estimate the average exec time at the beginning*/
  u64 avg_us = (u64)(total_cal_us / cnt);
  if (avg_us > 50000)
    exec_tmout = avg_us * 2 / 1000;
  else if (avg_us > 10000)
    exec_tmout = avg_us * 3 / 1000;
  else
    exec_tmout = avg_us * 5 / 1000;

  exec_tmout = (exec_tmout + 20) / 20 * 20;
  exec_tmout = exec_tmout;
  OKFLOG("avg %d time out %d cnt %d sum %lld .", (int)avg_us, exec_tmout, cnt, total_cal_us);
  
  fn = "";
  container_to_queue();
  free_file_container(file_container);
  OKFLOG("dry run %ld edge coverage %d.", total_execs, count_non_255_bytes(virgin_bits));
  return;
}

void copy_file(char *src, char *dst) {
  FILE *fptr1, *fptr2;
  int c;
  fptr1 = fopen(src, "r");
  if (fptr1 == NULL) {
    WARNFLOG("Cannot open file %s ", src);
    exit(0);
  }

  fptr2 = fopen(dst, "w");
  if (fptr2 == NULL) {
    WARNFLOG("Cannot open file %s ", dst);
    exit(0);
  }

  c = fgetc(fptr1);
  while (c != EOF) {
    fputc(c, fptr2);
    c = fgetc(fptr1);
  }

  fclose(fptr1);
  fclose(fptr2);
  return;
}

/* copy seeds from in_idr to out_dir */
void copy_seeds(char *in_dir, char *out_dir) {
  struct dirent *de;
  DIR *dp;
  if ((dp = opendir(in_dir)) == NULL) {
    WARNF("cannot open directory: %s", in_dir);
    return;
  }
  char src[512], dst[512];
  while ((de = readdir(dp)) != NULL) {
    if (strcmp(".", de->d_name) == 0 || strcmp("..", de->d_name) == 0)
      continue;
    sprintf(src, "%s/%s", in_dir, de->d_name);
    sprintf(dst, "%s/%s/%s", out_dir, "seeds", de->d_name);
    copy_file(src, dst);
  }
  closedir(dp);
  return;
}

void fuzz_lop(char *grad_file, int sock) {
  grads_last=get_cur_time();
  copy_file("gradient_info_p", grad_file);
  FILE *stream = fopen(grad_file, "r");
  char *line = NULL;
  size_t llen = 0;
  ssize_t nread;
  if (stream == NULL) {
    WARNFLOG("fopen");
    exit(EXIT_FAILURE);
  }

  time_t tt1 = time(NULL);
  OKFLOG("currect cnt: %d, gen_mutate start", queue_cycle);
  
  /* parse the gradient to guide fuzzing */
  int total_execs_old=0;
  float nocov_seeds_threshold=10000.;
  int remap_interval =50;

  stage_cnt=0;
  while ((nread = getline(&line, &llen, stream)) != -1) {
    check_nn_alive();
    stage_cnt = stage_cnt + 1;

    /* parse gradient info */
    char *loc_str = strtok(line, "|");
    char *sign_str = strtok(NULL, "|");
    fn = strtok(strtok(NULL, "|"), "\n");
    parse_array(loc_str, loc);
    parse_array(sign_str, sign);

    /* print edge coverage per 10 files*/
    if ((stage_cnt % 10) == 0) {
      /*Nocov stats update*/
      execs_per_line = total_execs -total_execs_old;
      total_execs_old = total_execs;
      write_nocov = count_seeds("nocov","+nocov") < nocov_seeds_threshold*(1+round_cnt);
      if(stage_cnt ==1) write_nocov =0;
      nocov_statistic = 1000000*(nocov_seeds_threshold/(200*execs_per_line));
      OKFLOG("fuzzing state: stage_cnt %d edge num %d uniq_crash %d total_crash %d uniq_hang %d total_hang %d", stage_cnt, count_non_255_bytes(virgin_bits),unique_crashes,total_crashes,unique_tmout,total_tmout);
      fflush(stdout);
    }

    /*Send remap signal*/
    if ((stage_cnt % remap_interval) == 0){
        OKFLOG("Remap Signal ");
        send(sock,"MAP", 5,0);
    }

    /* read seed into mem */
    int fn_fd = open(fn, O_RDONLY);
    if (fn_fd == -1) {
      WARNFLOG("open failed");
      exit(0);
    }
    struct stat st;
    int ret = fstat(fn_fd, &st);
    int file_len = st.st_size;
    memset(out_buf,  0, len);
    memset(out_buf1, 0, len);
    memset(out_buf2, 0, len);
    memset(out_buf3, 0, 20000);
    ck_read(fn_fd, out_buf, file_len, fn);

    /* generate mutation */
    gen_mutate();
    close(fn_fd);
  }

  time_t tt2 = time(NULL);
  OKFLOG("current cnt: %d, gen_mutate finished, starting havoc stage", queue_cycle);
  OKFLOG("gen_mutate use time %fs", difftime(tt2, tt1));

  /* afl havoc stage */
  struct queue_entry* q_entry = queue_havoc->head->next;

  stage_cnt = 0;
  stage_tot= queue_havoc->size;

  while (q_entry) {
    fn=q_entry->fname;
    afl_havoc_stage(q_entry);
    q_entry = q_entry->next;
    stage_cnt++;

    if ((stage_cnt % 50) == 0) {
      ACTFLOG("rate of havoc stage: %.2lf%%\r", stage_cnt * 100.0 / stage_tot);
      fflush(stdout);
    }
  }

  time_t tt3 = time(NULL);
  OKFLOG("current cnt: %d, havoc finished", queue_cycle);
  OKFLOG("havoc use time %fs", difftime(tt3, tt2));
  free(line);
  fclose(stream);
  send(sock, "train", 5, 0);
  OKFLOG("Train Signal");
  round_cnt++;
}

/* connect to python NN module, then read the gradient file to guide fuzzing */
void start_fuzz(int f_len) {
  /* connect to python module */
  struct sockaddr_in address;
  int sock = 0;
  struct sockaddr_in serv_addr;
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    WARNF("Socket creation error, %s", strerror(errno));
    exit(0);
  }



  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
    WARNF("Invalid address/ Address not supported");
    exit(0);
  }
  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    WARNF("Connection Failed");
    exit(0);
  }

  int on;
  on = fcntl(sock,F_GETFL);
  on = (on | O_NONBLOCK);
  if(fcntl(sock,F_SETFL,on) < 0)
      {
        perror("turning NONBLOCKING on failed\n");
      }

  ACTF("start of the fuzzing module");

  /* set up buffer, I know this is a bad idea*/

  out_buf = malloc(10000);
  if (!out_buf)
    WARNF("malloc failed");
  out_buf1 = malloc(10000);
  if (!out_buf1)
    WARNF("malloc failed");
  out_buf2 = malloc(10000);
  if (!out_buf2)
    WARNF("malloc failed");
  out_buf3 = malloc(20000);
  if (!out_buf3)
    WARNF("malloc failed");
  
  queue_havoc = create_queue();
  if (!queue_havoc) WARNF("init queue failed");
  
  len = f_len;

  /* dry run initial seeds*/
  /* Use log functions to message from here because the screen will be up*/
  dry_run("seeds");

  /* start fuzz */
  char buf[16];
  while (1) {
    check_nn_alive();
    if (read(sock, buf, 5) != -1){
      fuzz_lop("gradient_info", sock);
      ACTFLOG("%dth iteration, receive", ++queue_cycle);
    }
    stage_name="Waiting for grads";
    fn="";
    stage_cnt=0;
    stage_tot=0;
    show_stots();
    sleep(0.5);
  }
  return;
}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

static u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}


/* Trim and possibly create a banner for the run. */

static void fix_up_banner(u8* name) {

  if (!use_banner) {

    u8* trim = strrchr(name, '/');
    if (!trim) use_banner = name; else use_banner = trim + 1;

  }

  if (strlen(use_banner) > 40) {

    u8* tmp = malloc(44);
    sprintf(tmp, "%.40s...", use_banner);
    use_banner = tmp;

  }

}


static void check_if_tty(void) {

  struct winsize ws;

  if (getenv("AFL_NO_UI")) {
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws)) {

    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      not_on_tty = 1;
    }

    return;
  }

}

/* Check terminal dimensions after resize. */

static void check_term_size(void) {

  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) return;

  if (ws.ws_row == 0 && ws.ws_col == 0) return;
  if (ws.ws_row < 25 || ws.ws_col < 80) term_too_small = 1;

}


/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */

static u8* DI(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}

/* Describe time delta. Returns one static buffer, 34 chars of less. */

static u8* DTD(u64 cur_ms, u64 event_ms) {

  static u8 tmp[64];
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms) return "-";

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  sprintf(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
  return tmp;

}

static u8* DF(double val) {

  static u8 tmp[16];

  if (val < 99.995) {
    sprintf(tmp, "%0.02f", val);
    return tmp;
  }

  if (val < 999.95) {
    sprintf(tmp, "%0.01f", val);
    return tmp;
  }

  return DI((u64)val);

}


static void show_stots(void) {

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8  tmp[256];

  cur_ms = get_cur_time();

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;

  /* Calculate smoothed exec speed stats. */

  if (!last_execs) {
  
    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);

  } else {

    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);

  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((int)t_bytes * 100) / MAP_SIZE;

  /* If we're not on TTY, bail out. */

  if (not_on_tty) return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* Now, for the visuals... */

  if (clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    clear_screen = 0;

    check_term_size();

  }

  SAYF(TERM_HOME);

  if (term_too_small) {

    SAYF(cBRI "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 80x25.\n" cRST);

    return;

  }

  /* Let's start by drawing a centered banner. */

  banner_len = 23 + strlen(use_banner);
  banner_pad = (70 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, "%s " cLCY cLGN
          " (%s)", cYEL "Extreme Fuzzing Machine", use_banner);

  SAYF("\n%s\n\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG    bSTART cGRA
#define bH2     bH bH
#define bH5     bH2 bH2 bH
#define bH10    bH5 bH5
#define bH20    bH10 bH10
#define bH30    bH20 bH10
#define SP      " "
#define SP2     "  "
#define SP5     "     "
#define SP10    SP5 SP5
#define SP20    SP10 SP10

  /* Lord, forgive me this. */
  /* The actual screen, I wish I could convey how hard this was to make even if I did just copy afl*/

  /* Top box time */
  SAYF(SET_G1 SP10 bSTG bLT bH bSTOP cBCYA "Time " bSTG bH30 bH10 bH2 bRT bSTOP"\n");

  SAYF(bSTART SP10 bV bSTOP "   run time : " cRST "%-33s " bSTG bV bSTOP"\n",
       DTD(cur_ms, start_time));
       
  SAYF(bSTART SP10 bV bSTOP " last grads : " cRST "%-33s " bSTG bV bSTOP"\n",
       DTD(cur_ms, grads_last));
  
  /* Middle Box */
  SAYF(bSTG bLT bH5 bH2 bH2 bHT bH bSTOP cLGN "Neural Net Engine " bSTG bH5 bHB bH bSTOP cPIN "Fuzzer " bSTG bH10 bH5 bHT bH2 bH2 bH5 bRT bSTOP"\n");

  SAYF(bSTG bV bSTOP "       Status : " cRST "%-18s" bSTG bV bSTOP " Rounds done : " cRST "%-18d" bSTG bV bSTOP"\n",nn_arr[0],round_cnt);
  
  sprintf(tmp, "%s%%", nn_arr[1]);

  SAYF(bSTG bV bSTOP " training acc : " cRST "%-18s" bSTG bV bSTOP,tmp);

  sprintf(tmp, "%s/sec", DF(avg_exec));

  SAYF("  Exec speed : " bSTG bSTOP cRST "%-18s" bSTG bV bSTOP"\n",tmp);

  SAYF(bSTG bVR bH bSTOP cLGX "data " bSTG bH10 bH5 bH2 bHB bH bSTOP cPIX "state " bSTG bH2 bH bHT bH30 bH2 bH bVL bSTOP "\n");

  SAYF(bSTG bV bSTOP " Bitmap size : " cRST "%-8s" bSTG bV bSTOP "    Stage : " cRST "%-32s" bSTG bV bSTOP"\n",nn_arr[2], stage_name);

  sprintf(tmp, "%s/%s (%s%%)", DI(stage_cnt),DI(stage_tot),(stage_tot == 0 ? "---" : DI(stage_cnt * 100 /stage_tot))); 

  SAYF(bSTG bV bSTOP " Corpus size : " cRST "%-8s" bSTG bV bSTOP " Progress : " cRST "%-32s" bSTG bV bSTOP"\n",nn_arr[3],tmp);

  /* Stops it turning into when you move a image 1mm on word (if seed is a bit too long)*/
  if (strlen(fn) > 28) sprintf(tmp, "%.28s ..." , fn );
  
  else sprintf(tmp, "%s" , fn );

  SAYF(bSTG bV bSTOP "  Nocov size : " cRST "%-8s" bSTG bV bSTOP "     Seed : " cRST "%-32s" bSTG bV bSTOP"\n",nn_arr[4],tmp);

  SAYF(bSTG bVR bH bSTOP cLGX "module load " bSTG bH10 bHT bH bH2 bH5 bHB bH bSTOP cPIX "findings " bSTG bH20 bH5 bVL bSTOP "\n");

  sprintf(tmp, "%s total, %s unique", DI(total_crashes),DI(unique_crashes)); 
  
  SAYF(bSTG bV bSTOP "  Mapping time : " cRST "%-15s" bSTG bV bSTOP "    Crashes : " cRST "%-21s" bSTG bV bSTOP"\n",nn_arr[5], tmp);

  sprintf(tmp, "%s total, %s unique", DI(total_tmout),DI(unique_tmout)); 

  SAYF(bSTG bV bSTOP " T-mining time : " cRST "%-15s" bSTG bV bSTOP "  Time outs : " cRST "%-21s" bSTG bV bSTOP"\n",nn_arr[6], tmp);

  SAYF(bSTG bV bSTOP " Training time : " cRST "%-15s" bSTG bV bSTOP " Edge count : " cRST "%-21d" bSTG bV bSTOP"\n",nn_arr[7], t_bytes);

  /*LAST BOX */
  SAYF(bSTG bLB bH30 bH2 bX bSTOP cCYA " Log messages" bSTG bH10 bH2 bH2 bHB bH5 bH2 bRB bSTOP "\n");

  if (log_warn > 10000) sprintf(tmp, "10000(+)!");

  else sprintf(tmp, "%s" , DI(log_warn));

  SAYF(bSTG SP SP20 SP10 SP2 bV bSTOP cYEL " [!]" cRST" %-7s", tmp);

  if (log_fatal > 10000) sprintf(tmp, "10000(+)!");

  else sprintf(tmp, "%s" , DI(log_fatal));

  SAYF(SP2 cLRD "[-] " cRST "%-7s" bSTG SP2 bV bSTOP "\n", tmp);

  SAYF(bSTG SP SP20 SP10 SP2 bLB bH20 bH5 bH2 bRB bSTOP "\n");
 
  fflush(0);
}

static void usage(u8* argv0) {
  SAYF("\n efm-fuzz [ options ] -- /path/to/fuzzed_app -fuzzed -app -args\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for fuzzer findings\n\n"

       "Optional: \n\n"
       "  -m megs       - memory limit for child process \n"
       "  -d            - disables auto-lanuching python neural net module, launch seperately for debugging.\n\n"     
 
       "For additional tips, please consult the README.\n\n"

       );

  exit(1);

}

void main(int argc, char *argv[]) {
  int opt;
  ELMLOGO();
  while ((opt = getopt(argc, argv, "+i:o:d:m:")) > 0)

    switch (opt) {
    case 'i': /* input dir */
      if (in_dir) WARNF("Multiple -i options not supported");
      in_dir = optarg;
      break;

    case 'o': /* output dir */
      if (out_dir) WARNF("Multiple -o options not supported");
      out_dir = optarg;
      break;

    case 'd': /* output dir */
      WARNF("Python debug debug mode, not spawing the engine.");
      start_nn = 0;
      break;

    case 'm': /* memory limit: use -m none option for ASAN */
      if (!strcmp(optarg, "none")) {
        mem_limit = 0;
        break;
      }

      char suffix = 'M';
      if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 || optarg[0] == '-') {
        WARNF("Bad syntax used for -m");
        return -1;
      }

      switch (suffix) {
        case 'T': mem_limit *= 1024 * 1024; break;
        case 'G': mem_limit *= 1024; break;
        case 'k': mem_limit /= 1024; break;
        case 'M': break;
        default:
          WARNF("Unsupported suffix or bad syntax for -m");
          return -1;
      }

      if (mem_limit < 5) {
        WARNF("Dangerously low value of -m");
        return -1;
      }
      if (sizeof(rlim_t) == 4 && mem_limit > 2000) {
        WARNF("Value of -m out of range on 32-bit systems");
        return -1;
      }
      break;
      

    default:
      usage(argv[0]);
    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  set_havoc_template(in_dir);
  setup_signal_handlers();
  check_cpu_governor();
  get_core_count();
  bind_to_free_cpu();
  setup_shm();
  set_up_nn_pointers(nn_stats,nn_arr);
  init_count_class16();
  setup_dirs_fds();
  if (!out_file) setup_stdio_file();
  detect_file_args(argc, argv + optind + 1);
  setup_targetpath(argv[optind]);
  check_crash_handling();
  copy_seeds(in_dir, out_dir);
  start_nn_mod(argv + optind);
  check_nn_alive();
  OKF("Neural network server up and running");
  chdir(out_dir);
  init_forkserver(argv + optind);
  srand(time(NULL));
  fix_up_banner(argv[optind]);
  check_if_tty();

  OKF("Ok, all set up and ready to go:\n\n"

      cGRA "       Memory limit : " cRST "%d Mb\n"
      cGRA "      Timeout limit : " cRST "%d ms\n", mem_limit, exec_tmout); 

  sleep(5);
  start_time=get_cur_time();

  start_fuzz(len);

  OKF("total execs %ld edge coverage %d.", total_execs, count_non_255_bytes(virgin_bits));
  return;
}
