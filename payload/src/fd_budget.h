#ifndef FD_BUDGET_H
#define FD_BUDGET_H

/*
 * Leftover-fd accounting for the CFI → pipe-physrw handoff.
 * Each pipe() consumes two fds.  Host checks feed (open, limit, pipes)
 * fixtures; the guest path uses the same helper on live rlimit counts.
 */

#ifndef FD_BUDGET_SLACK
#define FD_BUDGET_SLACK 32
#endif

#ifndef PIPE_PHYS_PIPE_COUNT
#ifdef PIPE_DRAIN
#define PIPE_PHYS_PIPE_COUNT (PIPE_DRAIN + PIPE_RECLAIM + 1)
#else
#define PIPE_PHYS_PIPE_COUNT (15 * 16 + 15 * 16 + 1)
#endif
#endif

static inline int fd_budget_fds_needed(int pipe_count, int slack) {
  if (pipe_count < 0 || slack < 0) {
    return -1;
  }
  return pipe_count * 2 + slack;
}

static inline int fd_budget_has_room(int open_count, int limit, int pipe_count,
                                     int slack) {
  int need = fd_budget_fds_needed(pipe_count, slack);
  if (need < 0 || open_count < 0 || limit < 0) {
    return 0;
  }
  if (open_count >= limit) {
    return 0;
  }
  return (limit - open_count) >= need;
}

#endif
