/*
 * Host-side check of fd_budget_has_room() against fixtures.
 * Does not start QEMU and does not open a live fd table.
 */
#include "fd_budget.h"

#include <stdio.h>

int main(void) {
  int pipes = PIPE_PHYS_PIPE_COUNT;
  int slack = FD_BUDGET_SLACK;
  int need = fd_budget_fds_needed(pipes, slack);
  int exhausted;
  int room;

  printf("pipe_count=%d slack=%d need=%d\n", pipes, slack, need);
  if (need != pipes * 2 + slack || need <= 0) {
    fprintf(stderr, "FAIL: fd_budget_fds_needed\n");
    return 1;
  }

  /* Exhausted table: last CFI-class open count vs a 4096 rlimit. */
  exhausted = fd_budget_has_room(4000, 4096, pipes, slack);
  printf("exhausted open=4000 limit=4096 room=%d\n", exhausted);
  if (exhausted) {
    fprintf(stderr, "FAIL: exhausted table must be rejected\n");
    return 1;
  }
  exhausted = fd_budget_has_room(4096, 4096, pipes, slack);
  if (exhausted) {
    fprintf(stderr, "FAIL: full table must be rejected\n");
    return 1;
  }

  /* Room for PIPE_DRAIN+PIPE_RECLAIM+result pipes. */
  room = fd_budget_has_room(64, 4096, pipes, slack);
  printf("room open=64 limit=4096 room=%d\n", room);
  if (!room) {
    fprintf(stderr, "FAIL: table with room for pipe-physrw must be accepted\n");
    return 1;
  }

  printf("fd budget check OK\n");
  return 0;
}
