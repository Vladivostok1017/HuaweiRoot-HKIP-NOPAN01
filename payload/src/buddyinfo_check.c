/*
 * Host-side check of buddyinfo_order3_from_file() against a fixture.
 * Does not start QEMU and does not open live /proc/buddyinfo.
 */
#include "buddyinfo.h"

#include <stdio.h>
#include <string.h>

static const char k_fixture[] =
    "Node 0, zone      DMA      1    2    3    4    0    0    0    0    0    0    0\n"
    "Node 0, zone    DMA32      10   20   30   40    1    0    0    0    0    0    0\n"
    "Node 0, zone   Normal      5    6    7   99    2    0    0    0    0    0    0\n"
    "Node 0, zone  Movable      0    0    0    8    0    0    0    0    0    0    0\n";

int main(void) {
  FILE *fp = fmemopen((void *)k_fixture, sizeof(k_fixture) - 1, "r");
  long got;

  if (!fp) {
    fprintf(stderr, "FAIL: fmemopen fixture\n");
    return 1;
  }
  got = buddyinfo_order3_from_file(fp);
  fclose(fp);

  printf("buddyinfo_order3=%ld\n", got);
  if (got != 99) {
    fprintf(stderr, "FAIL: expected Normal zone order-3=99, got %ld\n", got);
    return 1;
  }
  printf("buddyinfo check OK\n");
  return 0;
}
