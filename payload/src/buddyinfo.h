#ifndef BUDDYINFO_H
#define BUDDYINFO_H

/*
 * Parse /proc/buddyinfo.  Column 4 after the zone name is order-3.
 * Prefer the Normal zone; otherwise the largest order-3 count seen.
 * Host layout-check feeds a fixture FILE* so this is not a live /proc.
 */

#include <stdio.h>
#include <string.h>

static inline long buddyinfo_order3_from_file(FILE *fp) {
  char line[512];
  long fallback = -1;
  long normal = -1;

  if (!fp) {
    return -1;
  }

  while (fgets(line, sizeof(line), fp)) {
    char *p = strstr(line, "zone");
    if (!p) {
      continue;
    }
    char name[32];
    unsigned long c0, c1, c2, c3;
    if (sscanf(p + 4, "%31s %lu %lu %lu %lu", name, &c0, &c1, &c2, &c3) != 5) {
      continue;
    }
    if ((long)c3 > fallback) {
      fallback = (long)c3;
    }
    if (!strcmp(name, "Normal")) {
      normal = (long)c3;
    }
  }
  return normal >= 0 ? normal : fallback;
}

static inline long buddyinfo_order3_free(void) {
  FILE *fp = fopen("/proc/buddyinfo", "r");
  long n;
  if (!fp) {
    return -1;
  }
  n = buddyinfo_order3_from_file(fp);
  fclose(fp);
  return n;
}

#endif
