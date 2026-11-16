#pragma once

#define _GNU_SOURCE
#include <sched.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#if !defined(__ARM) && !defined(__INTEL) && !defined(__AMD)
#define __INTEL
#endif

#define RDPRU ".byte 0x0f, 0x01, 0xfd"
#define RDPRU_ECX_MPERF 0
#define RDPRU_ECX_APERF 1

#if defined(__ARM)
/*
 * Kirin/Huawei: EL0 cntvct_el0 is either trapped (frozen) or too coarse
 * (~19.2 MHz) to resolve an empty-bucket FUTEX_WAKE.  KernelSnitch then
 * sees approx_time=0 and treats every sample as a collision.  Probe once;
 * if dead or later forced, use a direct clock_gettime syscall (not vDSO).
 */
static volatile int g_ksnitch_cntvct_state = -1; /* -1=unprobed, 0=ok, 1=dead */

static inline int ksnitch_cntvct_dead(void)
{
    int s = g_ksnitch_cntvct_state;
    if (s >= 0)
        return s;
    unsigned long long a, b;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(a));
    struct timespec ts;
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(b));
    asm volatile("isb" ::: "memory");
    s = (a == b) ? 1 : 0;
    g_ksnitch_cntvct_state = s;
    return s;
}

static inline size_t ksnitch_clock_monotonic_ns(void)
{
    struct timespec ts;
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    return (size_t)ts.tv_sec * 1000000000ull + (size_t)ts.tv_nsec;
}
#endif

static inline size_t rdtsc_begin(void)
{
#if defined(__INTEL)
    size_t a, d;
    asm volatile("mfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    a = (d << 32) | a;
    asm volatile("lfence");
    return a;
#elif defined(__AMD)
    unsigned long low_a, high_a;
    asm volatile("mfence");
    asm volatile(RDPRU : "=a"(low_a), "=d"(high_a) : "c"(RDPRU_ECX_APERF));
    unsigned long aval = ((low_a) | (high_a) << 32);
    asm volatile("lfence");
    return aval;
#elif defined(__ARM)
    if (ksnitch_cntvct_dead())
        return ksnitch_clock_monotonic_ns();
    unsigned long long vct;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
    asm volatile("isb" ::: "memory");
    return (size_t)vct;
#else
#error "Invalid TIMEUTILS_ARCH value"
#endif
}

static inline size_t rdtsc_end(void)
{
#if defined(__INTEL)
    size_t a, d;
    asm volatile("lfence");
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    a = (d << 32) | a;
    asm volatile("mfence");
    return a;
#elif defined(__AMD)
    unsigned long low_a, high_a;
    asm volatile("lfence");
    asm volatile(RDPRU : "=a"(low_a), "=d"(high_a) : "c"(RDPRU_ECX_APERF));
    unsigned long aval = ((low_a) | (high_a) << 32);
    asm volatile("mfence");
    return aval;
#elif defined(__ARM)
    if (g_ksnitch_cntvct_state > 0)
        return ksnitch_clock_monotonic_ns();
    unsigned long long vct;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
    asm volatile("isb" ::: "memory");
    return (size_t)vct;
#else
#error "Invalid TIMEUTILS_ARCH value"
#endif
}
