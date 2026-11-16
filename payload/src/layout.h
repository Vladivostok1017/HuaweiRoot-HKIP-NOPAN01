#ifndef LAYOUT_H
#define LAYOUT_H

/*
 * Linear VA <-> struct page for HWWLZ 5.10.43.
 *
 * Device (default): physical PFN includes memstart_addr / P0_PHYS_OFFSET.
 *   pfn  = ((va - PAGE_OFFSET) + memstart_addr) >> PAGE_SHIFT
 *   page = VMEMMAP_START + pfn * sizeof(struct page)
 *   va   = PAGE_OFFSET + (pfn << PAGE_SHIFT) - memstart_addr
 *
 * QEMU wrap (QEMU_LAYOUT only): copy_page_to_iter identity
 *   pfn  = (va - PAGE_OFFSET) >> PAGE_SHIFT
 * that wrap is not __va and is not the device formula.
 */

#include <stdint.h>

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#endif

static inline uintptr_t layout_page_align(uintptr_t addr) {
  return addr & ~((uintptr_t)PAGE_SIZE - 1);
}

static inline uintptr_t device_linear_to_pfn(uintptr_t va) {
  uintptr_t aligned = layout_page_align(va);
  return ((aligned - (uintptr_t)DIRECT_MAP_BASE) + (uintptr_t)P0_PHYS_OFFSET) >>
         PAGE_SHIFT;
}

static inline uintptr_t device_linear_to_page(uintptr_t va) {
  return (uintptr_t)VMEMMAP_START +
         device_linear_to_pfn(va) * (uintptr_t)STRUCT_PAGE_SIZE;
}

static inline uintptr_t device_page_to_linear(uintptr_t page) {
  uintptr_t pfn =
      (page - (uintptr_t)VMEMMAP_START) / (uintptr_t)STRUCT_PAGE_SIZE;
  return (uintptr_t)DIRECT_MAP_BASE + (pfn << PAGE_SHIFT) -
         (uintptr_t)P0_PHYS_OFFSET;
}

static inline uintptr_t qemu_wrap_linear_to_pfn(uintptr_t va) {
  uintptr_t aligned = layout_page_align(va);
  return (aligned - (uintptr_t)DIRECT_MAP_BASE) >> PAGE_SHIFT;
}

static inline uintptr_t qemu_wrap_linear_to_page(uintptr_t va) {
  return (uintptr_t)VMEMMAP_START +
         qemu_wrap_linear_to_pfn(va) * (uintptr_t)STRUCT_PAGE_SIZE;
}

static inline uintptr_t qemu_wrap_page_to_linear(uintptr_t page) {
  uintptr_t pfn =
      (page - (uintptr_t)VMEMMAP_START) / (uintptr_t)STRUCT_PAGE_SIZE;
  return (uintptr_t)DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

#ifdef QEMU_LAYOUT
#define layout_linear_to_page qemu_wrap_linear_to_page
#define layout_page_to_linear qemu_wrap_page_to_linear
#else
#define layout_linear_to_page device_linear_to_page
#define layout_page_to_linear device_page_to_linear
#endif

#endif
