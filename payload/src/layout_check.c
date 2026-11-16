/*
 * Host-side check of the shipped VA <-> struct page helpers in layout.h.
 * Does not start QEMU and does not run a guest payload.
 */
#define TARGET_CONFIG_H "targets/huawei_wlz_5_10_43/target.h"

#include "offset.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#include "layout.h"

int main(void) {
  uintptr_t page_offset = (uintptr_t)DIRECT_MAP_BASE;
  uintptr_t vmemmap = (uintptr_t)VMEMMAP_START;
  uintptr_t memstart = (uintptr_t)P0_PHYS_OFFSET;
  uintptr_t va = page_offset;

  uintptr_t phys_pfn = device_linear_to_pfn(va);
  uintptr_t device_page = device_linear_to_page(va);
  uintptr_t wrap_pfn = qemu_wrap_linear_to_pfn(va);
  uintptr_t wrap_page = qemu_wrap_linear_to_page(va);
  uintptr_t va2 = device_page_to_linear(device_page);
  uintptr_t default_page = layout_linear_to_page(va);
  uintptr_t default_va = layout_page_to_linear(default_page);

  printf("PAGE_OFFSET=0x%" PRIxPTR "\n", page_offset);
  printf("VMEMMAP_START=0x%" PRIxPTR "\n", vmemmap);
  printf("memstart_addr=0x%" PRIxPTR "\n", memstart);
  printf("phys_pfn=0x%" PRIxPTR "\n", phys_pfn);
  printf("device_page=0x%" PRIxPTR "\n", device_page);
  printf("qemu_wrap_pfn=0x%" PRIxPTR "\n", wrap_pfn);
  printf("qemu_wrap_page=0x%" PRIxPTR "\n", wrap_page);
  printf("pages_differ=%d\n", device_page != wrap_page);
  printf("roundtrip_va=0x%" PRIxPTR "\n", va2);
  printf("default_is_device=%d\n", default_page == device_page);
  printf("default_roundtrip=%d\n", default_va == va);

  if (phys_pfn == 0) {
    fprintf(stderr, "FAIL: phys_pfn is 0; device formula must add memstart\n");
    return 1;
  }
  if (device_page == wrap_page) {
    fprintf(stderr, "FAIL: device page equals QEMU wrap page\n");
    return 1;
  }
  if (va2 != va) {
    fprintf(stderr, "FAIL: device reverse mismatch\n");
    return 1;
  }
  if (default_page != device_page || default_va != va) {
    fprintf(stderr, "FAIL: default layout path is not the device formula\n");
    return 1;
  }
#ifdef QEMU_LAYOUT
  fprintf(stderr, "FAIL: layout_check must be built without QEMU_LAYOUT\n");
  return 1;
#endif
  printf("layout check OK\n");
  return 0;
}
