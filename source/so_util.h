/* so_util.h -- utils to load and hook .so modules
 *
 * Copyright (C) 2021 Andy Nguyen, fgsfds
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef __SO_UTIL_H__
#define __SO_UTIL_H__

#include <stdint.h>
#include "elf.h"

#define ALIGN_MEM(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define MAX_DATA_SEG 4
typedef struct {
  int size;
  uint32_t field_4;
  uint32_t attr;
  uint32_t field_C;
  uint32_t paddr;
  int alignment;
  uint32_t extraLow;
  uint32_t extraHigh;
  uint32_t mirror_blockid;
  int pid;
}SceKernelAllocMemBlockKernelOpt;
//64-bit so_module
typedef struct {
  struct so_module *next;

  SharedMemory patch_blockid, text_blockid, data_blockid[MAX_DATA_SEG];
  uintptr_t patch_base, patch_head, cave_base, cave_head, text_base, data_base[MAX_DATA_SEG];
  size_t patch_size, cave_size, text_size, data_size[MAX_DATA_SEG];
  int n_data;

  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;

  Elf64_Dyn *dynamic;
  Elf64_Sym *dynsym;
  Elf64_Rel *reldyn;
  Elf64_Rel *relplt;

  int (** init_array)(void);
  uint32_t *hash;

  int num_dynamic;
  int num_dynsym;
  int num_reldyn;
  int num_relplt;
  int num_init_array;

  char *soname;
  char *shstr;
  char *dynstr;
} so_module;


typedef struct {
  char *symbol;
  uintptr_t func;
} DynLibFunction;

extern void *text_base, *data_base;
extern size_t text_size, data_size;

void hook_thumb(uintptr_t addr, uintptr_t dst);
void hook_arm(uintptr_t addr, uintptr_t dst);
void hook_arm64(uintptr_t addr, uintptr_t dst);

void so_flush_caches(so_module *mod);
void so_free_temp(void);
int so_load(so_module *mod, const char *filename);
int so_relocate(so_module *mod);
int so_resolve(so_module *mod, DynLibFunction *default_dynlib, int size_default_dynlib, int default_dynlib_only);
uintptr_t so_resolve_link(so_module *mod, const char *symbol);
void so_initialize(so_module *mod);
uintptr_t so_find_addr(const char *symbol);
uintptr_t so_find_addr_rx(const char *symbol);
uintptr_t so_find_rel_addr(const char *symbol);
DynLibFunction *so_find_import(DynLibFunction *funcs, int num_funcs, const char *name);
void so_finalize(void);
int so_unload(void);

#endif
