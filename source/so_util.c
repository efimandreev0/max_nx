/* so_util.c -- utils to load and hook .so modules
 *
 * Copyright (C) 2021 Andy Nguyen, fgsfds
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <switch.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <elf.h>

#include "main.h"
#include "dialog.h"
#include "so_util.h"

typedef struct b_enc {
  union {
    struct __attribute__((__packed__)) {
      int imm24: 24;
      unsigned int l: 1; // Branch with Link flag
      unsigned int enc: 3; // 0b101
      unsigned int cond: 4; // 0b1110
    } bits;
    uint32_t raw;
  };
} b_enc;

typedef struct ldst_enc {
  union {
    struct __attribute__((__packed__)) {
      int imm12: 12;
      unsigned int rt: 4; // Source/Destination register
      unsigned int rn: 4; // Base register
      unsigned int bit20_1: 1; // 0: store to memory, 1: load from memory
      unsigned int w: 1; // 0: no write-back, 1: write address into base
      unsigned int b: 1; // 0: word, 1: byte
      unsigned int u: 1; // 0: subtract offset from base, 1: add to base
      unsigned int p: 1; // 0: post indexing, 1: pre indexing
      unsigned int enc: 3;
      unsigned int cond: 4;
    } bits;
    uint32_t raw;
  };
} ldst_enc;

#define B_RANGE ((1 << 24) - 1)
#define B_OFFSET(x) (x + 8) // branch jumps into addr - 8, so range is biased forward
#define B(PC, DEST) ((b_enc){.bits = {.cond = 0b1110, .enc = 0b101, .l = 0, .imm24 = (((intptr_t)DEST-(intptr_t)PC) / 4) - 2}})
#define LDR_OFFS(RT, RN, IMM) ((ldst_enc){.bits = {.cond = 0b1110, .enc = 0b010, .p = 1, .u = (IMM >= 0), .b = 0, .w = 0, .bit20_1 = 1, .rn = RN, .rt = RT, .imm12 = (IMM >= 0) ? IMM : -IMM}})

#define PATCH_SZ 0x10000 //64 KB-ish arenas
static so_module *head = NULL, *tail = NULL;

void hook_thumb(uintptr_t addr, uintptr_t dst) {
  if (addr == 0)
    return;
  addr &= ~1;
  if (addr & 2) {
    uint16_t nop = 0xbf00;
    memcpy((void *)addr, &nop, sizeof(nop));
    addr += 2;
  }
  uint32_t hook[2];
  hook[0] = 0xf000f8df; // LDR PC, [PC]
  hook[1] = dst;
  memcpy((void *)addr, hook, sizeof(hook));
}

void hook_arm(uintptr_t addr, uintptr_t dst) {
  if (addr == 0)
    return;
  uint32_t hook[2];
  hook[0] = 0xe51ff004; // LDR PC, [PC, #-0x4]
  hook[1] = dst;
  memcpy((void *)addr, hook, sizeof(hook));
}

void hook_arm64(uintptr_t addr, uintptr_t dst) {
  if (addr == 0)
    return;
  uint32_t *hook = (uint32_t *)addr;
  hook[0] = 0x58000051u; // LDR X17, #0x8
  hook[1] = 0xd61f0220u; // BR X17
  *(uint64_t *)(hook + 2) = dst;
}

void so_flush_caches(so_module *mod) {
  armDCacheFlush(mod->text_base, mod->text_size);
  armICacheInvalidate(mod->text_base, mod->text_size);
}

void so_free_temp(void) {
  free(so_base);
  so_base = NULL;
}

void so_finalize(void) {
  Result rc = 0;

  // map the entire thing as code memory
  rc = svcMapProcessCodeMemory(envGetOwnProcessHandle(), (u64)load_virtbase, (u64)load_base, load_size);
  if (R_FAILED(rc)) fatal_error("Error: svcMapProcessCodeMemory failed:\n%08x", rc);

  // map code sections as R+X
  const u64 text_asize = ALIGN_MEM(text_size, 0x1000); // align to page
  rc = svcSetProcessMemoryPermission(envGetOwnProcessHandle(), (u64)text_virtbase, text_asize, Perm_Rx);
  if (R_FAILED(rc)) fatal_error("Error: could not map %u bytes of RX memory at %p:\n%08x", text_asize, text_virtbase, rc);

  // map the rest as R+W
  const u64 rest_asize = load_size - text_asize;
  const uintptr_t rest_virtbase = (uintptr_t)text_virtbase + text_asize;
  rc = svcSetProcessMemoryPermission(envGetOwnProcessHandle(), rest_virtbase, rest_asize, Perm_Rw);
  if (R_FAILED(rc)) fatal_error("Error: could not map %u bytes of RW memory at %p (%p) (2):\n%08x", rest_asize, data_virtbase, rest_virtbase, rc);
}

int _so_load(so_module *mod, int so_blockid, void *so_data, uintptr_t load_addr) {
	int res = 0;
	uintptr_t data_addr = 0;
	
	if (memcmp(so_data, ELFMAG, SELFMAG) != 0) {
		res = -1;
		goto err_free_so;
	}

	mod->ehdr = (Elf64_Ehdr *)so_data;
	mod->phdr = (Elf64_Phdr *)((uintptr_t)so_data + mod->ehdr->e_phoff);
	mod->shdr = (Elf64_Shdr *)((uintptr_t)so_data + mod->ehdr->e_shoff);

	mod->shstr = (char *)((uintptr_t)so_data + mod->shdr[mod->ehdr->e_shstrndx].sh_offset);

	for (int i = 0; i < mod->ehdr->e_phnum; i++) {
		if (mod->phdr[i].p_type == PT_LOAD) {
			void *prog_data;
			size_t prog_size;

			if ((mod->phdr[i].p_flags & PF_X) == PF_X) {
				// Allocate arena for code patches, trampolines, etc
				// Sits exactly under the desired allocation space
				mod->patch_size = ALIGN_MEM(PATCH_SZ, mod->phdr[i].p_align);
				SceKernelAllocMemBlockKernelOpt opt;
				memset(&opt, 0, sizeof(SceKernelAllocMemBlockKernelOpt));
				opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
				opt.attr = 0x1;
				opt.field_C = (uint32_t)load_addr - mod->patch_size;
				res = mod->patch_blockid = kuKernelAllocMemBlock("rx_block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RX, mod->patch_size, &opt);
				if (res < 0)
					goto err_free_so;

				sceKernelGetMemBlockBase(mod->patch_blockid, &mod->patch_base);
				mod->patch_head = mod->patch_base;

				prog_size = ALIGN_MEM(mod->phdr[i].p_memsz, mod->phdr[i].p_align);
				memset(&opt, 0, sizeof(SceKernelAllocMemBlockKernelOpt));
				opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
				opt.attr = 0x1;
				opt.field_C = (SceUInt32)load_addr;
				res = mod->text_blockid = kuKernelAllocMemBlock("rx_block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RX, prog_size, &opt);
				if (res < 0)
					goto err_free_so;

				sceKernelGetMemBlockBase(mod->text_blockid, &prog_data);

				mod->phdr[i].p_vaddr += (Elf64_Addr)prog_data;

				mod->text_base = mod->phdr[i].p_vaddr;
				mod->text_size = mod->phdr[i].p_memsz;

				// Use the .text segment padding as a code cave
				// Word-align it to make it simpler for instruction arena allocation
				mod->cave_size = ALIGN_MEM(prog_size - mod->phdr[i].p_memsz, 0x4);
				mod->cave_base = mod->cave_head = prog_data + mod->phdr[i].p_memsz;
				mod->cave_base = ALIGN_MEM(mod->cave_base, 0x4);
				mod->cave_head = mod->cave_base;
				debugPrintf("code cave: %d bytes (@0x%08X).\n", mod->cave_size, mod->cave_base);

				data_addr = (uintptr_t)prog_data + prog_size;
			} else {
				if (data_addr == 0)
					goto err_free_so;

				if (mod->n_data >= MAX_DATA_SEG)
					goto err_free_data;

				prog_size = ALIGN_MEM(mod->phdr[i].p_memsz + mod->phdr[i].p_vaddr - (data_addr - mod->text_base), mod->phdr[i].p_align);

				SceKernelAllocMemBlockKernelOpt opt;
				memset(&opt, 0, sizeof(SceKernelAllocMemBlockKernelOpt));
				opt.size = sizeof(SceKernelAllocMemBlockKernelOpt);
				opt.attr = 0x1;
				opt.field_C = (SceUInt32)data_addr;
				res = mod->data_blockid[mod->n_data] = kuKernelAllocMemBlock("rw_block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, prog_size, &opt);
				if (res < 0)
					goto err_free_text;

				sceKernelGetMemBlockBase(mod->data_blockid[mod->n_data], &prog_data);
				data_addr = (uintptr_t)prog_data + prog_size;

				mod->phdr[i].p_vaddr += (Elf64_Addr)mod->text_base;

				mod->data_base[mod->n_data] = mod->phdr[i].p_vaddr;
				mod->data_size[mod->n_data] = mod->phdr[i].p_memsz;
				mod->n_data++;
			}

			char *zero = malloc(prog_size - mod->phdr[i].p_filesz);
			memset(zero, 0, prog_size - mod->phdr[i].p_filesz);
			kuKernelCpuUnrestrictedMemcpy(prog_data + mod->phdr[i].p_filesz, zero, prog_size - mod->phdr[i].p_filesz);
			free(zero);

			kuKernelCpuUnrestrictedMemcpy((void *)mod->phdr[i].p_vaddr, (void *)((uintptr_t)so_data + mod->phdr[i].p_offset), mod->phdr[i].p_filesz);
		}
	}

	for (int i = 0; i < mod->ehdr->e_shnum; i++) {
		char *sh_name = mod->shstr + mod->shdr[i].sh_name;
		uintptr_t sh_addr = mod->text_base + mod->shdr[i].sh_addr;
		size_t sh_size = mod->shdr[i].sh_size;
		if (strcmp(sh_name, ".dynamic") == 0) {
			mod->dynamic = (Elf64_Dyn *)sh_addr;
			mod->num_dynamic = sh_size / sizeof(Elf64_Dyn);
		} else if (strcmp(sh_name, ".dynstr") == 0) {
			mod->dynstr = (char *)sh_addr;
		} else if (strcmp(sh_name, ".dynsym") == 0) {
			mod->dynsym = (Elf64_Sym *)sh_addr;
			mod->num_dynsym = sh_size / sizeof(Elf64_Sym);
		} else if (strcmp(sh_name, ".rel.dyn") == 0) {
			mod->reldyn = (Elf64_Rel *)sh_addr;
			mod->num_reldyn = sh_size / sizeof(Elf64_Rel);
		} else if (strcmp(sh_name, ".rel.plt") == 0) {
			mod->relplt = (Elf64_Rel *)sh_addr;
			mod->num_relplt = sh_size / sizeof(Elf64_Rel);
		} else if (strcmp(sh_name, ".init_array") == 0) {
			mod->init_array = (void *)sh_addr;
			mod->num_init_array = sh_size / sizeof(void *);
		} else if (strcmp(sh_name, ".hash") == 0) {
			mod->hash = (void *)sh_addr;
		}
	}

	if (mod->dynamic == NULL ||
		mod->dynstr == NULL ||
		mod->dynsym == NULL ||
		mod->reldyn == NULL ||
		mod->relplt == NULL) {
		res = -2;
		goto err_free_data;
	}

	for (int i = 0; i < mod->num_dynamic; i++) {
		switch (mod->dynamic[i].d_tag) {
		case DT_SONAME:
			mod->soname = mod->dynstr + mod->dynamic[i].d_un.d_ptr;
			break;
		default:
			break;
		}
	}

	sceKernelFreeMemBlock(so_blockid);

	if (!head && !tail) {
		head = mod;
		tail = mod;
	} else {
		tail->next = mod;
		tail = mod;
	}

	return 0;

err_free_data:
	for (int i = 0; i < mod->n_data; i++)
		sceKernelFreeMemBlock(mod->data_blockid[i]);
err_free_text:
	sceKernelFreeMemBlock(mod->text_blockid);
err_free_so:
	sceKernelFreeMemBlock(so_blockid);

	return res;
}

int so_mem_load(so_module *mod, void *buffer, size_t so_size, uintptr_t load_addr) {
	SceUID so_blockid;
	void *so_data;

	memset(mod, 0, sizeof(so_module));

	so_blockid = sceKernelAllocMemBlock("so block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, (so_size + 0xfff) & ~0xfff, NULL);
	if (so_blockid < 0)
		return so_blockid;

	sceKernelGetMemBlockBase(so_blockid, &so_data);
	sceClibMemcpy(so_data, buffer, so_size);
	
	return _so_load(mod, so_blockid, so_data, load_addr);
}

int so_file_load(so_module *mod, const char *filename, uintptr_t load_addr) {
	SceUID so_blockid;
	void *so_data;

	memset(mod, 0, sizeof(so_module));

	SceUID fd = sceIoOpen(filename, SCE_O_RDONLY, 0);
	if (fd < 0)
		return fd;

	size_t so_size = sceIoLseek(fd, 0, SCE_SEEK_END);
	sceIoLseek(fd, 0, SCE_SEEK_SET);

	so_blockid = sceKernelAllocMemBlock("so block", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW, (so_size + 0xfff) & ~0xfff, NULL);
	if (so_blockid < 0)
		return so_blockid;

	sceKernelGetMemBlockBase(so_blockid, &so_data);

	sceIoRead(fd, so_data, so_size);
	sceIoClose(fd);

	return _so_load(mod, so_blockid, so_data, load_addr);
}

int so_relocate(so_module *mod) {
  for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
    Elf64_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
    Elf64_Sym *sym = &mod->dynsym[ELF64_R_SYM(rel->r_info)];
    uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

    int type = ELF64_R_TYPE(rel->r_info);
    switch (type) {
      case R_AARCH64_ABS64:
        if (sym->st_shndx != SHN_UNDEF)
          *ptr += mod->text_base + sym->st_value;
        else
          *ptr = mod->text_base + rel->r_offset; // make it crash for debugging
        break;

      case R_AARCH64_RELATIVE:
        *ptr += mod->text_base;
        break;

      case R_AARCH64_GLOB_DAT:
      {
        if (sym->st_shndx != SHN_UNDEF)
          *ptr = mod->text_base + sym->st_value;
        else
          *ptr = mod->text_base + rel->r_offset; // make it crash for debugging
        break;
      }

      default:
        fatal_error("Error unknown relocation type %x\n", type);
        break;
    }
  }

  return 0;
}
int so_resolve(so_module *mod, DynLibFunction *default_dynlib, int size_default_dynlib, int default_dynlib_only) {
  for (int i = 0; i < mod->num_reldyn + mod->num_relplt; i++) {
    Elf64_Rel *rel = i < mod->num_reldyn ? &mod->reldyn[i] : &mod->relplt[i - mod->num_reldyn];
    Elf64_Sym *sym = &mod->dynsym[ELF64_R_SYM(rel->r_info)];
    uintptr_t *ptr = (uintptr_t *)(mod->text_base + rel->r_offset);

    int type = ELF64_R_TYPE(rel->r_info);
    switch (type) {
      case R_AARCH64_ABS64:
      case R_AARCH64_GLOB_DAT:
      case R_AARCH64_JUMP_SLOT:
      {
        if (sym->st_shndx == SHN_UNDEF) {
          int resolved = 0;
          if (!default_dynlib_only) {
            uintptr_t link = so_resolve_link(mod, mod->dynstr + sym->st_name);
            if (link) {
              // debugPrintf("Resolved from dependencies: %s\n", mod->dynstr + sym->st_name);
              *ptr = link;
              resolved = 1;
            }
          }

          for (int j = 0; j < size_default_dynlib / sizeof(DynLibFunction); j++) {
            if (strcmp(mod->dynstr + sym->st_name, default_dynlib[j].symbol) == 0) {
              if (resolved) {
                // debugPrintf("Overriden: %s\n", mod->dynstr + sym->st_name);
              } else {
                // debugPrintf("Resolved manually: %s\n", mod->dynstr + sym->st_name);
              }
              *ptr = default_dynlib[j].func;
              resolved = 1;
              break;
            }
          }

          if (!resolved) {
            // debugPrintf("Missing: %s\n", mod->dynstr + sym->st_name);
          }
        }

        break;
      }

      default:
        break;
    }
  }

  return 0;
}
uintptr_t so_resolve_link(so_module *mod, const char *symbol) {
  for (int i = 0; i < mod->num_dynamic; i++) {
    switch (mod->dynamic[i].d_tag) {
      case DT_NEEDED:
      {
        so_module *curr = head;
        while (curr) {
          if (curr != mod && strcmp(curr->soname, mod->dynstr + mod->dynamic[i].d_un.d_ptr) == 0) {
            uintptr_t link = so_symbol(curr, symbol);
            if (link)
              return link;
          }
          curr = curr->next;
        }

        break;
      }
      default:
        break;
    }
  }

  return 0;
}
void so_initialize(so_module *mod) {
  for (int i = 0; i < mod->num_init_array; i++) {
    if (mod->init_array[i])
      mod->init_array[i]();
  }
}

uintptr_t so_find_addr(const char *symbol) {
  for (int i = 0; i < num_syms; i++) {
    char *name = dynstrtab + syms[i].st_name;
    if (strcmp(name, symbol) == 0)
      return (uintptr_t)text_base + syms[i].st_value;
  }

  fatal_error("Error: could not find symbol:\n%s\n", symbol);
  return 0;
}

uintptr_t so_find_rel_addr(const char *symbol) {
  for (int i = 0; i < elf_hdr->e_shnum; i++) {
    char *sh_name = shstrtab + sec_hdr[i].sh_name;
    if (strcmp(sh_name, ".rela.dyn") == 0 || strcmp(sh_name, ".rela.plt") == 0) {
      Elf64_Rela *rels = (Elf64_Rela *)((uintptr_t)text_base + sec_hdr[i].sh_addr);
      for (int j = 0; j < sec_hdr[i].sh_size / sizeof(Elf64_Rela); j++) {
        Elf64_Sym *sym = &syms[ELF64_R_SYM(rels[j].r_info)];

        int type = ELF64_R_TYPE(rels[j].r_info);
        if (type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT) {
          char *name = dynstrtab + sym->st_name;
          if (strcmp(name, symbol) == 0)
            return (uintptr_t)text_base + rels[j].r_offset;
        }
      }
    }
  }

  fatal_error("Error: could not find symbol:\n%s\n", symbol);
  return 0;
}

uintptr_t so_find_addr_rx(const char *symbol) {
  for (int i = 0; i < num_syms; i++) {
    char *name = dynstrtab + syms[i].st_name;
    if (strcmp(name, symbol) == 0)
      return (uintptr_t)text_virtbase + syms[i].st_value;
  }

  fatal_error("Error: could not find symbol:\n%s\n", symbol);
  return 0;
}

DynLibFunction *so_find_import(DynLibFunction *funcs, int num_funcs, const char *name) {
  for (int i = 0; i < num_funcs; ++i)
    if (!strcmp(funcs[i].symbol, name))
      return &funcs[i];
  return NULL;
}

int so_unload(void) {
  if (load_base == NULL)
    return -1;

  if (so_base) {
    // someone forgot to free the temp data
    so_free_temp();
  }

  // remap text as RW
  const u64 text_asize = ALIGN_MEM(text_size, 0x1000); // align to page
  svcSetProcessMemoryPermission(envGetOwnProcessHandle(), (u64)text_virtbase, text_asize, Perm_Rw);
  // unmap everything
  svcUnmapProcessCodeMemory(envGetOwnProcessHandle(), (u64)load_virtbase, (u64)load_base, load_size);

  // release virtual address range
  virtmemLock();
  virtmemRemoveReservation(load_memrv);
  virtmemUnlock();

  return 0;
}
