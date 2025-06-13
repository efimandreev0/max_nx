/* main.c
 *
 * Copyright (C) 2021 fgsfds, Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <switch.h>

#include "config.h"
#include "util.h"
#include "error.h"
#include "so_util.h"
#include "hooks.h"
#include "imports.h"

static void *heap_so_base = NULL;
static size_t heap_so_limit = 0;
so_module max_mod;
// provide replacement heap init function to separate newlib heap from the .so
void __libnx_initheap(void) {
  void *addr;
  size_t size = 0, fake_heap_size = 0;
  size_t mem_available = 0, mem_used = 0;

  if (envHasHeapOverride()) {
    addr = envGetHeapOverrideAddr();
    size = envGetHeapOverrideSize();
  } else {
    svcGetInfo(&mem_available, InfoType_TotalMemorySize, CUR_PROCESS_HANDLE, 0);
    svcGetInfo(&mem_used, InfoType_UsedMemorySize, CUR_PROCESS_HANDLE, 0);
    if (mem_available > mem_used + 0x200000)
      size = (mem_available - mem_used - 0x200000) & ~0x1FFFFF;
    if (size == 0)
      size = 0x2000000 * 16;
    Result rc = svcSetHeapSize(&addr, size);
    if (R_FAILED(rc))
      diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_HeapAllocFailed));
  }

  // only allocate a fixed amount for the newlib heap
  extern char *fake_heap_start;
  extern char *fake_heap_end;
  fake_heap_size  = umin(size, MEMORY_MB * 1024 * 1024);
  fake_heap_start = (char *)addr;
  fake_heap_end   = (char *)addr + fake_heap_size;

  heap_so_base = (char *)addr + fake_heap_size;
  heap_so_base = (void *)ALIGN_MEM((uintptr_t)heap_so_base, 0x1000); // align to page size
  heap_so_limit = (char *)addr + size - (char *)heap_so_base;
}

static void check_data(void) {
  const char *files[] = {
    "MaxPayneSoundsv2.msf",
    "x_data.ras",
    "x_english.ras",
    "x_level1.ras",
    "x_level2.ras",
    "x_level3.ras",
    "data",
    "es2",
    // if this is missing, assets folder hasn't been merged in
    "es2/DefaultPixel.txt",
    // mod file goes here
    "",
  };
  struct stat st;
  unsigned int numfiles = (sizeof(files) / sizeof(*files)) - 1;
  // if mod is enabled, also check for mod file
  if (config.mod_file[0])
    files[numfiles++] = config.mod_file;
  // check if all the required files are present
  for (unsigned int i = 0; i < numfiles; ++i) {
    if (stat(files[i], &st) < 0) {
      fatal_error("Could not find\n%s.\nCheck your data files.", files[i]);
      break;
    }
  }
}

static void check_syscalls(void) {
  if (!envIsSyscallHinted(0x77))
    fatal_error("svcMapProcessCodeMemory is unavailable.");
  if (!envIsSyscallHinted(0x78))
    fatal_error("svcUnmapProcessCodeMemory is unavailable.");
  if (!envIsSyscallHinted(0x73))
    fatal_error("svcSetProcessMemoryPermission is unavailable.");
  if (envGetOwnProcessHandle() == INVALID_HANDLE)
    fatal_error("Own process handle is unavailable.");
}

static void set_screen_size(int w, int h) {
  if (w <= 0 || h <= 0 || w > 1920 || h > 1080) {
    // auto; pick resolution based on docked mode
    if (appletGetOperationMode() == AppletOperationMode_Console) {
      screen_width = 1920;
      screen_height = 1080;
    } else {
      screen_width = 1280;
      screen_height = 720;
    }
  } else {
    screen_width = w;
    screen_height = h;
  }
  debugPrintf("screen mode: %dx%d\n", screen_width, screen_height);
}

int main(void) {
  // try to read the config file and create one with default values if it's missing
  if (read_config(CONFIG_NAME) < 0)
    write_config(CONFIG_NAME);

  check_syscalls();
  check_data();

  // calculate actual screen size
  set_screen_size(config.screen_width, config.screen_height);

  debugPrintf("heap size = %u KB\n", MEMORY_MB * 1024);
  debugPrintf(" lib base = %p\n", heap_so_base);
  debugPrintf("  lib max = %u KB\n", heap_so_limit / 1024);

  if (so_load(&max_mod, SO_NAME) < 0)
    fatal_error("Open app in the applet-mode.\n");

  // won't save without it
  mkdir("savegames", 0777);

  update_imports();

  so_relocate(&max_mod);
  so_resolve(&max_mod, dynlib_functions, sizeof(dynlib_numfunctions), 0);

  patch_openal();
  patch_opengl();
  patch_game();

  // can't set it in the initializer because it's not constant
  stderr_fake = stderr;

  strcpy((char *)so_find_addr("StorageRootBuffer"), ".");
  *(uint8_t *)so_find_addr("IsAndroidPaused") = 0;
  *(uint8_t *)so_find_addr("UseRGBA8") = 1; // RGB565 FBOs suck

  uint32_t (* initGraphics)(void) = (void *)so_find_addr_rx("_Z12initGraphicsv");
  uint32_t (* ShowJoystick)(int show) = (void *)so_find_addr_rx("_Z12ShowJoystickb");
  int (* NVEventAppMain)(int argc, char *argv[]) = (void *)so_find_addr_rx("_Z14NVEventAppMainiPPc");

  so_flush_caches(&max_mod);

  so_initialize(&max_mod);


  initGraphics();
  ShowJoystick(0);
  NVEventAppMain(0, NULL);

  return 0;
}
