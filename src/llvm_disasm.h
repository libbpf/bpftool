/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#ifndef __BPFTOOL_LLVM_DISASM_H
#define __BPFTOOL_LLVM_DISASM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Stable C ABI between bpftool and its optional libLLVM-based JIT disassembler
 * plugin (bpftool-llvm.so). bpftool resolves these symbols with dlsym()
 * after dlopen()ing the plugin; the plugin is the only object that links
 * against libLLVM. See jit_disasm.c (loader) and llvm_disasm.c (plugin).
 */

/* Initialize the libLLVM targets and disassemblers. Returns 0 on success. */
int bpftool_llvm_init(void);

/*
 * Create a disassembler context for @arch (NULL selects the host
 * architecture). Returns an opaque context pointer, or NULL on failure.
 */
void *bpftool_llvm_create_context(const char *arch);

/* Release a context previously returned by bpftool_llvm_create_context(). */
void bpftool_llvm_destroy_context(void *ctx);

/*
 * Disassemble the single instruction at @image[@pc] into @buf as a NUL
 * terminated string. @func_ksym is the kernel address of @image and is used to
 * render absolute branch targets. Returns the instruction length in bytes, or
 * 0 if the instruction could not be decoded.
 */
int bpftool_llvm_disassemble(void *ctx, unsigned char *image, ssize_t len,
			     int pc, uint64_t func_ksym, char *buf,
			     size_t buf_sz);

#endif /* __BPFTOOL_LLVM_DISASM_H */
