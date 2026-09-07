// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * libLLVM-based BPF JIT disassembler plugin for bpftool.
 *
 * This translation unit is built into a standalone shared object
 * (bpftool-llvm.so) which is the only bpftool component that links against
 * libLLVM. bpftool loads it lazily with dlopen() (see jit_disasm.c) so that
 * the bpftool binary itself does not depend on the large libLLVM shared
 * object. Only the small, stable C ABI declared in llvm_disasm.h is exposed.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <llvm-c/Core.h>
#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>

#include "llvm_disasm.h"

/* This callback to set the ref_type is necessary to have the LLVM disassembler
 * print PC-relative addresses instead of byte offsets for branch instruction
 * targets.
 */
static const char *
symbol_lookup_callback(void *disasm_info, uint64_t ref_value,
		       uint64_t *ref_type, uint64_t ref_PC,
		       const char **ref_name)
{
	*ref_type = LLVMDisassembler_ReferenceType_InOut_None;
	return NULL;
}

int bpftool_llvm_init(void)
{
	LLVMInitializeAllTargetInfos();
	LLVMInitializeAllTargetMCs();
	LLVMInitializeAllDisassemblers();

	return 0;
}

void *bpftool_llvm_create_context(const char *arch)
{
	LLVMDisasmContextRef ctx;
	char *triple;

	if (arch)
		triple = LLVMNormalizeTargetTriple(arch);
	else
		triple = LLVMGetDefaultTargetTriple();
	if (!triple)
		return NULL;

	/*
	 * Enable all aarch64 ISA extensions so the disassembler can handle any
	 * instruction the kernel JIT might emit (e.g. ARM64 LSE atomics).
	 */
	if (!strncmp(triple, "aarch64", 7))
		ctx = LLVMCreateDisasmCPUFeatures(triple, "", "+all", NULL, 0,
						  NULL, symbol_lookup_callback);
	else
		ctx = LLVMCreateDisasm(triple, NULL, 0, NULL,
				       symbol_lookup_callback);
	LLVMDisposeMessage(triple);

	return ctx;
}

void bpftool_llvm_destroy_context(void *ctx)
{
	LLVMDisasmDispose(ctx);
}

int bpftool_llvm_disassemble(void *ctx, unsigned char *image, ssize_t len,
			     int pc, uint64_t func_ksym, char *buf,
			     size_t buf_sz)
{
	return LLVMDisasmInstruction(ctx, image + pc, len - pc, func_ksym + pc,
				     buf, buf_sz);
}
