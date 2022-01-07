/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#ifndef __TOOLS_LIBC_COMPAT_H
#define __TOOLS_LIBC_COMPAT_H

#include <limits.h>
#include <stdlib.h>

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/*
 * Re-implement glibc's reallocarray(). This function is not available in all
 * versions of glibc. The version of bpftool shipped with the kernel deals with
 * this by doing an extra feature detection, and by using a stub in
 * <tools/libc_compat.h> (this file) when COMPAT_NEED_REALLOCARRAY is set.
 * Let's keep things simple here: it is trivial to re-implement the function.
 * Libbpf does the same in libbpf_internal.h: we can copy its version.
 */
static inline void *bpftool_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

#if __has_builtin(__builtin_mul_overflow)
	if (unlikely(__builtin_mul_overflow(nmemb, size, &total)))
		return NULL;
#else
	if (size == 0 || nmemb > ULONG_MAX / size)
		return NULL;
	total = nmemb * size;
#endif
	return realloc(ptr, total);
}

/*
 * Overwrite default reallocarray(). It would probably be cleaner to use
 * "bpftool_reallocarray()" in the source code to make the distinction
 * explicit, but we want to avoid touching the code to remain in sync with the
 * kernel and ease maintenance.
 */
#define reallocarray(ptr, nmemb, size) bpftool_reallocarray(ptr, nmemb, size)

#endif
