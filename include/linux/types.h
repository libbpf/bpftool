/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */

#ifndef __LINUX_TYPES_H
#define __LINUX_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <asm/types.h>
#include <asm/posix_types.h>

typedef uint64_t u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

#define __bitwise__
#define __bitwise __bitwise__

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;

#ifndef __aligned_u64
# define __aligned_u64 __u64 __attribute__((aligned(8)))
#endif

struct list_head {
	struct list_head *next, *prev;
};

#endif
