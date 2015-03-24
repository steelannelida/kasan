#ifndef __MM_KASAN_KASAN_H
#define __MM_KASAN_KASAN_H

#include <linux/kasan.h>

#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)

#define KASAN_FREE_PAGE         0xFF  /* page was freed */
#define KASAN_FREE_PAGE         0xFF  /* page was freed */
#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
#define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
#define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */

/*
 * Stack redzone shadow values
 * (Those are compiler's ABI, don't change them)
 */
#define KASAN_STACK_LEFT        0xF1
#define KASAN_STACK_MID         0xF2
#define KASAN_STACK_RIGHT       0xF3
#define KASAN_STACK_PARTIAL     0xF4

/* Don't break randconfig/all*config builds */
#ifndef KASAN_ABI_VERSION
#define KASAN_ABI_VERSION 1
#endif

struct kasan_access_info {
	const void *access_addr;
	const void *first_bad_addr;
	size_t access_size;
	bool is_write;
	unsigned long ip;
};

/* The layout of struct dictated by compiler */
struct kasan_source_location {
	const char *filename;
	int line_no;
	int column_no;
};

/* The layout of struct dictated by compiler */
struct kasan_global {
	const void *beg;		/* Address of the beginning of the global variable. */
	size_t size;			/* Size of the global variable. */
	size_t size_with_redzone;	/* Size of the variable + size of the red zone. 32 bytes aligned */
	const void *name;
	const void *module_name;	/* Name of the module where the global variable is declared. */
	unsigned long has_dynamic_init;	/* This needed for C++ */
#if KASAN_ABI_VERSION >= 4
	struct kasan_source_location *location;
#endif
};

/**
 * Structures to keep alloc and free tracks *
 */

enum kasan_state {
	KSN_INIT,
	KSN_ALLOC,
	KSN_FREE
};

#define kasan_stack_handle u32
#define KASAN_STACK_BITS (32)  /* up to 16GB of stack storage */

struct kasan_track {
	u64 cpu : 6;					/* for NR_CPUS = 64 */
	u64 pid : 16;					/* 65536 processes */
	u64 when : 42;					/* ~140 years */
	kasan_stack_handle stack : KASAN_STACK_BITS;
};

struct kasan_alloc {
	enum kasan_state state : 2;
	u32 alloc_size : 30;
	struct kasan_track track;
};

struct kasan_free {
	void **freelist;
	struct kasan_track track;
};

struct kasan_alloc *get_alloc_info(struct kmem_cache *cache,
				   const void *object);
struct kasan_free *get_free_info(struct kmem_cache *cache,
				 const void *object);

void kasan_report_error(struct kasan_access_info *info);
void kasan_report_user_access(struct kasan_access_info *info);

static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
{
	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET)
		<< KASAN_SHADOW_SCALE_SHIFT);
}

static inline bool kasan_enabled(void)
{
	return !current->kasan_depth;
}

void kasan_report(unsigned long addr, size_t size,
		bool is_write, unsigned long ip);

struct stack_trace;

kasan_stack_handle kasan_save_stack(struct stack_trace *trace, gfp_t flags);
void kasan_fetch_stack(kasan_stack_handle handle, struct stack_trace *trace);

#endif
