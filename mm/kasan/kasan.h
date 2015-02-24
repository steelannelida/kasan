#ifndef __MM_KASAN_KASAN_H
#define __MM_KASAN_KASAN_H

#include <linux/kasan.h>
#include <linux/compiler.h>
#include <linux/list.h>
#include <linux/gfp.h>

/*
 * Prevent randconfig/allconfig build
 * errors on old compilers
 */
#ifndef ASAN_ABI_VERSION
#define ASAN_ABI_VERSION 1
#endif

#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)

struct access_info {
	unsigned long access_addr;
	unsigned long first_bad_addr;
	size_t access_size;
	bool is_write;
	unsigned long ip;
};

struct kasan_source_location {
	const char *filename;
	int line_no;
	int column_no;
};

struct kasan_global {
	const void *beg;		/* Address of the beginning of the global variable. */
	size_t size;			/* Initial size of the global variable. */
	size_t size_with_redzone;	/* Size of the variable + size of the
					   red zone. 32 bytes aligned */
	const void *name;
	const void *module_name;	/* Name of the module where the global variable is declared. */
	unsigned long has_dynamic_init;	/* this needed only for C++ */

#if ASAN_ABI_VERSION >= 4
	struct asan_source_location *location;
#endif
};

/**************************
 * Structures to keep alloc and free tracks *
 ********************************************/

enum kasan_state {
	KSN_INIT,
	KSN_ALLOC,
	KSN_QUARANTINE,
	KSN_FREE
};

#define kasan_stack_handle u64
#define KASAN_STACK_BITS (24)

struct kasan_track {
	u64 cpu : 6;			/* for NR_CPUS = 64 */
	u64 when : 18;			/* ~256 seconds */
	u64 pid : 16;			/* 65536 processes */
	kasan_stack_handle stack : 24;  /* 256 MB of stacks */
};

struct kasan_alloc {
	enum kasan_state state : 2;
	size_t alloc_size : 62;
	struct kasan_track track;
};

struct kasan_free {
	/* This field is used while the object is in quarantine.
	 * Otherwise it might be used by the freelist */
	void **quarantine_link;  /* TODO: don't offset free_info by 8 bytes */
	struct kasan_track track;
};

struct kasan_alloc *get_alloc_info(struct kmem_cache *cache, void *object);
struct kasan_free *get_free_info(struct kmem_cache *cache, void *object);

void kasan_report_error(struct access_info *info);
void kasan_report_user_access(struct access_info *info);

static inline unsigned long kasan_shadow_to_mem(unsigned long shadow_addr)
{
	return (shadow_addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
}

static inline bool kasan_enabled(void)
{
	return !current->kasan_depth;
}

static __always_inline void kasan_report(unsigned long addr,
					size_t size,
					bool is_write)
{
	struct access_info info;

	if (likely(!kasan_enabled()))
		return;

	info.access_addr = addr;
	info.access_size = size;
	info.is_write = is_write;
	info.ip = _RET_IP_;
	kasan_report_error(&info);
}

/*
 * API for stack depot *
 */

struct stack_trace;

kasan_stack_handle kasan_save_stack(struct stack_trace *trace, gfp_t flags);
void kasan_fetch_stack(kasan_stack_handle handle, struct stack_trace *trace);

void quarantine_put(struct kasan_free *info, struct kmem_cache *cache);
void quarantine_flush(void);
void quarantine_remove_cache(struct kmem_cache *cache);


#endif
