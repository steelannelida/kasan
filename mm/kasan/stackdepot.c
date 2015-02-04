/*
 * Stack depot
 * KASAN needs to safe alloc and free stacks per object, but storing 2 stack
 * traces per object is too much overhead (e.g. SLUB_DEBUG needs 256 bytes per
 * object).
 *
 * Instead, stack depot maintains a hashtable of unique stacktraces. Since alloc
 * and free stacks repeat a lot, we save about 100x space.
 * Stacks are never removed from depot, so we store them contiguously one after
 * another in a contiguos memory allocation.
 */


#include "kasan.h"
#include <linux/gfp.h>
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/hash.h>
#include <linux/atomic.h>

#define STACK_ALLOC_ORDER 4
#define STACK_ALLOC_SIZE (1L << (PAGE_SHIFT + STACK_ALLOC_ORDER))
#define STACK_ALLOC_GFP_MASK (__GFP_WAIT | __GFP_IO | __GFP_FS | __GFP_NOWARN)

/* Storage for raw stacks */
struct stack_slab {
	void *base;
	size_t offset;
};

static DEFINE_PER_CPU(struct stack_slab, slabs);

/* Allocation of a new area for raw stack storage */
static inline void kasan_stack_expand(struct stack_slab *slab, gfp_t flags)
{
	struct page *page;

	page = alloc_pages(flags & STACK_ALLOC_GFP_MASK, STACK_ALLOC_ORDER);
	if (unlikely(!page))
		slab->base = NULL;
	else
		slab->base = page_address(page);

	slab->offset = 0;
}

/* Allocation of a new stack in raw storage */
static struct kasan_stack *kasan_alloc_stack(unsigned long *entries, int size,
				      u32 hash, gfp_t alloc_flags)
{
	int required_size = offsetof(struct kasan_stack, entries) +
		sizeof(unsigned long) * size;
	struct stack_slab *slab;
	struct kasan_stack *stack;
	unsigned long flags;

	if (unlikely(size <= 0))
		return NULL;

	local_irq_save(flags);
	slab = &get_cpu_var(slabs);

	if (unlikely(!slab->base) ||
	    unlikely(slab->offset + required_size > STACK_ALLOC_SIZE))
		kasan_stack_expand(slab, alloc_flags);

	if (unlikely(!slab->base)) {
		pr_warn("Failed to allocate stack in kasan depot");
		stack = NULL;
		goto out;
	}
	stack = slab->base + slab->offset;
	slab->offset += required_size;

	stack->hash = hash;
	stack->size = size;
	__memcpy(stack->entries, entries, size * sizeof(unsigned long));

out:
	put_cpu_var(slabs);
	local_irq_restore(flags);

	return stack;
}

#define STACK_HASH_ORDER 20
#define STACK_HASH_SIZE (1L << STACK_HASH_ORDER)
#define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
#define STACK_HASH_SEED 0x9747b28c

struct kasan_stack *stack_table[STACK_HASH_SIZE] = {
	[0 ...	STACK_HASH_SIZE - 1] = NULL
};

/* Calculate hash for a stack */
static inline u32 hash_stack(unsigned long *entries, int size)
{
	/* TODO: copy hashing formula from ASAN. */
	return arch_fast_hash2((u32 *)entries,
			       size * sizeof(unsigned long) / sizeof(u32),
			       STACK_HASH_SEED);
}

/*
 * kasan_save_stack - save stack in a stack depot.
 * @entries - array of stack entries.
 * @size - size of stack array.
 * @alloc_flags - flags for allocating additional memory if required.
 *
 * Returns a pointer to the stack struct stored in depot.
 */
struct kasan_stack *kasan_save_stack(unsigned long *entries, int size,
					    gfp_t alloc_flags)
{
	u32 hash;
	struct kasan_stack *found, *new, **bin;

	if (unlikely(size <= 0))
		return NULL;

	hash = hash_stack(entries, size);
	bin = &stack_table[hash & STACK_HASH_MASK];
	found = *bin;
	while (found) {
		if (found->hash == hash &&
		    !memcmp(entries, found->entries,
			    size * sizeof(unsigned long))) {
			break;
		}
		found = found->next;
	}
	if (likely(found))
		return found;

	new = kasan_alloc_stack(entries, size, hash, alloc_flags);
	do {
		new->next = ACCESS_ONCE(*bin);
	} while (cmpxchg(bin, new->next, new) != new->next);
	return new;
}
