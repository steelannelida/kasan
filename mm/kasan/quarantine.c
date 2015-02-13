/* Kasan quarantine */

#include <linux/gfp.h>
#include <linux/hash.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "../slab.h"
#include "kasan.h"

struct quarantine {
	void **head;
	void **tail;
	int objects;
	size_t bytes;
};

static DEFINE_PER_CPU(struct quarantine, cpu_quar);

static struct quarantine global_quar;
static DEFINE_SPINLOCK(quar_lock);

#define QUARANTINE_SIZE (128 << 20)
#define QUARANTINE_LOW_SIZE (QUARANTINE_SIZE * 3 / 4)
#define QUARANTINE_PERCPU_SIZE (1 << 20)
#define QUAR_INIT { NULL, NULL, 0, 0 }

static inline bool empty_quar(struct quarantine *q)
{
	return !q->objects;
}

static inline void init_quar(struct quarantine *q)
{
	q->head = q->tail = NULL;
	q->objects = q->bytes = 0;
}

static inline void quar_put(struct quarantine *q, void **qlink, size_t size)
{
	if (unlikely(empty_quar(q)))
		q->head = qlink;
	else
		*q->tail = qlink;
	q->tail = qlink;
	*qlink = NULL;
	q->objects++;
	q->bytes += size;
}

static inline void quar_move_one(struct quarantine *from, struct quarantine *to,
			  size_t size)
{
	void **qlink;

	BUG_ON(empty_quar(from));

	qlink = from->head;
	from->head = *qlink;
	if (unlikely(!from->head))
		from->tail = NULL;
	from->bytes -= size;
	from->objects--;

	quar_put(to, qlink, size);
}

static inline void quar_move_all(struct quarantine *from, struct quarantine *to)
{
	if (unlikely(empty_quar(from)))
		return;

	if (empty_quar(to)) {
		*to = *from;
		init_quar(from);
		return;
	}

	*to->tail = from->head;
	to->tail = from->tail;
	to->objects += from->objects;
	to->bytes += from->bytes;

	init_quar(from);
}

static inline struct kmem_cache *qlink_to_cache(void **qlink)
{
	struct page *page = virt_to_head_page(qlink);
	struct kmem_cache *ret;

	BUG_ON(!PageSlab(page));
	ret = page->slab_cache;
	BUG_ON(!ret);
	return ret;
}

static inline void *qlink_to_object(void **qlink, struct kmem_cache *cache)
{
	struct kasan_free *free_info =
		container_of((void ***)qlink, struct kasan_free,
			     quarantine_link);
	void *ret;

	BUG_ON(!cache);
	BUG_ON(!(cache->flags & SLAB_KASAN));
	ret = ((void *)free_info) - cache->kasan_info.free_offset;
	BUG_ON(virt_to_head_page(ret) != virt_to_head_page(qlink));
	return ret;
}

static inline void quar_free(void **qlink, struct kmem_cache *cache)
{
	void *object = qlink_to_object(qlink, cache);
	struct kasan_alloc *alloc_info = get_alloc_info(cache, object);
#ifdef CONFIG_SLAB
	unsigned long flags;

	local_irq_save(flags);
#endif
	alloc_info->state = KSN_FREE;
	nokasan_free(cache, object, _THIS_IP_);
#ifdef CONFIG_SLAB
	local_irq_restore(flags);
#endif
}

static inline void quar_free_all(struct quarantine *q, struct kmem_cache *cache)
{
	void **qlink;

	if (unlikely(empty_quar(q)))
		return;

	qlink = q->head;
	while (qlink) {
		struct kmem_cache *obj_cache =
			cache ? cache :	qlink_to_cache(qlink);
		void **next = *qlink;

		quar_free(qlink, obj_cache);
		qlink = next;
	}
	init_quar(q);
}

void quarantine_put(struct kasan_free *info, struct kmem_cache *cache)
{
	unsigned long flags;
	struct quarantine *q;
	struct quarantine temp = QUAR_INIT;

	local_irq_save(flags);

	q = this_cpu_ptr(&cpu_quar);
	quar_put(q, (void **) &info->quarantine_link, cache->size);
	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE))
		quar_move_all(q, &temp);

	local_irq_restore(flags);

	if (unlikely(!empty_quar(&temp))) {
		spin_lock_irqsave(&quar_lock, flags);
		quar_move_all(&temp, &global_quar);
		spin_unlock_irqrestore(&quar_lock, flags);
	}
}

void quarantine_flush(void)
{
	unsigned long flags;
	struct quarantine to_free = QUAR_INIT;

	if (likely(ACCESS_ONCE(global_quar.bytes) <= QUARANTINE_SIZE))
		return;

	spin_lock_irqsave(&quar_lock, flags);
	while (global_quar.bytes > QUARANTINE_LOW_SIZE) {
		void **qlink = global_quar.head;
		struct kmem_cache *cache = qlink_to_cache(qlink);

		quar_move_one(&global_quar, &to_free, cache->size);
	}
	spin_unlock_irqrestore(&quar_lock, flags);

	quar_free_all(&to_free, NULL);
}

static inline void quar_move_cache(struct quarantine *from,
				   struct quarantine *to,
				   struct kmem_cache *cache)
{
	void ***prev;

	if (unlikely(empty_quar(from)))
		return;

	prev = &from->head;
	while (*prev) {
		void **qlink = *prev;
		struct kmem_cache *obj_cache = qlink_to_cache(qlink);

		if (obj_cache == cache) {
			if (unlikely(from->tail == qlink))
				from->tail = (void **) prev;
			*prev = (void **) *qlink;
			from->objects--;
			from->bytes -= cache->size;
			quar_put(to, qlink, cache->size);
		} else
			prev = (void ***) *prev;
	}
}

static void per_cpu_remove_cache(void *arg)
{
	struct kmem_cache *cache = arg;
	struct quarantine to_free = QUAR_INIT;
	struct quarantine *q;
	unsigned long flags;

	local_irq_save(flags);
	q = this_cpu_ptr(&cpu_quar);
	quar_move_cache(q, &to_free, cache);
	local_irq_restore(flags);

	quar_free_all(&to_free, cache);
}

void quarantine_remove_cache(struct kmem_cache *cache)
{
	unsigned long flags;
	struct quarantine to_free = QUAR_INIT;

	on_each_cpu(per_cpu_remove_cache, cache, 0);

	spin_lock_irqsave(&quar_lock, flags);
	quar_move_cache(&global_quar, &to_free, cache);
	spin_unlock_irqrestore(&quar_lock, flags);

	quar_free_all(&to_free, cache);
}


