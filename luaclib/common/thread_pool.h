#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <pthread.h>

struct thread_pool;


typedef void (*thread_consumer)(struct thread_pool* pool, int index, int session, void* data, size_t size, void* ud);

typedef void (*thread_init)(struct thread_pool* pool, int index, void* ud);
typedef void (*thread_wakeup)(struct thread_pool* pool, int index, void* ud);
typedef void (*thread_fina)(struct thread_pool* pool, int index, void* ud);

struct thread_pool* thread_pool_create(thread_init init_func, thread_fina fina_func, thread_wakeup wakeup_func, void* ud);
void thread_pool_release(struct thread_pool*);

void thread_pool_start(struct thread_pool* pool, int thread_count);
void thread_pool_close(struct thread_pool* pool);

pthread_t thread_pool_pid(struct thread_pool* pool, int index);

void thread_pool_push_task(struct thread_pool* pool, thread_consumer consumer, int session, void* data, size_t size);


#endif