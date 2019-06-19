#ifndef LOCK_H
#define LOCK_H

#include <pthread.h>

typedef struct mutex {
	pthread_mutex_t lock;
} mutex_t;

typedef struct cond {
	pthread_cond_t cond;
} cond_t;

void mutex_init(mutex_t* mutex);
void mutex_destroy(mutex_t* mutex);

void mutex_lock(mutex_t* mutex);
void mutex_unlock(mutex_t* mutex);

int mutex_trylock(mutex_t* mutex);

void cond_init(cond_t* cond);
void cond_destroy(cond_t* cond);
void cond_notify_one(cond_t* cond);
void cond_notify_all(cond_t* cond);

void cond_wait(cond_t* cond, mutex_t* mutex);
void cond_timed_wait(cond_t* cond, mutex_t* mutex, int millis);
#endif