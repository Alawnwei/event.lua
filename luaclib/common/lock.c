#include "lock.h"

void
mutex_init(mutex_t* mutex) {
	pthread_mutex_init(&mutex->lock, NULL);
}

void
mutex_destroy(mutex_t* mutex) {
	pthread_mutex_destroy(&mutex->lock);
}

void
mutex_lock(mutex_t* mutex) {
	pthread_mutex_lock(&mutex->lock);
}

void
mutex_unlock(mutex_t* mutex) {
	pthread_mutex_unlock(&mutex->lock);
}

int
mutex_trylock(mutex_t* mutex) {
	return pthread_mutex_trylock(&mutex->lock);
}

void
cond_init(cond_t* cond) {
	pthread_cond_init(&cond->cond, NULL);
}

void
cond_destroy(cond_t* cond) {
	pthread_cond_destroy(&cond->cond);
}

void
cond_notify_one(cond_t* cond) {
	pthread_cond_signal(&cond->cond);
}

void
cond_notify_all(cond_t* cond) {
	pthread_cond_broadcast(&cond->cond);
}

void
cond_wait(cond_t* cond, mutex_t* mutex) {
	pthread_cond_wait(&cond->cond, &mutex->lock);
}

void
cond_timed_wait(cond_t* cond, mutex_t* mutex, int millis) {
	struct timespec timeout;
	clock_gettime(CLOCK_REALTIME, &timeout);
	timeout.tv_nsec = timeout.tv_nsec + 1000 * 1000 * millis;
	if (timeout.tv_nsec >= 1000 * 1000 * 1000) {
		timeout.tv_sec++;
		timeout.tv_nsec = timeout.tv_nsec % 1000 * 1000 * 1000;
	}
	pthread_cond_timedwait(&cond->cond, &mutex->lock, &timeout);
}