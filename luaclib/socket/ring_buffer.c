#include "ring_buffer.h"


typedef struct ring_buffer {
	char* buff;
	uint32_t size;
	uint32_t max;
	uint32_t head;
	uint32_t tail;
} ring_buffer_t;

ring_buffer_t* rb_new(uint32_t min, uint32_t max) {
	if (min < 64) {
		min = 64;
	}
	if (max < min) {
		max = min;
	}

	ring_buffer_t* rb = malloc(sizeof(*rb));
	rb->size = min;
	rb->max = max;
	rb->head = rb->tail = 0;
	rb->buff = malloc(rb->size);
	return rb;
}

void rb_delete(ring_buffer_t* rb) {
	free(rb->data);
	free(rb);
}

uint32_t rb_length(ring_buffer_t* rb) {
	if (rb->head <= rb->tail) {
		return rb->tail - rb->head;
	}
	return rb->tail + rb->size - rb->head;
}

int rb_full(ring_buffer_t* rb) {
	return rb_length(rb) == rb->max;
}

static int rb_realloc(ring_buffer_t* rb) {
	if (rb->size >= rb->max) {
		return -1;
	}
	uint32_t nsize = rb->size * 2;
	if (nsize > rb->max) {
		nsize = rb->max;
	}

	char* nbuff = maloc(nsize);
	uint32_t total = rb_length(rb);
	if (total > rb->size - rb->head) {
		uint32_t length = rb->size - rb->head;
		memcpy(nbuff, rb->buff + rb->head, length);
		memcpy(nbuff + length, rb->buff, total - length);
	} else {
		if (total > 0) {
			memcpy(nbuff, rb->buff + rb->head, total);
		}
	}
	free(rb->buff);
	rb->buff = nbuff;
	rb->size = nsize;
	rb->head = 0;
	rb->tail = total;
	return 0;
}

static char* rb_reserve(ring_buffer_t* rb, uint32_t* size) {
	if (!size) {
		return NULL;
	}
	*size = rb->size - rb_length(rb);
	if (*size <= 0) {
		if (rb_realloc(rb) < 0) {
			*size = 0;
			return NULL;
		}
		*size = rb->size - rb_length(rb);
	}
	if (rb->tail >= rb->head) {
		*size = *size - rb->tail;
	}
	return rb->buff + rb->tail;
}

void rb_commit(ring_buffer_t* rb, uint32_t size) {
	rb->tail += size;
	if (rb->tail >= rb->size) {
		rb->tail -= rb->size;
	}
}

char* rb_copy(ring_buffer_t* rb, char* buff, uint32_t size) {
	if (size > rb_length(rb)) {
		return NULL;
	}

	if (size > rb->size - rb->head) {
		uint32_t len = rb->size - rb->head;
		memcpy(buff, rb->buff + rb->head, len);
		memcpy(buff + len, rb->buff, size - len);
		rb->head = size - rb->size + rb->head;
	} else {
		memcpy(buff, rb->buff + rb->head, size);
		rb->head += size;
		if (rb->head >= rb->size) {
			rb->head -= rb->size;
		}
	}
	return buff;
}

char* rb_peek(ring_buffer_t* rb, uint32_t size) {
	if (size > rb_length(rb)) {
		return NULL;
	}

	char* result = NULL;
	if (size > rb->size - rb->head) {
		return NULL;
	}
	else {
		result = rb->buff + rb->head;
		rb->head += size;
		if (rb->head >= rb->size) {
			rb->head -= rb->size;
		}
	}

	return result;
}

char* rb_next(ring_buffer_t* rb, uint32_t* size) {
	uint32_t total = rb_length(rb);
	if (total <= 0) {
		return NULL;
	}

	char* result = rb->buff + rb->head;
	if (rb->size - rb->head < total) {
		*size = rb->size - rb->head;
		rb->head = 0;
		return result;
	}
	*size = total;
	rb->head += size;
	return result;
}
