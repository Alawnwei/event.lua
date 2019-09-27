#ifndef RING_BUFFER_H
#define RING_BUFFER_H
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct ring_buffer;
typedef struct ring_buffer ring_buffer_t;

struct ring_buffer* rb_new(uint32_t min, uint32_t max);
void rb_delete(struct ring_buffer* rb);
uint32_t rb_length(struct ring_buffer* rb);
int rb_full(struct ring_buffer* rb);
char* rb_reserve(struct ring_buffer* rb, uint32_t* size);
void rb_commit(struct ring_buffer* rb, uint32_t size);
char* rb_copy(struct ring_buffer* rb, char* buff, uint32_t size);
char* rb_peek(struct ring_buffer* rb, uint32_t size);
char* rb_next(struct ring_buffer* rb, uint32_t* size);
#endif