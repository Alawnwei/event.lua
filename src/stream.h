#ifndef STREAM_H
#define STREAM_H
#include <stdint.h>

typedef struct stream_reader {
	uint8_t* data;
	int size;
	int offset;
} stream_reader;

typedef struct stream_writer {
	uint8_t* data;
	int size;
	int offset;
} stream_writer;

inline stream_reader
reader_init(uint8_t* data, int size) {
	stream_reader reader = { data, size, 0 };
	return reader;
}

inline void
reader_pop(stream_reader* reader, uint8_t* val, size_t sz) {
	assert(reader->size - reader->offset >= sz);
	memcpy(val, reader->data + reader->offset, sz);
	reader->offset += sz;
}

inline char
read_char(stream_reader* reader) {
	char ch;
	assert(reader->size - reader->offset >= 1);
	memcpy(&ch, reader->data + reader->offset, 1);
	reader->offset += 1;
	return ch;
}

inline uint8_t
read_uint8(stream_reader* reader) {
	uint8_t val;
	reader_pop(reader, (uint8_t*)&val, sizeof(uint8_t));
	return val;
}

inline uint16_t
read_uint16(stream_reader* reader) {
	uint16_t val;
	reader_pop(reader, (uint8_t*)&val, sizeof(uint16_t));
	return val;
}

inline uint32_t
read_uint32(stream_reader* reader) {
	uint32_t val;
	reader_pop(reader, (uint8_t*)&val, sizeof(uint32_t));
	return val;
}

inline uint64_t
read_uint64(stream_reader* reader) {
	uint64_t val;
	reader_pop(reader, (uint8_t*)&val, sizeof(uint64_t));
	return val;
}

inline int8_t
read_int8(stream_reader* reader) {
	int8_t val;
	reader_pop(reader, (uint8_t*)&val, sizeof(int8_t));
	return val;
}

inline int16_t
read_int16(stream_reader* reader) {
	int16_t val;
	reader_pop(reader, (uint8_t*)&val, sizeof(int16_t));
	return val;
}

inline int32_t
read_int32(stream_reader* reader) {
	int32_t val;
	reader_pop(reader, (uint8_t*)&val, sizeof(int32_t));
	return val;
}

inline int64_t
read_int64(stream_reader* reader) {
	int64_t val;
	reader_pop(reader, (uint8_t*)&val, sizeof(int64_t));
	return val;
}

inline char*
read_string(stream_reader* reader, size_t sz) {
	char* result;
	assert(reader->size - reader->offset >= sz);
	result = (char*)reader->data;
	reader->offset += sz;
	return result;
}

#endif