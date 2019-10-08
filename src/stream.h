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

inline stream_writer
writer_init(int size) {
	uint8_t* data = malloc(size);
	stream_writer writer = { data, size, 0 };
	return writer;
}

inline void
writer_release(stream_writer* writer) {
	if (writer->data) {
		free(writer->data);
	}
}

inline void
writer_reserve(stream_writer* writer, size_t sz) {
	if (sz + writer->offset <= writer->size) {
		return;
	}
	size_t size = writer->size * 2;
	if (size < sz + writer->offset) {
		size = sz + writer->offset;
	}
	writer->data = (uint8_t*)realloc(writer->data, size);
	writer->size = size;
}

inline void
writer_push(stream_writer* writer, uint8_t* val, size_t sz) {
	if (sz == 0) {
		return;
	}
	writer_reserve(writer, sz);
	memcpy((void*)&writer->data[writer->offset], val, sz);
	writer->offset += sz;
}

inline void
write_char(stream_writer* writer, char ch) {
	assert(writer->size - writer->offset >= 1);
	memcpy(writer->data + writer->offset, &ch, 1);
	writer->offset += 1;
}

inline void
write_uint8(stream_writer* writer, uint8_t val) {
	writer_push(writer, (uint8_t*)&val, sizeof(uint8_t));
}

inline void
write_uint16(stream_writer* writer, uint16_t val) {
	writer_push(writer, (uint8_t*)&val, sizeof(uint16_t));
}

inline void
write_uint32(stream_writer* writer, uint32_t val) {
	writer_push(writer, (uint8_t*)&val, sizeof(uint32_t));
}

inline void
write_uint64(stream_writer* writer, uint64_t val) {
	writer_push(writer, (uint8_t*)&val, sizeof(uint64_t));
}

inline void
write_int8(stream_writer* writer, int8_t val) {
	writer_push(writer, (uint8_t*)&val, sizeof(int8_t));
}

inline void
write_int16(stream_writer* writer, int16_t val) {
	writer_push(writer, (uint8_t*)&val, sizeof(int16_t));
}

inline void
write_int32(stream_writer* writer, int32_t val) {
	writer_push(writer, (uint8_t*)&val, sizeof(int32_t));
}

inline void
write_int64(stream_writer* writer, int64_t val) {
	writer_push(writer, (uint8_t*)&val, sizeof(int64_t));
}

inline void
write_string(stream_writer* writer, char* val, size_t sz) {
	writer_reserve(writer, sz);
	memcpy((void*)&writer->data[writer->offset], val, sz);
	writer->offset += sz;
}

#endif