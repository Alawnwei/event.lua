#include <lua.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "khash.h"

#ifdef _MSC_VER
typedef unsigned short ushort;
#define inline __inline
#define strdup _strdup
#endif

#define FTYPE_BOOL 		0
#define FTYPE_BYTE      1
#define FTYPE_SHORT     2
#define FTYPE_INT 		3
#define FTYPE_FLOAT 	4
#define FTYPE_DOUBLE 	5
#define FTYPE_STRING 	6
#define FTYPE_PROTOCOL 	7

#define MAX_DEPTH     16
#define MAX_INT       0xffffffffffffff
#define MAX_INT16     0x7ffff
#define MIN_INT16    (-0x7ffff-1)
#define MAX_INT8      0x7f
#define MIN_INT8     (-0x7f-1)


#define BUFFER_SIZE 128

struct field;
struct writer;
struct reader;

typedef void(*writer_func)(lua_State* L, struct writer* writer, struct field* field, int index, int depth);
typedef void(*reader_func)(lua_State* L, struct reader* reader, struct field* field, int index, int depth);

static inline void pack_one(lua_State* L, struct writer* writer, struct field* field, int index, int depth);
static inline void unpack_one(lua_State* L, struct reader* reader, struct field* field, int index, int depth);

KHASH_MAP_INIT_STR(protocol, int);

typedef khash_t(protocol) hash_t;

typedef struct writer {
	char* ptr;
	int offset;
	int size;
	char init[BUFFER_SIZE];
} writer_t;

typedef struct reader {
	char* ptr;
	int offset;
	int size;
} reader_t;

typedef struct field_set {
	struct field* field;
	int cap;
	int size;
} field_set_t;

typedef struct field {
	char* name;
	int array;
	int type;
	writer_func wfunc;
	reader_func rfunc;
	field_set_t fields;
} field_t;

typedef struct protocol {
	char* name;
	field_set_t fields;
} protocol_t;

struct context {
	struct protocol** slots;
	int cap;
	hash_t* hash;
	lua_State* L;
};

#define hash_new() kh_init(protocol)
#define hash_foreach(self, k, v, code) kh_foreach(self, k, v, code)

static void hash_set(hash_t *self, const char* name, int id) {
	int ok;
	khiter_t k = kh_put(protocol, self, strdup(name), &ok);
	assert(ok == 1 || ok == 2);
	kh_value(self, k) = id;
}

static void hash_del(hash_t *self, const char* name) {
	khiter_t k = kh_get(protocol, self, name);
	assert(k != kh_end(self));
	kh_del(protocol, self, k);
}

static int hash_find(hash_t *self, const char* name) {
	khiter_t k = kh_get(protocol, self, name);
	if (k == kh_end(self)) {
		return -1;
	}
	return kh_value(self, k);
}

static void hash_free(hash_t *self) {
	const char* name;
	int id;
	(void)id;
	hash_foreach(self, name, id, {
		free((void*)name);
	});
	kh_destroy(protocol, self);
}

static inline void writer_reserve(writer_t* writer, size_t sz) {
	if (writer->offset + sz > writer->size) {
		size_t nsize = writer->size * 2;
		while (nsize < writer->offset + sz)
			nsize = nsize * 2;

		char* nptr = (char*)malloc(nsize);
		memcpy(nptr, writer->ptr, writer->size);
		writer->size = nsize;

		if (writer->ptr != writer->init)
			free(writer->ptr);
		writer->ptr = nptr;
	}
}

static inline void writer_init(writer_t* writer) {
	writer->ptr = writer->init;
	writer->offset = 0;
	writer->size = BUFFER_SIZE;
}

static inline void writer_release(writer_t* writer) {
	if (writer->ptr != writer->init) {
		free(writer->ptr);
	}
}

static inline void writer_push(writer_t* writer, void* data, size_t size) {
	writer_reserve(writer, size);
	memcpy(writer->ptr + writer->offset, data, size);
	writer->offset += size;
}

static inline void write_byte(writer_t* writer, uint8_t val) {
	writer_push(writer, &val, sizeof(uint8_t));
}

static inline void write_ushort(writer_t* writer, ushort val) {
	writer_push(writer, &val, sizeof(ushort));
}

static inline void write_short(writer_t* writer, short val) {
	writer_push(writer, &val, sizeof(short));
}

static inline void write_int(writer_t* writer, lua_Integer val) {
	if (val == 0) {
		write_byte(writer, 0);
		return;
	}
	uint64_t value;
	uint8_t positive = 0;
	if (val < 0) {
		positive = 0x0;
		value = -val;
	} else {
		positive = 0x1;
		value = val;
	}

	int length;
	if (value <= 0xff) {
		length = 1;
	} else if (value <= 0xffff) {
		length = 2;
	} else if (value <= 0xffffff) {
		length = 3;
	} else if (value <= 0xffffffff) {
		length = 4;
	} else if (value <= 0xffffffffff) {
		length = 5;
	} else if (value <= 0xffffffffffff) {
		length = 6;
	} else {
		length = 7;
	}

	uint8_t tag = length;
	tag = (tag << 1) | positive;

	uint8_t data[8] = { 0 };
	data[0] = tag;
	memcpy(&data[1], &value, length);

	writer_push(writer, data, length + 1);
}

static inline void write_float(writer_t* writer, float val) {
	writer_push(writer, &val, sizeof(float));
}

static inline void write_double(writer_t* writer, double val) {
	writer_push(writer, &val, sizeof(double));
}

static inline void write_string(writer_t* writer, const char* str, size_t size) {
	write_ushort(writer, size);
	writer_push(writer, (void*)str, size);
}

static inline void reader_pop(lua_State* L, reader_t* reader, uint8_t* data, size_t size) {
	if (reader->size - reader->offset < size) {
		luaL_error(L, "decode error:invalid mesasge");
	}
	memcpy(data, reader->ptr + reader->offset, size);
	reader->offset += size;
}

static inline int reader_left(reader_t* reader) {
	return reader->size - reader->offset;
}

static inline uint8_t read_byte(lua_State* L, reader_t* reader) {
	uint8_t val;
	reader_pop(L, reader, (uint8_t*)&val, sizeof(uint8_t));
	return val;
}

static inline ushort read_ushort(lua_State* L, reader_t* reader) {
	ushort val;
	reader_pop(L, reader, (uint8_t*)&val, sizeof(ushort));
	return val;
}

static inline short read_short(lua_State* L, reader_t* reader) {
	short val;
	reader_pop(L, reader, (uint8_t*)&val, sizeof(short));
	return val;
}

static inline lua_Integer read_int(lua_State* L, reader_t* reader) {
	uint8_t tag;
	reader_pop(L, reader, &tag, sizeof(uint8_t));

	if (tag == 0) {
		return 0;
	}

	int length = tag >> 1;

	uint64_t value = 0;
	reader_pop(L, reader, (uint8_t*)&value, length);

	return (tag & 0x1) == 1 ? value : -(lua_Integer)value;
}

static inline float read_float(lua_State* L, reader_t* reader) {
	float val;
	reader_pop(L, reader, (uint8_t*)&val, sizeof(float));
	return val;
}

static inline double read_double(lua_State* L, reader_t* reader) {
	double val;
	reader_pop(L, reader, (uint8_t*)&val, sizeof(double));
	return val;
}

static inline char* read_string(lua_State* L, reader_t* reader, size_t* size) {
	char* result;
	*size = read_ushort(L, reader);
	if (reader_left(reader) < *size) {
		luaL_error(L, "decode error:invalid mesasge");
	}
	result = reader->ptr + reader->offset;
	reader->offset += *size;
	return result;
}

static inline void pack_bool(lua_State* L, writer_t* writer, field_t* f, int index, int depth) {
	int vt = lua_type(L, index);
	if (vt != LUA_TBOOLEAN) {
		writer_release(writer);
		luaL_error(L, "field:%s expect bool,not %s", f->name, lua_typename(L, vt));
	}
	write_byte(writer, lua_toboolean(L, index));
}

static inline void pack_byte(lua_State* L, writer_t* writer, field_t* f, int index, int depth) {
	int vt = lua_type(L, index);
	if (vt != LUA_TNUMBER) {
		writer_release(writer);
		luaL_error(L, "field:%s expect integer,not %s", f->name, lua_typename(L, vt));
	}
	write_byte(writer, lua_tointeger(L, index));
}

static inline void pack_short(lua_State* L, writer_t* writer, field_t* f, int index, int depth) {
	int vt = lua_type(L, index);
	if (vt != LUA_TNUMBER) {
		writer_release(writer);
		luaL_error(L, "field:%s expect short,not %s", f->name, lua_typename(L, vt));
	}
	write_short(writer, lua_tointeger(L, index));
}

static inline void pack_int(lua_State* L, writer_t* writer, field_t* f, int index, int depth) {
	int vt = lua_type(L, index);
	if (vt != LUA_TNUMBER) {
		writer_release(writer);
		luaL_error(L, "field:%s expect int,not %s", f->name, lua_typename(L, vt));
	}
	lua_Integer val = lua_tointeger(L, index);
	if (val > MAX_INT || val < -MAX_INT) {
		writer_release(writer);
		luaL_error(L, "field:%s int out of range,%I", f->name, val);
	}
	write_int(writer, val);
}

static inline void pack_float(lua_State* L, writer_t* writer, field_t* f, int index, int depth) {
	int vt = lua_type(L, index);
	if (vt != LUA_TNUMBER) {
		writer_release(writer);
		luaL_error(L, "field:%s expect float,not %s", f->name, lua_typename(L, vt));
	}
	write_float(writer, lua_tonumber(L, index));
}

static inline void pack_double(lua_State* L, writer_t* writer, field_t* f, int index, int depth) {
	int vt = lua_type(L, index);
	if (vt != LUA_TNUMBER) {
		writer_release(writer);
		luaL_error(L, "field:%s expect double,not %s", f->name, lua_typename(L, vt));
	}
	write_double(writer, lua_tonumber(L, index));
}

static inline void pack_string(lua_State* L, writer_t* writer, field_t* f, int index, int depth) {
	int vt = lua_type(L, index);
	if (vt != LUA_TSTRING) {
		writer_release(writer);
		luaL_error(L, "field:%s expect string,not %s", f->name, lua_typename(L, vt));
	}
	size_t size;
	const char* str = lua_tolstring(L, index, &size);
	if (size > 0xffff) {
		writer_release(writer);
		luaL_error(L, "field:%s string size more than 0xffff:%d", f->name, size);
	}
	write_string(writer, str, size);
}

static inline void pack_field(lua_State* L, writer_t* writer, field_t* field, int index, int depth) {
	depth++;
	if (depth > MAX_DEPTH) {
		writer_release(writer);
		luaL_error(L, "message pack too depth");
	}

	luaL_checkstack(L, LUA_MINSTACK, NULL);

	int vt = lua_type(L, index);
	if (vt != LUA_TTABLE) {
		writer_release(writer);
		luaL_error(L, "field:%s expect table,not %s", field->name, lua_typename(L, vt));
	}

	int i;
	for (i = 0; i < field->fields.size; i++) {
		field_t* f = &field->fields.field[i];
		lua_getfield(L, index, f->name);
		pack_one(L, writer, f, index + 1, depth);
		lua_pop(L, 1);
	}
}

static inline void pack_one(lua_State* L, writer_t* writer, field_t* field, int index, int depth) {
	if (field->array) {
		int vt = lua_type(L, index);
		if (vt != LUA_TTABLE) {
			luaL_error(L, "%s expect table,not %s", field->name, lua_typename(L, vt));
		}

		size_t size = lua_rawlen(L, index);
		if (size > 0xff) {
			luaL_error(L, "%s array size more than 0xff:%ld", field->name, size);
		}
		write_ushort(writer, size);

		size_t i;
		for (i = 0; i < size; i++) {
			lua_rawgeti(L, index, i + 1);
			field->wfunc(L, writer, field, index + 1, depth);
			lua_pop(L, 1);
		}
	} else {
		field->wfunc(L, writer, field, index, depth);
	}
}

static inline void unpack_bool(lua_State* L, reader_t* reader, field_t* field, int index, int depth) {
	uint8_t val = read_byte(L, reader);
	lua_pushboolean(L, val);
}

static inline void unpack_byte(lua_State* L, reader_t* reader, field_t* field, int index, int depth) {
	uint8_t val = read_byte(L, reader);
	lua_pushinteger(L, val);
}

static inline void unpack_short(lua_State* L, reader_t* reader, field_t* field, int index, int depth) {
	short val = read_short(L, reader);
	lua_pushinteger(L, val);
}

static inline void unpack_int(lua_State* L, reader_t* reader, field_t* field, int index, int depth) {
	lua_Integer val = read_int(L, reader);
	lua_pushinteger(L, val);
}

static inline void unpack_float(lua_State* L, reader_t* reader, field_t* field, int index, int depth) {
	float val = read_float(L, reader);
	lua_pushnumber(L, val);
}

static inline void unpack_double(lua_State* L, reader_t* reader, field_t* field, int index, int depth) {
	double val = read_double(L, reader);
	lua_pushnumber(L, val);
}

static inline void unpack_string(lua_State* L, reader_t* reader, field_t* field, int index, int depth) {
	size_t size;
	char* val = read_string(L, reader, &size);
	lua_pushlstring(L, val, size);
}

static inline void unpack_field(lua_State* L, reader_t* reader, field_t* field, int index, int depth) {
	depth++;
	if (depth > MAX_DEPTH) {
		luaL_error(L, "message unpack too depth");
	}

	luaL_checkstack(L, LUA_MINSTACK, NULL);

	lua_createtable(L, 0, field->fields.size);
	int i;
	for (i = 0; i < field->fields.size; i++) {
		field_t* f = &field->fields.field[i];
		unpack_one(L, reader, f, index + 1, depth);
	}
}

static inline void unpack_one(lua_State* L, reader_t* reader, field_t* field, int index, int depth) {
	if (field->array) {
		uint8_t size = read_ushort(L, reader);
		lua_createtable(L, size, 0);
		int i;
		for (i = 1; i <= size; i++) {
			field->rfunc(L, reader, field, index + 1, depth);
			lua_rawseti(L, index + 1, i);
		}
		lua_setfield(L, index, field->name);
	} else {
		field->rfunc(L, reader, field, index, depth);
		lua_setfield(L, index, field->name);
	}
}

static protocol_t* get_protocol(lua_State* L, struct context* ctx) {
	int index = -1;

	if (lua_type(L, 2) == LUA_TNUMBER) {
		index = luaL_checkinteger(L, 2);
	} else {
		size_t size;
		const char* name = luaL_checklstring(L, 2, &size);
		int index = hash_find(ctx->hash, name);
		if (index < 0) {
			luaL_error(L, "encode protocol error:no such protocol:%s", name);
		}
	}

	if (index >= ctx->cap || ctx->slots[index] == NULL) {
		luaL_error(L, "encode protocol error:no such protocol:%d", index);
	}
	return ctx->slots[index];
}

static int lencode(lua_State* L) {
	struct context* ctx = lua_touserdata(L, 1);
	protocol_t* pto = get_protocol(L, ctx);
	luaL_checktype(L, 3, LUA_TTABLE);

	writer_t writer;
	writer_init(&writer);

	int depth = 1;
	luaL_checkstack(L, MAX_DEPTH * 2 + 8, NULL);

	int i;
	for (i = 0; i < pto->fields.size; i++) {
		field_t* field = &pto->fields.field[i];
		lua_getfield(L, 3, field->name);
		pack_one(L, &writer, field, 4, depth);
		lua_pop(L, 1);
	}

	lua_pushlstring(L, writer.ptr, writer.offset);

	writer_release(&writer);
	return 1;
}

static int ldecode(lua_State* L) {
	struct context* ctx = lua_touserdata(L, 1);
	protocol_t* pto = get_protocol(L, ctx);

	size_t size = 0;
	const char* str = NULL;
	switch (lua_type(L, 3)) {
		case LUA_TSTRING: {
			str = lua_tolstring(L, 3, &size);
			break;
		}
		case LUA_TLIGHTUSERDATA:{
			str = lua_touserdata(L, 3);
			size = lua_tointeger(L, 4);
			break;
		}
		default:
			luaL_error(L, "decode protocol:%s error,unkown type:%s", pto->name, lua_typename(L, lua_type(L, 3)));
	}

	reader_t reader;
	reader.ptr = (char*)str;
	reader.offset = 0;
	reader.size = size;

	int depth = 1;
	luaL_checkstack(L, MAX_DEPTH * 2 + 8, NULL);

	lua_createtable(L, 0, pto->fields.size);
	int top = lua_gettop(L);
	int i;
	for (i = 0; i < pto->fields.size; i++) {
		field_t* field = &pto->fields.field[i];
		unpack_one(L, &reader, field, top, depth);
	}

	if (reader.offset != reader.size) {
		luaL_error(L, "decode protocol:%s error", pto->name);
	}
	lua_pushstring(L, pto->name);
	return 2;
}

static char* str_alloc(struct context* ctx, const char* str, size_t size) {
	lua_getfield(ctx->L, 1, str);
	if (!lua_isnoneornil(ctx->L, -1)) {
		char* result = lua_touserdata(ctx->L, -1);
		lua_pop(ctx->L, 1);
		return result;
	}
	lua_pop(ctx->L, 1);

	lua_pushlstring(ctx->L, str, size);
	char* ptr = (char*)lua_tostring(ctx->L, -1);
	lua_pushlightuserdata(ctx->L, ptr);
	lua_settable(ctx->L, 1);
	return ptr;
}

static protocol_t* create_pto(struct context* ctx, int id, char* name, size_t size) {
	protocol_t* pto = malloc(sizeof(*pto));
	memset(pto, 0, sizeof(*pto));
	pto->name = str_alloc(ctx, name, size);
	memset(&pto->fields, 0, sizeof(pto->fields));

	if (id >= ctx->cap) {
		int ncap = ctx->cap * 2;
		if (id >= ncap) {
			ncap = id + 1;
		}
		protocol_t** nslots = (protocol_t**)malloc(sizeof(*nslots) * ncap);
		memset(nslots, 0, sizeof(*nslots) * ncap);
		memcpy(nslots, ctx->slots, sizeof(*ctx->slots) * ctx->cap);
		free(ctx->slots);
		ctx->slots = nslots;
		ctx->cap = ncap;
	}

	ctx->slots[id] = pto;
	return pto;
}

static field_t* create_field(struct context* ctx, field_set_t* fields, const char* name, int array, int type, writer_func wfunc, reader_func rfunc) {
	if (fields->field == NULL) {
		fields->cap = 4;
		fields->size = 0;
		fields->field = malloc(sizeof(*fields->field) * fields->cap);
		memset(fields->field, 0, sizeof(*fields->field) * fields->cap);
	} else {
		if (fields->size >= fields->cap) {
			int ncap = fields->cap * 2;
			field_t* nf = malloc(sizeof(*nf) * ncap);
			memset(nf, 0, sizeof(*nf) * ncap);
			memcpy(nf, fields->field, sizeof(*fields->field) * fields->cap);
			free(fields->field);
			fields->field = nf;
			fields->cap = ncap;
		}
	}
	field_t* field = &fields->field[fields->size++];

	field->name = str_alloc(ctx, name, strlen(name));
	field->array = array;
	field->type = type;
	memset(&field->fields, 0, sizeof(field->fields));
	field->wfunc = wfunc;
	field->rfunc = rfunc;
	return field;
}

static void import_field(lua_State* L, struct context* ctx, field_set_t* fields, int index, int depth) {
	int size = lua_rawlen(L, index);
	int i;
	for (i = 1; i <= size; i++) {
		lua_rawgeti(L, index, i);

		lua_getfield(L, -1, "type");
		int type = lua_tointeger(L, -1);
		lua_pop(L, 1);

		lua_getfield(L, -1, "array");
		int array = lua_toboolean(L, -1);
		lua_pop(L, 1);

		lua_getfield(L, -1, "name");
		const char* name = lua_tostring(L, -1);
		lua_pop(L, 1);

		writer_func wfunc = NULL;
		reader_func rfunc = NULL;
		switch (type) {
			case FTYPE_BOOL:
				wfunc = pack_bool;
				rfunc = unpack_bool;
				break;
			case FTYPE_BYTE:
				wfunc = pack_byte;
				rfunc = unpack_byte;
				break;
			case FTYPE_SHORT:
				wfunc = pack_short;
				rfunc = unpack_short;
				break;
			case FTYPE_INT:
				wfunc = pack_int;
				rfunc = unpack_int;
				break;
			case FTYPE_FLOAT:
				wfunc = pack_float;
				rfunc = unpack_float;
				break;
			case FTYPE_DOUBLE:
				wfunc = pack_double;
				rfunc = unpack_double;
				break;
			case FTYPE_STRING:
				wfunc = pack_string;
				rfunc = unpack_string;
				break;
			case FTYPE_PROTOCOL:
				wfunc = pack_field;
				rfunc = unpack_field;
				break;
			default:
				break;
		}

		field_t* field = create_field(ctx, fields, (char*)name, array, type, wfunc, rfunc);
		if (type == FTYPE_PROTOCOL) {
			lua_getfield(L, -1, "pto");
			import_field(L, ctx, &field->fields, lua_gettop(L), ++depth);
			lua_pop(L, 1);
		}

		lua_pop(L, 1);
	}
}

static int limport(lua_State* L) {
	struct context* ctx = lua_touserdata(L, 1);
	luaL_checktype(L, 2, LUA_TTABLE);

	luaL_checkstack(L, MAX_DEPTH * 2 + 8, NULL);

	lua_pushnil(L);
	while (lua_next(L, 2) != 0) {
		int id = lua_tointeger(L, -2);
		if (id >= 0xffff) {
			luaL_error(L, "pto id must less than 0xffff");
		}

		lua_getfield(L, -1, "name");
		size_t sz = 0;
		const char* name = lua_tolstring(L, -1, &sz);

		protocol_t* pto = create_pto(ctx, id, (char*)name, sz + 1);
		lua_pop(L, 1);

		assert(hash_find(ctx->hash, name) == -1);
		hash_set(ctx->hash, name, id);

		lua_getfield(L, -1, "pto");
		import_field(L, ctx, &pto->fields, lua_gettop(L), 0);

		lua_pop(L, 2);
	}

	return 0;
}

static int llist(lua_State* L) {
	struct context* ctx = lua_touserdata(L, 1);
	lua_newtable(L);
	int i;
	for (i = 0; i < ctx->cap; i++) {
		protocol_t* pto = ctx->slots[i];
		if (pto) {
			lua_pushstring(L, pto->name);
			lua_pushinteger(L, i);
			lua_settable(L, -3);
		}
	}
	return 1;
}

static void export_fields(lua_State* L, field_set_t* fields) {
	lua_newtable(L);
	int i;
	for (i = 0; i < fields->size; i++) {
		lua_newtable(L);
		field_t* field = &fields->field[i];
		lua_pushstring(L, field->name);
		lua_setfield(L, -2, "name");
		lua_pushinteger(L, field->array);
		lua_setfield(L, -2, "array");
		lua_pushinteger(L, field->type);
		lua_setfield(L, -2, "type");
		if (field->type == FTYPE_PROTOCOL) {
			export_fields(L, &field->fields);
			lua_setfield(L, -2, "fields");
		}
		lua_seti(L, -2, i + 1);
	}
}

static int lexport(lua_State* L) {
	struct context* ctx = lua_touserdata(L, 1);
	protocol_t* pto = get_protocol(L, ctx);
	lua_pushstring(L, pto->name);
	export_fields(L, &pto->fields);
	return 2;
}

static void free_fields(field_t* field) {
	int i;
	for (i = 0; i < field->fields.size; i++) {
		field_t* f = &field->fields.field[i];
		if (f->fields.field != NULL) {
			free_fields(f);
			free(f->fields.field);
		}
	}
}

static int lcontext_release(lua_State* L) {
	struct context* ctx = lua_touserdata(L, 1);
	int i;
	for (i = 0; i < ctx->cap; i++) {
		protocol_t* pto = ctx->slots[i];
		if (!pto) {
			continue;
		}

		int j;
		for (j = 0; j < pto->fields.size; j++) {
			field_t* f = &pto->fields.field[j];
			if (f->fields.field != NULL) {
				free_fields(f);
				free(f->fields.field);
			}
		}
		free(pto->fields.field);
		free(pto);
	}

	free(ctx->slots);
	hash_free(ctx->hash);
	lua_close(ctx->L);

	return 0;
}

static int lcontext_new(lua_State* L) {
	struct context* ctx = lua_newuserdata(L, sizeof(*ctx));
	memset(ctx, 0, sizeof(*ctx));

	ctx->cap = 64;
	ctx->slots = malloc(sizeof(*ctx->slots) * ctx->cap);
	memset(ctx->slots, 0, sizeof(*ctx->slots) * ctx->cap);

	ctx->hash = hash_new();

	ctx->L = luaL_newstate();
	lua_settop(ctx->L, 0);
	lua_newtable(ctx->L);

	if (luaL_newmetatable(L, "meta_pto")) {
		const luaL_Reg method[] = {
			{ "encode", lencode },
			{ "decode", ldecode },
			{ "import", limport },
			{ "export", lexport },
			{ "list", llist },
			{ NULL, NULL },
		};
		luaL_newlib(L, method);
		lua_setfield(L, -2, "__index");

		lua_pushcfunction(L, lcontext_release);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	return 1;
}

int luaopen_pto(lua_State* L) {
	luaL_checkversion(L);
	luaL_Reg l[] = {
		{ "new", lcontext_new },
		{ NULL, NULL },
	};
	luaL_newlib(L, l);
	return 1;
}
