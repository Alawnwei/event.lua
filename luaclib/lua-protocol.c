#include <lua.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "khash.h"


#define FTYPE_BOOL 		0
#define FTYPE_SHORT     1
#define FTYPE_INT 		2
#define FTYPE_FLOAT 	3
#define FTYPE_DOUBLE 	4
#define FTYPE_STRING 	5
#define FTYPE_PROTOCOL 	6

#define PARENT_TPROTOCOL 0
#define PARENT_TFIELD	 1

#define MAX_INT 	0xffffffffffffff
#define MAX_DEPTH	32
#define BUFFER_SIZE 128

KHASH_MAP_INIT_STR(protocol, int);

typedef khash_t(protocol) hash_t;

typedef struct message_writer {
	char* ptr;
	int offset;
	int size;
	char init[BUFFER_SIZE];
} writer_t;

typedef struct message_reader {
	char* ptr;
	int offset;
	int size;
} reader_t;

struct field_parent {
	union {
		struct protocol* pto;
		struct field* field;
	} param;
	int type;
};

typedef struct field {
	char* name;
	int array;
	int type;
	struct field* field;
	int cap;
	int size;
} field_t;

typedef struct protocol {
	char* name;
	struct field* field;
	int cap;
	int size;
} protocol_t;

struct context {
	struct protocol** slots;
	int cap;
	hash_t* hash;
	lua_State* L;
};

#define hash_new() kh_init(protocol)
#define hash_foreach(self, k, v, code) kh_foreach(self, k, v, code)

void 
hash_set(hash_t *self, const char* name, int id) {
	int ok;
	khiter_t k = kh_put(protocol, self, strdup(name), &ok);
	assert(ok == 1 || ok == 2);
	kh_value(self, k) = id;
}

void 
hash_del(hash_t *self, const char* name) {
	khiter_t k = kh_get(protocol, self, name);
	assert(k != kh_end(self));
	kh_del(protocol, self, k);
}

int hash_find(hash_t *self, const char* name) {
	khiter_t k = kh_get(protocol, self, name);
	if (k == kh_end(self)) {
		return -1;
	}
	return kh_value(self, k);
}

void hash_free(hash_t *self) {
	char* name;
	int id;
	hash_foreach(self, name, id, {
		free(name);
	});
	kh_destroy(protocol, self);
}

inline static void
writer_reserve(writer_t* writer,size_t sz) {
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

inline static void
writer_init(struct message_writer* writer) {
	writer->ptr = writer->init;
	writer->offset = 0;
	writer->size = BUFFER_SIZE;
}

inline static void
writer_release(writer_t* writer) {
	if (writer->ptr != writer->init) {
		free(writer->ptr);
	}
}

inline static void
writer_push(writer_t* writer,void* data,size_t size) {
	writer_reserve(writer,size);
	memcpy(writer->ptr+writer->offset,data,size);
	writer->offset += size;
}

inline static void
write_byte(writer_t* writer,uint8_t val) {
	writer_push(writer,&val,sizeof(uint8_t));
}

inline static void
write_ushort(writer_t* writer,ushort val) {
	writer_push(writer,&val,sizeof(ushort));
}

inline static void
write_short(writer_t* writer,short val) {
	writer_push(writer,&val,sizeof(short));
}

inline static void
write_int(writer_t* writer,lua_Integer val) {
	if (val == 0) {
		write_byte(writer,0);
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
	}
	else if (value <= 0xffff) {
		length = 2;
	}
	else if (value <= 0xffffff) {
		length = 3;
	}
	else if (value <= 0xffffffff) {
		length = 4;
	}
	else if (value <= 0xffffffffff) {
		length = 5;
	}
	else if (value <= 0xffffffffffff) {
		length = 6;
	}
	else {
		length = 7;
	}

	uint8_t tag = length;
	tag = (tag << 1) | positive;

	uint8_t data[8] = {0};
	data[0] = tag;
	memcpy(&data[1],&value,length);

	writer_push(writer, data, length + 1);
}

inline static void
write_float(writer_t* writer,float val) {
	writer_push(writer,&val,sizeof(float));
}

inline static void
write_double(writer_t* writer,double val) {
	writer_push(writer,&val,sizeof(double));
}

inline static void
write_string(writer_t* writer,const char* str,size_t size) {
	write_ushort(writer,size);
	writer_push(writer,(void*)str,size);
}

inline static void
reader_pop(lua_State* L,reader_t* reader,uint8_t* data,size_t size) {
	if (reader->size - reader->offset < size) {
		luaL_error(L,"decode error:invalid mesasge");
	}
	memcpy(data,reader->ptr+reader->offset,size);
	reader->offset += size;
}

inline static int
reader_left(reader_t* reader) {
	return reader->size - reader->offset;
}

inline static uint8_t
read_byte(lua_State* L,reader_t* reader) {
	uint8_t val;
	reader_pop(L,reader,(uint8_t*)&val,sizeof(uint8_t));
	return val;
}

inline static ushort
read_ushort(lua_State* L,reader_t* reader) {
	ushort val;
	reader_pop(L,reader,(uint8_t*)&val,sizeof(ushort));
	return val;
}

inline static short
read_short(lua_State* L,reader_t* reader) {
	short val;
	reader_pop(L,reader,(uint8_t*)&val,sizeof(short));
	return val;
}

inline static lua_Integer
read_int(lua_State* L,reader_t* reader) {
	
	uint8_t tag;
	reader_pop(L,reader,&tag,sizeof(uint8_t));

	if (tag == 0) {
		return 0;
	}

	int length = tag >> 1;

	uint64_t value = 0;
	reader_pop(L,reader,(uint8_t*)&value,length);

	return (tag & 0x1) == 1 ? value : -value;
}

inline static float
read_float(lua_State* L,reader_t* reader) {
	float val;
	reader_pop(L,reader,(uint8_t*)&val,sizeof(float));
	return val;
}

inline static double
read_double(lua_State* L,reader_t* reader) {
	double val;
	reader_pop(L,reader,(uint8_t*)&val,sizeof(double));
	return val;
}

inline static char*
read_string(lua_State* L,reader_t* reader,size_t* size) {
	char* result;
	*size = read_ushort(L,reader);
	if (reader_left(reader) < *size) {
		luaL_error(L,"decode error:invalid mesasge");
	}
	result = reader->ptr + reader->offset;
	reader->offset += *size;
	return result;
}

inline static int
check_array(lua_State* L,writer_t* writer,field_t* f,int index,int vt) {
	if (vt != LUA_TTABLE) {
		writer_release(writer);
		luaL_error(L,"field:%s expect %s,not %s",f->name,lua_typename(L,LUA_TTABLE),lua_typename(L,vt));
	}

	int array_size = lua_rawlen(L, index);
	if (array_size > 0xffff) {
		writer_release(writer);
		luaL_error(L,"field:%s array size more than 0xffff",f->name);
	}
	return array_size;
}

inline void
pack_bool(lua_State* L,writer_t* writer,field_t* f,int index) {
	int vt = lua_type(L,index);

	if (f->array) {
		int array_size = check_array(L,writer,f,index,vt);

		write_ushort(writer,array_size);
		int i;
		for (i = 1; i <= array_size; i++) {
			lua_rawgeti(L, index, i);
			vt = lua_type(L,-1);
			if (vt != LUA_TBOOLEAN) {
				writer_release(writer);
				luaL_error(L,"field:%s array member expect bool,not %s",f->name,lua_typename(L,vt));
			}
			write_byte(writer,lua_toboolean(L,-1));
			lua_pop(L, 1);
		}
	} else {
		if (vt != LUA_TBOOLEAN) {
			writer_release(writer);
			luaL_error(L,"field:%s expect bool,not %s",f->name,lua_typename(L,vt));
		}
		write_byte(writer,lua_toboolean(L,index));
	}
}  

inline void
pack_short(lua_State* L,writer_t* writer,field_t* f,int index) {
	int vt = lua_type(L,index);

	if (f->array) {
		int array_size = check_array(L,writer,f,index,vt);

		write_ushort(writer,array_size);
		int i;
		for (i = 1; i <= array_size; i++) {
			lua_rawgeti(L, index, i);
			vt = lua_type(L,-1);
			if (vt != LUA_TNUMBER) {
				writer_release(writer);
				luaL_error(L,"field:%s array member expect short,not %s",f->name,lua_typename(L,vt));
			}
			write_short(writer,lua_tointeger(L,-1));
			lua_pop(L, 1);
		}
	} else {
		if (vt != LUA_TNUMBER) {
			writer_release(writer);
			luaL_error(L,"field:%s expect short,not %s",f->name,lua_typename(L,vt));
		}
		write_short(writer,lua_tointeger(L,index));
	}
} 

inline void
pack_int(lua_State* L,writer_t* writer,field_t* f,int index) {
	int vt = lua_type(L,index);

	if (f->array) {
		int array_size = check_array(L,writer,f,index,vt);

		write_ushort(writer,array_size);
		int i;
		for (i = 1; i <= array_size; i++) {
			lua_rawgeti(L, index, i);
			vt = lua_type(L,-1);
			if (vt != LUA_TNUMBER) {
				writer_release(writer);
				luaL_error(L,"field:%s array member expect int,not %s",f->name,lua_typename(L,vt));
			}
			lua_Integer val = lua_tointeger(L,-1);
			if (val > MAX_INT || val < -MAX_INT) {
				writer_release(writer);
				luaL_error(L,"field:%s array member int out of range,%I",f->name,val);
			}
			write_int(writer,val);
			lua_pop(L, 1);
		}
	} else {
		if (vt != LUA_TNUMBER) {
			writer_release(writer);
			luaL_error(L,"field:%s expect int,not %s",f->name,lua_typename(L,vt));
		}
		lua_Integer val = lua_tointeger(L,index);
		if (val > MAX_INT || val < -MAX_INT) {
			writer_release(writer);
			luaL_error(L,"field:%s int out of range,%I",f->name,val);
		}
		
		write_int(writer,val);
	}
}  

inline void
pack_float(lua_State* L,writer_t* writer,field_t* f,int index) {
	int vt = lua_type(L,index);

	if (f->array) {
		int array_size = check_array(L,writer,f,index,vt);

		write_ushort(writer,array_size);
		int i;
		for (i = 1; i <= array_size; i++) {
			lua_rawgeti(L, index, i);
			vt = lua_type(L,-1);
			if (vt != LUA_TNUMBER) {
				writer_release(writer);
				luaL_error(L,"field:%s array member expect float,not %s",f->name,lua_typename(L,vt));
			}
			write_float(writer,lua_tonumber(L,-1));
			lua_pop(L, 1);
		}
	} else {
		if (vt != LUA_TNUMBER) {
			writer_release(writer);
			luaL_error(L,"field:%s expect float,not %s",f->name,lua_typename(L,vt));
		}
		write_float(writer,lua_tonumber(L,index));
	}
} 

inline void
pack_double(lua_State* L,writer_t* writer,field_t* f,int index) {
	int vt = lua_type(L,index);
	if (f->array) {
		int array_size = check_array(L,writer,f,index,vt);

		write_ushort(writer,array_size);
		int i;
		for (i = 1; i <= array_size; i++) {
			lua_rawgeti(L, index, i);
			vt = lua_type(L,-1);
			if (vt != LUA_TNUMBER) {
				writer_release(writer);
				luaL_error(L,"field:%s array member expect double,not %s",f->name,lua_typename(L,vt));
			}
			write_double(writer,lua_tonumber(L,-1));
			lua_pop(L, 1);
		}
	} else {
		if (vt != LUA_TNUMBER) {
			writer_release(writer);
			luaL_error(L,"field:%s expect double,not %s",f->name,lua_typename(L,vt));
		}
		write_double(writer,lua_tonumber(L,index));
	}
}

inline void
pack_string(lua_State* L,writer_t* writer,field_t* f,int index) {
	int vt = lua_type(L,index);
	if (f->array) {
		int array_size = check_array(L,writer,f,index,vt);

		write_ushort(writer,array_size);
		int i;
		for (i = 1; i <= array_size; i++) {
			lua_rawgeti(L, index, i);
			vt = lua_type(L,-1);
			if (vt != LUA_TSTRING) {
				writer_release(writer);
				luaL_error(L,"field:%s array member expect string,not %s",f->name,lua_typename(L,vt));
			}
			size_t size;
			const char* str = lua_tolstring(L,-1,&size);
			if (size > 0xffff) {
				writer_release(writer);
				luaL_error(L,"field:%s string size more than 0xffff:%d",f->name,size);
			}
			write_string(writer,str,size);
			lua_pop(L, 1);
		}
	} else {
		if (vt != LUA_TSTRING) {
			writer_release(writer);
			luaL_error(L,"field:%s expect string,not %s",f->name,lua_typename(L,vt));
		}
		size_t size;
		const char* str = lua_tolstring(L,index,&size);
		if (size > 0xffff) {
			writer_release(writer);
			luaL_error(L,"field:%s string size more than 0xffff:%d",f->name,size);
		}
		write_string(writer,str,size);
	}
}

static inline void pack_one(lua_State* L,writer_t* writer,field_t* f,int index,int depth);

void
pack_field(lua_State* L,writer_t* writer,field_t* parent,int index,int depth) {
	depth++;
	if (depth > MAX_DEPTH) {
		writer_release(writer);
		luaL_error(L,"message pack too depth");
	}
	
	int vt = lua_type(L,index);
	if (vt != LUA_TTABLE) {
		writer_release(writer);
		luaL_error(L,"field:%s expect table,not %s",parent->name,lua_typename(L,vt));
	}

	if (parent->array) {
		int array_size = check_array(L,writer,parent,index,vt);
		
		write_ushort(writer,array_size);

		int i;
		for (i = 0; i < array_size; i++) {
			lua_rawgeti(L, index, i+1);
			vt = lua_type(L,-1);
			if (vt != LUA_TTABLE) {
				writer_release(writer);
				luaL_error(L,"field:%s array member expect table,not %s",parent->name,lua_typename(L,vt));
			}

			int j;
			for(j=0;j < parent->size;j++) {
				field_t* f = &parent->field[j];
				lua_getfield(L, -1, f->name);
				pack_one(L,writer,f,index+2,depth);
				lua_pop(L,1);
			}
			lua_pop(L,1);
		}
	} else {
		int i;
		for(i=0;i < parent->size;i++) {
			field_t* f = &parent->field[i];
			lua_getfield(L, index, f->name);
			pack_one(L,writer,f,index+1,depth);
			lua_pop(L,1);
		}
	}
}

static inline void
pack_one(lua_State* L,writer_t* writer,field_t* f,int index,int depth) {
	switch(f->type) {
		case FTYPE_BOOL: {
			pack_bool(L,writer,f,index);
			break;
		}
		case FTYPE_SHORT: {
			pack_short(L,writer,f,index);
			break;
		}
		case FTYPE_INT: {
			pack_int(L,writer,f,index);
			break;
		}
		case FTYPE_FLOAT: {
			pack_float(L,writer,f,index);
			break;
		}
		case FTYPE_DOUBLE: {
			pack_double(L,writer,f,index);
			break;
		}
		case FTYPE_STRING: {
			pack_string(L,writer,f,index);
			break;
		}
		case FTYPE_PROTOCOL: {
			pack_field(L,writer,f,index,depth);
			break;
		}
		default: {
			writer_release(writer);
			luaL_error(L,"pack error:invalid name:%s,type:%d",f->name,f->type);
		}
	}
}

inline void
unpack_bool(lua_State* L,reader_t* reader,field_t* f,int index) {
	if (f->array) {
		int array_size = read_ushort(L,reader);
		lua_createtable(L,0,0);
		int i;
		for (i = 1; i <= array_size; i++) {
			uint8_t val = read_byte(L,reader);
			lua_pushboolean(L,val);
			lua_rawseti(L,-2,i);
		}
		lua_setfield(L,index,f->name);
	} else {
		uint8_t val = read_byte(L,reader);
		lua_pushboolean(L,val);
		lua_setfield(L,index,f->name);
	}
}

inline void
unpack_short(lua_State* L,reader_t* reader,field_t* f,int index) {
	if (f->array) {
		int array_size = read_ushort(L,reader);
		lua_createtable(L,0,0);
		int i;
		for (i = 1; i <= array_size; i++) {
			short val = read_short(L,reader);
			lua_pushinteger(L,val);
			lua_rawseti(L,-2,i);
		}
		lua_setfield(L,index,f->name);
	} else {
		short val = read_short(L,reader);
		lua_pushinteger(L,val);
		lua_setfield(L,index,f->name);
	}
} 

inline void
unpack_int(lua_State* L,reader_t* reader,field_t* f,int index) {
	if (f->array) {
		int array_size = read_ushort(L,reader);
		lua_createtable(L,0,0);
		int i;
		for (i = 1; i <= array_size; i++) {
			lua_Integer val = read_int(L,reader);
			lua_pushinteger(L,val);
			lua_rawseti(L,-2,i);
		}
		lua_setfield(L,index,f->name);
	} else {
		lua_Integer val = read_int(L,reader);
		lua_pushinteger(L,val);
		lua_setfield(L,index,f->name);
	}
}  

inline void
unpack_float(lua_State* L,reader_t* reader,field_t* f,int index) {
	if (f->array) {
		int array_size = read_ushort(L,reader);
		lua_createtable(L,0,0);
		int i;
		for (i = 1; i <= array_size; i++) {
			float val = read_float(L,reader);
			lua_pushnumber(L,val);
			lua_rawseti(L,-2,i);
		}
		lua_setfield(L,index,f->name);
	} else {
		float val = read_float(L,reader);
		lua_pushnumber(L,val);
		lua_setfield(L,index,f->name);
	}
} 

inline void
unpack_double(lua_State* L,reader_t* reader,field_t* f,int index) {
	if (f->array) {
		int array_size = read_ushort(L,reader);
		lua_createtable(L,0,0);
		int i;
		for (i = 1; i <= array_size; i++) {
			double val = read_double(L,reader);
			lua_pushnumber(L,val);
			lua_rawseti(L,-2,i);
		}
		lua_setfield(L,index,f->name);
	} else {
		double val = read_double(L,reader);
		lua_pushnumber(L,val);
		lua_setfield(L,index,f->name);
	}
}

inline void
unpack_string(lua_State* L,reader_t* reader,field_t* f,int index) {
	if (f->array) {
		int array_size = read_ushort(L,reader);
		lua_createtable(L,0,0);
		int i;
		for (i = 1; i <= array_size; i++) {
			size_t size;
			char* val = read_string(L,reader,&size);
			lua_pushlstring(L,val,size);
			lua_rawseti(L,-2,i);
		}
		lua_setfield(L,index,f->name);
	} else {
		size_t size;
		char* val = read_string(L,reader,&size);
		lua_pushlstring(L,val,size);
		lua_setfield(L,index,f->name);
	}
}

static inline void unpack_one(lua_State* L,reader_t* reader,field_t* f,int index,int depth);

void
unpack_field(lua_State* L,reader_t* reader,field_t* parent,int index,int depth) {
	depth++;
	if (depth > MAX_DEPTH) {
		luaL_error(L,"message unpack too depth");
	}
	
	if (parent->array) {
		int array_size = read_ushort(L,reader);
		lua_createtable(L,0,0);
		int i;
		for (i = 1; i <= array_size; i++) {
			int j;
			lua_createtable(L,0,parent->size);
			for(j=0;j < parent->size;j++) {
				field_t* f = &parent->field[j];
				unpack_one(L,reader,f,index + 2,depth);
			}
			lua_seti(L,-2,i);
		}
		lua_setfield(L,index,parent->name);
	} else {
		lua_createtable(L,0,parent->size);
		int i;
		for(i=0;i < parent->size;i++) {
			field_t* f = &parent->field[i];
			unpack_one(L,reader,f,index + 1,depth);
		}
		lua_setfield(L,index,parent->name);
	}
}

static inline void
unpack_one(lua_State* L,reader_t* reader,field_t* f,int index,int depth) {
	switch(f->type) {
		case FTYPE_BOOL: {
			unpack_bool(L,reader,f,index);
			break;
		}
		case FTYPE_SHORT: {
			unpack_short(L,reader,f,index);
			break;
		}
		case FTYPE_INT: {
			unpack_int(L,reader,f,index);
			break;
		}
		case FTYPE_FLOAT: {
			unpack_float(L,reader,f,index);
			break;
		}
		case FTYPE_DOUBLE: {
			unpack_double(L,reader,f,index);
			break;
		}
		case FTYPE_STRING: {
			unpack_string(L,reader,f,index);
			break;
		}
		case FTYPE_PROTOCOL: {
			unpack_field(L,reader,f,index,depth);
			break;
		}
		default: {
			luaL_error(L,"unpack error:invalid name:%s,type:%d",f->name,f->type);
		}
	}
}

static protocol_t*
get_protocol(lua_State* L, struct context* ctx) {
	int index = -1;

	if (lua_type(L, 2) == LUA_TNUMBER) {
		index = luaL_checkinteger(L,2);
	} else {
		size_t size;
		const char* name = luaL_checklstring(L, 2, &size);
		int index = hash_find(ctx->hash, name);
		if (index < 0) {
			luaL_error(L, "encode protocol error:no such protocol:%s", name);
		}
	}
	
	if (index >= ctx->cap || ctx->slots[index] == NULL) {
		luaL_error(L,"encode protocol error:no such protocol:%d",index);
	}
	return ctx->slots[index];
}

int
lencode_protocol(lua_State* L) {
	struct context* ctx = lua_touserdata(L,1);
	protocol_t* pto = get_protocol(L, ctx);
	luaL_checktype(L, 3, LUA_TTABLE);

	writer_t writer;
	writer_init(&writer);

	int depth = 1;
	luaL_checkstack(L, MAX_DEPTH*2 + 8, NULL);

	int i;
	for(i=0;i < pto->size;i++) {
		field_t* field = &pto->field[i];
		lua_getfield(L, 3, field->name);
		pack_one(L,&writer, field, 4, depth);
		lua_pop(L, 1);
	}

	lua_pushlstring(L,writer.ptr,writer.offset);

	writer_release(&writer);
	return 1;
}

int
ldecode_protocol(lua_State* L) {
	struct context* ctx = lua_touserdata(L,1);
	protocol_t* pto = get_protocol(L, ctx);

	size_t size;
	const char* str = NULL;
	switch(lua_type(L, 3)) {
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
			luaL_error(L,"decode protocol:%s error,unkown type:%s",pto->name,lua_typename(L,lua_type(L,3)));
	}

	reader_t reader;
	reader.ptr = (char*)str;
	reader.offset = 0;
	reader.size = size;

	int depth = 1;
	luaL_checkstack(L, MAX_DEPTH*2 + 8, NULL);

	lua_createtable(L, 0, pto->size);
	int top = lua_gettop(L);
	int i;
	for(i=0;i < pto->size; i++) {
		field_t* field = &pto->field[i];
		unpack_one(L, &reader, field, top, depth);
	}
	
	if (reader.offset != reader.size) {
		luaL_error(L,"decode protocol:%s error",pto->name);
	}
	return 1;
}

char* 
str_alloc(struct context* ctx,const char* str,size_t size) {
	lua_getfield(ctx->L, 1, str);
	if (!lua_isnoneornil(ctx->L,-1)) {
		char* result = lua_touserdata(ctx->L,-1);
		lua_pop(ctx->L,1);
		return result;
	}
	lua_pop(ctx->L,1);

	lua_pushlstring(ctx->L,str,size);
	char* ptr = (char*)lua_tostring(ctx->L,-1);
	lua_pushlightuserdata(ctx->L,ptr);
	lua_settable(ctx->L,1);
	return ptr;
}

protocol_t* 
create_protocol(struct context* ctx,int id,char* name,size_t size) {
	protocol_t* pto = malloc(sizeof(*pto));
	memset(pto,0,sizeof(*pto));
	pto->name = str_alloc(ctx,name,size);
	pto->cap = 4;
	pto->size = 0;
	pto->field = malloc(sizeof(*pto->field) * pto->cap);
	memset(pto->field,0,sizeof(*pto->field) * pto->cap);

	if (id >= ctx->cap) {
		int ncap = ctx->cap * 2;
		if (id >= ncap)
			ncap = id + 1;
		protocol_t** nslots = malloc(sizeof(*nslots) * ncap);
		memset(nslots,0,sizeof(*nslots) * ncap);
		memcpy(nslots,ctx->slots,sizeof(*ctx->slots) * ctx->cap);
		free(ctx->slots);
		ctx->slots = nslots;
		ctx->cap = ncap;
	}

	ctx->slots[id] = pto;
	return pto;
}

field_t* 
create_field(struct context* ctx,struct field_parent* parent,const char* name,int array,int type) {

	field_t* f = NULL;
	if (parent->type == PARENT_TPROTOCOL) {
		protocol_t* pto = parent->param.pto;
		if (pto->size >= pto->cap) {
			int ncap = pto->cap * 2;
			field_t* nf = malloc(sizeof(*nf) * ncap);
			memset(nf,0,sizeof(*nf) * ncap);
			memcpy(nf,pto->field,sizeof(*pto->field) * pto->cap);
			free(pto->field);
			pto->field = nf;
			pto->cap = ncap;
		}
		f = &pto->field[pto->size++];
	} else {
		field_t* field = parent->param.field;
		if (field->field == NULL) {
			field->cap = 4;
			field->size = 0;
			field->field = malloc(sizeof(*field->field) * field->cap);
			memset(field->field,0,sizeof(*field->field) * field->cap);
		} else {
			if (field->size >= field->cap) {
				int ncap = field->cap * 2;
				field_t* nf = malloc(sizeof(*nf) * ncap);
				memset(nf,0,sizeof(*nf) * ncap);
				memcpy(nf,field->field,sizeof(*field->field) * field->cap);
				free(field->field);
				field->field = nf;
				field->cap = ncap;
			}
		}
		f = &field->field[field->size++];
	}

	f->name = str_alloc(ctx,name,strlen(name));
	f->array = array;
	f->type = type;
	f->field = NULL;
	f->size = 0;
	f->cap = 0;

	return f;
}

void
import_field(lua_State* L,struct context* ctx,struct field_parent* parent,int index,int depth) {
	int array_size = lua_rawlen(L, index);
	int i;
	for (i = 1; i <= array_size; i++) {
		lua_rawgeti(L, index, i);
		
		lua_getfield(L,-1,"type");
		int type = lua_tointeger(L,-1);
		lua_pop(L, 1);

		lua_getfield(L,-1,"array");
		int array = lua_toboolean(L,-1);
		lua_pop(L, 1);

		lua_getfield(L,-1,"name");
		const char* name = lua_tostring(L,-1);
		lua_pop(L, 1);

		field_t* f = create_field(ctx,parent,(char*)name,array,type);
		if (type == FTYPE_PROTOCOL) {
			lua_getfield(L,-1,"fields");
			struct field_parent sub_parent;
			sub_parent.type = PARENT_TFIELD;
			sub_parent.param.field = f;
			import_field(L,ctx,&sub_parent,lua_gettop(L),++depth);
			lua_pop(L, 1);
		}

		lua_pop(L, 1);
	}
}

int
limport_protocol(lua_State* L) {
	struct context* ctx = lua_touserdata(L, 1);
	int id = lua_tointeger(L, 2);
	size_t size;
	const char* name = lua_tolstring(L, 3, &size);
	luaL_checktype(L, 4, LUA_TTABLE);

	if (id < ctx->cap && ctx->slots[id] != NULL) {
		luaL_error(L, "id:%d already load", id);
	}

	luaL_checkstack(L, MAX_DEPTH * 2 + 8, NULL);

	protocol_t* pto = create_protocol(ctx, id, (char*)name, size + 1);
	int depth = 0;
	lua_getfield(L,-1,"fields");
	if (!lua_isnil(L,-1)) {
		struct field_parent parent;
		parent.type = PARENT_TPROTOCOL;
		parent.param.pto = pto;
		import_field(L,ctx,&parent,lua_gettop(L),++depth);
	}

	assert(hash_find(ctx->hash, name) == -1);
	hash_set(ctx->hash, name, id);
	return 0;
}

int
llist_protocol(lua_State* L) {
	struct context* ctx = lua_touserdata(L, 1);
	lua_newtable(L);
	int i;
	for(i = 0; i < ctx->cap; i++) {
		protocol_t* pto = ctx->slots[i];
		if (pto) {
			lua_pushstring(L, pto->name);
			lua_pushinteger(L, i);
			lua_settable(L, -3);
		}
	}
	return 1;
}

void
dump_nest(lua_State* L,field_t* parent) {
	lua_newtable(L);
	int i;
	for(i=0;i<parent->size;i++) {
		lua_newtable(L);
		field_t* f = &parent->field[i];
		lua_pushstring(L,f->name);
		lua_setfield(L,-2,"name");
		lua_pushinteger(L,f->array);
		lua_setfield(L,-2,"array");
		lua_pushinteger(L,f->type);
		lua_setfield(L,-2,"type");
		if (f->type == FTYPE_PROTOCOL) {
			dump_nest(L,f);
			lua_setfield(L,-2,"fields");
		}
		lua_seti(L,-2,i+1);
	}
}

int
ldump_protocol(lua_State* L) {
	struct context* ctx = lua_touserdata(L,1);
	protocol_t* pto = get_protocol(L, ctx);

	lua_newtable(L);

	lua_pushstring(L, pto->name);
	lua_setfield(L, -2, "name");

	lua_newtable(L);

	int i;
	for(i = 0;i < pto->size; i++) {
		field_t* field = &pto->field[i];
		lua_newtable(L);

		lua_pushstring(L,field->name);
		lua_setfield(L,-2,"name");

		lua_pushinteger(L,field->array);
		lua_setfield(L,-2,"array");

		lua_pushinteger(L,field->type);
		lua_setfield(L,-2,"type");

		if (field->type == FTYPE_PROTOCOL) {
			dump_nest(L, field);
			lua_setfield(L, -2, "fields");
		}

		lua_seti(L, -2, i+1);
	}
	lua_setfield(L,-2,"fields");

	return 1;
}

void
free_nest(field_t* field) {
	int i;
	for(i=0;i< field->size;i++) {
		field_t* f = &field->field[i];
		if (f->field != NULL) {
			free_nest(f);
			free(f->field);
		}
	}
}

int
lcontext_release(lua_State* L) {
	struct context* ctx = lua_touserdata(L,1);
	int i;
	for(i=0;i<ctx->cap;i++) {
		protocol_t* pto = ctx->slots[i];
		if (!pto) {
			continue;
		}

		int j;
		for(j=0;j< pto->size;j++) {
			field_t* f = &pto->field[j];
			if (f->field != NULL) {
				free_nest(f);
				free(f->field);
			}
		}
		free(pto->field);
		free(pto);
	}
	
	free(ctx->slots);
	hash_free(ctx->hash);
	lua_close(ctx->L);

	return 0;
}

int
lcontext_new(lua_State* L) {
	struct context* ctx = lua_newuserdata(L, sizeof(*ctx));
	memset(ctx,0,sizeof(*ctx));

	ctx->cap = 64;
	ctx->slots = malloc(sizeof(*ctx->slots) * ctx->cap);
	memset(ctx->slots,0,sizeof(*ctx->slots) * ctx->cap);

	ctx->hash = hash_new();

	ctx->L = luaL_newstate();
	lua_settop(ctx->L,0);
	lua_newtable(ctx->L);

	if (luaL_newmetatable(L, "meta_protocol")) {
        const luaL_Reg meta[] = {
            { "encode", lencode_protocol },
			{ "decode", ldecode_protocol },
			{ "import", limport_protocol },
			{ "list", llist_protocol },
			{ "dump", ldump_protocol },
            { NULL, NULL },
        };
        luaL_newlib(L,meta);
        lua_setfield(L, -2, "__index");

        lua_pushcfunction(L, lcontext_release);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);
    return 1;
}

int
luaopen_protocolcore(lua_State* L) {
	luaL_checkversion(L);
	luaL_Reg l[] = {
		{ "new", lcontext_new },
		{ NULL, NULL },
	};
	luaL_newlib(L,l);
	return 1;
}