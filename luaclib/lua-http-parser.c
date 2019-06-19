#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "common/string.h"

#include "http_parser.h"

#define HEADER_PHASE_FIELD 0
#define HEADER_PHASE_VALUE 1

struct header {
	struct string field;
	struct string value;
};

struct lua_http_parser {
	struct http_parser parser;
	
	struct header* header;
	int offset;
	int size;
	int phase;

	struct string status;
	struct string url;
	struct string body;

	int more;
};

#define META_PARSER "http_parser"

int
parser_message_begin(struct http_parser* parser) {
	return 0;
}

int
parser_message_complete(struct http_parser* parser) {
	struct lua_http_parser* lparser = (struct lua_http_parser*)parser;
	lparser->more = 0;
	return 0;
}

int
parser_headers_complete(struct http_parser* parser) {
	return 0;
}

int
parser_chunk_header(struct http_parser* parser) {
	return 0;
}

int
parser_chunk_complete(struct http_parser* parser) {
	return 0;
}

int
parser_url(struct http_parser* parser,const char* at,size_t length) {
	struct lua_http_parser* lparser = (struct lua_http_parser*)parser;
	string_append_lstr(&lparser->url, at, length);
	return 0;
}

int
parser_status(struct http_parser* parser,const char* at,size_t length) {
	struct lua_http_parser* lparser = (struct lua_http_parser*)parser;
	string_append_lstr(&lparser->status, at, length);
	return 0;
}

int
parser_header_field(struct http_parser* parser,const char* at,size_t length) {
	struct lua_http_parser* lparser = (struct lua_http_parser*)parser;
	if (lparser->phase == HEADER_PHASE_VALUE) {
		lparser->phase = HEADER_PHASE_FIELD;

		lparser->offset++;
		if (lparser->offset >= lparser->size) {
			int nsize = lparser->size * 2;
			lparser->header = realloc(lparser->header, sizeof(struct header) * nsize);
			lparser->size = nsize;
		}

		struct header* header = &lparser->header[lparser->offset];
		string_init(&header->field, NULL, 64);
		string_init(&header->value, NULL, 64);
	}

	struct header* header = &lparser->header[lparser->offset];
	string_append_lstr(&header->field, at, length);
	return 0;
}

int
parser_header_value(struct http_parser* parser,const char* at,size_t length) {
	struct lua_http_parser* lparser = (struct lua_http_parser*)parser;
	lparser->phase = HEADER_PHASE_VALUE;

	struct header* header = &lparser->header[lparser->offset];
	string_append_lstr(&header->value, at, length);
	return 0;
}

int
parser_body(struct http_parser* parser,const char* at,size_t length) {
	struct lua_http_parser* lparser = (struct lua_http_parser*)parser;
	string_append_lstr(&lparser->body, at, length);
	return 0;
}


static const http_parser_settings settings = {
        parser_message_begin,
        parser_url,
        parser_status,
        parser_header_field,
        parser_header_value,
        parser_headers_complete,
        parser_body,
        parser_message_complete,
        parser_chunk_header,
        parser_chunk_complete
    };

int
meta_execute(lua_State* L) {
	struct lua_http_parser* lparser = (struct lua_http_parser*)lua_touserdata(L, 1);
	size_t length;
	const char* data = lua_tolstring(L,2,&length);

	lparser->more = 1;

	http_parser_execute(&lparser->parser,&settings,data,length);
	if (HTTP_PARSER_ERRNO(&lparser->parser) != HPE_OK) {
		lua_pushboolean(L,0);
		lua_pushstring(L,http_errno_name(HTTP_PARSER_ERRNO(&lparser->parser)));
		return 2;
	}

	lua_pushboolean(L,1);
	lua_pushboolean(L,lparser->more);

	if (lparser->more) {
		return 2;
	}

	lua_newtable(L);

	lua_pushinteger(L,lparser->parser.upgrade);
	lua_setfield(L,-2,"upgrade");

	lua_pushstring(L,http_method_str(lparser->parser.method));
	lua_setfield(L,-2,"method");

	lua_pushinteger(L,lparser->parser.http_major);
	lua_setfield(L,-2,"major");

	lua_pushinteger(L,lparser->parser.http_minor);
	lua_setfield(L,-2,"minor");

	lua_pushboolean(L, http_should_keep_alive(&lparser->parser));
	lua_setfield(L,-2,"keepalive");

	lua_pushlstring(L, string_str(&lparser->status), string_length(&lparser->status));
	lua_setfield(L,-2,"status");

	lua_pushlstring(L, string_str(&lparser->url), string_length(&lparser->url));
	lua_setfield(L,-2,"url");

	lua_pushlstring(L, string_str(&lparser->body), string_length(&lparser->body));
	lua_setfield(L,-2,"body");

	lua_newtable(L);

	int i;
	for(i = 0;i<=lparser->offset;i++) {
		struct header* header = &lparser->header[i];

		lua_pushlstring(L, string_str(&header->field), string_length(&header->field));
		lua_pushlstring(L, string_str(&header->value), string_length(&header->value));

		lua_settable(L, -3);
	}

	lua_setfield(L,-2,"header");


	return 3;
}

int
parser_release(lua_State* L) {
	struct lua_http_parser* lparser = (struct lua_http_parser*)lua_touserdata(L, 1);
	string_release(&lparser->status);
	string_release(&lparser->url);
	string_release(&lparser->body);
	int i;
	for(i = 0;i<=lparser->offset;i++) {
		struct header* header = &lparser->header[i];
		string_release(&header->field);
		string_release(&header->value);
	}
	free(lparser->header);
	return 0;
}

int
parser_new(lua_State* L) {
	struct lua_http_parser* lparser = lua_newuserdata(L, sizeof(*lparser));

	int parser_type = lua_tointeger(L,1);
	switch(parser_type) {
		case 0:
		{
			http_parser_init(&lparser->parser,HTTP_REQUEST);
			break;
		}
		case 1:
		{
			http_parser_init(&lparser->parser,HTTP_RESPONSE);
			break;
		}
		default:
		{
			luaL_error(L,"unknown httpd parser type");
		}
	}

	lparser->size = 4;
	lparser->offset = -1;
	lparser->header = malloc(sizeof(struct header) * lparser->size);
	lparser->phase = HEADER_PHASE_VALUE;

	string_init(&lparser->status, NULL, 64);
	string_init(&lparser->url, NULL, 64);
	string_init(&lparser->body, NULL, 64);

	luaL_newmetatable(L,META_PARSER);
 	lua_setmetatable(L, -2);
	
	return 1;
}

int
luaopen_http_parser(lua_State* L) {

	luaL_newmetatable(L, META_PARSER);
	const luaL_Reg meta_parser[] = {
		{ "execute", meta_execute },
		{ NULL, NULL },
	};
	luaL_newlib(L,meta_parser);
	lua_setfield(L, -2, "__index");

	lua_pushcfunction(L, parser_release);
    lua_setfield(L, -2, "__gc");

	lua_pop(L,1);

	const luaL_Reg l[] = {
		{ "new", parser_new },
		{ NULL, NULL },
	};
	luaL_newlib(L, l);
	return 1;
}
