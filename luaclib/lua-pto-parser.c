#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <setjmp.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "khash.h"


#define TRY(l) if (setjmp((l)->exception) == 0)
#define THROW(l) longjmp((l)->exception, 1)


#define TYPE_BOOL 		0
#define TYPE_SHORT     	1
#define TYPE_INT 		2
#define TYPE_FLOAT 		3
#define TYPE_DOUBLE 	4
#define TYPE_STRING 	5
#define TYPE_PROTOCOL 	6


#define MAX_DEPTH	32

#define MAX_PATH_LENGTH 	64

static const char* BUILTIN_TYPE[] = { "bool", "short", "int", "float", "double", "string"};


struct protocol;

KHASH_MAP_INIT_STR(pto,struct protocol*);

typedef khash_t(pto) hash_pto_t;

#define pto_hash_new() kh_init(pto)
#define pto_hash_foreach(self, k, v, code) kh_foreach(self, k, v, code)


struct field {
	char* name;
	int type;
	int array;
	struct protocol* protocol;
};


struct protocol {
	struct protocol* parent;
	hash_pto_t* children;

	char* file;
	char* name;

	struct field** field;
	int cap;
	int size;
};

typedef struct lexer {
	char* cursor;
	char* data;
	int line;

	char* file;

	struct lexer* parent;

	jmp_buf exception;
} lexer_t;

struct parser_context {
	hash_pto_t* pto_ctx;
	lua_State* L;
	lexer_t** importer;
	int offset;
	int size;
	char* path;
	char* token;
	int token_size;
};

char* 
stralloc(struct parser_context* parser,const char* str,size_t size) {
	lua_getfield(parser->L, 1, str);
	if (!lua_isnil(parser->L,2)) {
		char* result = lua_touserdata(parser->L,-1);
		lua_pop(parser->L,1);
		return result;
	}
	lua_pop(parser->L,1);

	lua_pushlstring(parser->L,str,size);
	char* ptr = (char*)lua_tostring(parser->L,-1);
	lua_pushlightuserdata(parser->L,ptr);
	lua_settable(parser->L,1);
	return ptr;
}


/*
protocol hash
 */
void 
pto_hash_set(hash_pto_t *self, char* name, struct protocol* pto) {
	int ok;
	khiter_t k = kh_put(pto, self, strdup(name), &ok);
	assert(ok == 1 || ok == 2);
	kh_value(self, k) = pto;
}

void 
pto_hash_del(hash_pto_t *self, char* name) {
	khiter_t k = kh_get(pto, self, name);
	assert(k != kh_end(self));
	kh_del(pto, self, k);
}

struct protocol* 
pto_hash_find(hash_pto_t *self, char* name) {
	khiter_t k = kh_get(pto, self, name);
	if (k == kh_end(self)) {
		return NULL;
	}
	return kh_value(self, k);
}

void pto_hash_free(hash_pto_t *self) {
	char* name;
	int id;
	pto_hash_foreach(self, name, id, {
		free(name);
	});
	kh_destroy(pto, self);
}

/*
string skiper
 */
static inline int 
eos(struct lexer *l, int n) {
	if (*(l->cursor + n) == 0)
		return 1;
	else
		return 0;
}

static inline void skip_space(struct lexer *l);

static inline void 
next_line(struct lexer *l) {
	char *n = l->cursor;
	while (*n != '\n' && *n)
		n++;
	if (*n == '\n')
		n++;
	l->line++;
	l->cursor = n;
	skip_space(l);
	return;
}

static inline void 
skip_space(struct lexer *l) {
	char *n = l->cursor;
	while (isspace(*n) && *n) {
		if (*n == '\n')
			l->line++;
		n++;
	}

	l->cursor = n;
	if (*n == '#' && *n)
		next_line(l);
	return;
}

static inline void 
skip(struct lexer* l, int size) {
	char *n = l->cursor;
	int index = 0;
	while (!eos(l,0) && index < size) {
		n++;
		index++;
	}
	l->cursor = n;
}

static inline int 
expect(struct lexer* l, char ch) {
	return *l->cursor == ch;
}

static inline int 
expect_space(struct lexer* l) {
	return isspace(*l->cursor);
}

static inline char*
next_token(struct parser_context* parser,struct lexer* l,size_t* size) {
	char ch = *l->cursor;
	int index = 0;
	while(ch != 0 && (ch == '_' || isalpha(ch) || isdigit(ch))) {
		if (index >= parser->token_size) {
			parser->token_size *= 2;
			if (index > parser->token_size)
				parser->token_size = index;
			parser->token = realloc(parser->token,parser->token_size);
		}
		parser->token[index] = ch;
		index++;
		++l->cursor;
		ch = *l->cursor;
	}
	skip_space(l);
	*size = index;
	parser->token[index] = '\0';
	return parser->token;
}

struct protocol* 
create_protocol(struct parser_context* parser, const char* file, const char* name) {
	struct protocol* pto = (struct protocol*)malloc(sizeof(*pto));
	pto->name = stralloc(parser, name, strlen(name));
	pto->file = stralloc(parser, file, strlen(file));
	pto->parent = NULL;
	pto->children = pto_hash_new();
	pto->cap = 4;
	pto->size = 0;
	pto->field = (struct field**)malloc(sizeof(struct field*) * pto->cap);
	memset(pto->field, 0, sizeof(struct field*) * pto->cap);
	return pto;
}

void 
add_field(struct protocol* protocol, struct field* f) {
	if (protocol->size == protocol->cap) {
		int ncap = protocol->cap * 2;
		struct field** nptr = (struct field**)malloc(sizeof(*nptr) * ncap);
		memset(nptr, 0, sizeof(*nptr) * ncap);
		memcpy(nptr, protocol->field, sizeof(*nptr) * protocol->cap);
		free(protocol->field);
		protocol->field = nptr;
		protocol->cap = ncap;
	}
	protocol->field[protocol->size++] = f;
}

struct field* 
create_field(struct protocol* pto,int array,int field_type,struct protocol* reference, char* field_name) {
	struct field* f = (struct field*)malloc(sizeof(*f));
	memset(f, 0, sizeof(*f));
	f->name = field_name;
	f->type = field_type;
	f->protocol = reference;
	f->array = array;

	add_field(pto, f);
	return f;
}


void lexer_execute(struct parser_context* parser,lexer_t* lexer, hash_pto_t* pto_hash);

/*
parser
 */
void
parser_init(struct parser_context* parser, const char* path) {
	parser->L = luaL_newstate();
	lua_settop(parser->L, 0);
	lua_newtable(parser->L);

	parser->pto_ctx = pto_hash_new();
	
	parser->path = stralloc(parser, path, strlen(path));
	parser->token_size = 64;
	parser->token = malloc(parser->token_size);

	parser->offset = 0;
	parser->size = 4;
	parser->importer = malloc(sizeof(*parser->importer)* parser->size);
	memset(parser->importer, 0, sizeof(*parser->importer) * parser->size);
}

void free_pto(struct protocol* proto);

void
parser_release(struct parser_context* parser) {
	char* name;
	struct protocol* pto;
	pto_hash_foreach(parser->pto_ctx, name, pto, {
		free(name);
		free_pto(pto);
	});

	kh_destroy(pto, parser->pto_ctx);

	lua_close(parser->L);
	free(parser->token);
	free(parser->importer);
}

void 
parse_end(struct parser_context* parser, lexer_t* lexer) {
	if (parser->offset == parser->size) {
		int nsize = parser->size;
		struct lexer** nptr = (struct lexer**)malloc(sizeof(*nptr) * nsize);
		memset(nptr, 0, sizeof(*nptr)*nsize);
		memcpy(nptr, parser->importer, parser->size * sizeof(*nptr));
		free(parser->importer);
		parser->size = nsize;
		parser->importer = nptr;
	}
	parser->importer[parser->offset++] = lexer;
}
int 
parser_prepare(struct parser_context* parser, lexer_t* lexer, const char* file) {
	char fullname[MAX_PATH_LENGTH];
	memset(fullname, 0, MAX_PATH_LENGTH);
	snprintf(fullname, MAX_PATH_LENGTH, "%s%s", parser->path, file);

	FILE* F = fopen(fullname, "r");
	if (F == NULL) {
		if (lexer->parent) {
			fprintf(stderr, "%s@line:%d syntax error:no such file:%s\n", lexer->parent->file, lexer->parent->line, file);
		} else {
			fprintf(stderr, "no such file:%s\n", file);
		}
		return -1;
	}
	fseek(F, 0, SEEK_END);
	int len = ftell(F);
	lexer->cursor = (char*)malloc(len + 1);
	memset(lexer->cursor, 0, len + 1);
	rewind(F);
	fread(lexer->cursor, 1, len, F);
	lexer->cursor[len] = 0;
	fclose(F);

	lexer->data = lexer->cursor;
	lexer->line = 1;
	lexer->file = stralloc(parser, file, strlen(file));

	TRY(lexer) {
		skip_space(lexer);
		while (!eos(lexer, 0))
			lexer_execute(parser, lexer, parser->pto_ctx);
		parse_end(parser, lexer);
		return 0;
	}
	return -1;
}

/*
lexer
 */
lexer_t* 
lexer_create(struct parser_context* parser,lexer_t* parent) {
	lexer_t* lexer = malloc(sizeof(*lexer));
	lexer->parent = parent;
	lexer->cursor = lexer->data = lexer->file = NULL;
	lexer->line = 0;
	return lexer;
}

void 
lexer_release(lexer_t* lexer) {
	if (lexer->data != NULL) {
		free(lexer->data);
	}
	free(lexer);
}

int
lexer_has_import(struct parser_context* parser,const char* file) {
	int i;
	for(i=0;i < parser->offset;i++) {
		lexer_t* lexer = parser->importer[i];
		if (strncmp(lexer->file, file, strlen(file)) == 0)
			return 1;
	}
	return 0;
}

struct protocol* 
create_pto(struct parser_context* parser, const char* file, const char* name) {
	struct protocol* pto = (struct protocol*)malloc(sizeof(*pto));
	pto->name = stralloc(parser, name, strlen(name));
	pto->file = stralloc(parser, file, strlen(file));
	pto->parent = NULL;
	pto->children = pto_hash_new();
	pto->cap = 4;
	pto->size = 0;
	pto->field = (struct field**)malloc(sizeof(struct field*) * pto->cap);
	memset(pto->field, 0, sizeof(struct field*) * pto->cap);
	return pto;
}

void
free_pto(struct protocol* pto) {
	char* name;
	struct protocol* childpto;
	pto_hash_foreach(pto->children, name, childpto, {
		free(name);
		free_pto(childpto);
	});

	kh_destroy(pto, pto->children);

	int i;
	for(i=0;i<pto->size;i++) {
		free(pto->field[i]);
	}
	free(pto->field);
	free(pto);
}

void 
import_pto(struct parser_context* parser, lexer_t* parent, char* name) {
	char file[MAX_PATH_LENGTH];
	memset(file, 0, MAX_PATH_LENGTH);
	snprintf(file, MAX_PATH_LENGTH, "%s.protocol", name);

	lexer_t* lexer = lexer_create(parser, parent);
	if (parser_prepare(parser, lexer, file) < 0) {
		THROW(parent);
	}
	lexer_release(lexer);
}

void 
parse_pto(struct parser_context* parser, lexer_t* lexer, struct protocol* parent) {
	hash_pto_t* pto_hash = (parent == NULL) ? parser->pto_ctx:parent->children;

	size_t len = 0;
	char* name = next_token(parser, lexer, &len);

	if (!expect(lexer,'{')) {
		fprintf(stderr, "%s@line:%d syntax error:protocol must start with {\n", lexer->file, lexer->line);
		THROW(lexer);
	}

	struct protocol* opto = pto_hash_find(pto_hash, name);
	if (opto) {
		fprintf(stderr, "%s@line:%d syntax error:protocol name:%s already define in file:%s\n", lexer->file, lexer->line, name, opto->file);
		THROW(lexer);
	}

	struct protocol* pto = create_protocol(parser, lexer->file, name);
	pto->parent = parent;
	pto_hash_set(pto_hash, name, pto);

	//跳过{
	skip(lexer, 1);
	skip_space(lexer);
	while (!expect(lexer, '}')) {
		name = next_token(parser, lexer, &len);
		if (len == 0) {
			fprintf(stderr, "%s@line:%d syntax error\n", lexer->file, lexer->line);
			THROW(lexer);
		}

		if (strncmp(name, "protocol", len) == 0) {
			parse_pto(parser, lexer, pto);
			continue;
		}

		int field_type = TYPE_PROTOCOL;
		int i;
		for (i = 0; i < sizeof(BUILTIN_TYPE) / sizeof(void*); i++) {
			if (strncmp(name, BUILTIN_TYPE[i], len) == 0) {
				field_type = i;
				break;
			}
		}

		int isarray = 0;
		if (strncmp(lexer->cursor, "[]", 2) == 0) {
			isarray = 1;
			skip(lexer, 2);
			if (!expect_space(lexer)) {
				fprintf(stderr, "%s@line:%d syntax error,expect space\n", lexer->file, lexer->line);
				THROW(lexer);
			}
			skip_space(lexer);
		}

		struct protocol* ref_pto = NULL;
		//不是内置类型，必然是protocol
		if (field_type == TYPE_PROTOCOL) {
			struct protocol* cursor = pto;
			while (cursor) {
				ref_pto = pto_hash_find(cursor->children, name);
				if (ref_pto != NULL)
					break;
				cursor = cursor->parent;
			}
			if (ref_pto == NULL) {
				ref_pto = pto_hash_find(parser->pto_ctx, name);
				if (!ref_pto) {
					fprintf(stderr, "%s@line:%d syntax error:unknown type:%s\n", lexer->file, lexer->line, name);
					THROW(lexer);
				}
			}
		}
		
		name = next_token(parser, lexer, &len);
		if (len == 0) {
			fprintf(stderr, "%s@line:%d syntax error\n", lexer->file, lexer->line);
			THROW(lexer);
		}

		create_field(pto,isarray,field_type,ref_pto,stralloc(parser, name, len));
	}
	skip(lexer, 1);
	skip_space(lexer);
}

void 
lexer_execute(struct parser_context* parser,lexer_t* lexer, hash_pto_t* pto_hash) {
	size_t len = 0;
	char* name = next_token(parser, lexer, &len);
	if (len == 0) {
		fprintf(stderr, "%s@line:%d syntax error\n", lexer->file, lexer->line);
		THROW(lexer);
	}

	if (strncmp(name, "protocol", len) == 0) {
		return parse_pto(parser, lexer, NULL);
	
	} else if (strncmp(name, "import", len) == 0) {
		skip_space(lexer);

		if (!expect(lexer, '\"')) {
			fprintf(stderr, "%s@line:%d syntax error:import format must start with \"\n", lexer->file, lexer->line);
			THROW(lexer);
		}

		skip(lexer, 1);
		name = next_token(parser, lexer, &len);
		if (len == 0) {
			fprintf(stderr, "%s@line:%d syntax error:import pto name empty\n", lexer->file, lexer->line);
			THROW(lexer);
		}

		if (!expect(lexer, '\"')) {
			fprintf(stderr, "%s@line:%d syntax error:import error\n", lexer->file, lexer->line);
			THROW(lexer);
		}

		skip(lexer, 1);

		if (lexer_has_import(parser, name) == 0)
			import_pto(parser, lexer, name);

		skip_space(lexer);
		return;
	}
	fprintf(stderr, "%s@line:%d syntax error:unknown %s\n", lexer->file, lexer->line, name);
	THROW(lexer);
}

void 
pto_export(lua_State* L, struct protocol* pto, int index, int depth) {
	depth++;

	if (depth >= MAX_DEPTH) {
		luaL_error(L, "pto export too depth");
	}

	lua_newtable(L);

		lua_newtable(L);
		char* name;
		struct protocol* child_pto;
		pto_hash_foreach(pto->children, name, child_pto, {
			pto_export(L, child_pto, lua_gettop(L), depth);
			lua_setfield(L, -2, name);
		});

	lua_setfield(L,-2,"children");

	lua_pushstring(L, pto->file);
	lua_setfield(L, -2, "file");

	lua_pushstring(L, pto->name);
	lua_setfield(L, -2, "name");

	lua_newtable(L);

	int i;
	for (i = 0; i < pto->size; ++i) {

		struct field* f = pto->field[i];
		
		lua_newtable(L);

		lua_pushinteger(L,f->type);
		lua_setfield(L,-2,"type");

		lua_pushboolean(L,f->array);
		lua_setfield(L,-2,"array");

		if (f->type == TYPE_PROTOCOL) {
			lua_pushstring(L,f->protocol->name);
		} else {
			lua_pushstring(L,BUILTIN_TYPE[f->type]);
		}
		lua_setfield(L,-2,"type_name");

		lua_pushstring(L,f->name);
		lua_setfield(L,-2,"name");

		lua_pushinteger(L,i);
		lua_setfield(L,-2,"index");

		lua_setfield(L,-2,f->name);
	}

	lua_setfield(L,-2,"fields");
}

static int 
_execute(lua_State* L) {
	const char* path = luaL_checkstring(L,1);
	const char* file = luaL_checkstring(L,2);

	struct parser_context parser;
	parser_init(&parser, path);

	lexer_t* lexer = lexer_create(&parser, NULL);

	if (parser_prepare(&parser, lexer, file) < 0) {
		parser_release(&parser);
		lexer_release(lexer);
		luaL_error(L,"parse error");
	}

	lua_pop(L,2);
	int depth = 0;
	luaL_checkstack(L, MAX_DEPTH*2 + 8, NULL);
	
	lua_newtable(L);

	char* name;
	struct protocol* pto;
	pto_hash_foreach(parser.pto_ctx, name, pto, {
		pto_export(L, pto, lua_gettop(L), depth);
		lua_setfield(L, -2, name);
	});

	lexer_release(lexer);
	parser_release(&parser);
	return 1;
}

int
luaopen_ptoparser(lua_State* L){
	luaL_Reg l[] = {
		{ "execute", _execute },
		{ NULL, NULL },
	};
	luaL_checkversion(L);
	luaL_newlib(L,l);
	return 1;
}