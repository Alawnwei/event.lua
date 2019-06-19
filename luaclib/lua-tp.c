#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h> 
#include <errno.h>
#include <semaphore.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "common/thread_pool.h"
#include "socket/socket_pipe.h"
#include "socket/socket_util.h"


typedef struct thread_ctx {
	int index;
	int fd;
	
	int ref;
	int callback;
	lua_State* L;

	struct pipe_message* first;
	struct pipe_message* last;
} thread_ctx_t;

typedef struct lthread_pool {
	struct thread_pool* core;
	int fd;
	char* boot_param;
	sem_t sem;
	int count;
	thread_ctx_t** slots;
} lthread_pool_t;

static int ltp_send_pipe(lua_State* L);
int ltp_dispatch(lua_State* L);
int load_helper(lua_State *L);

static inline void
tp_do_send_pipe(thread_ctx_t* ctx) {
	while(ctx->first) {
		struct pipe_message* message = ctx->first;
		struct pipe_message* next_message = message->next;
		if (socket_pipe_write(ctx->fd, (void*)&message, sizeof(void*)) < 0) {
			return;
		}
		ctx->first = next_message;
	}
	ctx->first = ctx->last = NULL;
}

static void
tp_consumer(struct thread_pool* pool, int index, int session, void* data, size_t size, void* ud) {
	lthread_pool_t* ltp = ud;

	thread_ctx_t* ctx = ltp->slots[index];

	lua_rawgeti(ctx->L, LUA_REGISTRYINDEX, ctx->callback);

	lua_pushinteger(ctx->L, session);
	if (data) {
		lua_pushlightuserdata(ctx->L, data);
		lua_pushinteger(ctx->L, size);
		lua_pcall(ctx->L, 3, 0, 0);
		free(data);
	} else {
		lua_pcall(ctx->L, 1, 0, 0);
	}

	tp_do_send_pipe(ctx);
}

static void 
tp_wakeup(struct thread_pool* pool, int index, void* ud) {
	lthread_pool_t* ltp = ud;

	thread_ctx_t* ctx = ltp->slots[index];

	tp_do_send_pipe(ctx);
}

static void 
tp_init(struct thread_pool* pool, int index, void* ud) {
	lthread_pool_t* ltp = ud;

	lua_State* L = luaL_newstate();
	luaL_openlibs(L);
	luaL_requiref(L,"helper",load_helper,0);
	
	luaL_newmetatable(L, "meta_tp");
	const luaL_Reg meta_tp[] = {
		{ "send", ltp_send_pipe },
		{ "dispatch", ltp_dispatch },
		{ NULL, NULL },
	};
	luaL_newlib(L,meta_tp);
	lua_setfield(L, -2, "__index");
	lua_pop(L,1);

	lua_settop(L, 0);

	if (luaL_loadfile(L,"lualib/bootstrap.lua") != LUA_OK)  {
		fprintf(stderr,"%s\n",lua_tostring(L,-1));
		exit(1);
	}

	lua_pushinteger(L, 3);
	
	char* boot = strdup(ltp->boot_param);
	char* boot_begin = boot;
	char *token;
	for(token = strsep(&boot, "@"); token != NULL; token = strsep(&boot, "@")) {
		lua_pushstring(L, token);
	}
	free(boot_begin);

	thread_ctx_t* ctx = lua_newuserdata(L,sizeof(*ctx));
	memset(ctx,0,sizeof(*ctx));

	ctx->index = index;
	ctx->fd = ltp->fd;
	ctx->L = L;
	ctx->callback = 0;

	luaL_newmetatable(L,"meta_tp");
 	lua_setmetatable(L, -2);
	lua_pushvalue(L, -1);

	ctx->ref = luaL_ref(L, LUA_REGISTRYINDEX);
	
	if (lua_pcall(L,lua_gettop(L)-1,0,0) != LUA_OK)  {
		fprintf(stderr,"%s\n",lua_tostring(L,-1));
		exit(1);
	}

	assert(ctx->callback != 0);

	ltp->slots[index] = ctx;

	sem_post(&ltp->sem);
}

static void 
tp_fina(struct thread_pool* pool, int index, void* ud) {
	lthread_pool_t* ltp = ud;
	thread_ctx_t* ctx = ltp->slots[index];
	lua_close(ctx->L);
}

static int
ltp_push(lua_State* L) {
	lthread_pool_t* ltp = lua_touserdata(L, 1);
	int session = lua_tointeger(L, 2);

	void* data = NULL;
	size_t size = 0;

	switch(lua_type(L, 3)) {
		case LUA_TSTRING: {
			const char* str = lua_tolstring(L, 3, &size);
			data = malloc(size);
			memcpy(data,str,size);
			break;
		}
		case LUA_TLIGHTUSERDATA:{
			data = lua_touserdata(L, 3);
			size = lua_tointeger(L, 4);
			break;
		}
		default: {
			luaL_error(L, "unkown type:%s", lua_typename(L, lua_type(L, 3)));
		}
	}

	thread_pool_push_task(ltp->core, tp_consumer, session, data, size);
	return 0;
}

static int
ltp_release(lua_State* L) {
	lthread_pool_t* ltp = lua_touserdata(L, 1);
	thread_pool_close(ltp->core);
	
	int i;
	for(i = 0;i < ltp->count;i++) {
		pthread_join(thread_pool_pid(ltp->core, i), NULL);
	}

	thread_pool_release(ltp->core);
	sem_destroy(&ltp->sem);
	free(ltp->slots);
	free(ltp->boot_param);

	return 0;
}

static int
lcreate(lua_State* L) {
	int fd = luaL_checkinteger(L, 1);
	int count = luaL_checkinteger(L, 2);
	const char* boot_param = luaL_checkstring(L, 3);

	lthread_pool_t* ltp = lua_newuserdata(L,sizeof(*ltp));

	if (luaL_newmetatable(L, "meta_tp")) {
        const luaL_Reg meta[] = {
            { "push", ltp_push },
			{ NULL, NULL },
        };
        luaL_newlib(L, meta);
        lua_setfield(L, -2, "__index");

        lua_pushcfunction(L, ltp_release);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);

	ltp->core = thread_pool_create(tp_init, tp_fina, tp_wakeup, ltp);
	ltp->fd = fd;
	ltp->boot_param = strdup(boot_param);
	ltp->count = count;
	ltp->slots = malloc(ltp->count * sizeof(*ltp->slots));
	memset(ltp->slots, 0, ltp->count * sizeof(*ltp->slots));

	sem_init(&ltp->sem, 0, -ltp->count);

	thread_pool_start(ltp->core, ltp->count);

	sem_wait(&ltp->sem);

	return 1;
}


static int
ltp_send_pipe(lua_State* L) {
	thread_ctx_t* ctx = lua_touserdata(L, 1);

	int session = lua_tointeger(L, 2);

	void* data = NULL;
	size_t size = 0;

	switch(lua_type(L,3)) {
		case LUA_TSTRING: {
			const char* str = lua_tolstring(L, 3, &size);
			data = malloc(size);
			memcpy(data,str,size);
			break;
		}
		case LUA_TLIGHTUSERDATA:{
			data = lua_touserdata(L, 3);
			size = lua_tointeger(L, 4);
			break;
		}
		default:
			luaL_error(L,"unkown type:%s",lua_typename(L,lua_type(L,3)));
	}

	struct pipe_message* message = malloc(sizeof(*message));
	message->next = NULL;
	message->source = 0;
	message->session = session;
	message->data = data;
	message->size = size;
	if (ctx->first == NULL) {
		ctx->first = ctx->last = message;
	} else {
		ctx->last->next = message;
		ctx->last = message;
	}
	return 0;

}

int
ltp_dispatch(lua_State* L) {
	thread_ctx_t* ctx = lua_touserdata(L, 1);
	luaL_checktype(L,2,LUA_TFUNCTION);
	ctx->callback = luaL_ref(L,LUA_REGISTRYINDEX);
	return 0;
}

int
luaopen_tp_core(lua_State* L) {
	const luaL_Reg l[] = {
		{ "create", lcreate },
		{ NULL, NULL },
	};
	luaL_newlib(L, l);
	return 1;
}