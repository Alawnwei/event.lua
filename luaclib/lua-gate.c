#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <math.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "lstate.h"

#include "socket/gate.h"

struct lgate_ctx {
	gate_t* gate;
	int alive;
	lua_State* L;
	int ref;
	int accept_ref;
	int close_ref;
	int data_ref;
};

static void 
laccept(void* ud, uint32_t id, const char* addr) {
	struct lgate_ctx* lgate = ud;
	lua_rawgeti(lgate->L, LUA_REGISTRYINDEX, lgate->accept_ref);
	lua_pushinteger(lgate->L, id);
	lua_pushstring(lgate->L, addr);
	lua_pcall(lgate->L, 2, 0, 0);
}

static void 
lclose(void* ud, uint32_t id, const char* reason) {
	struct lgate_ctx* lgate = ud;
	lua_rawgeti(lgate->L, LUA_REGISTRYINDEX, lgate->close_ref);
	lua_pushinteger(lgate->L, id);
	lua_pushstring(lgate->L, reason);
	lua_pcall(lgate->L, 2, 0, 0);
}

static void
ldata(void* ud,uint32_t client_id,int message_id,void* data,size_t size) {
	struct lgate_ctx* lgate = ud;
	lua_rawgeti(lgate->L, LUA_REGISTRYINDEX, lgate->data_ref);
	lua_pushinteger(lgate->L, client_id);
	lua_pushinteger(lgate->L, message_id);
	lua_pushlightuserdata(lgate->L, data);
	lua_pushinteger(lgate->L, size);
	lua_pcall(lgate->L, 4, 0, 0);
}

static int
lgate_start(lua_State* L){
	struct lgate_ctx* lgate = lua_touserdata(L, 1);
	const char* ip = luaL_checkstring(L, 2);
	int port = luaL_checkinteger(L, 3);
	if (lgate->accept_ref == 0) {
		luaL_error(L,"gate start error,should set accept callback first");
	}
	if (lgate->close_ref == 0) {
		luaL_error(L,"gate start error,should set close callback first");
	}
	if (lgate->data_ref == 0) {
		luaL_error(L,"gate start error,should set data callback first");
	}
	gate_stop(lgate->gate);
	int real_port = gate_start(lgate->gate,ip,port);
	if (real_port == -1) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, strerror(errno));
		return 2;
	}
	lua_pushinteger(L, real_port);
	return 1;
}

static int
lgate_stop(lua_State* L) {
	struct lgate_ctx* lgate = lua_touserdata(L, 1);
	if (gate_stop(lgate->gate) < 0) {
		lua_pushboolean(L, false);
	}
	lua_pushboolean(L, true);
	return 1;
}

static int
lgate_close(lua_State* L) {
	struct lgate_ctx* lgate = lua_touserdata(L, 1);
	int client_id = luaL_checkinteger(L, 2);
	int grace = luaL_optinteger(L, 3, 0);
	if (gate_close(lgate->gate,client_id,grace) < 0) {
		luaL_error(L,"gate close client failed,no such client:%d",client_id);
	}
	return 0;
}

static int
lgate_send(lua_State* L) {
	struct lgate_ctx* lgate = lua_touserdata(L, 1);
	int client_id = luaL_checkinteger(L, 2);
	int message_id = luaL_checkinteger(L, 3);

	size_t size;
  	void* data = NULL;
  	int vt = lua_type(L, 4);
    switch(vt) {
        case LUA_TSTRING: {
            data = (void*)lua_tolstring(L, 4, &size);
            break;
        }
        case LUA_TLIGHTUSERDATA:{
            data = lua_touserdata(L, 4);
            size = lua_tointeger(L, 5);
            break;
        }
        default:
            luaL_error(L,"lgate send error:unkown type:%s",lua_typename(L,vt));
    }

    if (size == 0) {
    	luaL_error(L,"lgate send error:size is zero");
    }

    int status = gate_send(lgate->gate,client_id,message_id,data,size);
    if (vt == LUA_TLIGHTUSERDATA) {
    	free(data);
    }
    if (status < 0) {
    	luaL_error(L,"lgate send error:no such client:%d",client_id);
    }
    return 0;
}

static int
lgate_callback(lua_State* L) {
	struct lgate_ctx* lgate = lua_touserdata(L, 1);
	luaL_checktype(L, 2, LUA_TFUNCTION);
	luaL_checktype(L, 3, LUA_TFUNCTION);
	luaL_checktype(L, 4, LUA_TFUNCTION);

	lgate->data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	lgate->close_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	lgate->accept_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	gate_callback(lgate->gate,laccept,lclose,ldata);
	return 0;
}

int
lgate_release(lua_State* L) {
	struct lgate_ctx* lgate = lua_touserdata(L, 1);
	if (lgate->alive == 0) {
		luaL_error(L, "gate:%p already release", lgate);
	}

	lgate->alive = 0;
	gate_release(lgate->gate);

	luaL_unref(L, LUA_REGISTRYINDEX, lgate->ref);

	if (lgate->accept_ref == 0) {
		luaL_unref(L, LUA_REGISTRYINDEX, lgate->accept_ref);
	}
	if (lgate->close_ref == 0) {
		luaL_unref(L, LUA_REGISTRYINDEX, lgate->close_ref);
	}
	if (lgate->data_ref == 0) {
		luaL_unref(L, LUA_REGISTRYINDEX, lgate->data_ref);
	}
	return 0;
}

int
lgate_create(lua_State* L, struct ev_loop_ctx* loop_ctx, uint32_t max_client, uint32_t max_freq, uint32_t timeout) {
	struct lgate_ctx* lgate = lua_newuserdata(L, sizeof(*lgate));
	memset(lgate, 0, sizeof(*lgate));

	lgate->gate = gate_create(loop_ctx, max_client, max_freq, timeout, lgate);
	lgate->alive = 1;    
	lgate->L = G(L)->mainthread;

	if (luaL_newmetatable(L, "meta_gate")) {
        const luaL_Reg meta_gate[] = {
            { "start", lgate_start },
            { "stop", lgate_stop },
            { "close", lgate_close },
            { "send", lgate_send },
            { "release", lgate_release },
            { "set_callback", lgate_callback },
            { NULL, NULL },
        };
        luaL_newlib(L,meta_gate);
        lua_setfield(L, -2, "__index");
    }
    lua_setmetatable(L, -2);

    lua_pushvalue(L, -1);
    lgate->ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 1;
}
