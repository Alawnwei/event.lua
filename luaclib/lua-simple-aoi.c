#include <lua.h>
#include <lauxlib.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "aoi/simple/simple-aoi.h"


typedef struct laoi {
	struct aoi_context* aoi;
	int scene_id;
} laoi_t;


typedef struct aoi_param {
	lua_State *L;
	int self;
	int stack_enter_self;
	int index_enter_self;
	int stack_enter_other;
	int index_enter_other;
	int stack_leave_self;
	int index_leave_self;
	int stack_leave_other;
	int index_leave_other;
} param_t;

void on_enter(int self, int other, void* ud) {
	param_t* param = ud;
	if (param->self == self) {
		lua_pushinteger(param->L, other);
		lua_rawseti(param->L, param->stack_enter_self, ++param->index_enter_self);
	} else {
		lua_pushinteger(param->L, self);
		lua_rawseti(param->L, param->stack_enter_other, ++param->index_enter_other);
	}
}

void on_leave(int self, int other, void* ud) {
	param_t* param = ud;
	if (param->self == self) {
		lua_pushinteger(param->L, other);
		lua_rawseti(param->L, param->stack_leave_self, ++param->index_leave_self);
	} else {
		lua_pushinteger(param->L, self);
		lua_rawseti(param->L, param->stack_leave_other, ++param->index_leave_other);
	}
}

int
laoi_new(lua_State *L) {
	int scene_id = luaL_checkinteger(L, 1);
	int scene_width = luaL_checkinteger(L, 2);
	int scene_height = luaL_checkinteger(L, 3);
	int tile_cell = luaL_optinteger(L, 4, 5);
	int range = luaL_optinteger(L, 5, 5);

	laoi_t* laoi = lua_newuserdata(L, sizeof(*laoi));
	memset(laoi, 0, sizeof(*laoi));
	laoi->aoi = aoi_create(scene_width, scene_height, tile_cell, range, 64, on_enter, on_leave);
	laoi->scene_id = scene_id;

	luaL_newmetatable(L, "meta_fast_aoi");
	lua_setmetatable(L, -2);
	return 1;
}

int
laoi_release(lua_State* L) {
	laoi_t* laoi = lua_touserdata(L, 1);
	aoi_release(laoi->aoi);
	return 0;
}

int
laoi_enter(lua_State *L) {
	laoi_t* laoi = lua_touserdata(L, 1);
	int uid = luaL_checkinteger(L, 2);
	float x = luaL_checknumber(L, 3);
	float z = luaL_checknumber(L, 4);
	int layer = luaL_checkinteger(L, 5);

	assert(lua_gettop(L) == 5);

	lua_newtable(L);
	lua_newtable(L);

	param_t param;
	memset(&param, 0, sizeof(param_t));
	param.L = L;
	param.self = uid;
	param.stack_enter_self = 6;
	param.stack_enter_other = 7;

	int status = aoi_enter(laoi->aoi, uid, x, z, layer, &param);
	if (status < 0) {
		luaL_error(L, "aoi enter error:%s", aoi_error(status));
	}

	lua_pushinteger(L, status);
	lua_insert(L, 6);
	return 3;
}

int
laoi_leave(lua_State *L) {
	laoi_t* laoi = lua_touserdata(L, 1);
	int id = lua_tointeger(L, 2);

	int uid = aoi_uid(laoi->aoi, id);
	if (uid < 0) {
		luaL_error(L, "aoi leave error:%s", aoi_error(uid));
	}

	lua_settop(L, 2);

	lua_newtable(L);

	param_t param;
	memset(&param, 0, sizeof(param_t));

	param.L = L;
	param.self = uid;
	param.stack_leave_other = 3;

	int status = aoi_leave(laoi->aoi, id, &param);
	if (status != 0) {
		luaL_error(L, "aoi leave error:%s", aoi_error(status));
	}
	return 1;
}

int
laoi_update(lua_State *L) {
	laoi_t* laoi = lua_touserdata(L, 1);
	int id = lua_tointeger(L, 2);
	float x = luaL_checknumber(L, 3);
	float z = luaL_checknumber(L, 4);

	int uid = aoi_uid(laoi->aoi, id);
	if (uid < 0) {
		luaL_error(L, "aoi update error:%s", aoi_error(uid));
	}

	lua_settop(L, 4);

	lua_newtable(L);
	lua_newtable(L);
	lua_newtable(L);
	lua_newtable(L);

	param_t param;
	memset(&param, 0, sizeof(param_t));

	param.L = L;
	param.self = uid;
	param.stack_enter_self = 5;
	param.stack_enter_other = 6;
	param.stack_leave_self = 7;
	param.stack_leave_other = 8;

	int status = aoi_update(laoi->aoi, id, x, z, &param);
	if (status != 0) {
		luaL_error(L, "aoi update error:%s", aoi_error(status));
	}

	return 4;
}

int
lwitness_list(lua_State *L) {

	return 1;
}

int
lvisible_list(lua_State *L) {

	return 1;
}

int
luaopen_simpleaoi_core(lua_State *L) {
	luaL_checkversion(L);

	luaL_newmetatable(L, "meta_fast_aoi");
	const luaL_Reg meta[] = {
		{ "enter", laoi_enter },
		{ "leave", laoi_leave },
		{ "update", laoi_update },
		{ "witness_list", lwitness_list },
		{ "visible_list", lvisible_list },
		{ NULL, NULL },
	};
	luaL_newlib(L, meta);
	lua_setfield(L, -2, "__index");

	lua_pushcfunction(L, laoi_release);
	lua_setfield(L, -2, "__gc");
	lua_pop(L, 1);


	luaL_Reg l[] = {
		{ "new", laoi_new },
		{ NULL, NULL },
	};

	lua_createtable(L, 0, (sizeof(l)) / sizeof(luaL_Reg) - 1);
	luaL_setfuncs(L, l, 0);
	return 1;
}
