#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <stdint.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "aoi/tower/tower-aoi.h"

typedef struct laoi_context {
	struct aoi* aoi;
	int scene_id;
} laoi_context_t;

struct callback_param {
	lua_State* L;
	int index;
	int stack;
};

void 
entity_enter_cb(int self, int other, void* ud) {
	struct callback_param* param = ud;
	lua_pushinteger(param->L,other);
	lua_rawseti(param->L,param->stack,param->index++);
}

void 
entity_leave_cb(int self, int other, void* ud) {
	struct callback_param* param = ud;
	lua_pushinteger(param->L,other);
	lua_rawseti(param->L,param->stack,param->index++);
}

void 
trigger_enter_cb(int self, int other, void* ud) {
	struct callback_param* param = ud;
	lua_pushinteger(param->L,other);
	lua_rawseti(param->L,param->stack,param->index++);
}

void 
trigger_leave_cb(int self, int other, void* ud) {
	struct callback_param* param = ud;
	lua_pushinteger(param->L,other);
	lua_rawseti(param->L,param->stack,param->index++);
}

static int
lcreate_entity(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);

	int uid = luaL_checkinteger(L, 2);
	uint8_t mask = luaL_checkinteger(L, 3);
	float x = luaL_checknumber(L, 4);
	float z = luaL_checknumber(L, 5);

	lua_newtable(L);
	struct callback_param param;
	param.L = L;
	param.index = 1;
	param.stack = lua_gettop(L);
	
	int id = create_entity(laoi->aoi, uid, mask, x, z, entity_enter_cb, &param);

	lua_pushinteger(L, id);
	lua_insert(L, param.stack);
	
	return 2;
}

static int
lremove_entity(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	int id = luaL_checkinteger(L, 2);

	lua_newtable(L);
	struct callback_param param;
	param.L = L;
	param.index = 1;
	param.stack = lua_gettop(L);
	remove_entity(laoi->aoi, id, entity_leave_cb, &param);
	return 1;
}

static int
lmove_entity(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	int id = luaL_checkinteger(L, 2);
	float nx = luaL_checknumber(L, 3);
	float nz = luaL_checknumber(L, 4);

	lua_newtable(L);
	struct callback_param enter_param;
	enter_param.L = L;
	enter_param.index = 1;
	enter_param.stack = lua_gettop(L);

	lua_newtable(L);
	struct callback_param leave_param;
	leave_param.L = L;
	leave_param.index = 1;
	leave_param.stack = lua_gettop(L);

	move_entity(laoi->aoi, id, nx, nz, entity_enter_cb, &enter_param, entity_leave_cb, &leave_param);

	return 2;
}

static int
lcreate_trigger(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	int uid = luaL_checkinteger(L, 2);
	uint8_t mask = luaL_checkinteger(L, 3);
	float x = luaL_checknumber(L, 4);
	float z = luaL_checknumber(L, 5);
	int range = luaL_checkinteger(L, 6);

	lua_newtable(L);
	struct callback_param enter_param;
	enter_param.L = L;
	enter_param.index = 1;
	enter_param.stack = lua_gettop(L);

	int id = create_trigger(laoi->aoi, uid, mask, x, z, range, trigger_enter_cb, &enter_param);

	lua_pushinteger(L, id);

	lua_insert(L, enter_param.stack);
	
	return 2;
}

static int
lremove_trigger(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	int id = luaL_checkinteger(L, 2);
	remove_trigger(laoi->aoi, id);
	return 0;
}

static int
lmove_trigger(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	int id = luaL_checkinteger(L, 2);
	float nx = luaL_checknumber(L, 3);
	float nz = luaL_checknumber(L, 4);

	lua_newtable(L);
	struct callback_param enter_param;
	enter_param.L = L;
	enter_param.index = 1;
	enter_param.stack = lua_gettop(L);

	lua_newtable(L);
	struct callback_param leave_param;
	leave_param.L = L;
	leave_param.index = 1;
	leave_param.stack = lua_gettop(L);

	move_trigger(laoi->aoi, id, nx, nz, trigger_enter_cb, &enter_param, trigger_leave_cb, &leave_param);

	return 2;
}

void 
witness_func(int other, void* ud) {
	struct callback_param* param = ud;
	lua_pushinteger(param->L,other);
	lua_rawseti(param->L,param->stack,param->index++);
}

static int
lget_witness(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	int id = luaL_checkinteger(L, 2);

	lua_newtable(L);
	struct callback_param param;
	param.L = L;
	param.index = 1;
	param.stack = lua_gettop(L);

	get_witness(laoi->aoi, id, witness_func, &param);
	return 1;
}

void 
visible_func(int other, void* ud) {
	struct callback_param* param = ud;
	lua_pushinteger(param->L,other);
	lua_rawseti(param->L,param->stack,param->index++);
}

static int
lget_visible(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	int id = luaL_checkinteger(L, 2);

	lua_newtable(L);
	struct callback_param param;
	param.L = L;
	param.index = 1;
	param.stack = lua_gettop(L);

	get_visible(laoi->aoi, id, visible_func, &param);
	return 1;
}

static int
lrelease(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	release_aoi(laoi->aoi);
	return 0;
}


static int
lcreate(lua_State* L) {
	int scene = luaL_checkinteger(L, 1);
	int width = luaL_checkinteger(L, 2);
	int height = luaL_checkinteger(L, 3);
	int cell = luaL_checkinteger(L, 4);

	laoi_context_t* laoi = (laoi_context_t*)lua_newuserdata(L, sizeof(laoi_context_t));
	memset(laoi, 0, sizeof(*laoi));

	laoi->scene_id = scene;
	laoi->aoi = create_aoi(width, height, cell);

	lua_newtable(L);

	lua_pushcfunction(L, lrelease);
	lua_setfield(L, -2, "__gc");

	luaL_Reg l[] = {
		{ "create_entity", lcreate_entity },
		{ "remove_entity", lremove_entity },
		{ "move_entity", lmove_entity },
		{ "create_trigger", lcreate_trigger },
		{ "remove_trigger", lremove_trigger },
		{ "move_trigger", lmove_trigger },
		{ "get_witness", lget_witness },
		{ "get_visible", lget_visible },
		{ NULL, NULL },
	};
	luaL_newlib(L,l);

	lua_setfield(L, -2, "__index");

	lua_setmetatable(L, -2);

	return 1;
}

int
luaopen_toweraoi_core(lua_State* L){
	luaL_Reg l[] = {
		{ "create", lcreate },
		{ NULL, NULL },
	};
	luaL_newlib(L,l);
	return 1;
}
