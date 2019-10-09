#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <stdint.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "aoi/link/link-aoi.h"


#define CELL(object,x) x / object->cell;

typedef struct laoi_context {
	struct aoi_context* aoi;
	int scene_id;
	int cell;
} laoi_context_t;

typedef struct laoi_object {
	struct aoi_context* aoi;
	struct aoi_object* object;
	int cell;
	int uid;
} laoi_object_t;

typedef struct callback_param {
	lua_State* L;
	int self;
	int enter_index;
	int enter_stack;
	int leave_index;
	int leave_stack;
} param_t;

void
entity_enter_cb(int self, int other, void* ud) {
	param_t* param = ud;
	if (other == param->self) {
		return;
	}
	lua_pushinteger(param->L, other);
	lua_rawseti(param->L, param->enter_stack, param->enter_index++);
}

void
entity_leave_cb(int self, int other, void* ud) {
	param_t* param = ud;
	if (other == param->self) {
		return;
	}
	lua_pushinteger(param->L, other);
	lua_rawseti(param->L, param->leave_stack, param->leave_index++);
}

void
trigger_enter_cb(int self, int other, void* ud) {
	param_t* param = ud;
	if (other == param->self) {
		return;
	}
	lua_pushinteger(param->L, other);
	lua_rawseti(param->L, param->enter_stack, param->enter_index++);
}

void
trigger_leave_cb(int self, int other, void* ud) {
	param_t* param = ud;
	if (other == param->self) {
		return;
	}
	lua_pushinteger(param->L, other);
	lua_rawseti(param->L, param->leave_stack, param->leave_index++);
}

static int
lcreate_entity(lua_State* L) {
	laoi_object_t* lobject = (laoi_object_t*)lua_touserdata(L, 1);
	float fx = luaL_checknumber(L, 2);
	float fz = luaL_checknumber(L, 3);

	int ix = CELL(lobject, fx);
	int iz = CELL(lobject, fz);

	lua_newtable(L);
	param_t param;
	param.self = lobject->uid;
	param.L = L;
	param.enter_index = 1;
	param.enter_stack = lua_gettop(L);

	create_entity(lobject->aoi, lobject->object, ix, iz, entity_enter_cb, entity_leave_cb, &param);

	return 1;
}

static int
lremove_entity(lua_State* L) {
	laoi_object_t* lobject = (laoi_object_t*)lua_touserdata(L, 1);

	lua_newtable(L);
	param_t param;
	param.self = lobject->uid;
	param.L = L;
	param.leave_index = 1;
	param.leave_stack = lua_gettop(L);

	delete_entity(lobject->aoi, lobject->object, 1, &param);
	return 1;
}

static int
lmove_entity(lua_State* L) {
	laoi_object_t* lobject = (laoi_object_t*)lua_touserdata(L, 1);
	float fx = luaL_checknumber(L, 2);
	float fz = luaL_checknumber(L, 3);

	int ix = CELL(lobject, fx);
	int iz = CELL(lobject, fz);

	param_t param;
	param.self = lobject->uid;
	param.L = L;

	lua_newtable(L);
	param.enter_index = 1;
	param.enter_stack = lua_gettop(L);

	lua_newtable(L);
	param.leave_index = 1;
	param.leave_stack = lua_gettop(L);

	move_entity(lobject->aoi, lobject->object, ix, iz, &param);
	return 2;
}

static int
lcreate_trigger(lua_State* L) {
	laoi_object_t* lobject = (laoi_object_t*)lua_touserdata(L, 1);
	float fx = luaL_checknumber(L, 2);
	float fz = luaL_checknumber(L, 3);

	int ix = CELL(lobject, fx);
	int iz = CELL(lobject, fz);

	int range = luaL_checkinteger(L, 4);

	lua_newtable(L);
	param_t param;
	param.self = lobject->uid;
	param.L = L;
	param.enter_index = 1;
	param.enter_stack = lua_gettop(L);

	create_trigger(lobject->aoi, lobject->object, ix, iz, range, trigger_enter_cb, trigger_leave_cb, &param);
	return 1;
}

static int
lremove_trigger(lua_State* L) {
	laoi_object_t* lobject = (laoi_object_t*)lua_touserdata(L, 1);
	delete_trigger(lobject->aoi, lobject->object);
	return 0;
}

static int
lmove_trigger(lua_State* L) {
	laoi_object_t* lobject = (laoi_object_t*)lua_touserdata(L, 1);
	float fx = luaL_checknumber(L, 2);
	float fz = luaL_checknumber(L, 3);

	int ix = CELL(lobject, fx);
	int iz = CELL(lobject, fz);

	param_t param;
	param.L = L;
	param.self = lobject->uid;

	lua_newtable(L);
	param.enter_index = 1;
	param.enter_stack = lua_gettop(L);

	lua_newtable(L);
	param.leave_index = 1;
	param.leave_stack = lua_gettop(L);

	move_trigger(lobject->aoi, lobject->object, ix, iz, &param);
	return 2;
}

static int
lrelease_object(lua_State* L) {
	laoi_object_t* lobject = (laoi_object_t*)lua_touserdata(L, 1);
	release_aoi_object(lobject->aoi, lobject->object);
	return 0;
}

static int
lcreate_object(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	int uid = luaL_checkinteger(L, 2);

	laoi_object_t* lobject = (laoi_object_t*)lua_newuserdata(L, sizeof(laoi_object_t));
	memset(lobject, 0, sizeof(*lobject));
	lobject->object = create_aoi_object(laoi->aoi, uid);
	lobject->uid = uid;
	lobject->aoi = laoi->aoi;
	lobject->cell = laoi->cell;

	if (luaL_newmetatable(L, "meta_link_aoi_object")) {
		const luaL_Reg meta[] = {
			{ "create_entity", lcreate_entity },
			{ "remove_entity", lremove_entity },
			{ "move_entity", lmove_entity },
			{ "create_trigger", lcreate_trigger },
			{ "remove_trigger", lremove_trigger },
			{ "move_trigger", lmove_trigger },
			{ NULL, NULL },
		};
		luaL_newlib(L, meta);
		lua_setfield(L, -2, "__index");

		lua_pushcfunction(L, lrelease_object);
		lua_setfield(L, -2, "__gc");
	}

	lua_setmetatable(L, -2);

	return 1;
}

static int
lrelease(lua_State* L) {
	laoi_context_t* laoi = (laoi_context_t*)lua_touserdata(L, 1);
	release_aoi_ctx(laoi->aoi);
	return 0;
}

static int
lcreate(lua_State* L) {
	int scene = luaL_checkinteger(L, 1);
	int cell = luaL_optinteger(L, 2, 5);
	laoi_context_t* laoi = (laoi_context_t*)lua_newuserdata(L, sizeof(laoi_context_t));
	memset(laoi, 0, sizeof(*laoi));

	laoi->scene_id = scene;
	laoi->aoi = create_aoi_ctx();
	laoi->cell = cell;

	lua_newtable(L);

	lua_pushcfunction(L, lrelease);
	lua_setfield(L, -2, "__gc");

	luaL_Reg l[] = {
		{ "create_object", lcreate_object },
		{ NULL, NULL },
	};
	luaL_newlib(L, l);

	lua_setfield(L, -2, "__index");

	lua_setmetatable(L, -2);

	return 1;
}

int
luaopen_linkaoi_core(lua_State* L) {
	luaL_Reg l[] = {
		{ "create", lcreate },
		{ NULL, NULL },
	};
	luaL_newlib(L, l);
	return 1;
}
