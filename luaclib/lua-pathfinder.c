#include <lua.h>
#include <lauxlib.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "pathfinder/tile/pathfinder.h"

#define TO_TILE(ctx,val) (int)(val / ctx->grid)
#define TO_COORD(ctx,val) (double)(((double)val + 0.5) * (double)ctx->grid)

typedef struct pathfinder_context {
	int scene;
	int grid;
	struct pathfinder* finder;
} finder_ctx_t;

typedef struct pathfinder_ud {
	lua_State *L;
	finder_ctx_t *ctx;
	int index;
} finder_ud_t;

void finder_result_callback(void *ud, int x, int z) {
	finder_ud_t* args = (finder_ud_t*)ud;

	lua_createtable(args->L, 2, 0);
	lua_pushnumber(args->L, TO_COORD(args->ctx, x));
	lua_rawseti(args->L, -2, 1);
	lua_pushnumber(args->L, TO_COORD(args->ctx, z));
	lua_rawseti(args->L, -2, 2);
	lua_rawseti(args->L, -2, ++args->index);
}

static int
_release(lua_State *L) {
	finder_ctx_t* ctx = (finder_ctx_t*)lua_touserdata(L, 1);
	finder_release(ctx->finder);
	return 0;
}

static int
_find(lua_State *L) {
	finder_ctx_t* ctx = (finder_ctx_t*)lua_touserdata(L, 1);
	double x0 = luaL_checknumber(L, 2);
	double z0 = luaL_checknumber(L, 3);
	double x1 = luaL_checknumber(L, 4);
	double z1 = luaL_checknumber(L, 5);
	int smooth = luaL_checkinteger(L, 6);

	int ix0 = TO_TILE(ctx, x0);
	int iz0 = TO_TILE(ctx, z0);
	int ix1 = TO_TILE(ctx, x1);
	int iz1 = TO_TILE(ctx, z1);

	finder_ud_t ud;
	ud.L = L;
	ud.ctx = ctx;
	ud.index = 0;

	lua_newtable(L);

	int ok = finder_find(ctx->finder, ix0, iz0, ix1, iz1, smooth, finder_result_callback, &ud, NULL, NULL, 64);
	lua_pushinteger(L, ok);
	lua_pushvalue(L, -2);
	if (ok == FINDER_SAME_POINT_ERROR) {
		lua_newtable(L);
		lua_pushnumber(L, x0);
		lua_rawseti(L, -2, 1);
		lua_pushnumber(L, z0);
		lua_rawseti(L, -2, 2);

		lua_rawseti(L, -2, 1);

		lua_newtable(L);
		lua_pushnumber(L, x1);
		lua_rawseti(L, -2, 1);
		lua_pushnumber(L, z1);
		lua_rawseti(L, -2, 2);

		lua_rawseti(L, -2, 2);
	}

	return 2;
}

static int
_raycast(lua_State *L) {
	finder_ctx_t* ctx = (finder_ctx_t*)lua_touserdata(L, 1);
	double x0 = luaL_checknumber(L, 2);
	double z0 = luaL_checknumber(L, 3);
	double x1 = luaL_checknumber(L, 4);
	double z1 = luaL_checknumber(L, 5);
	int ignore = luaL_checkinteger(L, 6);

	int ix0 = TO_TILE(ctx, x0);
	int iz0 = TO_TILE(ctx, z0);
	int ix1 = TO_TILE(ctx, x1);
	int iz1 = TO_TILE(ctx, z1);

	int rx, rz;
	int sx, sz;
	if (finder_raycast(ctx->finder, ix0, iz0, ix1, iz1, ignore, &rx, &rz, &sx, &sz, NULL, NULL) == 0) {
		lua_pushnumber(L, x1);
		lua_pushnumber(L, z1);
	} else {
		lua_pushnumber(L, TO_COORD(ctx, rx));
		lua_pushnumber(L, TO_COORD(ctx, rz));
	}
	return 2;
}

static int
_bound(lua_State* L) {
	finder_ctx_t* ctx = (finder_ctx_t*)lua_touserdata(L, 1);
	int width, heigh;
	finder_bound(ctx->finder, &width, &heigh);
	lua_pushinteger(L, width);
	lua_pushinteger(L, heigh);
	return 2;
}

static int
_movable(lua_State *L) {
	finder_ctx_t* ctx = (finder_ctx_t*)lua_touserdata(L, 1);
	double x = luaL_checknumber(L, 2);
	double z = luaL_checknumber(L, 3);
	int ignore = luaL_checkinteger(L, 4);

	int ix = TO_TILE(ctx, x);
	int iz = TO_TILE(ctx, z);

	int ok = finder_movable(ctx->finder, ix, iz, ignore);
	lua_pushboolean(L, ok);
	return 1;
}

static int
_random(lua_State* L) {
	finder_ctx_t* ctx = (finder_ctx_t*)lua_touserdata(L, 1);
	int x, z;
	finder_random(ctx->finder, &x, &z);
	lua_pushnumber(L, TO_COORD(ctx, x));
	lua_pushnumber(L, TO_COORD(ctx, z));
	return 2;
}

static int
_random_in_circle(lua_State* L) {
	finder_ctx_t* ctx = (finder_ctx_t*)lua_touserdata(L, 1);
	double cx = luaL_checknumber(L, 2);
	double cz = luaL_checknumber(L, 3);
	int r = luaL_checkinteger(L, 4);

	int icx = TO_TILE(ctx, cx);
	int icz = TO_TILE(ctx, cz);

	int x, z;
	if (finder_random_in_circle(ctx->finder, icx, icz, r, &x, &z) < 0) {
		lua_pushboolean(L, 0);
		lua_pushliteral(L, "error circle range");
		return 2;
	}
	lua_pushnumber(L, TO_COORD(ctx, x));
	lua_pushnumber(L, TO_COORD(ctx, z));
	return 2;
}

static int
_mask_set(lua_State *L) {
	finder_ctx_t* ctx = (finder_ctx_t*)lua_touserdata(L, 1);
	int index = luaL_checkinteger(L, 2);
	int enable = luaL_checkinteger(L, 3);
	finder_mask_set(ctx->finder, index, enable);
	return 0;
}

static int
_mask_reset(lua_State *L) {
	finder_ctx_t* ctx = (finder_ctx_t*)lua_touserdata(L, 1);
	finder_mask_reset(ctx->finder);
	return 0;
}

static int
create(lua_State *L) {
	int scene = lua_tointeger(L, 1);
	const char* file = lua_tostring(L, 2);

	int width;
	int heigh;
	int version;
	int grid;

	char* data = NULL;

	FILE* ptr = fopen(file, "r");
	if (!ptr) {
		luaL_error(L, "no such file:%s", file);
	}

	fread(&version, 1, sizeof(int), ptr);
	fread(&width, 1, sizeof(int), ptr);
	fread(&heigh, 1, sizeof(int), ptr);
	fread(&grid, 1, sizeof(int), ptr);
	int size = width * heigh;
	data = malloc(size);
	memset(data, 0, size);
	fread(data, 1, size, ptr);
	fclose(ptr);

	finder_ctx_t* ctx = (finder_ctx_t*)lua_newuserdata(L, sizeof(finder_ctx_t));
	ctx->scene = scene;
	ctx->grid = grid;
	ctx->finder = finder_create(width, heigh, data);
	free(data);

	lua_newtable(L);

	lua_pushcfunction(L, _release);
	lua_setfield(L, -2, "__gc");

	luaL_Reg l[] = {
		{ "find", _find },
		{ "raycast", _raycast },
		{ "bound", _bound },
		{ "movable", _movable },
		{ "random", _random },
		{ "random_in_circle", _random_in_circle },
		{ "mask_set", _mask_set },
		{ "mask_reset", _mask_reset },
		{ NULL, NULL },
	};
	luaL_newlib(L, l);

	lua_setfield(L, -2, "__index");

	lua_setmetatable(L, -2);

	return 1;
}

int
luaopen_pathfinder_core(lua_State *L) {
	luaL_checkversion(L);
	luaL_Reg l[] = {
		{ "create", create },
		{ NULL, NULL },
	};

	lua_createtable(L, 0, (sizeof(l)) / sizeof(luaL_Reg) - 1);
	luaL_setfuncs(L, l, 0);
	return 1;
}
