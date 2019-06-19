#include <lua.h>
#include <lauxlib.h>
#include <luaconf.h>
#include <lobject.h>
#include <lstate.h>
#include <lstring.h>
#include <ltable.h>
#include <lfunc.h>

extern TValue *index2addr (lua_State *L, int idx);

static inline int
need_sizeof(lua_State* L) {
    lua_pushvalue(L, 1);
    lua_gettable(L, 2);
    if (!lua_isnil(L, -1)) {
       lua_pop(L, 1);
       return -1;
    }
    lua_pop(L, 1);

    lua_pushvalue(L, 1);
    lua_pushboolean(L, 1);
    lua_settable(L, 2);
    return 0;
}

int
lsize_of(lua_State* L) {
    TValue* value = index2addr(L, 1);
    int type = lua_type(L,1);

    if (lua_isnoneornil(L, 2)) {
        lua_newtable(L);
    }

    switch(type) {
        case LUA_TSTRING: {
            GCObject* o = gcvalue(value);
            switch (o->tt) {
                case LUA_TSHRSTR: {
                    if (need_sizeof(L) == 0) {
                        size_t len = sizelstring(gco2ts(o)->shrlen);
                        lua_pushinteger(L, len);
                    } else {
                        lua_pushinteger(L, 0);
                    }
                    break;
                }
                case LUA_TLNGSTR: {
                    size_t len = sizelstring(gco2ts(o)->u.lnglen);
                    lua_pushinteger(L, len);
                    break;
                }
                default:
                    break;
            }
            break;
        }
        case LUA_TUSERDATA: {
            GCObject* o = gcvalue(value);
            if (need_sizeof(L) == 0) {
                size_t len = sizeudata(gco2u(o));
                lua_pushinteger(L, len);
            } else {
                lua_pushinteger(L, 0);
            }
            break;
        }
        case LUA_TFUNCTION: {
            GCObject* o = gcvalue(value);
            if (need_sizeof(L) < 0) {
                lua_pushinteger(L, 0);
            } else {
                   switch (o->tt) {
                    case LUA_TLCL: {
                        LClosure *cl = gco2lcl(o);
                        size_t size = sizeLclosure(cl->nupvalues);
                        lua_pushinteger(L, size);
                        break;
                    }
                    case LUA_TCCL: {
                        CClosure *cl = gco2ccl(o);
                        size_t size = sizeLclosure(cl->nupvalues);
                        lua_pushinteger(L, size);
                        break;
                    }
                    default:
                        break;
                }
            }
         
            break;
        }
        case LUA_TPROTO: {
            GCObject* o = gcvalue(value);
            if (need_sizeof(L) < 0) {
                lua_pushinteger(L, 0);
            } else {
               Proto *f = gco2p(o);
                size_t size = sizeof(Proto) + sizeof(Instruction) * f->sizecode +
                             sizeof(Proto *) * f->sizep +
                             sizeof(TValue) * f->sizek +
                             sizeof(int) * f->sizelineinfo +
                             sizeof(LocVar) * f->sizelocvars +
                             sizeof(Upvaldesc) * f->sizeupvalues;

                lua_pushinteger(L ,size); 
            }
            
            break;
        }

        case LUA_TTABLE: {
            GCObject* o = gcvalue(value);
            if (need_sizeof(L) < 0) {
                lua_pushinteger(L, 0);
            } else {
                Table *h = gco2t(o);
                size_t size = sizeof(Table) + sizeof(TValue) * h->sizearray + sizeof(Node) * cast(size_t, allocsizenode(h));

                lua_pushnil(L);
                while (lua_next(L, 1) != 0) {

                    int vtype = lua_type(L, -1);
                    if (vtype == LUA_TTABLE || vtype == LUA_TSTRING || vtype == LUA_TUSERDATA || vtype == LUA_TFUNCTION || vtype == LUA_TPROTO) {
                        lua_pushcfunction(L, lsize_of);
                        lua_pushvalue(L, -2);
                        lua_pushvalue(L, 2);
                        if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
                            luaL_error(L,lua_tostring(L, -1));
                        }
                        size += lua_tointeger(L, -1);
                        lua_pop(L, 1); 
                    }
                    
                    int ktype = lua_type(L, -2);
                    if (ktype == LUA_TTABLE || ktype == LUA_TSTRING || ktype == LUA_TUSERDATA || ktype == LUA_TFUNCTION || ktype == LUA_TPROTO) {
                        lua_pushcfunction(L, lsize_of);
                        lua_pushvalue(L, -3);
                        lua_pushvalue(L, 2);
                         if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
                            luaL_error(L,lua_tostring(L, -1));
                        }
                        size += lua_tointeger(L, -1);
                        lua_pop(L, 1);
                    }
                    
                    lua_pop(L, 1);
                }

                lua_pushinteger(L ,size);
            }
           
            break;
        }
        default:
            luaL_error(L, "unsupport type %s to sizeof", lua_typename(L, type));
    }
    return 1;
}