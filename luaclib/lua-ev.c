#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "ev.h"
#include "socket/socket_tcp.h"
#include "socket/socket_httpc.h"
#include "socket/socket_util.h"
#include "socket/socket_udp.h"
#include "socket/socket_pipe.h"
#include "socket/dns_resolver.h"

#define LUA_EV_ERROR    0
#define LUA_EV_TIMEOUT	1
#define LUA_EV_ACCEPT   2
#define LUA_EV_CONNECT  3
#define LUA_EV_DATA     4

#define META_EVENT 			"meta_event"
#define META_SESSION 		"meta_session"
#define META_TIMER			"meta_timer"
#define META_LISTENER 		"meta_listener"
#define META_UDP 			"meta_udp"
#define META_PIPE			"meta_pipe"

#define HEADER_TYPE_WORD 	2
#define HEADER_TYPE_DWORD 	4

#define THREAD_CACHED_SIZE (1024 * 1024)
#define MAX_PACKET_SIZE (16 * 1024 * 1024)

#define MB (1024*1024)

__thread char THREAD_CACHED_BUFFER[THREAD_CACHED_SIZE];

struct lev_timer;

typedef struct lev {
	struct ev_loop_ctx* loop_ctx;
	struct dns_resolver* resolver;
	struct http_multi* multi;
	struct lev_timer* freelist;
	lua_State* main;
	int ref;
	int callback;
} lev_t;

typedef struct ltcp_session {
	lev_t* lev;
	struct ev_session* session;
	int ref;
	int closed;

	int min;
	int max;

	int loop;
	int markdead;

	int header;
	int need;

	char* buff;
	int offset;
	int size;

	int threhold;
} ltcp_session_t;

typedef struct ltcp_listener {
	lev_t* lev;
	struct ev_listener* listener;
	int ref;
	int closed;
	int header;
	int min;
	int max;
} ltcp_listener_t;

typedef struct ltcp_connecter {
	lev_t* lev;
	struct ev_connecter* connecter;
	int wakeup;
	int header;
	int min;
	int max;
} ltcp_connecter_t;

typedef struct ludp_session {
	lev_t* lev;
	struct udp_session* session;
	int ref;
	int closed;
	int callback;
} ludp_session_t;

typedef struct lpipe_session {
	lev_t* lev;
	struct pipe_session* session;
	int ref;
	int callback;
	int closed;
} lpipe_session_t;

typedef struct ldns_resolver {
	lev_t* lev;
	struct dns_resolver* core;
	int ref;
	int callback;
} ldns_resolver_t;

typedef struct lev_timer {
	lev_t* lev;
	struct ev_timer io;
	int ref;
	struct lev_timer* next;
} lev_timer_t;

union un_sockaddr {
	struct sockaddr_un su;
	struct sockaddr_in si;
};

static int
meta_init(lua_State* L, const char* meta) {
	luaL_newmetatable(L, meta);
	lua_setmetatable(L, -2);
	lua_pushvalue(L, -1);
	return luaL_ref(L, LUA_REGISTRYINDEX);
}

static inline void*
get_buffer(size_t size) {
	char* buffer = THREAD_CACHED_BUFFER;
	if (size > THREAD_CACHED_SIZE) {
		buffer = malloc(size);
	}
	return buffer;
}

static inline void
free_buffer(void* buffer) {
	if (buffer != THREAD_CACHED_BUFFER)
		free(buffer);
}

//-------------------------tcp session api---------------------------
static void
tcp_session_error(struct ev_session* ev_session, void* ud);

static void
read_fd(struct ev_session* ev_session, void* ud);

static ltcp_session_t*
tcp_session_create(lua_State* L, lev_t* lev, int fd, int header, int min, int max) {
	ltcp_session_t* ltcp_session = lua_newuserdata(L, sizeof(ltcp_session_t));
	memset(ltcp_session, 0, sizeof(ltcp_session_t));

	ltcp_session->lev = lev;
	ltcp_session->closed = 0;
	ltcp_session->header = header;
	ltcp_session->loop = 0;
	ltcp_session->markdead = 0;
	ltcp_session->threhold = MB;
	ltcp_session->buff = NULL;
	ltcp_session->offset = 0;
	ltcp_session->size = 0;
	ltcp_session->ref = meta_init(L, META_SESSION);
	ltcp_session->session = ev_session_bind(lev->loop_ctx, fd, min, max);
	ev_session_setcb(ltcp_session->session, read_fd, NULL, tcp_session_error, ltcp_session);
	ev_session_enable(ltcp_session->session, EV_READ);

	return ltcp_session;
}

static int
tcp_session_release(ltcp_session_t* ltcp_session) {
	lev_t* lev = ltcp_session->lev;
	luaL_unref(lev->main, LUA_REGISTRYINDEX, ltcp_session->ref);
	ev_session_free(ltcp_session->session);
	if (ltcp_session->buff) {
		free(ltcp_session->buff);
	}
	return 0;
}

static void
tcp_session_error(struct ev_session* ev_session, void* ud) {
	ltcp_session_t* ltcp_session = ud;
	lev_t* lev = ltcp_session->lev;

	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lev->callback);
	lua_pushinteger(lev->main, LUA_EV_ERROR);
	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, ltcp_session->ref);
	lua_pcall(lev->main, 2, 0, 0);

	ltcp_session->closed = 1;

	if (ltcp_session->loop) {
		ltcp_session->markdead = 1;
	} else {
		tcp_session_release(ltcp_session);
	}
}

static char*
tcp_session_collect(ltcp_session_t* ltcp_session, int length, int* size) {
	if (!ltcp_session->buff) {
		ltcp_session->buff = (char*)malloc(length);
		ltcp_session->size = length;
		ltcp_session->offset = 0;
	}
	if (length > ltcp_session->size - ltcp_session->offset) {
		ltcp_session->size = length + ltcp_session->offset;
		ltcp_session->buff = (char*)realloc(ltcp_session->buff, ltcp_session->size);
	}

	ev_session_read(ltcp_session->session, ltcp_session->buff + ltcp_session->offset, length);
	ltcp_session->offset += length;
	if (size) {
		*size = ltcp_session->offset;
	}
	return ltcp_session->buff;
}

static void
read_fd(struct ev_session* ev_session, void* ud) {
	ltcp_session_t* ltcp_session = ud;
	ltcp_session->loop = 1;

	lev_t* lev = ltcp_session->lev;

	if (ltcp_session->header == 0) {
		lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lev->callback);
		lua_pushinteger(lev->main, LUA_EV_DATA);
		lua_rawgeti(lev->main, LUA_REGISTRYINDEX, ltcp_session->ref);
		lua_pcall(lev->main, 2, 0, 0);
		return;
	}

	while (ltcp_session->markdead == 0) {
		size_t len = ev_session_input_size(ltcp_session->session);
		if (ltcp_session->need == 0) {
			if (len < ltcp_session->header)
				break;

			if (ltcp_session->header == HEADER_TYPE_WORD) {
				uint8_t header[HEADER_TYPE_WORD];
				ev_session_read(ltcp_session->session, (char*)header, HEADER_TYPE_WORD);
				ltcp_session->need = header[0] | header[1] << 8;
			} else {
				assert(ltcp_session->header == HEADER_TYPE_DWORD);
				uint8_t header[HEADER_TYPE_DWORD];
				ev_session_read(ltcp_session->session, (char*)header, HEADER_TYPE_DWORD);
				ltcp_session->need = header[0] | header[1] << 8 | header[2] << 16 | header[3] << 24;
			}
			ltcp_session->need -= ltcp_session->header;
			if (ltcp_session->need > MAX_PACKET_SIZE) {
				tcp_session_error(ev_session, ud);
				break;
			}
		} else {
			if (len < ltcp_session->need) {
				if (ev_session_input_full(ltcp_session->session) == 0) {
					tcp_session_collect(ltcp_session, len, NULL);
					ltcp_session->need -= len;
				}
				break;
			}

			char* data = NULL;
			int size = 0;
			if (ltcp_session->offset > 0) {
				data = tcp_session_collect(ltcp_session, ltcp_session->need, &size);
			} else {
				data = ev_session_read_peek(ev_session, ltcp_session->need);
				if (data) {
					size = ltcp_session->need;
				} else {
					data = tcp_session_collect(ltcp_session, ltcp_session->need, &size);
				}
			}

			lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lev->callback);
			lua_pushinteger(lev->main, LUA_EV_DATA);
			lua_rawgeti(lev->main, LUA_REGISTRYINDEX, ltcp_session->ref);
			lua_pushlightuserdata(lev->main, data);
			lua_pushinteger(lev->main, ltcp_session->need);
			lua_pcall(lev->main, 4, 0, 0);

			ltcp_session->need = 0;
		}
	}

	ltcp_session->loop = 0;

	if (ltcp_session->markdead) {
		tcp_session_release(ltcp_session);
	}
}

static void
accept_fd(struct ev_listener *listener, int fd, const char* addr, void *ud) {
	ltcp_listener_t* lev_listener = ud;
	lev_t* lev = lev_listener->lev;

	socket_nonblock(fd);
	socket_no_delay(fd);
	socket_keep_alive(fd);
	socket_closeonexec(fd);

	tcp_session_create(lev->main, lev, fd, lev_listener->header, lev_listener->min, lev_listener->max);

	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lev->callback);
	lua_pushinteger(lev->main, LUA_EV_ACCEPT);
	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lev_listener->ref);
	lua_pushvalue(lev->main, -4);
	lua_pushstring(lev->main, addr);

	lua_pcall(lev->main, 4, 0, 0);
}

static void
close_complete(struct ev_session* ev_session, void* ud) {
	ltcp_session_t* ltcp_session = ud;
	lev_t* lev = ltcp_session->lev;
	assert(ltcp_session->closed == 1);

	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lev->callback);
	lua_pushinteger(lev->main, LUA_EV_ERROR);
	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, ltcp_session->ref);

	tcp_session_release(ltcp_session);

	lua_pcall(lev->main, 2, 0, 0);
}


static void
connect_complete(struct ev_connecter* connecter, int fd, const char* reason, void *userdata) {
	ltcp_connecter_t* ltcp_connecter = userdata;
	lev_t* lev = ltcp_connecter->lev;

	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lev->callback);
	lua_pushinteger(lev->main, LUA_EV_CONNECT);
	lua_pushinteger(lev->main, ltcp_connecter->wakeup);

	if (fd < 0) {
		lua_pushboolean(lev->main, 0);
		lua_pushstring(lev->main, reason);
	} else {
		socket_nonblock(fd);
		socket_keep_alive(fd);
		socket_closeonexec(fd);

		lua_pushboolean(lev->main, 1);
		tcp_session_create(lev->main, lev, fd, ltcp_connecter->header, ltcp_connecter->min, ltcp_connecter->max);
	}
	lua_pcall(lev->main, 4, 0, 0);
	ev_connecter_free(connecter);
	free(ltcp_connecter);
}

static inline ltcp_session_t*
get_tcp_session(lua_State* L, int index) {
	ltcp_session_t* ltcp_session = (ltcp_session_t*)lua_touserdata(L, 1);
	if (ltcp_session->closed) {
		luaL_error(L, "session:%p already closed", ltcp_session);
	}
	return ltcp_session;
}

struct sockaddr*
	make_addr(lua_State* L, int index, union un_sockaddr* sa, int* len, int listen) {
	luaL_checktype(L, index, LUA_TTABLE);
	lua_getfield(L, index, "file");

	struct sockaddr* addr;

	if (!lua_isnoneornil(L, -1)) {
		sa->su.sun_family = AF_UNIX;

		const char* file = luaL_checkstring(L, -1);
		strcpy(sa->su.sun_path, file);

		if (listen) {
			unlink(file);
		}

		lua_pop(L, 1);

		addr = (struct sockaddr*)&sa->su;
		*len = sizeof(sa->su);
	} else {
		sa->si.sin_family = AF_INET;

		lua_pop(L, 1);
		lua_getfield(L, index, "ip");
		const char* ip = luaL_checkstring(L, -1);
		sa->si.sin_addr.s_addr = inet_addr(ip);
		lua_pop(L, 1);

		lua_getfield(L, index, "port");
		int port = luaL_checkinteger(L, -1);
		sa->si.sin_port = htons(port);
		lua_pop(L, 1);

		addr = (struct sockaddr*)&sa->si;
		*len = sizeof(sa->si);
	}
	return addr;
}

static inline int
check_header(lua_State* L, int index) {
	int header = luaL_checkinteger(L, 2);
	if (header != 0) {
		if (header != HEADER_TYPE_WORD && header != HEADER_TYPE_DWORD) {
			luaL_error(L, "error header size:%d", header);
		}
	}
	return header;
}

static int
lconnect(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	int header = check_header(L, 2);
	int min = luaL_checkinteger(L, 3);
	int max = luaL_checkinteger(L, 4);
	int wakeup = luaL_checkinteger(L, 5);

	union un_sockaddr sa;
	int len = 0;
	struct sockaddr* addr = make_addr(L, 6, &sa, &len, 0);

	if (wakeup <= 0) {
		int status;
		int fd = socket_connect(addr, len, 0, &status);
		if (fd < 0) {
			lua_pushboolean(L, 0);
			lua_pushstring(L, strerror(errno));
			return 2;
		}
		tcp_session_create(L, lev, fd, header, min, max);
		return 1;
	}

	ltcp_connecter_t* lev_connecter = malloc(sizeof(*lev_connecter));
	lev_connecter->lev = lev;
	lev_connecter->wakeup = wakeup;
	lev_connecter->header = header;
	lev_connecter->min = min;
	lev_connecter->max = max;
	lev_connecter->connecter = ev_connecter_create(lev->loop_ctx, addr, len, connect_complete, lev_connecter);
	if (lev_connecter->connecter == NULL) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, strerror(errno));
		free(lev_connecter);
		return 2;
	}

	lua_pushboolean(L, 1);
	return 1;
}

static int
lbind(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	int fd = luaL_checkinteger(L, 2);
	int min = luaL_checkinteger(L, 3);
	int max = luaL_checkinteger(L, 4);

	tcp_session_create(L, lev, fd, 0, min, max);
	return 1;
}


static int
ltcp_session_write(lua_State* L) {
	ltcp_session_t* ltcp_session = get_tcp_session(L, 1);

	int noheader = 0;
	size_t size = 0;
	char* data = NULL;

	int vt = lua_type(L, 2);
	switch (vt) {
		case LUA_TSTRING: {
			data = (char*)lua_tolstring(L, 2, &size);
			noheader = luaL_optinteger(L, 3, 0);
			break;
		}
		case LUA_TLIGHTUSERDATA:{
			data = lua_touserdata(L, 2);
			size = luaL_checkinteger(L, 3);
			noheader = luaL_optinteger(L, 4, 0);
			break;
		}
		default:
			luaL_error(L, "session:%p write error:unknow lua type:%s", ltcp_session, lua_typename(L, vt));
	}

	if (size == 0) {
		luaL_error(L, "session:%p write error:empty content", ltcp_session);
	}

	char* block = NULL;
	if (ltcp_session->header != 0 && noheader == 0) {

		if (ltcp_session->header == HEADER_TYPE_WORD) {
			ushort length = size + ltcp_session->header;
			block = malloc(length);
			memcpy(block, &length, sizeof(ushort));
			memcpy(block + sizeof(ushort), data, size);
			size = length;
		} else {
			uint32_t length = size + ltcp_session->header;
			block = malloc(length);
			memcpy(block, &length, sizeof(uint32_t));
			memcpy(block + sizeof(uint32_t), data, size);
			size = length;
		}

		if (vt == LUA_TLIGHTUSERDATA) {
			free(data);
		}
	} else {
		if (vt == LUA_TSTRING) {
			block = malloc(size);
			memcpy(block, data, size);
		} else {
			block = data;
		}
	}

	if (ev_session_write(ltcp_session->session, block, size) == -1) {
		free(block);
		lua_pushboolean(L, 0);
		return 1;
	}
	size_t total = ev_session_output_size(ltcp_session->session);
	if (total >= ltcp_session->threhold) {
		size_t howmuch = total / MB;
		ltcp_session->threhold += MB;
		fprintf(stderr, "session:%p more than %ldmb data need to send out\n", ltcp_session, howmuch);
	} else {
		size_t threhold = ltcp_session->threhold;
		if (threhold > MB && total < threhold / 2) {
			ltcp_session->threhold -= MB;
		}
	}
	lua_pushboolean(L, 1);

	return 1;
}

static int
ltcp_session_read(lua_State* L) {
	ltcp_session_t* ltcp_session = get_tcp_session(L, 1);
	size_t size = luaL_optinteger(L, 2, 0);

	size_t total = ev_session_input_size(ltcp_session->session);
	if (total == 0) {
		return 0;
	}

	if (size == 0 || size > total) {
		size = total;
	}

	char* data = get_buffer(size);

	ev_session_read(ltcp_session->session, data, size);

	lua_pushlstring(L, data, size);

	free_buffer(data);

	return 1;
}


static int
ltcp_session_alive(lua_State* L) {
	ltcp_session_t* ltcp_session = (ltcp_session_t*)lua_touserdata(L, 1);
	lua_pushboolean(L, ltcp_session->closed == 0);
	return 1;
}

static int
ltcp_session_close(lua_State* L) {
	ltcp_session_t* ltcp_session = get_tcp_session(L, 1);

	luaL_checktype(L, 2, LUA_TBOOLEAN);
	int immediately = lua_toboolean(L, 2);

	ltcp_session->closed = 1;

	if (!immediately) {
		ev_session_setcb(ltcp_session->session, NULL, close_complete, tcp_session_error, ltcp_session);
		ev_session_disable(ltcp_session->session, EV_READ);
		ev_session_enable(ltcp_session->session, EV_WRITE);
	} else {
		if (ltcp_session->loop) {
			ltcp_session->markdead = 1;
		} else {
			tcp_session_release(ltcp_session);
		}
	}

	return 0;
}

//-------------------------endof tcp session api---------------------------

//-------------------------tcp listener api---------------------------
static int
llisten(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	int header = check_header(L, 2);
	union un_sockaddr sa;
	int len = 0;
	struct sockaddr* addr = make_addr(L, 6, &sa, &len, 1);

	ltcp_listener_t* lev_listener = lua_newuserdata(L, sizeof(*lev_listener));
	lev_listener->lev = lev;
	lev_listener->closed = 0;
	lev_listener->min = luaL_checkinteger(L, 3);
	lev_listener->max = luaL_checkinteger(L, 4);
	lev_listener->header = header;

	int flag = SOCKET_OPT_NOBLOCK | SOCKET_OPT_CLOSE_ON_EXEC | SOCKET_OPT_REUSEABLE_ADDR;
	if (lua_toboolean(L, 5)) {
		flag |= SOCKET_OPT_REUSEABLE_PORT;
	}

	lev_listener->listener = ev_listener_create(lev->loop_ctx, addr, len, 16, flag, accept_fd, lev_listener);
	if (!lev_listener->listener) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, strdup(strerror(errno)));
		return 2;
	}

	lev_listener->ref = meta_init(L, META_LISTENER);

	return 1;
}

static int
llisten_alive(lua_State* L) {
	ltcp_listener_t* lev_listener = (ltcp_listener_t*)lua_touserdata(L, 1);
	lua_pushboolean(L, lev_listener->closed == 0);
	return 1;
}

static int
llisten_addr(lua_State* L) {
	ltcp_listener_t* lev_listener = (ltcp_listener_t*)lua_touserdata(L, 1);
	if (!lev_listener->listener) {
		return 0;
	}
	char addr[INET6_ADDRSTRLEN] = { 0 };
	int port = 0;
	if (ev_listener_addr(lev_listener->listener, addr, INET6_ADDRSTRLEN, &port) < 0) {
		return 0;
	}

	lua_newtable(L);
	if (port == 0) {
		lua_pushstring(L, addr);
		lua_setfield(L, -2, "file");
	} else {
		lua_pushstring(L, addr);
		lua_setfield(L, -2, "ip");
		lua_pushinteger(L, port);
		lua_setfield(L, -2, "port");
	}
	return 1;
}

static int
llisten_close(lua_State* L) {
	ltcp_listener_t* lev_listener = (ltcp_listener_t*)lua_touserdata(L, 1);
	if (lev_listener->closed)
		luaL_error(L, "listener alreay closed");

	lev_listener->closed = 1;
	luaL_unref(L, LUA_REGISTRYINDEX, lev_listener->ref);
	ev_listener_free(lev_listener->listener);
	return 0;
}
//-------------------------endof tcp listener api---------------------------

//-------------------------timer api---------------------------

static void
timeout(struct ev_loop* loop, struct ev_timer* io, int revents) {
	lev_timer_t* timer = io->data;
	lev_t* lev = timer->lev;
	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lev->callback);
	lua_pushinteger(lev->main, LUA_EV_TIMEOUT);
	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, timer->ref);
	lua_pcall(lev->main, 2, 0, 0);
}

static int
ltimer(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);

	double ti = luaL_checknumber(L, 2);
	double freq = 0;
	if (!lua_isnoneornil(L, 3)) {
		freq = luaL_checknumber(L, 3);
	}

	lev_timer_t* timer = NULL;
	if (lev->freelist) {
		timer = lev->freelist;
		lev->freelist = lev->freelist->next;
		lua_rawgeti(L, LUA_REGISTRYINDEX, timer->ref);
	} else {
		timer = lua_newuserdata(L, sizeof(*timer));
		timer->lev = lev;
		timer->ref = meta_init(L, META_TIMER);
	}

	timer->io.data = timer;
	ev_timer_init((struct ev_timer*)&timer->io, timeout, ti, freq);
	ev_timer_start(loop_ctx_get(lev->loop_ctx), (struct ev_timer*)&timer->io);

	return 1;
}

static int
ltimer_cancel(lua_State* L) {
	lev_timer_t* timer = (lev_timer_t*)lua_touserdata(L, 1);
	if (ev_is_active(&timer->io) == 0) {
		lua_pushboolean(L, 0);
		lua_pushliteral(L, "timer already cancel");
		return 2;
	}
	lev_t* lev = timer->lev;
	ev_timer_stop(loop_ctx_get(lev->loop_ctx), (struct ev_timer*)&timer->io);
	timer->next = lev->freelist;
	lev->freelist = timer;

	lua_pushboolean(L, 1);
	return 1;
}

static int
ltimer_alive(lua_State* L) {
	lev_timer_t* timer = (lev_timer_t*)lua_touserdata(L, 1);
	lua_pushboolean(L, ev_is_active(&timer->io));
	return 1;
}
//-------------------------endof timer api---------------------------

//-------------------------udp api---------------------------

static void
read_udp(struct udp_session* session, char* buffer, size_t size, const char* ip, ushort port, void* userdata) {
	ludp_session_t* ludp_session = userdata;
	lev_t* lev = ludp_session->lev;

	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, ludp_session->callback);
	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, ludp_session->ref);
	lua_pushlstring(lev->main, buffer, size);
	lua_pushstring(lev->main, ip);
	lua_pushinteger(lev->main, port);
	lua_pcall(lev->main, 4, 0, 0);
}

static inline void
udp_session_release(ludp_session_t* ludp_session) {
	lev_t* lev = ludp_session->lev;
	luaL_unref(lev->main, LUA_REGISTRYINDEX, ludp_session->ref);
	luaL_unref(lev->main, LUA_REGISTRYINDEX, ludp_session->callback);
	ludp_session->closed = 1;
	udp_session_destroy(ludp_session->session);
}

static int
ludp_session_new(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	size_t recv_size = lua_tointeger(L, 2);
	luaL_checktype(L, 3, LUA_TFUNCTION);

	const char* ip = NULL;
	ushort port = 0;
	if (!lua_isnoneornil(L, 4)) {
		ip = luaL_checkstring(L, 4);
		port = luaL_checkinteger(L, 5);
	}

	struct udp_session* session = NULL;
	if (ip) {
		session = udp_session_bind(lev->loop_ctx, ip, port, recv_size);
	} else {
		session = udp_session_new(lev->loop_ctx, recv_size);
	}

	if (!session) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, "udp new error");
		return 2;
	}

	lua_pushvalue(L, 3);
	int callback = luaL_ref(L, LUA_REGISTRYINDEX);

	ludp_session_t* ludp_session = lua_newuserdata(L, sizeof(ludp_session_t));
	memset(ludp_session, 0, sizeof(*ludp_session));

	ludp_session->lev = lev;
	ludp_session->session = session;
	ludp_session->closed = 0;
	ludp_session->callback = callback;
	ludp_session->ref = meta_init(L, META_UDP);

	udp_session_setcb(ludp_session->session, read_udp, NULL, ludp_session);

	return 1;
}

static int
ludp_session_send(lua_State* L) {
	ludp_session_t* ludp_session = (ludp_session_t*)lua_touserdata(L, 1);
	if (ludp_session->closed == 1) {
		luaL_error(L, "udp session:%p already closed", ludp_session);
	}

	const char* ip = luaL_checkstring(L, 2);
	int port = luaL_checkinteger(L, 3);

	size_t size;
	char* data = NULL;
	int needfree = 0;

	switch (lua_type(L, 4)) {
		case LUA_TSTRING: {
			data = (char*)lua_tolstring(L, 4, &size);
			break;
		}
		case LUA_TUSERDATA:{
			data = (char*)lua_touserdata(L, 4);
			size = lua_tointeger(L, 5);
			needfree = 1;
			break;
		}
		default:
			luaL_error(L, "session write error:unknow lua type:%s", lua_typename(L, lua_type(L, 2)));
	}

	if (size == 0) {
		luaL_error(L, "udp session send error size");
	}

	int total = udp_session_write(ludp_session->session, data, size, ip, port);

	if (needfree) {
		free(data);
	}

	if (total < 0) {
		udp_session_release(ludp_session);
		lua_pushboolean(L, 0);
		lua_pushstring(L, strerror(errno));
		return 2;
	}
	assert(total == size);
	lua_pushboolean(L, 1);
	return 1;
}

static int
ludp_session_alive(lua_State* L) {
	ludp_session_t* ludp_session = (ludp_session_t*)lua_touserdata(L, 1);
	lua_pushinteger(L, ludp_session->closed);
	return 1;
}

static int
ludp_session_close(lua_State* L) {
	ludp_session_t* ludp_session = (ludp_session_t*)lua_touserdata(L, 1);
	if (ludp_session->closed == 1) {
		luaL_error(L, "udp session:%p already closed", ludp_session);
	}
	udp_session_release(ludp_session);
	return 0;
}
//-------------------------endof udp api---------------------------

//-------------------------pipe api---------------------------

static void
read_pipe(struct pipe_session* session, struct pipe_message* message, void *userdata) {
	lpipe_session_t* lpipe = userdata;
	lev_t* lev = lpipe->lev;

	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lpipe->callback);
	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lpipe->ref);
	lua_pushinteger(lev->main, message->source);
	lua_pushinteger(lev->main, message->session);
	lua_pushlightuserdata(lev->main, message->data);
	lua_pushinteger(lev->main, message->size);
	lua_pcall(lev->main, 5, 0, 0);

	free(message->data);
}

static int
lpipe(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);

	luaL_checktype(L, 2, LUA_TFUNCTION);
	int callback = luaL_ref(L, LUA_REGISTRYINDEX);

	struct pipe_session* session = pipe_sesson_new(lev->loop_ctx);
	if (!session) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, strerror(errno));
		return 2;
	}

	lpipe_session_t* lpipe = lua_newuserdata(L, sizeof(lpipe_session_t));
	memset(lpipe, 0, sizeof(*lpipe));

	lpipe->lev = lev;
	lpipe->session = session;
	lpipe->callback = callback;
	lpipe->closed = 0;
	lpipe->ref = meta_init(L, META_PIPE);
	pipe_session_setcb(session, read_pipe, lpipe);

	lua_pushinteger(L, pipe_session_write_fd(session));

	return 2;
}

static int
lpipe_alive(lua_State* L) {
	lpipe_session_t* lpipe = (lpipe_session_t*)lua_touserdata(L, 1);
	lua_pushinteger(L, lpipe->closed == 1);
	return 1;
}

static int
lpipe_release(lua_State* L) {
	lpipe_session_t* lpipe = (lpipe_session_t*)lua_touserdata(L, 1);
	if (lpipe->closed) {
		luaL_error(L, "pipe already closed");
	}

	pipe_session_destroy(lpipe->session);

	luaL_unref(L, LUA_REGISTRYINDEX, lpipe->ref);
	luaL_unref(L, LUA_REGISTRYINDEX, lpipe->callback);

	lpipe->closed = 1;
	return 1;
}
//-------------------------endof pipe api---------------------------

static void
dns_resolver_result(int ok, struct hostent *host, const char* reason, void* ud) {
	ldns_resolver_t* lresolver = ud;
	lev_t* lev = lresolver->lev;

	lua_rawgeti(lev->main, LUA_REGISTRYINDEX, lresolver->callback);
	if (ok == 0) {
		lua_pushboolean(lev->main, 0);
		lua_pushstring(lev->main, reason);
		lua_pcall(lev->main, 2, 0, 0);
	} else {
		lua_newtable(lev->main);
		char ip[INET6_ADDRSTRLEN];
		int i;
		for (i = 0; host->h_addr_list[i]; ++i) {
			inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
			lua_pushstring(lev->main, ip);
			lua_seti(lev->main, -2, i + 1);
		}
		lua_pcall(lev->main, 1, 0, 0);
	}
	luaL_unref(lev->main, LUA_REGISTRYINDEX, lresolver->ref);
}

static int
ldns_resolve(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	const char* host = luaL_checkstring(L, 2);

	luaL_checktype(L, 3, LUA_TFUNCTION);
	int callback = luaL_ref(L, LUA_REGISTRYINDEX);

	ldns_resolver_t* lresolver = lua_newuserdata(L, sizeof(*lresolver));
	memset(lresolver, 0, sizeof(*lresolver));

	lresolver->lev = lev;
	lresolver->core = lev->resolver;
	lresolver->callback = callback;

	lua_pushvalue(L, -1);
	lresolver->ref = luaL_ref(L, LUA_REGISTRYINDEX);

	dns_query(lresolver->core, host, dns_resolver_result, lresolver);

	return 1;
}
//-------------------------event api---------------------------

static int
ldispatch(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	loop_ctx_dispatch(lev->loop_ctx);
	return 0;
}

static int
lrelease(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	http_multi_delete(lev->multi);
	dns_resolver_delete(lev->resolver);
	loop_ctx_release(lev->loop_ctx);
	luaL_unref(L, LUA_REGISTRYINDEX, lev->ref);
	return 0;
}

static int
lbreak(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	loop_ctx_break(lev->loop_ctx);
	return 0;
}

static int
lclean(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	loop_ctx_clean(lev->loop_ctx);
	while (lev->freelist) {
		lev_timer_t* timer = lev->freelist;
		lev->freelist = lev->freelist->next;
		luaL_unref(L, LUA_REGISTRYINDEX, timer->ref);
	}
	return 0;
}

static int
lnow(lua_State* L) {
	lev_t* lev = (lev_t*)lua_touserdata(L, 1);
	double now = loop_ctx_now(lev->loop_ctx) * 1000;
	lua_pushinteger(L, now);
	return 1;
}
//-------------------------endof event api---------------------------

static int
levent_loop_new(lua_State* L) {
	luaL_checktype(L, 1, LUA_TFUNCTION);
	int callback = luaL_ref(L, LUA_REGISTRYINDEX);

	lev_t* lev = lua_newuserdata(L, sizeof(*lev));
	lev->loop_ctx = loop_ctx_create();
	lev->multi = http_multi_new(lev->loop_ctx);
	lev->resolver = dns_resolver_new(lev->loop_ctx);
	lev->main = L;
	lev->callback = callback;
	lev->freelist = NULL;
	lev->ref = meta_init(L, META_EVENT);

	return 1;
}

int
luaopen_ev_core(lua_State* L) {
	luaL_checkversion(L);

	luaL_newmetatable(L, META_EVENT);
	const luaL_Reg meta_event[] = {
		{ "listen", llisten },
		{ "connect", lconnect },
		{ "bind", lbind },
		{ "timer", ltimer },
		{ "udp", ludp_session_new },
		{ "pipe", lpipe },
		{ "dns_resolve", ldns_resolve },
		{ "breakout", lbreak },
		{ "dispatch", ldispatch },
		{ "clean", lclean },
		{ "now", lnow },
		{ "release", lrelease },
		{ NULL, NULL },
	};
	luaL_newlib(L, meta_event);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luaL_newmetatable(L, META_SESSION);
	const luaL_Reg meta_session[] = {
		{ "write", ltcp_session_write },
		{ "read", ltcp_session_read },
		{ "alive", ltcp_session_alive },
		{ "close", ltcp_session_close },
		{ NULL, NULL },
	};
	luaL_newlib(L, meta_session);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luaL_newmetatable(L, META_LISTENER);
	const luaL_Reg meta_listener[] = {
		{ "alive", llisten_alive },
		{ "addr", llisten_addr },
		{ "close", llisten_close },
		{ NULL, NULL },
	};
	luaL_newlib(L, meta_listener);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luaL_newmetatable(L, META_TIMER);
	const luaL_Reg meta_timer[] = {
		{ "cancel", ltimer_cancel },
		{ "alive", ltimer_alive },
		{ NULL, NULL },
	};
	luaL_newlib(L, meta_timer);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luaL_newmetatable(L, META_UDP);
	const luaL_Reg meta_udp[] = {
		{ "send", ludp_session_send },
		{ "alive", ludp_session_alive },
		{ "close", ludp_session_close },
		{ NULL, NULL },
	};
	luaL_newlib(L, meta_udp);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luaL_newmetatable(L, META_PIPE);
	const luaL_Reg meta_pipe[] = {
		{ "alive", lpipe_alive },
		{ "release", lpipe_release },
		{ NULL, NULL },
	};
	luaL_newlib(L, meta_pipe);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	const luaL_Reg l[] = {
		{ "new", levent_loop_new },
		{ NULL, NULL },
	};
	luaL_newlib(L, l);
	return 1;
}
