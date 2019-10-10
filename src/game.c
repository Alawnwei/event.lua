#include "constants.h"
#include "stream.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "socket/socket_tcp.h"
#include "common/encrypt.h"
#include "common/object_container.h"
#include <stdint.h>

struct netd;

typedef struct game {
	int id;
	int type;
	int login_master_id;
	int scene_master_id;
	int netd_num;

	struct ev_loop_ctx* loop_ctx;
	struct ev_timer timer;

	struct ev_connecter* connecter_slot[kMAX_NETD];
	struct netd* netd_slot[kMAX_NETD];

	char error[kERROR];

	double last_update;

	lua_State* L;

	struct netd* deadnetd;
} game_t;

typedef struct netd {
	game_t* game;
	struct ev_session* session;
	int id;
	int markdead;
	int need;
	struct netd* next;
} netd_t;

union un_sockaddr {
	struct sockaddr_un su;
	struct sockaddr_in si;
};

typedef struct conf {
	int id;
	int type;
	int netd_num;
	char* netd_ip;
	uint16_t netd_port;
	char* netd_ipc;
} conf_t;

static game_t* g_game = NULL;
static conf_t g_conf;
static uint8_t g_cached[kCACHED];

static inline uint8_t*
get_buffer(uint32_t size) {
	uint8_t* data = g_cached;
	if (size > kCACHED) {
		data = malloc(size);
	}
	return data;
}

static inline void
free_buffer(uint8_t* buffer) {
	if (buffer != g_cached) {
		free(buffer);
	}
}

static game_t* game_create(struct ev_loop_ctx* loop_ctx, int id, int type);
static void game_release(game_t* game);
static void game_update(struct ev_loop* loop, struct ev_timer* io, int revents);
static void game_init(game_t* game, int netd_num);
static int game_connect_netd(game_t* game, int index, int nonblock);
static void game_netd_handle_connect(game_t* game, int index, int fd);
static void game_netd_complete_connect(struct ev_connecter* connecter, int fd, const char* reason, void *userdata);
static void game_netd_read(struct ev_session* ev_session, void* ud);
static void game_netd_exit(netd_t* netd, const char* reason);
static void game_netd_error(struct ev_session* session, void* ud);
static void game_netd_release(netd_t* netd);
static void game_netd_send(game_t* game, int id, uint8_t* data, size_t sz);
static void game_netd_broadcast(game_t* game, uint8_t* data, size_t sz);
static void game_netd_handle_cmd(netd_t* netd, uint16_t cmd, stream_reader* reader);
static void game_netd_client_enter(netd_t* netd, stream_reader* reader);
static void game_netd_client_leave(netd_t* netd, stream_reader* reader);
static void game_netd_client_data(netd_t* netd, stream_reader* reader);
static void game_netd_update_login_master(netd_t* netd, stream_reader* reader);
static void game_netd_update_scene_master(netd_t* netd, stream_reader* reader);
static void game_netd_server_down(netd_t* netd, stream_reader* reader);
static void game_netd_server_repeat(netd_t* netd, stream_reader* reader);

typedef void(*netd_cmd_func)(netd_t* netd, stream_reader* reader);

static netd_cmd_func g_netd_cmd[] = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	game_netd_server_down,
	game_netd_server_repeat,
	game_netd_update_login_master,
	game_netd_update_scene_master,
	game_netd_client_enter,
	game_netd_client_leave,
	game_netd_client_data,
};


static game_t*
game_create(struct ev_loop_ctx* loop_ctx, int id, int type) {
	game_t* game = malloc(sizeof(*game));
	memset(game, 0, sizeof(*game));

	game->id = id;
	game->type = type;
	game->login_master_id = -1;
	game->scene_master_id = -1;

	game->loop_ctx = loop_ctx;

	game->timer.data = game;
	ev_timer_init(&game->timer, game_update, 0.01f, 0.01f);
	ev_timer_start(loop_ctx_get(game->loop_ctx), &game->timer);

	lua_State* L = luaL_newstate();
	luaL_openlibs(L);

	if (luaL_loadfile(L, "script/game.lua") != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(L, -1));
		exit(1);
	}

	if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(L, -1));
		exit(1);
	}

	game->L = L;

	g_game = game;
	return game;
}

static void
game_release(game_t* game) {
	lua_getglobal(game->L, "game_fina");
	if (lua_pcall(game->L, 0, 0, 0) != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(game->L, -1));
	}
	ev_timer_stop(loop_ctx_get(game->loop_ctx), (struct ev_timer*)&game->timer);

	int i;
	for (i = 0; i < kMAX_NETD; i++) {
		netd_t* netd = game->netd_slot[i];
		if (netd) {
			game_netd_release(netd);
		}
	}

	while (game->deadnetd) {
		netd_t* netd = game->deadnetd;
		game->deadnetd = netd->next;
		game_netd_release(netd);
	}

	lua_close(game->L);
	free(game);
}


static void
game_update(struct ev_loop* loop, struct ev_timer* io, int revents) {
	assert(revents & EV_TIMER);
	game_t* game = io->data;

	double now = loop_ctx_now(game->loop_ctx);
	if (now - game->last_update >= 1) {
		game->last_update = now;
		int i;
		for (i = 0; i < game->netd_num; i++) {
			netd_t* netd = game->netd_slot[i];
			if (netd) {
				continue;
			}
			struct ev_connecter* connecter = game->connecter_slot[i];
			if (connecter) {
				continue;
			}
			game_connect_netd(game, i, 1);
		}
	}

	while (game->deadnetd) {
		netd_t* netd = game->deadnetd;
		game->deadnetd = netd->next;
		game_netd_release(netd);
	}

	lua_getglobal(game->L, "game_update");
	if (lua_pcall(game->L, 0, 0, 0) != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(game->L, -1));
	}
}

static void
game_init(game_t* game, int netd_num) {
	game->netd_num = netd_num;
	int i;
	for (i = 0; i < game->netd_num; i++) {
		while (true) {
			if (game_connect_netd(game, i, 0) < 0) {
				usleep(1000 * 1000);
			} else {
				break;
			}
		}
	}

	for (i = 0; i < game->netd_num; i++) {
		netd_t* netd = game->netd_slot[i];
		if (!netd) {
			continue;
		}
		stream_writer writer = writer_init(64);
		write_uint32(&writer, 0);
		if (game->type == 0) {
			write_uint16(&writer, kCMD_SCENE_REGISTER);
			write_int32(&writer, netd->id);
		} else {
			write_uint16(&writer, kCMD_LOGIN_REGISTER);
			write_int32(&writer, netd->id);
		}
		game_netd_send(game, netd->id, writer.data, writer.offset);
	}

	lua_getglobal(game->L, "game_init");
	if (lua_pcall(game->L, 0, 0, 0) != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(game->L, -1));
	}
}

static int
game_connect_netd(game_t* game, int index, int nonblock) {
	union un_sockaddr sa;
	int addrlen = 0;
	memset(&sa, 0, sizeof(sa));

	if (g_conf.netd_ipc) {
		sa.su.sun_family = AF_UNIX;
		char ipc[kMAX_IPC] = { 0 };
		snprintf(ipc, kMAX_IPC, "%s%02d.ipc", g_conf.netd_ipc, index);
		strcpy(sa.su.sun_path, ipc);
		addrlen = sizeof(sa.su);
		fprintf(stderr, "connect netd:%s\n", sa.su.sun_path);
	} else {
		sa.si.sin_family = AF_INET;
		sa.si.sin_addr.s_addr = inet_addr(g_conf.netd_ip);
		sa.si.sin_port = htons(g_conf.netd_port + index);
		addrlen = sizeof(sa.si);
		fprintf(stderr, "connect netd:%s:%d\n", g_conf.netd_ip, g_conf.netd_port + index);
	}

	if (nonblock) {
		struct ev_connecter* connecter = ev_connecter_create(game->loop_ctx, (struct sockaddr*)&sa, addrlen, game_netd_complete_connect, (void*)&index);
		if (!connecter) {
			fprintf(stderr, "connect netd error:%s\n", strerror(errno));
			return -1;
		}
		game->connecter_slot[index] = connecter;
		return 0;
	} else {
		int status = 0;
		int fd = socket_connect((struct sockaddr*)&sa, addrlen, 0, &status);
		if (fd > 0) {
			game_netd_handle_connect(game, index, fd);
			return 0;
		}
	}
	return -1;
}

static void
game_netd_handle_connect(game_t* game, int index, int fd) {
	socket_nonblock(fd);
	socket_keep_alive(fd);
	socket_closeonexec(fd);

	netd_t* netd = malloc(sizeof(netd_t));
	memset(netd, 0, sizeof(*netd));

	netd->game = game;
	netd->session = ev_session_bind(game->loop_ctx, fd, 64, 1024 * 1024 * 64);
	netd->id = index;

	ev_session_setcb(netd->session, game_netd_read, NULL, game_netd_error, netd);
	ev_session_enable(netd->session, EV_READ);

	game->netd_slot[index] = netd;

	stream_writer writer = writer_init(64);
	write_uint32(&writer, 0);
	write_uint16(&writer, kCMD_REGISTER);
	write_int32(&writer, index);

	game_netd_send(game, index, writer.data, writer.offset);
}

static void
game_netd_complete_connect(struct ev_connecter* connecter, int fd, const char* reason, void *userdata) {
	g_game->connecter_slot[(int)(intptr_t)userdata] = NULL;
	//free connecter
	if (fd < 0) {
		fprintf(stderr, "connect netd:%d error:%s\n", (int)(intptr_t)userdata, reason);
		return;
	}
	game_netd_handle_connect(g_game, (int)(intptr_t)userdata, fd);
}

static void
game_netd_read(struct ev_session* ev_session, void* ud) {
	netd_t* netd = ud;
	while (netd->markdead == 0) {
		if (netd->need == 0) {
			size_t total = ev_session_input_size(netd->session);
			if (total < kNETD_HEADER) {
				return;
			}

			uint8_t stack[kNETD_HEADER] = { 0 };
			uint8_t* header = (uint8_t*)ev_session_read_peek(netd->session, kNETD_HEADER);
			if (!header) {
				ev_session_read(netd->session, (char*)stack, kNETD_HEADER);
				header = stack;
			}

			netd->need = header[0] | header[1] << 8;
			netd->need -= kNETD_HEADER;
		} else {
			size_t total = ev_session_input_size(netd->session);
			if (total < netd->need) {
				return;
			}

			int peekok = 1;
			uint8_t* data = (uint8_t*)ev_session_read_peek(netd->session, netd->need);
			if (!data) {
				peekok = 0;
				data = get_buffer(netd->need);
				ev_session_read(netd->session, (char*)data, netd->need);
			}

			uint16_t id = data[0] | data[1] << 8;
			stream_reader reader = reader_init(&data[2], netd->need - 2);
			game_netd_handle_cmd(netd, id, &reader);

			netd->need = 0;
			if (!peekok) {
				free_buffer(data);
			}
		}
	}
}

static void
game_netd_exit(netd_t* netd, const char* reason) {
	netd->markdead = 1;
	game_t* game = netd->game;
	netd->next = game->deadnetd;
	game->deadnetd = netd;
	if (netd->id >= 0) {
		game->netd_slot[netd->id] = NULL;
	}
}

static void
game_netd_error(struct ev_session* session, void* ud) {
	netd_t* netd = ud;
	game_netd_exit(netd, "netd error");
}

static void
game_netd_release(netd_t* netd) {
	ev_session_free(netd->session);
	free(netd);
}

static void
game_netd_send(game_t* game, int id, uint8_t* data, size_t sz) {
	netd_t* netd = game->netd_slot[id];
	if (!netd) {
		fprintf(stderr, "no netd:%d found\n", id);
		free(data);
		return;
	}
	*(int*)data = sz;
	ev_session_write(netd->session, (char*)data, sz);
}

static void
game_netd_broadcast(game_t* game, uint8_t* data, size_t sz) {
	*(int*)data = sz;
	int i;
	for (i = 0; i < kMAX_NETD; i++) {
		netd_t* netd = game->netd_slot[i];
		if (!netd) {
			continue;
		}
		char* copy = malloc(sz);
		memcpy(copy, data, sz);
		ev_session_write(netd->session, copy, sz);
	}
	free(data);
}

static void
game_netd_handle_cmd(netd_t* netd, uint16_t cmd, stream_reader* reader) {
	printf("handle netd cmd:%d\n", cmd);
	g_netd_cmd[cmd](netd, reader);
}

static void
game_netd_client_enter(netd_t* netd, stream_reader* reader) {
	game_t* game = netd->game;

	uint32_t client_id = read_uint32(reader);
	size_t sz = 0;
	char* addr = read_string(reader, &sz);

	lua_getglobal(game->L, "client_enter");
	lua_pushinteger(game->L, client_id);
	lua_pushstring(game->L, addr);
	if (lua_pcall(game->L, 2, 0, 0) != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(game->L, -1));
	}
}

static void
game_netd_client_leave(netd_t* netd, stream_reader* reader) {
	game_t* game = netd->game;
	uint32_t client_id = read_uint32(reader);
	lua_getglobal(game->L, "client_leave");
	lua_pushinteger(game->L, client_id);
	if (lua_pcall(game->L, 1, 0, 0) != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(game->L, -1));
	}
}

static void
game_netd_client_data(netd_t* netd, stream_reader* reader) {
	game_t* game = netd->game;
	uint32_t client_id = read_uint32(reader);
	uint16_t message_id = read_uint16(reader);

	lua_getglobal(game->L, "client_data");
	lua_pushinteger(game->L, client_id);
	lua_pushinteger(game->L, message_id);
	lua_pushlightuserdata(game->L, reader->data + reader->offset);
	lua_pushinteger(game->L, reader->size + reader->offset);
	if (lua_pcall(game->L, 4, 0, 0) != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(game->L, -1));
	}
}

static void
game_netd_update_login_master(netd_t* netd, stream_reader* reader) {
	game_t* game = netd->game;
	uint32_t id = read_uint32(reader);
	if (game->login_master_id == id) {
		return;
	}
	game->login_master_id = id;

	lua_getglobal(game->L, "update_login_master");
	lua_pushinteger(game->L, id);
	if (lua_pcall(game->L, 1, 0, 0) != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(game->L, -1));
	}
}

static void
game_netd_update_scene_master(netd_t* netd, stream_reader* reader) {
	game_t* game = netd->game;
	uint32_t id = read_uint32(reader);
	if (game->scene_master_id == id) {
		return;
	}
	game->scene_master_id = id;

	lua_getglobal(game->L, "update_scene_master");
	lua_pushinteger(game->L, id);
	if (lua_pcall(game->L, 1, 0, 0) != LUA_OK) {
		fprintf(stderr, "%s\n", lua_tostring(game->L, -1));
	}
}

static void
game_netd_server_down(netd_t* netd, stream_reader* reader) {

}

static void
game_netd_server_repeat(netd_t* netd, stream_reader* reader) {
	uint32_t id = read_uint32(reader);
	fprintf(stderr, "game server:%d repeat\n", id);
	loop_ctx_break(netd->game->loop_ctx);
}

static void
init_conf(const char* file) {
	memset(&g_conf, 0, sizeof(g_conf));

	lua_State* L = luaL_newstate();
	if (luaL_loadfile(L, file) != LUA_OK) {
		fprintf(stderr, "load config:%s\n", lua_tostring(L, -1));
		exit(1);
	}

	if (lua_pcall(L, 0, 1, 0) != LUA_OK) {
		fprintf(stderr, "load config:%s\n", lua_tostring(L, -1));
		exit(1);
	}

	luaL_checktype(L, -1, LUA_TTABLE);

#define GET_CONF_INT(L, field, value) \
	lua_getfield(L, -1, #field);\
	if (lua_type(L, -1) == LUA_TNUMBER) {\
		g_conf.field = lua_tointeger(L, -1);\
			} else {\
		g_conf.field = value;\
			}\
	lua_pop(L, 1);\

#define GET_CONF_STR(L, field) \
	lua_getfield(L, -1, #field);\
	if (lua_type(L, -1) == LUA_TSTRING) {\
		g_conf.field = strdup(lua_tostring(L, -1));\
			}\
	lua_pop(L, 1);\

	GET_CONF_INT(L, id, 1);
	GET_CONF_INT(L, type, 1);
	GET_CONF_INT(L, netd_num, 1);
	GET_CONF_STR(L, netd_ip);
	GET_CONF_INT(L, netd_port, 9999);
	GET_CONF_STR(L, netd_ipc);

#undef GET_CONF_INT
#undef GET_CONF_STR
	lua_close(L);
}

int main(int argc, const char* argv[]) {
	assert(argc == 2);
	init_conf(argv[1]);

	struct ev_loop_ctx* loop_ctx = loop_ctx_create();

	game_t* game = game_create(loop_ctx, g_conf.id, g_conf.type);
	game_init(game, g_conf.netd_num);
	loop_ctx_dispatch(loop_ctx);

	game_release(game);
	return 0;
}
