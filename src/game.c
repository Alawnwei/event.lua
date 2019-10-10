#include "game.h"
#include "stream.h"
#include "lua.h"
#include "lauxlib.h"
#include "socket/socket_tcp.h"
#include "common/encrypt.h"
#include "common/object_container.h"
#include <stdint.h>

#define kCACHED   1024 * 1024
#define kERROR    64
#define kMAX_NETD 16
#define kMAX_IPC  64
#define kNETD_HEADER 4

struct netd;

typedef struct game {
	int id;
	int type;
	int login_master_id;
	int scene_master_id;

	struct ev_loop_ctx* loop_ctx;
	struct ev_timer timer;

	struct ev_connecter* connecter_slot[kMAX_NETD];
	struct netd* netd_slot[kMAX_NETD];

	char error[kERROR];

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

static game_t* game_create(int id, int type);
static void game_release(game_t* game);
static void game_update(struct ev_loop* loop, struct ev_timer* io, int revents);
static void game_init(game_t* game);
static int game_connect_netd(game_t* game, int index, int nonblock);
static void game_netd_handle_connect(game_t* game, int index, int fd);
static void game_netd_complete_connect(struct ev_connecter* connecter, int fd, const char* reason, void *userdata);
static void game_netd_read(struct ev_session* ev_session, void* ud);
static void game_netd_exit(netd_t* netd, const char* reason);
static void game_netd_error(struct ev_session* session, void* ud);
static void game_netd_release(netd_t* netd);
static void game_netd_handle_cmd(netd_t* netd, uint16_t cmd, stream_reader* reader);

typedef void(*netd_cmd_func)(netd_t* netd, stream_reader* reader);

static netd_cmd_func g_netd_cmd[] = {

};


static game_t*
game_create(int id, int type) {
	game_t* game = malloc(sizeof(*game));
	memset(game, 0, sizeof(*game));

	game->id = id;
	game->type = type;
	game->login_master_id = -1;
	game->scene_master_id = -1;

	game->timer.data = game;
	ev_timer_init(&game->timer, game_update, 0.01f, 0.01f);
	ev_timer_start(loop_ctx_get(game->loop_ctx), &game->timer);

	g_game = game;
	return game;
}

static void
game_release(game_t* game) {
	ev_timer_stop(loop_ctx_get(game->loop_ctx), (struct ev_timer*)&game->timer);
	free(game);
}


static void
game_update(struct ev_loop* loop, struct ev_timer* io, int revents) {
	assert(revents & EV_TIMER);
	game_t* game = io->data;
}

static void
game_init(game_t* game) {
	int i;
	for (i = 0; i < g_conf.netd_num; i++) {
		while (true) {
			if (game_connect_netd(game, i, 0) < 0) {
				usleep(1000 * 1000);
			} else {
				break;
			}
		}
	}
}

static int
game_connect_netd(game_t* game, int index, int nonblock) {
	union un_sockaddr sa;
	int addrlen = 0;
	memset(&sa, 0, sizeof(sa));

	if (g_conf.netd_ipc) {
		sa.su.sun_family = AF_UNIX;
		char ipc[kMAX_NETD] = { 0 };
		snprintf(ipc, kMAX_NETD, "%s%02d.ipc", g_conf.netd_ipc, index);
		strcpy(sa.su.sun_path, ipc);
		addrlen = sizeof(sa.su);
	} else {
		sa.si.sin_family = AF_INET;
		sa.si.sin_addr.s_addr = inet_addr(g_conf.netd_ip);
		sa.si.sin_port = htons(g_conf.netd_port + index);
		addrlen = sizeof(sa.si);
	}

	if (nonblock) {
		game->connecter_slot[index] = ev_connecter_create(game->loop_ctx, (struct sockaddr*)&sa, addrlen, game_netd_complete_connect, index);
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
}

static void
game_netd_complete_connect(struct ev_connecter* connecter, int fd, const char* reason, void *userdata) {
	if (fd < 0) {
		fprintf(stderr, "connect netd:%d error:%s\n", (int)userdata, reason);
		return;
	}
	game_netd_handle_connect(g_game, (int)userdata, fd);
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
		game->netd_slot[game->id] = NULL;
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
game_netd_handle_cmd(netd_t* netd, uint16_t cmd, stream_reader* reader) {
	printf("handle netd cmd:%d\n", cmd);
	g_netd_cmd[cmd](netd, reader);
}


int main(int argc, const char* argv[]) {
	assert(argc == 2);

	struct ev_loop_ctx* loop_ctx = loop_ctx_create();

	game_t* game = game_create(1, 1);

	loop_ctx_dispatch(loop_ctx);

	game_release(game);
	return 0;
}
