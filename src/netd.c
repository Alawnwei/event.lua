#include "netd.h"
#include "stream.h"
#include "common/encrypt.h"
#include "common/object_container.h"


#define kCACHED      		1024 * 1024
#define kWARN_OUTPUT_FLOW 	1024 * 10
#define kMAX_PACKET_SIZE    1024 * 6
#define kCLIENT_HEADER      2
#define kSERVER_HEADER      4
#define kERROR              64
#define kMAX_SERVER         64


#define SLOT(id,max) (id - (id / max) * max)

struct client;
struct server;

typedef struct netd {
	struct ev_loop_ctx* loop_ctx;
	struct ev_timer timer;
	struct ev_listener* client_listener;
	struct ev_listener* server_listener;

	struct object_container* container;
	uint32_t max_client;
	uint32_t count;

	uint32_t max_offset;
	uint32_t max_index;
	uint32_t index;

	uint32_t max_freq;
	uint32_t timeout;

	struct server* server_slot[kMAX_SERVER];

	int login_master_id;
	int scene_master_id;

	char error[kERROR];

	struct client* deadclient;

	struct server* deadserver;
} netd_t;

typedef struct client {
	netd_t* netd;
	struct ev_session* session;
	struct ev_timer timer;
	uint32_t id;
	uint32_t countor;
	uint32_t need;
	uint32_t freq;
	uint16_t seed;
	double tick;
	int markdead;
	int server_id;
	struct client* next;
} client_t;

typedef struct server {
	netd_t* netd;
	struct ev_session* session;
	int id;
	int markdead;
	uint32_t need;
	struct server* next;
} server_t;

typedef void(*server_cmd_func)(server_t* server, stream_reader* reader);

static void netd_update(struct ev_loop* loop, struct ev_timer* io, int revents);
static void netd_client_accept(struct ev_listener *listener, int fd, const char* addr, void *ud);
static void netd_client_read(struct ev_session* ev_session, void* ud);
static void netd_client_exit(client_t* client, const char* reason);
static void netd_client_error(struct ev_session* session, void* ud);
static void netd_client_release(int id, void* data);
static void netd_client_update(struct ev_loop* loop, struct ev_timer* io, int revents);
static void netd_client_close_complete(struct ev_session* ev_session, void* ud);
static void netd_client_handle_message(client_t* client, uint16_t message_id, uint8_t* data, size_t sz);

static void netd_server_accept(struct ev_listener *listener, int fd, const char* addr, void *ud);
static void netd_server_read(struct ev_session* ev_session, void* ud);
static void netd_server_exit(server_t* server, const char* reason);
static void netd_server_error(struct ev_session* session, void* ud);
static void netd_server_release(server_t* server);
static void netd_server_send(netd_t* netd, int server_id, uint8_t* data, size_t sz);
static void netd_server_broadcast(netd_t* netd, uint8_t* data, size_t sz);
static void netd_server_handle_cmd(server_t* server, uint16_t cmd, stream_reader* reader);
static void netd_server_register(server_t* server, stream_reader* reader);
static void netd_server_login_master_register(server_t* server, stream_reader* reader);
static void netd_server_scene_master_register(server_t* server, stream_reader* reader);
static void netd_server_set_server_id(server_t* server, stream_reader* reader);
static void netd_server_client_send(server_t* server, stream_reader* reader);
static void netd_server_client_broadcast(server_t* server, stream_reader* reader);
static void netd_server_client_close(server_t* server, stream_reader* reader);

static server_cmd_func g_server_cmd[] = {
	NULL,
	netd_server_login_master_register,
	netd_server_scene_master_register,
	netd_server_set_server_id,
	netd_server_client_send,
	netd_server_client_broadcast,
	netd_server_client_close,
};

__thread uint8_t t_cached[kCACHED];

static inline uint8_t*
get_buffer(uint32_t size) {
	uint8_t* data = t_cached;
	if (size > kCACHED) {
		data = malloc(size);
	}
	return data;
}

static inline void
free_buffer(uint8_t* buffer) {
	if (buffer != t_cached) {
		free(buffer);
	}
}

netd_t*
netd_create(struct ev_loop_ctx* loop_ctx, uint32_t max_client, uint32_t max_freq, uint32_t timeout) {
	netd_t* netd = malloc(sizeof(*netd));
	memset(netd, 0, sizeof(*netd));

	netd->max_client = max_client;
	if (netd->max_client < 1) {
		netd->max_client = 1000;
	}

	netd->max_freq = max_freq;
	if (netd->max_freq < 1) {
		netd->max_freq = 100;
	}

	netd->timeout = timeout;
	if (netd->timeout < 1) {
		netd->timeout = 60;
	}

	netd->container = container_create(netd->max_client);
	netd->loop_ctx = loop_ctx;
	netd->count = 0;

	netd->max_offset = 1;

	max_client = netd->max_client;
	while (max_client > 0) {
		max_client /= 10;
		netd->max_offset *= 10;
	}

	netd->index = 1;
	netd->max_index = 0xffffffff / netd->max_offset;

	netd->timer.data = netd;
	ev_timer_init(&netd->timer, netd_update, 0.1f, 0.1f);
	ev_timer_start(loop_ctx_get(netd->loop_ctx), &netd->timer);

	return netd;
}

void
netd_release(netd_t* netd) {
	netd_client_stop(netd);
	netd_server_stop(netd);
	container_foreach(netd->container, netd_client_release);
	container_release(netd->container);
	free(netd);
}

int
netd_client_start(netd_t* netd, const char* ip, int port) {
	struct sockaddr_in si;
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = inet_addr(ip);
	si.sin_port = htons(port);

	int flag = SOCKET_OPT_NOBLOCK | SOCKET_OPT_CLOSE_ON_EXEC | SOCKET_OPT_REUSEABLE_ADDR;
	netd->client_listener = ev_listener_create(netd->loop_ctx, (struct sockaddr*)&si, sizeof(si), 16, flag, netd_client_accept, netd);
	if (!netd->client_listener) {
		return -1;
	}

	if (port == 0) {
		char addr[INET6_ADDRSTRLEN] = { 0 };
		if (ev_listener_addr(netd->client_listener, addr, INET6_ADDRSTRLEN, &port) < 0) {
			return port;
		}
	}
	return port;
}

int
netd_client_stop(netd_t* netd) {
	if (netd->client_listener == NULL) {
		return -1;
	}

	ev_listener_free(netd->client_listener);
	return 0;
}

static void
netd_update(struct ev_loop* loop, struct ev_timer* io, int revents) {
	assert(revents & EV_TIMER);
	netd_t* netd = io->data;
	while (netd->deadclient) {
		client_t* client = netd->deadclient;
		netd->deadclient = client->next;
		netd_client_release(client->id, client);
	}

	while (netd->deadserver) {
		server_t* server = netd->deadserver;
		netd->deadserver = server->next;
		netd_server_release(server);
	}
}

client_t*
netd_client_get(netd_t* netd, uint32_t id) {
	uint32_t slot = SLOT(id, netd->max_offset);
	client_t* client = container_get(netd->container, slot);
	if (!client || client->id != id) {
		return NULL;
	}

	if (client->markdead == 1) {
		return NULL;
	}
	return client;
}

int
netd_client_close(netd_t* netd, uint32_t client_id, int grace) {
	client_t* client = netd_client_get(netd, client_id);
	if (!client) {
		return -1;
	}

	if (!grace) {
		netd_client_exit(client, "server close");
	} else {
		client->markdead = 1;
		ev_session_setcb(client->session, NULL, netd_client_close_complete, netd_client_error, client);
		ev_session_enable(client->session, EV_WRITE);
		ev_session_disable(client->session, EV_READ);
	}
	return 0;
}

int
netd_client_send(netd_t* netd, uint32_t client_id, void* data, size_t size) {
	client_t* client = netd_client_get(netd, client_id);
	if (!client) {
		return -1;
	}
	ev_session_write(client->session, data, size);
	return 0;
}

static void
netd_client_accept(struct ev_listener *listener, int fd, const char* addr, void *ud) {
	netd_t* netd = ud;

	if (netd->count >= netd->max_client) {
		close(fd);
		return;
	}

	netd->count++;

	socket_nonblock(fd);
	socket_keep_alive(fd);
	socket_closeonexec(fd);

	client_t* client = malloc(sizeof(*client));
	memset(client, 0, sizeof(*client));

	struct ev_session* session = ev_session_bind(netd->loop_ctx, fd, 64, 1024 * 64);
	int slot = container_add(netd->container, client);

	uint32_t index = netd->index++;
	if (index >= netd->max_index) {
		netd->index = 1;
	}

	client->netd = netd;
	client->session = session;
	client->id = index * netd->max_offset + slot;
	client->server_id = netd->login_master_id;

	ev_session_setcb(client->session, netd_client_read, NULL, netd_client_error, client);
	ev_session_enable(client->session, EV_READ);

	client->timer.data = client;
	ev_timer_init(&client->timer, netd_client_update, 1, 1);
	ev_timer_start(loop_ctx_get(netd->loop_ctx), &client->timer);
}

static void
netd_client_read(struct ev_session* ev_session, void* ud) {
	client_t* client = ud;
	for (;;) {
		if (client->need == 0) {
			size_t total = ev_session_input_size(client->session);
			if (total < kCLIENT_HEADER) {
				return;
			}

			uint8_t stack[kCLIENT_HEADER] = { 0 };

			uint8_t* header = (uint8_t*)ev_session_read_peek(client->session, kCLIENT_HEADER);
			if (!header) {
				ev_session_read(client->session, (char*)stack, kCLIENT_HEADER);
				header = stack;
			}

			client->need = header[0] | header[1] << 8;
			client->need -= kCLIENT_HEADER;

			if (client->need > kMAX_PACKET_SIZE) {
				snprintf(client->netd->error, kERROR, "client packet size:%d too much", client->need);
				netd_client_exit(client, client->netd->error);
				return;
			}
		} else {
			size_t total = ev_session_input_size(client->session);
			if (total < client->need) {
				return;
			}

			uint8_t* data = (uint8_t*)ev_session_read_peek(client->session, client->need);
			if (!data) {
				data = get_buffer(client->need);
				ev_session_read(client->session, (char*)data, client->need);
			}
			if (message_decrypt(&client->seed, data, client->need) < 0) {
				free_buffer(data);
				netd_client_exit(client, "client message decrypt error");
				return;
			}

			uint16_t id = data[2] | data[3] << 8;

			client->freq++;
			client->tick = loop_ctx_now(client->netd->loop_ctx);

			netd_client_handle_message(client, id, &data[4], client->need - 4);

			client->need = 0;

			free_buffer(data);
		}
	}
}

static void netd_client_handle_message(client_t* client, uint16_t message_id, uint8_t* data, size_t sz) {

}

static void
netd_client_exit(client_t* client, const char* reason) {
	client->markdead = 1;
	netd_t* netd = client->netd;
	client->next = netd->deadclient;
	netd->deadclient = client;
}

static void
netd_client_error(struct ev_session* session, void* ud) {
	client_t* client = ud;
	netd_client_exit(client, "client error");
}

static void
netd_client_close_complete(struct ev_session* ev_session, void* ud) {
	client_t* client = ud;
	netd_client_exit(client, "server close client success");
}

static void
netd_client_release(int id, void* data) {
	client_t* client = data;
	ev_session_free(client->session);
	ev_timer_stop(loop_ctx_get(client->netd->loop_ctx), (struct ev_timer*)&client->timer);
	uint32_t slot = SLOT(client->id, client->netd->max_offset);
	container_remove(client->netd->container, slot);
	client->netd->count--;
	free(client);
}

static void
netd_client_update(struct ev_loop* loop, struct ev_timer* io, int revents) {
	assert(revents & EV_TIMER);
	client_t* client = io->data;

	if (ev_session_output_size(client->session) > kWARN_OUTPUT_FLOW) {
		fprintf(stderr, "client:%d more then %dkb flow need to send out\n", client->id, kWARN_OUTPUT_FLOW / 1024);
	}

	if (client->freq > client->netd->max_freq) {
		snprintf(client->netd->error, kERROR, "client receive message too much:%d in last 1s", client->freq);
		netd_client_exit(client, client->netd->error);
	} else {
		client->freq = 0;
		if (client->tick != 0 && loop_ctx_now(client->netd->loop_ctx) - client->tick > client->netd->timeout) {
			netd_client_exit(client, "client timeout");
		}
	}
}

int
netd_server_start(netd_t* netd, const char* file) {
	unlink(file);
	struct sockaddr_un un;
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, file);

	int flag = SOCKET_OPT_NOBLOCK | SOCKET_OPT_CLOSE_ON_EXEC;
	netd->server_listener = ev_listener_create(netd->loop_ctx, (struct sockaddr*)&un, sizeof(un), 16, flag, netd_server_accept, netd);
	if (!netd->server_listener) {
		return -1;
	}
	return 0;
}

int
netd_server_stop(netd_t* netd) {
	if (netd->server_listener == NULL) {
		return -1;
	}

	ev_listener_free(netd->server_listener);
	return 0;
}

static void
netd_server_send(netd_t* netd, int server_id, uint8_t* data, size_t sz) {
	server_t* server = netd->server_slot[server_id];
	if (!server) {
		return;
	}
	ev_session_write(server->session, (char*)data, sz);
}

static void
netd_server_broadcast(netd_t* netd, uint8_t* data, size_t sz) {
	int i;
	for (i = 0; i < kMAX_SERVER; i++) {
		server_t* server = netd->server_slot[i];
		if (!server) {
			continue;
		}
		ev_session_write(server->session, (char*)data, sz);
	}
}

static void
netd_server_accept(struct ev_listener *listener, int fd, const char* addr, void *ud) {
	netd_t* netd = ud;

	socket_nonblock(fd);
	socket_keep_alive(fd);
	socket_closeonexec(fd);

	server_t* server = malloc(sizeof(*server));
	memset(server, 0, sizeof(*server));

	struct ev_session* session = ev_session_bind(netd->loop_ctx, fd, 64, 1024 * 1024 * 64);

	server->netd = netd;
	server->session = session;
	server->id = -1;

	ev_session_setcb(server->session, netd_server_read, NULL, netd_server_error, server);
	ev_session_enable(server->session, EV_READ);
}

static void
netd_server_read(struct ev_session* ev_session, void* ud) {
	server_t* server = ud;
	for (;;) {
		if (server->need == 0) {
			size_t total = ev_session_input_size(server->session);
			if (total < kSERVER_HEADER) {
				return;
			}

			uint8_t stack[kSERVER_HEADER] = { 0 };

			uint8_t* header = (uint8_t*)ev_session_read_peek(server->session, kSERVER_HEADER);
			if (!header) {
				ev_session_read(server->session, (char*)stack, kSERVER_HEADER);
				header = stack;
			}

			server->need = header[0] | header[1] << 8;
			server->need -= kSERVER_HEADER;

			if (server->need > kMAX_PACKET_SIZE) {
				snprintf(server->netd->error, kERROR, "server packet size:%d too much", server->need);
				netd_server_exit(server, server->netd->error);
				return;
			}
		} else {
			size_t total = ev_session_input_size(server->session);
			if (total < server->need) {
				return;
			}

			uint8_t* data = (uint8_t*)ev_session_read_peek(server->session, server->need);
			if (!data) {
				data = get_buffer(server->need);
				ev_session_read(server->session, (char*)data, server->need);
			}

			uint16_t id = data[2] | data[3] << 8;
			stream_reader reader = reader_init(&data[4], server->need - 4);
			netd_server_handle_cmd(server, id, &reader);

			server->need = 0;
			free_buffer(data);
		}
	}
}

static void
netd_server_exit(server_t* server, const char* reason) {
	server->markdead = 1;
	netd_t* netd = server->netd;
	server->next = netd->deadserver;
	netd->deadserver = server;
	if (server->id >= 0) {
		netd->server_slot[server->id] = NULL;
	}
}

static void
netd_server_error(struct ev_session* session, void* ud) {
	server_t* server = ud;
	netd_server_exit(server, "server error");
}

static void
netd_server_release(server_t* server) {
	ev_session_free(server->session);
	free(server);
}

static void
netd_server_handle_cmd(server_t* server, uint16_t cmd, stream_reader* reader) {
	if (server->id < 0) {
		assert(cmd == kCMD_REGISTER);
		netd_server_register(server, reader);
		return;
	}
	g_server_cmd[cmd](server, reader);
}

static void
netd_server_register(server_t* server, stream_reader* reader) {
	int id = read_int32(reader);
	if (server->netd->server_slot[id] || id >= kMAX_SERVER) {
		return;
	}
	server->id = id;
	server->netd->server_slot[id] = server;
}

static void
netd_server_login_master_register(server_t* server, stream_reader* reader) {
	int id = read_int32(reader);
	assert(id == server->id);
	if (server->netd->login_master_id >= 0) {
		stream_writer writer = writer_init(64);
		write_uint32(&writer, 0);
		write_uint16(&writer, kCMD_UPDATE_LOGIN_MASTER);
		write_uint32(&writer, server->netd->login_master_id);
		netd_server_send(server->netd, server->id, writer.data, writer.offset);
	} else {
		server->netd->login_master_id = id;
		stream_writer writer = writer_init(64);
		write_uint32(&writer, 0);
		write_uint16(&writer, kCMD_UPDATE_LOGIN_MASTER);
		write_uint32(&writer, server->netd->login_master_id);
		netd_server_broadcast(server->netd, writer.data, writer.offset);
	}
	
}

static void
netd_server_scene_master_register(server_t* server, stream_reader* reader) {
	int id = read_int32(reader);
	assert(id == server->id);
	if (server->netd->scene_master_id >= 0) {
		stream_writer writer = writer_init(64);
		write_uint32(&writer, 0);
		write_uint16(&writer, kCMD_UPDATE_SCENE_MASTER);
		write_uint32(&writer, server->netd->scene_master_id);
		netd_server_send(server->netd, server->id, writer.data, writer.offset);
	} else {
		server->netd->scene_master_id = id;
		stream_writer writer = writer_init(64);
		write_uint32(&writer, 0);
		write_uint16(&writer, kCMD_UPDATE_SCENE_MASTER);
		write_uint32(&writer, server->netd->scene_master_id);
		netd_server_broadcast(server->netd, writer.data, writer.offset);
	}
}

static void
netd_server_set_server_id(server_t* server, stream_reader* reader) {
	netd_t* netd = server->netd;
	uint32_t client_id = read_uint32(reader);
	int server_id = read_int32(reader);

	client_t* client = netd_client_get(netd, client_id);
	if (!client) {
		return;
	}
	client->server_id = server_id;
}

static void
netd_server_client_send(server_t* server, stream_reader* reader) {

}

static void
netd_server_client_broadcast(server_t* server, stream_reader* reader) {

}

static void
netd_server_client_close(server_t* server, stream_reader* reader) {
	netd_t* netd = server->netd;
	uint32_t client_id = read_uint32(reader);
	client_t* client = netd_client_get(netd, client_id);
	if (!client) {
		return;
	}
	netd_client_close(netd, client_id, 1);
}

