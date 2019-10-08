#include "netd.h"
#include "common/encrypt.h"
#include "common/object_container.h"

#define CACHED_SIZE 		1024 * 1024
#define WARN_OUTPUT_FLOW 	1024 * 10
#define MAX_PACKET_SIZE		1024 * 6
#define HEADER_SIZE			2
#define ERROR_SIZE 			64

#define SLOT(id,max) (id - (id / max) * max)

struct client;

typedef struct netd {
	struct ev_loop_ctx* loop_ctx;
	struct ev_listener* listener;
	struct ev_timer timer;

	struct object_container* container;
	uint32_t max_client;
	uint32_t count;

	uint32_t max_offset;
	uint32_t max_index;
	uint32_t index;

	uint32_t max_freq;
	uint32_t timeout;

	char error[ERROR_SIZE];

	void* userdata;

	client_enter_cb enter_cb;
	client_leave_cb leave_cb;
	client_message_cb message_cb;

	struct client* deadclient;
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
	struct client* next;
} client_t;

static void netd_update(struct ev_loop* loop, struct ev_timer* io, int revents);
static void netd_client_accept(struct ev_listener *listener, int fd, const char* addr, void *ud);
static void netd_client_read(struct ev_session* ev_session, void* ud);
static void netd_client_exit(client_t* client, const char* reason);
static void netd_client_error(struct ev_session* session, void* ud);
static void netd_client_release(int id, void* data);
static void netd_client_update(struct ev_loop* loop, struct ev_timer* io, int revents);
static void netd_close_client_complete(struct ev_session* ev_session, void* ud);
static void netd_close_client_error(struct ev_session* session, void* ud);

__thread uint8_t t_cached[CACHED_SIZE];

static inline uint8_t*
get_buffer(uint32_t size) {
	uint8_t* data = t_cached;
	if (size > CACHED_SIZE) {
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
netd_create(struct ev_loop_ctx* loop_ctx, netd_create_opts* opts) {
	netd_t* netd = malloc(sizeof(*netd));
	memset(netd, 0, sizeof(*netd));

	netd->max_client = opts->max_client;
	if (netd->max_client < 1) {
		netd->max_client = 1000;
	}

	netd->max_freq = opts->max_client;
	if (netd->max_freq < 1) {
		netd->max_freq = 100;
	}

	netd->timeout = opts->timeout;
	if (netd->timeout < 1) {
		netd->timeout = 60;
	}

	netd->userdata = opts->userdata;

	netd->enter_cb = opts->enter_cb;
	netd->leave_cb = opts->leave_cb;
	netd->message_cb = opts->message_cb;

	netd->container = container_create(netd->max_client);
	netd->loop_ctx = loop_ctx;
	netd->count = 0;

	netd->max_offset = 1;

	uint32_t max_client = netd->max_client;
	while (max_client > 0) {
		max_client /= 10;
		netd->max_offset *= 10;
	}

	netd->index = 1;
	netd->max_index = 0xffffffff / netd->max_offset;

	return netd;
}

void
netd_release(netd_t* netd) {
	netd_stop(netd);
	container_foreach(netd->container, netd_client_release);
	container_release(netd->container);
	free(netd);
}

int
netd_start(netd_t* netd, const char* ip, int port) {
	struct sockaddr_in si;
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = inet_addr(ip);
	si.sin_port = htons(port);

	int flag = SOCKET_OPT_NOBLOCK | SOCKET_OPT_CLOSE_ON_EXEC | SOCKET_OPT_REUSEABLE_ADDR;
	netd->listener = ev_listener_create(netd->loop_ctx, (struct sockaddr*)&si, sizeof(si), 16, flag, netd_client_accept, netd);
	if (!netd->listener) {
		return -1;
	}

	netd->timer.data = netd;
	ev_timer_init(&netd->timer, netd_update, 0.1f, 0.1f);
	ev_timer_start(loop_ctx_get(netd->loop_ctx), &netd->timer);

	if (port == 0) {
		char addr[INET6_ADDRSTRLEN] = { 0 };
		if (ev_listener_addr(netd->listener, addr, INET6_ADDRSTRLEN, &port) < 0) {
			return port;
		}
	}
	return port;
}

int
netd_stop(netd_t* netd) {
	if (netd->listener == NULL) {
		return -1;
	}

	ev_listener_free(netd->listener);
	netd->listener = NULL;
	ev_timer_stop(loop_ctx_get(netd->loop_ctx), (struct ev_timer*)&netd->timer);
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
}

client_t*
netd_get_client(netd_t* netd, uint32_t id) {
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
netd_close_client(netd_t* netd, uint32_t client_id, int grace) {
	client_t* client = netd_get_client(netd, client_id);
	if (!client) {
		return -1;
	}

	if (!grace) {
		netd_client_exit(client, "server close");
	} else {
		client->markdead = 1;
		ev_session_setcb(client->session, NULL, netd_close_client_complete, netd_close_client_error, client);
		ev_session_enable(client->session, EV_WRITE);
		ev_session_disable(client->session, EV_READ);
	}
	return 0;
}

int
netd_send_client(netd_t* netd, uint32_t client_id, void* data, size_t size) {
	client_t* client = netd_get_client(netd, client_id);
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

	ev_session_setcb(client->session, netd_client_read, NULL, netd_client_error, client);
	ev_session_enable(client->session, EV_READ);

	client->timer.data = client;
	ev_timer_init(&client->timer, netd_client_update, 1, 1);
	ev_timer_start(loop_ctx_get(netd->loop_ctx), &client->timer);

	netd->enter_cb(netd->userdata, client->id, addr);
}

static void
netd_client_read(struct ev_session* ev_session, void* ud) {
	client_t* client = ud;
	for (;;) {
		if (client->need == 0) {
			size_t total = ev_session_input_size(client->session);
			if (total < HEADER_SIZE) {
				return;
			}

			uint8_t stack[HEADER_SIZE] = { 0 };

			uint8_t* header = (uint8_t*)ev_session_read_peek(client->session, HEADER_SIZE);
			if (!header) {
				ev_session_read(client->session, (char*)stack, HEADER_SIZE);
				header = stack;
			}

			client->need = header[0] | header[1] << 8;
			client->need -= HEADER_SIZE;

			if (client->need > MAX_PACKET_SIZE) {
				snprintf(client->netd->error, ERROR_SIZE, "client packet size:%d too much", client->need);
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

			client->netd->message_cb(client->netd->userdata, client->id, &data[4], client->need - 4);

			client->need = 0;

			free_buffer(data);
		}
	}
}

static void
netd_client_exit(client_t* client, const char* reason) {
	client->markdead = 1;
	netd_t* netd = client->netd;
	client->next = netd->deadclient;
	netd->deadclient = client;

	netd->leave_cb(netd->userdata, client->id, reason);
}

static void
netd_client_error(struct ev_session* session, void* ud) {
	client_t* client = ud;
	netd_client_exit(client, "client error");
}

static void
netd_close_client_complete(struct ev_session* ev_session, void* ud) {
	client_t* client = ud;
	netd_client_exit(client, "server close client success");
}

static void
netd_close_client_error(struct ev_session* session, void* ud) {
	client_t* client = ud;
	netd_client_exit(client, "server close client error");
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

	if (ev_session_output_size(client->session) > WARN_OUTPUT_FLOW) {
		fprintf(stderr, "client:%d more then %dkb flow need to send out\n", client->id, WARN_OUTPUT_FLOW / 1024);
	}

	if (client->freq > client->netd->max_freq) {
		snprintf(client->netd->error, ERROR_SIZE, "client receive message too much:%d in last 1s", client->freq);
		netd_client_exit(client, client->netd->error);
	} else {
		client->freq = 0;
		if (client->tick != 0 && loop_ctx_now(client->netd->loop_ctx) - client->tick > client->netd->timeout) {
			netd_client_exit(client, "client timeout");
		}
	}
}