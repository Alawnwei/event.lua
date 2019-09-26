#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <math.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "lstate.h"

#include "socket/gate.h"
#include "common/encrypt.h"

#define CACHED_SIZE 		1024 * 1024
#define WARN_OUTPUT_FLOW 	1024 * 10
#define MAX_PACKET_SIZE		1024 * 6
#define HEADER_SIZE			2
#define ERROR_SIZE 			64

#define SLOT(id,max) (id - (id / max) * max)


struct gate {
	struct ev_loop_ctx* loop_ctx;
	struct ev_listener* listener;

	struct object_container* container;
	uint32_t max_client;
	uint32_t count;

	uint32_t max_offset;
	uint32_t max_index;
	uint32_t index;

	uint32_t max_freq;
	uint32_t timeout;

	char error[ERROR_SIZE];

	accept_callback accept;
	close_callback close;
	data_callback data;
	void* ud;
};

typedef struct client {
	gate_t* gate;
	struct ev_session* session;
	struct ev_timer timer;
	uint32_t id;
	uint32_t countor;
	uint32_t need;
	uint32_t freq;
	uint16_t seed;
	double tick;
	int markdead;
} client_t;

__thread uint8_t CACHED_BUFFER[CACHED_SIZE];

static void
close_client(int id, void* data) {
	client_t* client = data;
	ev_session_free(client->session);
	ev_timer_stop(loop_ctx_get(client->gate->loop_ctx), (struct ev_timer*)&client->timer);
	uint32_t slot = SLOT(client->id, client->gate->max_offset);
	container_remove(client->gate->container, slot);
	client->gate->count--;
	free(client);
}

static inline void
grab_client(client_t* client) {
	client->countor++;
}

static inline void
release_client(client_t* client) {
	client->countor--;
	if (client->countor == 0) {
		close_client(0, client);
	}
}

static inline client_t*
get_client(gate_t* gate, uint32_t id) {
	uint32_t slot = SLOT(id, gate->max_offset);
	client_t* client = container_get(gate->container, slot);
	if (!client || client->id != id) {
		return NULL;
	}

	if (client->markdead == 1) {
		return NULL;
	}
	return client;
}

static inline uint8_t*
get_buffer(uint32_t size) {
	uint8_t* data = CACHED_BUFFER;
	if (size > CACHED_SIZE) {
		data = malloc(size);
	}
	return data;
}

static inline void
free_buffer(uint8_t* buffer) {
	if (buffer != CACHED_BUFFER) {
		free(buffer);
	}
}

static void
client_exit(client_t* client, const char* reason) {
	client->markdead = 1;
	gate_t* gate = client->gate;
	gate->close(gate->ud, client->id, reason);
	release_client(client);
}

static void
client_error(struct ev_session* session, void* ud) {
	client_t* client = ud;
	client_exit(client, "client error");
}

static int
read_header(client_t* client) {
	size_t total = ev_session_input_size(client->session);
	if (total < HEADER_SIZE) {
		return -1;
	}

	uint8_t header[HEADER_SIZE];
	ev_session_read(client->session, (char*)header, HEADER_SIZE);

	client->need = header[0] | header[1] << 8;
	client->need -= HEADER_SIZE;

	if (client->need > MAX_PACKET_SIZE) {
		snprintf(client->gate->error, ERROR_SIZE, "client packet size:%d too much", client->need);
		client_exit(client, client->gate->error);
		return -1;
	}
	return 0;
}

static int
read_body(client_t* client) {
	size_t total = ev_session_input_size(client->session);
	if (total < client->need) {
		return -1;
	}

	uint8_t* data = get_buffer(client->need);

	ev_session_read(client->session, (char*)data, client->need);

	if (message_decrypt(&client->seed, data, client->need) < 0) {
		free_buffer(data);
		client_exit(client, "client message decrypt error");
		return -1;
	}

	uint16_t id = data[2] | data[3] << 8;

	client->freq++;
	client->tick = loop_ctx_now(client->gate->loop_ctx);
	client->gate->data(client->gate->ud, client->id, id, &data[4], client->need - 4);
	client->need = 0;

	free_buffer(data);

	return 0;
}

static void
client_read(struct ev_session* ev_session, void* ud) {
	client_t* client = ud;

	grab_client(client);

	for (;;) {
		if (client->need == 0) {
			if (read_header(client) < 0) {
				break;
			}
		}
		else {
			if (read_body(client) < 0) {
				break;
			}
		}
	}

	release_client(client);
}

static void
client_update(struct ev_loop* loop, struct ev_timer* io, int revents) {
	assert(revents & EV_TIMER);
	client_t* client = io->data;
	grab_client(client);

	if (ev_session_output_size(client->session) > WARN_OUTPUT_FLOW) {
		fprintf(stderr, "client:%d more then %dkb flow need to send out\n", client->id, WARN_OUTPUT_FLOW / 1024);
	}

	if (client->freq > client->gate->max_freq) {
		snprintf(client->gate->error, ERROR_SIZE, "client receive message too much:%d in last 1s", client->freq);
		client_exit(client, client->gate->error);
	}
	else {
		client->freq = 0;
		if (client->tick != 0 && loop_ctx_now(client->gate->loop_ctx) - client->tick > client->gate->timeout) {
			client_exit(client, "client timeout");
		}
	}
	release_client(client);
}

static void
client_accept(struct ev_listener *listener, int fd, const char* addr, void *ud) {
	gate_t* gate = ud;

	if (gate->count >= gate->max_client) {
		close(fd);
		return;
	}

	gate->count++;

	socket_nonblock(fd);
	socket_keep_alive(fd);
	socket_closeonexec(fd);

	client_t* client = malloc(sizeof(*client));
	memset(client, 0, sizeof(*client));

	struct ev_session* session = ev_session_bind(gate->loop_ctx, fd, 64, 1024 * 64);
	int slot = container_add(gate->container, client);

	uint32_t index = gate->index++;
	if (index >= gate->max_index)
		gate->index = 1;

	client->gate = gate;
	client->session = session;
	client->id = index * gate->max_offset + slot;

	grab_client(client);

	ev_session_setcb(client->session, client_read, NULL, client_error, client);
	ev_session_enable(client->session, EV_READ);

	client->timer.data = client;
	ev_timer_init(&client->timer, client_update, 1, 1);
	ev_timer_start(loop_ctx_get(gate->loop_ctx), &client->timer);

	gate->accept(gate->ud, client->id, addr);
}

static void
close_complete(struct ev_session* ev_session, void* ud) {
	client_t* client = ud;
	release_client(client);
}

static void
close_error(struct ev_session* session, void* ud) {
	client_t* client = ud;
	fprintf(stderr, "client:%d close error\n", client->id);
	release_client(client);
}

gate_t*
gate_create(struct ev_loop_ctx* loop_ctx, uint32_t max_client, uint32_t max_freq, uint32_t timeout, void* ud) {
	if (max_client < 1 || max_freq < 1 || timeout < 1) {
		return NULL;
	}

	gate_t* gate = malloc(sizeof(*gate));
	memset(gate, 0, sizeof(*gate));

	gate->container = container_create(max_client);
	gate->loop_ctx = loop_ctx;
	gate->ud = ud;
	gate->max_freq = max_freq;
	gate->timeout = timeout;

	gate->count = 0;
	gate->max_client = max_client;

	gate->max_offset = 1;
	while (max_client > 0) {
		max_client /= 10;
		gate->max_offset *= 10;
	}

	gate->index = 1;
	gate->max_index = 0xffffffff / gate->max_offset;
	return gate;
}

int
gate_start(gate_t* gate, const char* ip, int port) {
	struct sockaddr_in si;
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = inet_addr(ip);
	si.sin_port = htons(port);

	int flag = SOCKET_OPT_NOBLOCK | SOCKET_OPT_CLOSE_ON_EXEC | SOCKET_OPT_REUSEABLE_ADDR;
	gate->listener = ev_listener_bind(gate->loop_ctx, (struct sockaddr*)&si, sizeof(si), 16, flag, client_accept, gate);
	if (!gate->listener) {
		return -1;
	}

	if (port == 0) {
		char addr[INET6_ADDRSTRLEN] = { 0 };
		if (ev_listener_addr(gate->listener, addr, INET6_ADDRSTRLEN, &port) < 0) {
			return port;
		}
	}
	return port;
}

void
gate_callback(gate_t* gate, accept_callback accept, close_callback close, data_callback data) {
	gate->accept = accept;
	gate->close = close;
	gate->data = data;
}

int
gate_stop(gate_t* gate) {
	if (gate->listener == NULL) {
		return -1;
	}

	ev_listener_free(gate->listener);
	gate->listener = NULL;
	return 0;
}

int
gate_close(gate_t* gate, uint32_t client_id, int grace) {
	client_t* client = get_client(gate, client_id);
	if (!client) {
		return -1;
	}
	grab_client(client);

	if (!grace) {
		release_client(client);
	}
	else {
		client->markdead = 1;
		ev_session_setcb(client->session, NULL, close_complete, close_error, client);
		ev_session_enable(client->session, EV_WRITE);
		ev_session_disable(client->session, EV_READ);
	}
	release_client(client);
	return 0;
}

int
gate_send(gate_t* gate, uint32_t client_id, ushort message_id, void* data, size_t size) {
	client_t* client = get_client(gate, client_id);
	if (!client) {
		return -1;
	}
	grab_client(client);

	ushort total = size + sizeof(short) * 2;

	uint8_t* mb = malloc(total);
	memcpy(mb, &total, sizeof(ushort));
	memcpy(mb + sizeof(ushort), &message_id, sizeof(ushort));
	memcpy(mb + sizeof(ushort) * 2, data, size);

	int ret = ev_session_write(client->session, (char*)mb, total);
	release_client(client);
	if (ret < 0) {
		free(mb);
		return -1;
	}
	return 0;
}

void
gate_release(gate_t* gate) {
	gate_stop(gate);
	container_foreach(gate->container, close_client);
	container_release(gate->container);
	free(gate);
}
