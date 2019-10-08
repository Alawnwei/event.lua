
#include "socket_tcp.h"
#include "ring_buffer.h"

#define MIN_BUFFER_SIZE 256
#define MAX_BUFFER_SIZE 1024*1024


typedef struct data_buffer {
	struct data_buffer* prev;
	struct data_buffer* next;
	void* data;
	int size;
	int wpos;
	int rpos;
} data_buffer_t;

typedef struct ev_buffer {
	data_buffer_t* head;
	data_buffer_t* tail;
	int total;
} ev_buffer_t;

typedef struct ev_loop_ctx {
	struct ev_loop* loop;
	data_buffer_t* freelist;
} ev_loop_ctx_t;

typedef struct ev_listener {
	struct ev_loop_ctx* loop_ctx;
	struct ev_io rio;
	int fd;
	listener_callback accept_cb;
	void* userdata;
} ev_listener_t;

typedef struct ev_connecter {
	struct ev_loop_ctx* loop_ctx;
	struct ev_io wio;
	int fd;
	connector_callback connect_cb;
	void* userdata;
} ev_connecter_t;

typedef struct ev_session {
	struct ev_loop_ctx* loop_ctx;
	struct ev_io rio;
	struct ev_io wio;

	int fd;
	int alive;

	ring_buffer_t* input;
	ev_buffer_t output;

	session_callback read_cb;
	session_callback write_cb;
	session_callback event_cb;

	void* userdata;
} ev_session_t;

void ev_session_free(ev_session_t* ev_session);
void ev_session_disable(ev_session_t* ev_session, int ev);

static inline struct data_buffer*
buffer_next(ev_loop_ctx_t* loop_ctx) {
	data_buffer_t* db = NULL;
	if (loop_ctx->freelist != NULL) {
		db = loop_ctx->freelist;
		loop_ctx->freelist = db->next;
	} else {
		db = malloc(sizeof(*db));
	}
	db->data = NULL;
	db->wpos = db->rpos = 0;
	db->size = 0;
	db->prev = NULL;
	db->next = NULL;

	return db;
}

static inline void
buffer_reclaim(ev_loop_ctx_t* loop_ctx, data_buffer_t* db) {
	db->next = loop_ctx->freelist;
	loop_ctx->freelist = db;
}

static inline void
buffer_append(ev_buffer_t* ev_buffer, data_buffer_t* db) {
	ev_buffer->total += db->wpos - db->rpos;
	if (ev_buffer->head == NULL) {
		assert(ev_buffer->tail == NULL);
		ev_buffer->head = ev_buffer->tail = db;
	} else {
		ev_buffer->tail->next = db;
		db->prev = ev_buffer->tail;
		db->next = NULL;
		ev_buffer->tail = db;
	}
}

static inline void
buffer_release(ev_buffer_t* ev_buffer) {
	while (ev_buffer->head) {
		data_buffer_t* tmp = ev_buffer->head;
		ev_buffer->head = ev_buffer->head->next;
		free(tmp->data);
		free(tmp);
	}
}

static void
_ev_accept_cb(struct ev_loop* loop, struct ev_io* io, int revents) {
	ev_listener_t* listener = io->data;

	const char addr[HOST_SIZE] = { 0 };
	int accept_fd = socket_accept(listener->fd, (char*)addr, HOST_SIZE);
	if (accept_fd < 0) {
		fprintf(stderr, "accept fd error:%s\n", addr);
		return;
	}
	listener->accept_cb(listener, accept_fd, addr, listener->userdata);
}

static void
_ev_read_cb(struct ev_loop* loop, struct ev_io* io, int revents) {
	ev_session_t* ev_session = io->data;
	for (;;) {
		uint32_t space;
		char* data = rb_reserve(ev_session->input, &space);
		if (!data || space == 0) {
			break;
		}
		int n = (int)read(ev_session->fd, data, space);
		if (n < 0) {
			if (errno) {
				if (errno == EINTR) {
					continue;
				} else if (errno == EAGAIN) {
					break;
				} else {
					goto fd_error;
				}
			} else {
				goto fd_error;
			}
		} else if (n == 0) {
			goto fd_error;
		} else {
			rb_commit(ev_session->input, n);
			if (n < space) {
				break;
			}
		}
	}

	if (ev_session->read_cb) {
		ev_session->read_cb(ev_session, ev_session->userdata);
	}
	return;

fd_error:
	ev_session_disable(ev_session, EV_READ | EV_WRITE);
	ev_session->alive = 0;
	if (ev_session->event_cb) {
		ev_session->event_cb(ev_session, ev_session->userdata);
	}
}

static void
_ev_write_cb(struct ev_loop* loop, struct ev_io* io, int revents) {
	ev_session_t* ev_session = io->data;

	while (ev_session->output.head != NULL) {
		struct data_buffer* wdb = ev_session->output.head;
		int left = wdb->wpos - wdb->rpos;
		int total = socket_write(ev_session->fd, wdb->data + wdb->rpos, left);
		if (total < 0) {
			ev_session_disable(ev_session, EV_READ | EV_WRITE);
			ev_session->alive = 0;
			if (ev_session->event_cb) {
				ev_session->event_cb(ev_session, ev_session->userdata);
			}
			return;
		} else {
			ev_session->output.total -= total;
			if (total == left) {
				free(wdb->data);
				ev_session->output.head = wdb->next;
				buffer_reclaim(ev_session->loop_ctx, wdb);
				if (ev_session->output.head == NULL) {
					ev_session->output.head = ev_session->output.tail = NULL;
					break;
				}
			} else {
				wdb->rpos += total;
				return;
			}
		}
	}

	ev_session_disable(ev_session, EV_WRITE);
	assert(ev_session->output.total == 0);
	if (ev_session->write_cb) {
		ev_session->write_cb(ev_session, ev_session->userdata);
	}
}

static void
_ev_connect_cb(struct ev_loop* loop, struct ev_io* io, int revents) {
	ev_io_stop(loop, io);

	ev_connecter_t* connector = io->data;
	int error = 0;
	socklen_t len = sizeof(error);
	int code = getsockopt(connector->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (code < 0 || error) {
		char* strerr = NULL;
		if (code >= 0) {
			strerr = strerror(error);
		} else {
			strerr = strerror(errno);
		}
		close(connector->fd);
		connector->connect_cb(connector, -1, strerr, connector->userdata);
	} else {
		socket_nonblock(connector->fd);
		socket_keep_alive(connector->fd);
		socket_closeonexec(connector->fd);

		connector->connect_cb(connector, connector->fd, NULL, connector->userdata);
	}
}

ev_loop_ctx_t*
loop_ctx_create() {
	ev_loop_ctx_t* loop_ctx = malloc(sizeof(*loop_ctx));
	memset(loop_ctx, 0, sizeof(*loop_ctx));
	loop_ctx->loop = ev_loop_new(0);
	return loop_ctx;
}

void
loop_ctx_release(ev_loop_ctx_t* loop_ctx) {
	ev_loop_destroy(loop_ctx->loop);

	while (loop_ctx->freelist) {
		data_buffer_t* tmp = loop_ctx->freelist;
		loop_ctx->freelist = loop_ctx->freelist->next;
		free(tmp);
	}
	free(loop_ctx);
}

struct ev_loop*
loop_ctx_get(ev_loop_ctx_t* loop_ctx) {
	return loop_ctx->loop;
}

void
loop_ctx_dispatch(ev_loop_ctx_t* loop_ctx) {
	ev_loop(loop_ctx->loop, 0);
}

void
loop_ctx_break(ev_loop_ctx_t* loop_ctx) {
	ev_break(loop_ctx->loop, EVBREAK_ALL);
}

double
loop_ctx_now(ev_loop_ctx_t* loop_ctx) {
	return ev_now(loop_ctx->loop);
}

void
loop_ctx_clean(ev_loop_ctx_t* loop_ctx) {
	while (loop_ctx->freelist) {
		data_buffer_t* tmp = loop_ctx->freelist;
		loop_ctx->freelist = loop_ctx->freelist->next;
		free(tmp);
	}
}

ev_listener_t*
ev_listener_create(struct ev_loop_ctx* loop_ctx, struct sockaddr* addr, int addrlen, int backlog, int flag, listener_callback accept_cb, void* userdata) {
	int fd = socket_listen(addr, addrlen, backlog, flag);
	if (fd < 0) {
		return NULL;
	}
	ev_listener_t* listener = malloc(sizeof(*listener));
	listener->loop_ctx = loop_ctx;
	listener->fd = fd;
	listener->accept_cb = accept_cb;
	listener->userdata = userdata;

	listener->rio.data = listener;
	ev_io_init(&listener->rio, _ev_accept_cb, fd, EV_READ);
	ev_io_start(loop_ctx->loop, &listener->rio);

	return listener;
}

int
ev_listener_fd(ev_listener_t* listener) {
	return listener->fd;
}

int
ev_listener_addr(ev_listener_t* listener, char* addr, size_t length, int* port) {
	if (get_sockname(listener->fd, addr, length, port) < 0) {
		return -1;
	}
	return 0;
}

void
ev_listener_free(ev_listener_t* listener) {
	if (ev_is_active(&listener->rio)) {
		ev_io_stop(listener->loop_ctx->loop, &listener->rio);
	}
	close(listener->fd);
	free(listener);
}

ev_connecter_t*
ev_connecter_create(struct ev_loop_ctx* loop_ctx, struct sockaddr* addr, int addrlen, connector_callback callback, void* userdata) {
	int result = 0;
	int fd = socket_connect(addr, addrlen, 1, &result);
	if (fd < 0) {
		return NULL;
	}

	if (!callback) {
		close(fd);
		return NULL;
	}

	ev_connecter_t* connector = malloc(sizeof(*connector));
	connector->loop_ctx = loop_ctx;
	connector->fd = fd;
	connector->connect_cb = callback;
	connector->userdata = userdata;
	connector->wio.data = connector;
	ev_io_init(&connector->wio, _ev_connect_cb, fd, EV_WRITE);
	ev_set_priority(&connector->wio, EV_MAXPRI);
	ev_io_start(loop_ctx->loop, &connector->wio);

	return connector;
}

void
ev_connecter_free(ev_connecter_t* connecter) {
	if (ev_is_active(&connecter->wio)) {
		ev_io_stop(connecter->loop_ctx->loop, &connecter->wio);
		close(connecter->fd);
	}
	free(connecter);
}


ev_session_t*
ev_session_bind(struct ev_loop_ctx* loop_ctx, int fd, int min, int max) {
	ev_session_t* ev_session = malloc(sizeof(*ev_session));
	memset(ev_session, 0, sizeof(*ev_session));
	ev_session->loop_ctx = loop_ctx;
	ev_session->fd = fd;

	ev_session->rio.data = ev_session;
	ev_io_init(&ev_session->rio, _ev_read_cb, ev_session->fd, EV_READ);

	ev_session->wio.data = ev_session;
	ev_io_init(&ev_session->wio, _ev_write_cb, ev_session->fd, EV_WRITE);
	ev_set_priority(&ev_session->wio, EV_MAXPRI);

	ev_session->alive = 1;

	ev_session->input = rb_new(min, max);

	return ev_session;
}

void
ev_session_free(ev_session_t* ev_session) {
	ev_session->alive = 0;
	close(ev_session->fd);
	ev_session_disable(ev_session, EV_READ | EV_WRITE);

	rb_delete(ev_session->input);
	buffer_release(&ev_session->output);

	free(ev_session);
}

void
ev_session_setcb(ev_session_t* ev_session, session_callback read_cb, session_callback write_cb, session_callback event_cb, void* userdata) {
	ev_session->read_cb = read_cb;
	ev_session->write_cb = write_cb;
	ev_session->event_cb = event_cb;
	ev_session->userdata = userdata;
}

void
ev_session_enable(ev_session_t* ev_session, int ev) {
	if (ev & EV_READ) {
		if (!ev_is_active(&ev_session->rio)) {
			ev_io_start(ev_session->loop_ctx->loop, &ev_session->rio);
		}
	}
	if (ev & EV_WRITE) {
		if (!ev_is_active(&ev_session->wio)) {
			ev_io_start(ev_session->loop_ctx->loop, &ev_session->wio);
		}
	}
}

void
ev_session_disable(ev_session_t* ev_session, int ev) {
	if (ev & EV_READ) {
		if (ev_is_active(&ev_session->rio)) {
			ev_io_stop(ev_session->loop_ctx->loop, &ev_session->rio);
		}
	}
	if (ev & EV_WRITE) {
		if (ev_is_active(&ev_session->wio)) {
			ev_io_stop(ev_session->loop_ctx->loop, &ev_session->wio);
		}
	}
}

int
ev_session_fd(ev_session_t* ev_session) {
	return ev_session->fd;
}

size_t
ev_session_input_size(ev_session_t* ev_session) {
	return rb_length(ev_session->input);
}

int
ev_session_input_full(ev_session_t* ev_session) {
	return rb_full(ev_session->input);
}

size_t
ev_session_output_size(ev_session_t* ev_session) {
	return ev_session->output.total;
}

size_t
ev_session_read(struct ev_session* ev_session, char* result, size_t size) {
	if (size > ev_session_input_size(ev_session)) {
		size = ev_session_input_size(ev_session);
	}
	result = rb_copy(ev_session->input, result, size);
	return size;
}

char*
ev_session_read_next(struct ev_session* ev_session, size_t* size) {
	uint32_t length = 0;
	char* result = rb_next(ev_session->input, &length);
	*size = length;
	return result;
}

char*
ev_session_read_peek(struct ev_session* ev_session, size_t size) {
	return rb_peek(ev_session->input, size);
}

int
ev_session_write(ev_session_t* ev_session, char* data, size_t size) {
	if (ev_session->alive == 0) {
		return -1;
	}

	struct data_buffer* wdb = buffer_next(ev_session->loop_ctx);
	wdb->data = data;
	wdb->rpos = 0;
	wdb->wpos = size;
	wdb->size = size;
	buffer_append(&ev_session->output, wdb);
	if (!ev_is_active(&ev_session->wio)) {
		ev_io_start(ev_session->loop_ctx->loop, &ev_session->wio);
	}
	return 0;
}
