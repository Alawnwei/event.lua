
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

typedef struct ev_session {
	struct ev_loop_ctx* loop_ctx;
	struct ev_io rio;
	struct ev_io wio;
	
	int fd;
	int alive;

	ring_buffer_t* input;
	ev_buffer_t output;

	ev_session_callback read_cb;
	ev_session_callback write_cb;
	ev_session_callback event_cb;

	void* userdata;
} ev_session_t;

void ev_session_free(ev_session_t* ev_session);
void ev_session_disable(ev_session_t* ev_session,int ev);

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
buffer_reclaim(ev_loop_ctx_t* loop_ctx,data_buffer_t* db) {
	db->next = loop_ctx->freelist;
	loop_ctx->freelist = db;
}

static inline void
buffer_append(ev_buffer_t* ev_buffer,data_buffer_t* db) {
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
	while(ev_buffer->head) {
		data_buffer_t* tmp = ev_buffer->head;
		ev_buffer->head = ev_buffer->head->next;
		free(tmp->data);
		free(tmp);
	}
}

static void
_ev_accept_cb(struct ev_loop* loop,struct ev_io* io,int revents) {
	ev_listener_t* listener = io->data;

	const char addr[HOST_SIZE] = {0};
	int accept_fd = socket_accept(listener->fd,(char*)addr,HOST_SIZE);
	if (accept_fd < 0) {
		fprintf(stderr,"accept fd error:%s\n",addr);
		return;
	}
	listener->accept_cb(listener,accept_fd,addr,listener->userdata);
}

static void
_ev_read_cb(struct ev_loop* loop,struct ev_io* io,int revents) {
	ev_session_t* ev_session = io->data;

	int fail = 0;
	//一次性接完数据，再回调(为了预防恶意流，理论上应该接一次回调一次，在上层判断数据合法性)
	for(;;) {
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
					fail = 1;
					break;
				}
			} else {
				assert(0);
			}
		} else if (n == 0) {
			fail = 1;
			break;
		} else {
			rb_commit(ev_session->input, n);
			if (n < space) {
				break;
			}
		}
	}

	if (fail) {
		ev_session_disable(ev_session,EV_READ | EV_WRITE);
		ev_session->alive = 0;
		if (ev_session->event_cb) {
			ev_session->event_cb(ev_session,ev_session->userdata);
		}
	} else {
		if (ev_session->read_cb) {
			ev_session->read_cb(ev_session,ev_session->userdata);
		}
	}
}

static void
_ev_write_cb(struct ev_loop* loop,struct ev_io* io,int revents) {
	ev_session_t* ev_session = io->data;

	while(ev_session->output.head != NULL) {
		struct data_buffer* wdb = ev_session->output.head;
		int left = wdb->wpos - wdb->rpos;
		int total = socket_write(ev_session->fd,wdb->data + wdb->rpos,left);
		if (total < 0) {
			ev_session_disable(ev_session,EV_READ | EV_WRITE);
			ev_session->alive = 0;
			if (ev_session->event_cb)
				ev_session->event_cb(ev_session,ev_session->userdata);
			return;
		} else {
			ev_session->output.total -= total;
			if (total == left) {
				free(wdb->data);
				ev_session->output.head = wdb->next;
				buffer_reclaim(ev_session->loop_ctx,wdb);
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

	ev_session_disable(ev_session,EV_WRITE);
	assert(ev_session->output.total == 0);
	if (ev_session->write_cb) {
		ev_session->write_cb(ev_session,ev_session->userdata);
	}
}

ev_loop_ctx_t*
loop_ctx_create() {
	ev_loop_ctx_t* loop_ctx = malloc(sizeof(*loop_ctx));
	memset(loop_ctx,0,sizeof(*loop_ctx));
	loop_ctx->loop = ev_loop_new(0);
	return loop_ctx;
}

void
loop_ctx_release(ev_loop_ctx_t* loop_ctx) {
	ev_loop_destroy(loop_ctx->loop);

	while(loop_ctx->freelist) {
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
	ev_loop(loop_ctx->loop,0);
}

void
loop_ctx_break(ev_loop_ctx_t* loop_ctx) {
	ev_break(loop_ctx->loop,EVBREAK_ALL);
}

double
loop_ctx_now(ev_loop_ctx_t* loop_ctx) {
	return ev_now(loop_ctx->loop);
}

void 
loop_ctx_clean(ev_loop_ctx_t* loop_ctx) {
	while(loop_ctx->freelist) {
		data_buffer_t* tmp = loop_ctx->freelist;
		loop_ctx->freelist = loop_ctx->freelist->next;
		free(tmp);
	}
}

ev_listener_t*
ev_listener_bind(struct ev_loop_ctx* loop_ctx,struct sockaddr* addr, int addrlen,int backlog,int flag,listener_callback accept_cb,void* userdata) {
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
	ev_io_init(&listener->rio,_ev_accept_cb,fd,EV_READ);
	ev_io_start(loop_ctx->loop,&listener->rio);

	return listener;
}

int
ev_listener_fd(ev_listener_t* listener) {
	return listener->fd;
}

int
ev_listener_addr(ev_listener_t* listener,char* addr,size_t length,int* port) {
	if (get_sockname(listener->fd,addr,length,port) < 0) {
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

ev_session_t*
ev_session_bind(struct ev_loop_ctx* loop_ctx,int fd, int min, int max) {
	ev_session_t* ev_session = malloc(sizeof(*ev_session));
	memset(ev_session,0,sizeof(*ev_session));
	ev_session->loop_ctx = loop_ctx;
	ev_session->fd = fd;

	ev_session->rio.data = ev_session;
	ev_io_init(&ev_session->rio,_ev_read_cb,ev_session->fd,EV_READ);

	ev_session->wio.data = ev_session;
	ev_io_init(&ev_session->wio,_ev_write_cb,ev_session->fd,EV_WRITE);
	ev_set_priority(&ev_session->wio, EV_MAXPRI);

	ev_session->alive = 1;

	ev_session->input = rb_new(min, max);

	return ev_session;
}

int
ev_session_connect(struct ev_loop_ctx* loop_ctx,struct sockaddr* addr, int addrlen, int nonblock,int* status) {
	int result = 0;
	int fd = socket_connect(addr,addrlen,nonblock,&result);
	if (fd < 0) {
		*status = CONNECT_STATUS_CONNECT_FAIL;
		return -1;
	}
	*status = CONNECT_STATUS_CONNECTING;
	if (result) {
		*status = CONNECT_STATUS_CONNECTED;
	}

	return fd;
}

void
ev_session_free(ev_session_t* ev_session) {
	ev_session->alive = 0;
	close(ev_session->fd);
	ev_session_disable(ev_session,EV_READ | EV_WRITE);

	rb_delete(ev_session->input);
	buffer_release(&ev_session->output);

	free(ev_session);
}

void
ev_session_setcb(ev_session_t* ev_session,ev_session_callback read_cb,ev_session_callback write_cb,ev_session_callback event_cb,void* userdata) {
	ev_session->read_cb = read_cb;
	ev_session->write_cb = write_cb;
	ev_session->event_cb = event_cb;
	ev_session->userdata = userdata;
}

void
ev_session_enable(ev_session_t* ev_session,int ev) {
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
ev_session_disable(ev_session_t* ev_session,int ev) {
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

size_t
ev_session_output_size(ev_session_t* ev_session) {
	return ev_session->output.total;
}

size_t 
ev_session_read(struct ev_session* ev_session,char* result,size_t size) {
	if (size > ev_session_input_size(ev_session)) {
		size = ev_session_input_size(ev_session);
	}
	result = rb_copy(ev_session->input, result, size);
	return size;
}

char* 
ev_session_read_next(struct ev_session* ev_session,size_t* size) {
	uint32_t length = 0;
	char* result = rb_next(ev_session->input, &length);
	*size = length;
	return result;
}

int
ev_session_write(ev_session_t* ev_session,char* data,size_t size) {
	if (ev_session->alive == 0)
		return -1;

	if (!ev_is_active(&ev_session->wio)) {
		int total = socket_write(ev_session->fd,data,size);
		if (total < 0) {
			ev_session_disable(ev_session,EV_READ | EV_WRITE);
			ev_session->alive = 0;
			// if (ev_session->event_cb)
			// 	ev_session->event_cb(ev_session,ev_session->userdata);
			return -1;
		} else {
			if (total == size) {
				free(data);
				if (ev_session->write_cb) {
					ev_session->write_cb(ev_session,ev_session->userdata);
				}
			} else {
				struct data_buffer* wdb = buffer_next(ev_session->loop_ctx);
				wdb->data = data;
				wdb->rpos = total;
				wdb->wpos = size;
				wdb->size = size;
				buffer_append(&ev_session->output,wdb);
				ev_io_start(ev_session->loop_ctx->loop,&ev_session->wio);
			}
			return total;
		}
	} else {
		struct data_buffer* wdb = buffer_next(ev_session->loop_ctx);
		wdb->data = data;
		wdb->rpos = 0;
		wdb->wpos = size;
		wdb->size = size;
		buffer_append(&ev_session->output,wdb);
		return 0;
	}
}
