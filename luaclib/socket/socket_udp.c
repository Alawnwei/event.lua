#include "socket_util.h"
#include "socket_tcp.h"
#include "socket_udp.h"

typedef struct udp_session {
	struct ev_loop_ctx* loop_ctx;
	struct ev_io io;
	int fd;
	char* recv_buffer;
	size_t recv_size;

	udp_session_read_callback read_cb;
	udp_session_event_callback event_cb;
	void* userdata;
} udp_session_t;


void udp_session_destroy(udp_session_t* session);

static void
_udp_read_cb(struct ev_loop* loop,struct ev_io* io,int revents) {
	udp_session_t* session = io->data;

	for(;;) {
		struct sockaddr_in si;
		socklen_t slen = sizeof(si);
		int n = recvfrom(session->fd, session->recv_buffer, session->recv_size, 0, (struct sockaddr*)&si, &slen);
		if (n<0) {
			switch(errno) {
				case EINTR:
					continue;
				case EAGAIN:
					return;
				default: {
					break;
				}
			}
			if (session->event_cb) {
				session->event_cb(session,session->userdata);
			}
			return;
		}

        char ip[INET6_ADDRSTRLEN];
        inet_ntop(si.sin_family, (void*)&si.sin_addr, ip, sizeof(ip));
		if (session->read_cb) {
			session->read_cb(session, session->recv_buffer, n, ip, ntohs(si.sin_port), session->userdata);
		}
	}
}


udp_session_t*
udp_session_new(struct ev_loop_ctx* loop_ctx, size_t recv_size) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return NULL;
	}

	socket_nonblock(fd);

	udp_session_t* session = malloc(sizeof(*session));
	memset(session, 0, sizeof(*session));

	session->loop_ctx = loop_ctx;
	session->fd = fd;

	if (recv_size <= 0) {
		recv_size = 1024;
	}

	session->recv_buffer = malloc(recv_size);
	session->recv_size = recv_size;

	ev_io_init(&session->io,_udp_read_cb,session->fd,EV_READ);
	session->io.data = session;
	ev_io_start(loop_ctx_get(loop_ctx),&session->io);

	return session;
}

void
udp_session_destroy(udp_session_t* session) {
	if (ev_is_active(&session->io)) {
		ev_io_stop(loop_ctx_get(session->loop_ctx), &session->io);
	}

	free(session->recv_buffer);
	close(session->fd);

	free(session);
}

udp_session_t*
udp_session_bind(struct ev_loop_ctx* loop_ctx, const char* ip, ushort port, size_t recv_size) {
	udp_session_t* session = udp_session_new(loop_ctx, recv_size);

	struct sockaddr_in si;
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = inet_addr(ip);
	si.sin_port = htons(port);

	int status = bind(session->fd, (struct sockaddr*)&si, sizeof(si));
	if (status != 0) {
		udp_session_destroy(session);
		return NULL;
	}

	return session;
}

int
udp_session_write(udp_session_t* session, char* data, size_t size, const char* ip, ushort port) {
	if (data == NULL || size == 0) {
		return 0;
	}

	struct sockaddr_in si;
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = inet_addr(ip);
	si.sin_port = htons(port);

	int total = socket_udp_write(session->fd,data,size,(struct sockaddr *)&si,sizeof(si));
	if (total < 0) {
		return -1;
	}
	assert(total == size);
	return total;
}

void
udp_session_setcb(udp_session_t* session, udp_session_read_callback read_cb, udp_session_event_callback event_cb, void* userdata) {
	session->read_cb = read_cb;
	session->event_cb = event_cb;
	session->userdata = userdata;
}
