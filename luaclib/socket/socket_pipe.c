#include "socket_tcp.h"
#include "socket_util.h"
#include "socket_pipe.h"

typedef struct pipe_session {
	struct ev_loop_ctx* loop_ctx;
	struct ev_io io;
	int recv_fd;
	int send_fd;

	pipe_session_callback read_cb;
	void* userdata;
} pipe_session_t;

static void
_pipe_read_cb(struct ev_loop* loop, struct ev_io* io, int revents) {
	pipe_session_t* session = io->data;

	for (;;) {
		struct pipe_message* message = NULL;
		int n = read(io->fd, &message, sizeof(message));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else if (errno == EAGAIN) {
				return;
			}
			else {
				assert(0);
			}
		}

		assert(n == sizeof(message));

		if (session->read_cb) {
			session->read_cb(session, message, session->userdata);
		}
		free(message);
	}
}

pipe_session_t*
pipe_sesson_new(struct ev_loop_ctx* loop_ctx) {
	int fd[2];
	if (pipe(fd)) {
		return NULL;
	}

	socket_nonblock(fd[0]);
	socket_nonblock(fd[1]);

	pipe_session_t* session = malloc(sizeof(*session));
	memset(session, 0, sizeof(*session));

	session->loop_ctx = loop_ctx;

	session->recv_fd = fd[0];
	session->send_fd = fd[1];

	session->io.data = session;

	ev_io_init(&session->io, _pipe_read_cb, session->recv_fd, EV_READ);
	ev_io_start(loop_ctx_get(loop_ctx), &session->io);

	return session;
}

void
pipe_session_destroy(pipe_session_t* session) {
	ev_io_stop(loop_ctx_get(session->loop_ctx), &session->io);
	close(session->recv_fd);
	close(session->send_fd);
	free(session);
}

int
pipe_session_write(pipe_session_t* session, void* data, size_t size) {
	return socket_pipe_write(session->send_fd, data, size);
}

int
pipe_session_write_fd(pipe_session_t* session) {
	return session->send_fd;
}

void
pipe_session_setcb(pipe_session_t* session, pipe_session_callback read_cb, void* userdata) {
	session->read_cb = read_cb;
	session->userdata = userdata;
}