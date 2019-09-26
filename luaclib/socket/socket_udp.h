#ifndef UDP_SESSION_H
#define UDP_SESSION_H

struct udp_session;
typedef void(*udp_session_read_callback)(struct udp_session*, char* buffer, size_t size, const char* ip, ushort port, void *userdata);
typedef void(*udp_session_event_callback)(struct udp_session*, void *userdata);


struct udp_session* udp_session_new(struct ev_loop_ctx* loop_ctx, size_t recv_size);
void udp_session_destroy(struct udp_session* session);
struct udp_session* udp_session_bind(struct ev_loop_ctx* loop_ctx, const char* ip, ushort port, size_t recv_size);
int udp_session_write(struct udp_session* session, char* data, size_t size, const char* ip, ushort port);
void udp_session_setcb(struct udp_session* session, udp_session_read_callback read_cb, udp_session_event_callback event_cb, void* userdata);
#endif
