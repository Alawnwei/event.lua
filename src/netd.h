#ifndef NETD_H
#define NETD_H

#include "socket/socket_tcp.h"

struct netd;
struct client;

typedef void(*client_enter_cb)(void* ud, uint32_t client_id, const char* addr);
typedef void(*client_leave_cb)(void* ud, uint32_t client_id, const char* reason);
typedef void(*client_message_cb)(void* ud, uint32_t client_id, const char* message, size_t sz);

struct netd* netd_create(struct ev_loop_ctx* loop_ctx, uint32_t max_client, uint32_t max_freq, uint32_t timeout);
void netd_release(struct netd* netd);
int netd_start(struct netd* netd, const char* ip, int port);
int netd_stop(struct netd* netd);
struct client* netd_get_client(struct netd* netd, uint32_t id);

void netd_set_client_enter_cb(struct netd* netd, client_enter_cb cb);
void netd_set_client_leave_cb(struct netd* netd, client_leave_cb cb);
void netd_set_client_message_cb(struct netd* netd, client_message_cb cb);

#endif