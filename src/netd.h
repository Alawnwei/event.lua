#ifndef NETD_H
#define NETD_H

#include "socket/socket_tcp.h"


#define kCMD_REGISTER       0
#define kCMD_LOGIN_REGISTER 1
#define kCMD_SCENE_REGISTER 2
#define kCMD_SET_SERVER     3
#define kCMD_CLIENT_SEND    4
#define kCMD_CLIENT_BROAD   5
#define kCMD_CLIENT_CLOSE   6

#define kCMD_UPDATE_LOGIN_MASTER  0
#define kCMD_UPDATE_SCENE_MASTER  1
#define kCMD_CLIENT_ENTER         2
#define kCMD_CLIENT_LEAVE         3
#define kCMD_CLIENT_DATA          4

struct netd;

struct netd* netd_create(struct ev_loop_ctx* loop_ctx, uint32_t max_client, uint32_t max_freq, uint32_t timeout);
void netd_release(struct netd* netd);

int netd_client_start(struct netd* netd, const char* ip, int port);
int netd_client_stop(struct netd* netd);

int netd_server_start(struct netd* netd, const char* file);
int netd_server_stop(struct netd* netd);
#endif