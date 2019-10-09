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


#endif