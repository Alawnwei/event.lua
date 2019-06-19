#ifndef GATE_H
#define GATE_H

#include "ev.h"
#include "socket/socket_tcp.h"
#include "socket/socket_util.h"
#include "common/object_container.h"
#include "common/common.h"

typedef struct gate gate_t;

typedef void (*accept_callback)(void* ud,uint32_t client_id,const char* addr);
typedef void (*close_callback)(void* ud,uint32_t client_id,const char* reason);
typedef void (*data_callback)(void* ud,uint32_t client_id,int message_id,void* data,size_t size);

gate_t* gate_create(struct ev_loop_ctx* loop_ctx,uint32_t max_client, uint32_t max_freq, uint32_t timeout,void* ud);
void gate_release(gate_t* gate);
int gate_start(gate_t* gate,const char* ip,int port);
int gate_stop(gate_t* gate);

int gate_send(gate_t* gate,uint32_t client_id,ushort message_id,void* data,size_t size);
int gate_close(gate_t* gate,uint32_t client_id,int grace);

void gate_callback(gate_t* gate,accept_callback accept,close_callback close,data_callback data);



#endif