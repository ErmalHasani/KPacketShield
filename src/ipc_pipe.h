#ifndef IPC_PIPE_H
#define IPC_PIPE_H

#include "common.h"

bool ipc_pipe_start(void);
void ipc_pipe_stop(void);
bool ipc_pipe_is_running(void);

// Broadcast an event string to all connected subscriber clients
void ipc_pipe_broadcast(const char *json_msg);

#endif // IPC_PIPE_H
