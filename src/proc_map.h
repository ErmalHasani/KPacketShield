#ifndef PROC_MAP_H
#define PROC_MAP_H

#include "common.h"

void proc_map_init(void);
void proc_map_cleanup(void);

// Resolve PID to process executable name and full path
bool proc_map_get_by_pid(DWORD pid, char *out_name, size_t name_len, char *out_path, size_t path_len);

// Look up owner PID from local/remote endpoint and protocol
DWORD proc_map_lookup_socket_v4(uint8_t protocol, uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port);
DWORD proc_map_lookup_socket_v6(uint8_t protocol, const uint8_t *local_ip, uint16_t local_port, const uint8_t *remote_ip, uint16_t remote_port);

#endif // PROC_MAP_H
