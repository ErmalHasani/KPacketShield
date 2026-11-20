#include "proc_map.h"
#include <shlwapi.h>

#define PROC_CACHE_SIZE 512

typedef struct {
    DWORD pid;
    char name[MAX_NAME_LEN];
    char path[MAX_PATH_LEN];
    time_t updated_at;
} ProcCacheEntry;

static ProcCacheEntry g_proc_cache[PROC_CACHE_SIZE];
static CRITICAL_SECTION g_cache_lock;
static bool g_initialized = false;

void proc_map_init(void) {
    if (!g_initialized) {
        InitializeCriticalSection(&g_cache_lock);
        memset(g_proc_cache, 0, sizeof(g_proc_cache));
        g_initialized = true;
    }
}

void proc_map_cleanup(void) {
    if (g_initialized) {
        DeleteCriticalSection(&g_cache_lock);
        g_initialized = false;
    }
}

bool proc_map_get_by_pid(DWORD pid, char *out_name, size_t name_len, char *out_path, size_t path_len) {
    if (pid == 0) {
        if (out_name) strncpy(out_name, "System Idle Process", name_len);
        if (out_path) strncpy(out_path, "System Idle Process", path_len);
        return true;
    }
    if (pid == 4) {
        if (out_name) strncpy(out_name, "System", name_len);
        if (out_path) strncpy(out_path, "System", path_len);
        return true;
    }

    EnterCriticalSection(&g_cache_lock);
    time_t now = time(NULL);
    int empty_idx = -1;

    for (int i = 0; i < PROC_CACHE_SIZE; i++) {
        if (g_proc_cache[i].pid == pid) {
            if (now - g_proc_cache[i].updated_at < 10) { // cache valid for 10s
                if (out_name) strncpy(out_name, g_proc_cache[i].name, name_len);
                if (out_path) strncpy(out_path, g_proc_cache[i].path, path_len);
                LeaveCriticalSection(&g_cache_lock);
                return true;
            }
            empty_idx = i;
            break;
        } else if (empty_idx == -1 && g_proc_cache[i].pid == 0) {
            empty_idx = i;
        }
    }

    // Not found or expired, query Windows
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    char full_path[MAX_PATH_LEN] = {0};
    char proc_name[MAX_NAME_LEN] = "Unknown";

    if (hProcess) {
        DWORD size = sizeof(full_path);
        if (QueryFullProcessImageNameA(hProcess, 0, full_path, &size)) {
            char *slash = strrchr(full_path, '\\');
            if (slash) {
                strncpy(proc_name, slash + 1, sizeof(proc_name) - 1);
            } else {
                strncpy(proc_name, full_path, sizeof(proc_name) - 1);
            }
        }
        CloseHandle(hProcess);
    } else {
        snprintf(proc_name, sizeof(proc_name), "PID:%lu", pid);
    }

    if (empty_idx == -1) {
        empty_idx = rand() % PROC_CACHE_SIZE; // Simple eviction
    }

    g_proc_cache[empty_idx].pid = pid;
    strncpy(g_proc_cache[empty_idx].name, proc_name, sizeof(g_proc_cache[empty_idx].name) - 1);
    strncpy(g_proc_cache[empty_idx].path, full_path, sizeof(g_proc_cache[empty_idx].path) - 1);
    g_proc_cache[empty_idx].updated_at = now;

    if (out_name) strncpy(out_name, proc_name, name_len);
    if (out_path) strncpy(out_path, full_path, path_len);

    LeaveCriticalSection(&g_cache_lock);
    return true;
}

DWORD proc_map_lookup_socket_v4(uint8_t protocol, uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port) {
    (void)local_ip;
    (void)remote_ip;
    DWORD pid = 0;
    DWORD size = 0;

    if (protocol == IPPROTO_TCP) {
        // Query TCP table
        if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
            MIB_TCPTABLE_OWNER_PID *table = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
            if (table && GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    MIB_TCPROW_OWNER_PID *row = &table->table[i];
                    uint16_t row_loc_port = ntohs((uint16_t)row->dwLocalPort);
                    uint16_t row_rem_port = ntohs((uint16_t)row->dwRemotePort);

                    if (row_loc_port == local_port && (remote_port == 0 || row_rem_port == remote_port)) {
                        pid = row->dwOwningPid;
                        break;
                    }
                }
            }
            if (table) free(table);
        }
    } else if (protocol == IPPROTO_UDP) {
        // Query UDP table
        if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
            MIB_UDPTABLE_OWNER_PID *table = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
            if (table && GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    MIB_UDPROW_OWNER_PID *row = &table->table[i];
                    uint16_t row_loc_port = ntohs((uint16_t)row->dwLocalPort);

                    if (row_loc_port == local_port) {
                        pid = row->dwOwningPid;
                        break;
                    }
                }
            }
            if (table) free(table);
        }
    }

    return pid;
}

DWORD proc_map_lookup_socket_v6(uint8_t protocol, const uint8_t *local_ip, uint16_t local_port, const uint8_t *remote_ip, uint16_t remote_port) {
    (void)local_ip;
    (void)remote_ip;
    DWORD pid = 0;
    DWORD size = 0;

    if (protocol == IPPROTO_TCP) {
        if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
            MIB_TCP6TABLE_OWNER_PID *table = (MIB_TCP6TABLE_OWNER_PID *)malloc(size);
            if (table && GetExtendedTcpTable(table, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    MIB_TCP6ROW_OWNER_PID *row = &table->table[i];
                    uint16_t row_loc_port = ntohs((uint16_t)row->dwLocalPort);
                    uint16_t row_rem_port = ntohs((uint16_t)row->dwRemotePort);

                    if (row_loc_port == local_port && (remote_port == 0 || row_rem_port == remote_port)) {
                        pid = row->dwOwningPid;
                        break;
                    }
                }
            }
            if (table) free(table);
        }
    } else if (protocol == IPPROTO_UDP) {
        if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
            MIB_UDP6TABLE_OWNER_PID *table = (MIB_UDP6TABLE_OWNER_PID *)malloc(size);
            if (table && GetExtendedUdpTable(table, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < table->dwNumEntries; i++) {
                    MIB_UDP6ROW_OWNER_PID *row = &table->table[i];
                    uint16_t row_loc_port = ntohs((uint16_t)row->dwLocalPort);

                    if (row_loc_port == local_port) {
                        pid = row->dwOwningPid;
                        break;
                    }
                }
            }
            if (table) free(table);
        }
    }

    return pid;
}
