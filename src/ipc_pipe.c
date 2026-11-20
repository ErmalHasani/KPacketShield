#include "ipc_pipe.h"
#include "rule_store.h"
#include "monitor.h"
#include "wfp_engine.h"
#include "service.h"
#include <sddl.h>

#define MAX_SUBSCRIBERS 16

static HANDLE h_listener_thread = NULL;
static HANDLE h_ticker_thread = NULL;
static volatile bool g_running = false;

static HANDLE g_subscriber_pipes[MAX_SUBSCRIBERS];
static uint32_t g_subscriber_count = 0;
static CRITICAL_SECTION g_subscriber_lock;

static DWORD WINAPI ipc_ticker_thread(LPVOID param) {
    (void)param;
    while (g_running) {
        Sleep(1000);
        if (!g_running) break;

        EnterCriticalSection(&g_subscriber_lock);
        uint32_t subs = g_subscriber_count;
        LeaveCriticalSection(&g_subscriber_lock);

        // When no GUI clients are subscribed, zero CPU serialization overhead
        if (subs == 0) continue;

        BandwidthStats stats;
        monitor_get_stats(&stats);
        uint32_t rule_count = rule_store_get_count();

        char tick[512];
        snprintf(tick, sizeof(tick),
            "{\"event\":\"TICK\",\"rx_bytes_sec\":%llu,\"tx_bytes_sec\":%llu,\"total_rx_mb\":%.2f,\"total_tx_mb\":%.2f,\"active_flows\":%u,\"active_rules\":%u}",
            stats.rx_bytes_per_sec,
            stats.tx_bytes_per_sec,
            (double)stats.total_rx_bytes / (1024.0 * 1024.0),
            (double)stats.total_tx_bytes / (1024.0 * 1024.0),
            stats.active_flows,
            rule_count
        );
        ipc_pipe_broadcast(tick);
    }
    return 0;
}

void ipc_pipe_broadcast(const char *json_msg) {
    if (!json_msg) return;
    EnterCriticalSection(&g_subscriber_lock);
    DWORD bytes_written = 0;
    size_t len = strlen(json_msg);

    for (uint32_t i = 0; i < g_subscriber_count; ) {
        HANDLE hPipe = g_subscriber_pipes[i];
        if (!WriteFile(hPipe, json_msg, (DWORD)len, &bytes_written, NULL) ||
            !WriteFile(hPipe, "\n", 1, &bytes_written, NULL)) {
            // Client disconnected, remove from subscribers
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            g_subscriber_pipes[i] = g_subscriber_pipes[g_subscriber_count - 1];
            g_subscriber_count--;
        } else {
            i++;
        }
    }
    LeaveCriticalSection(&g_subscriber_lock);
}

static void handle_client(HANDLE hPipe) {
    char request[IPC_BUFFER_SIZE] = {0};
    char response[IPC_BUFFER_SIZE * 4] = {0};
    DWORD bytes_read = 0;
    DWORD bytes_written = 0;

    if (!ReadFile(hPipe, request, sizeof(request) - 1, &bytes_read, NULL) || bytes_read == 0) {
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        return;
    }

    request[bytes_read] = '\0';
    // Trim newline/cr
    char *c = strpbrk(request, "\r\n");
    if (c) *c = '\0';

    if (strncmp(request, "SUBSCRIBE", 9) == 0) {
        EnterCriticalSection(&g_subscriber_lock);
        if (g_subscriber_count < MAX_SUBSCRIBERS) {
            g_subscriber_pipes[g_subscriber_count++] = hPipe;
            LeaveCriticalSection(&g_subscriber_lock);
            const char *ack = "{\"status\":\"subscribed\",\"message\":\"Listening for real-time firewall events\"}\n";
            WriteFile(hPipe, ack, (DWORD)strlen(ack), &bytes_written, NULL);
            // Kept open for broadcast
            return;
        } else {
            LeaveCriticalSection(&g_subscriber_lock);
            const char *err = "{\"error\":\"Max subscribers reached\"}\n";
            WriteFile(hPipe, err, (DWORD)strlen(err), &bytes_written, NULL);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            return;
        }
    }

    if (strncmp(request, "STATUS", 6) == 0) {
        BandwidthStats stats;
        monitor_get_stats(&stats);
        uint32_t rule_count = rule_store_get_count();

        snprintf(response, sizeof(response),
            "{\n"
            "  \"service\": \"KPacketShield\",\n"
            "  \"wfp_engine_active\": %s,\n"
            "  \"windivert_active\": %s,\n"
            "  \"active_rules\": %u,\n"
            "  \"active_flows\": %u,\n"
            "  \"rx_bytes_sec\": %llu,\n"
            "  \"tx_bytes_sec\": %llu,\n"
            "  \"total_rx_mb\": %.2f,\n"
            "  \"total_tx_mb\": %.2f\n"
            "}\n",
            wfp_engine_is_active() ? "true" : "false",
            monitor_is_divert_active() ? "true" : "false",
            rule_count,
            stats.active_flows,
            stats.rx_bytes_per_sec,
            stats.tx_bytes_per_sec,
            (double)stats.total_rx_bytes / (1024.0 * 1024.0),
            (double)stats.total_tx_bytes / (1024.0 * 1024.0)
        );
    } else if (strncmp(request, "LIST_RULES", 10) == 0) {
        uint32_t count = rule_store_get_count();
        size_t offset = snprintf(response, sizeof(response), "{\"rule_count\": %u, \"rules\": [\n", count);

        for (uint32_t i = 0; i < count; i++) {
            FirewallRule r;
            if (rule_store_get_at(i, &r)) {
                offset += snprintf(response + offset, sizeof(response) - offset,
                    "  {\"id\": %u, \"action\": \"%s\", \"type\": \"%s\", \"dir\": \"%s\", \"value\": \"%s\", \"desc\": \"%s\"}%s\n",
                    r.id,
                    (r.action == RULE_ACT_BLOCK ? "BLOCK" : "ALLOW"),
                    (r.type == RULE_TYPE_APP ? "APP" : (r.type == RULE_TYPE_IP ? "IP" : "PORT")),
                    (r.direction == RULE_DIR_OUTBOUND ? "OUT" : (r.direction == RULE_DIR_INBOUND ? "IN" : "BOTH")),
                    r.value,
                    r.description,
                    (i + 1 < count) ? "," : ""
                );
            }
        }
        snprintf(response + offset, sizeof(response) - offset, "]}\n");
    } else if (strncmp(request, "ADD_APP ", 8) == 0) {
        char act_str[16] = {0};
        char app_path[MAX_PATH_LEN] = {0};
        char desc[MAX_NAME_LEN] = {0};
        sscanf(request + 8, "%15s %511s %127[^\r\n]", act_str, app_path, desc);

        RuleAction act = (stricmp(act_str, "block") == 0) ? RULE_ACT_BLOCK : RULE_ACT_ALLOW;
        uint32_t id = rule_store_add_app(app_path, act, RULE_DIR_BOTH, desc[0] ? desc : "Custom App Rule");
        snprintf(response, sizeof(response), "{\"success\": %s, \"rule_id\": %u, \"action\": \"%s\", \"app\": \"%s\"}\n",
                 id > 0 ? "true" : "false", id, act_str, app_path);
    } else if (strncmp(request, "ADD_IP ", 7) == 0) {
        char act_str[16] = {0};
        char ip_str[MAX_IP_STR] = {0};
        char desc[MAX_NAME_LEN] = {0};
        sscanf(request + 7, "%15s %63s %127[^\r\n]", act_str, ip_str, desc);

        RuleAction act = (stricmp(act_str, "block") == 0) ? RULE_ACT_BLOCK : RULE_ACT_ALLOW;
        uint32_t id = rule_store_add_ip(ip_str, act, RULE_DIR_BOTH, desc[0] ? desc : "Custom IP Rule");
        snprintf(response, sizeof(response), "{\"success\": %s, \"rule_id\": %u, \"action\": \"%s\", \"ip\": \"%s\"}\n",
                 id > 0 ? "true" : "false", id, act_str, ip_str);
    } else if (strncmp(request, "ADD_PORT ", 9) == 0) {
        char act_str[16] = {0};
        uint16_t port = 0;
        char proto_str[16] = {0};
        char desc[MAX_NAME_LEN] = {0};
        sscanf(request + 9, "%15s %hu %15s %127[^\r\n]", act_str, &port, proto_str, desc);

        RuleAction act = (stricmp(act_str, "block") == 0) ? RULE_ACT_BLOCK : RULE_ACT_ALLOW;
        uint8_t proto = 0;
        if (stricmp(proto_str, "tcp") == 0) proto = IPPROTO_TCP;
        else if (stricmp(proto_str, "udp") == 0) proto = IPPROTO_UDP;

        uint32_t id = rule_store_add_port(port, proto, act, RULE_DIR_BOTH, desc[0] ? desc : "Custom Port Rule");
        snprintf(response, sizeof(response), "{\"success\": %s, \"rule_id\": %u, \"action\": \"%s\", \"port\": %u}\n",
                 id > 0 ? "true" : "false", id, act_str, port);
    } else if (strncmp(request, "DEL_RULE ", 9) == 0) {
        uint32_t id = (uint32_t)atoi(request + 9);
        bool ok = rule_store_delete(id);
        snprintf(response, sizeof(response), "{\"success\": %s, \"rule_id\": %u}\n", ok ? "true" : "false", id);
    } else if (strncmp(request, "STOP", 4) == 0) {
        snprintf(response, sizeof(response), "{\"status\": \"stopping\"}\n");
        WriteFile(hPipe, response, (DWORD)strlen(response), &bytes_written, NULL);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        app_core_stop();
        ExitProcess(0);
        return;
    } else if (strncmp(request, "GET_FLOWS", 9) == 0) {
        NetworkFlow flows[64];
        uint32_t count = monitor_get_flows(flows, 64);
        size_t offset = snprintf(response, sizeof(response), "{\"flow_count\": %u, \"flows\": [\n", count);

        for (uint32_t i = 0; i < count; i++) {
            char src_ip[64] = {0}, dst_ip[64] = {0};
            if (!flows[i].is_ipv6) {
                struct in_addr sa, da;
                sa.s_addr = flows[i].src_ip_v4;
                da.s_addr = flows[i].dst_ip_v4;
                inet_ntop(AF_INET, &sa, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET, &da, dst_ip, sizeof(dst_ip));
            } else {
                inet_ntop(AF_INET6, flows[i].src_ip_v6, src_ip, sizeof(src_ip));
                inet_ntop(AF_INET6, flows[i].dst_ip_v6, dst_ip, sizeof(dst_ip));
            }

            offset += snprintf(response + offset, sizeof(response) - offset,
                "  {\"proto\": %u, \"src\": \"%s:%u\", \"dst\": \"%s:%u\", \"bytes_sent\": %llu, \"bytes_recv\": %llu, \"pid\": %u, \"proc\": \"%s\"}%s\n",
                flows[i].protocol, src_ip, flows[i].src_port, dst_ip, flows[i].dst_port,
                flows[i].bytes_sent, flows[i].bytes_recv, flows[i].pid, flows[i].process_name,
                (i + 1 < count) ? "," : ""
            );
            if (offset >= sizeof(response) - 512) break;
        }
        snprintf(response + offset, sizeof(response) - offset, "]}\n");
    } else {
        snprintf(response, sizeof(response), "{\"error\": \"Unknown command\", \"input\": \"%s\"}\n", request);
    }

    WriteFile(hPipe, response, (DWORD)strlen(response), &bytes_written, NULL);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

static DWORD WINAPI ipc_listener_thread(LPVOID param) {
    (void)param;

    // Hardened Security Descriptor using SDDL:
    // D: = DACL
    // (A;;GA;;;SY)     = Allow Generic All to Local SYSTEM
    // (A;;GA;;;BA)     = Allow Generic All to Built-in Administrators
    // (A;;GRGWGX;;;IU) = Allow Read/Write/Execute to Interactively Logged-On User
    PSECURITY_DESCRIPTOR pSD = NULL;
    const char *sddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGWGX;;;IU)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl, SDDL_REVISION_1, &pSD, NULL)) {
        LOG_WARN("Failed to convert SDDL, using fallback security: %lu", GetLastError());
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    LOG_INFO("Named Pipe IPC Server listening at '%s' (DACL: Hardened)", KPACKETSHIELD_PIPE_NAME);

    while (g_running) {
        HANDLE hPipe = CreateNamedPipeA(
            KPACKETSHIELD_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            IPC_BUFFER_SIZE,
            IPC_BUFFER_SIZE,
            5000,
            &sa
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            if (!g_running) break;
            LOG_ERROR("CreateNamedPipe failed: %lu", err);
            Sleep(500);
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected && g_running) {
            handle_client(hPipe);
        } else {
            CloseHandle(hPipe);
        }
    }

    if (pSD) LocalFree(pSD);
    LOG_INFO("Named Pipe IPC Server terminated");
    return 0;
}

bool ipc_pipe_start(void) {
    if (g_running) return true;
    InitializeCriticalSection(&g_subscriber_lock);
    g_running = true;
    h_listener_thread = CreateThread(NULL, 0, ipc_listener_thread, NULL, 0, NULL);
    h_ticker_thread = CreateThread(NULL, 0, ipc_ticker_thread, NULL, 0, NULL);
    return (h_listener_thread != NULL && h_ticker_thread != NULL);
}

void ipc_pipe_stop(void) {
    if (!g_running) return;
    g_running = false;

    // Wake up listener with a dummy connection
    HANDLE hDummy = CreateFileA(KPACKETSHIELD_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDummy != INVALID_HANDLE_VALUE) {
        CloseHandle(hDummy);
    }

    if (h_listener_thread) {
        WaitForSingleObject(h_listener_thread, 2000);
        CloseHandle(h_listener_thread);
        h_listener_thread = NULL;
    }

    if (h_ticker_thread) {
        WaitForSingleObject(h_ticker_thread, 2000);
        CloseHandle(h_ticker_thread);
        h_ticker_thread = NULL;
    }

    EnterCriticalSection(&g_subscriber_lock);
    for (uint32_t i = 0; i < g_subscriber_count; i++) {
        DisconnectNamedPipe(g_subscriber_pipes[i]);
        CloseHandle(g_subscriber_pipes[i]);
    }
    g_subscriber_count = 0;
    LeaveCriticalSection(&g_subscriber_lock);

    DeleteCriticalSection(&g_subscriber_lock);
    LOG_INFO("IPC Pipe Server stopped cleanly");
}

bool ipc_pipe_is_running(void) {
    return g_running;
}
