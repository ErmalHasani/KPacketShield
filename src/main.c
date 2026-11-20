#include "common.h"
#include <shlobj.h>
#include <shellapi.h>
#include "service.h"
#include "rule_store.h"
#include "monitor.h"
#include "wfp_engine.h"

static bool is_admin(void) {
    return IsUserAnAdmin() != 0;
}

static volatile bool g_cli_running = true;

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT || ctrl_type == CTRL_CLOSE_EVENT) {
        LOG_INFO("Interrupt received, shutting down gracefully...");
        g_cli_running = false;
        return TRUE;
    }
    return FALSE;
}

// Client helper: send request over Named Pipe and print response
static bool client_send_cmd(const char *cmd, bool stream_events) {
    HANDLE hPipe = CreateFileA(
        KPACKETSHIELD_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("Error: Could not connect to KPacketShield Named Pipe at '%s'. (Is the engine running?)\n", KPACKETSHIELD_PIPE_NAME);
        return false;
    }

    DWORD written = 0;
    if (!WriteFile(hPipe, cmd, (DWORD)strlen(cmd), &written, NULL)) {
        printf("Error: Failed to write command to pipe.\n");
        CloseHandle(hPipe);
        return false;
    }

    char buf[IPC_BUFFER_SIZE];
    DWORD read_bytes = 0;

    if (stream_events) {
        printf("[Streaming live events from KPacketShield. Press Ctrl+C to exit]\n\n");
        while (ReadFile(hPipe, buf, sizeof(buf) - 1, &read_bytes, NULL) && read_bytes > 0) {
            buf[read_bytes] = '\0';
            printf("%s", buf);
            fflush(stdout);
        }
    } else {
        if (ReadFile(hPipe, buf, sizeof(buf) - 1, &read_bytes, NULL)) {
            buf[read_bytes] = '\0';
            printf("%s\n", buf);
        }
    }

    CloseHandle(hPipe);
    return true;
}

static void print_banner(void) {
    printf("====================================================================\n");
    printf("     KPacketShield - Windows WFP Firewall & WinDivert Monitor       \n");
    printf("====================================================================\n");
}

static void print_usage(const char *prog_name) {
    print_banner();
    printf("Usage:\n");
    printf("  Direct Engine Execution (Console Mode):\n");
    printf("    %s --run                 Run standalone engine (Dynamic WFP session)\n", prog_name);
    printf("    %s --interactive         Interactive CLI console with live management\n\n", prog_name);
    printf("  Windows Service Control:\n");
    printf("    %s --install             Install as Windows Service (LocalSystem)\n", prog_name);
    printf("    %s --uninstall           Uninstall Windows Service\n", prog_name);
    printf("    %s --start               Start the installed Windows Service\n", prog_name);
    printf("    %s --stop                Stop the Windows Service\n", prog_name);
    printf("    %s --svc-status          Check Windows Service status\n", prog_name);
    printf("    %s --service             Service entry point (called by SCM)\n\n", prog_name);
    printf("  Client Commands (Connects to background engine via Named Pipe):\n");
    printf("    %s --status              Query engine status and bandwidth\n", prog_name);
    printf("    %s --list                List all active firewall rules\n", prog_name);
    printf("    %s --flows               Show active network connections/flows\n", prog_name);
    printf("    %s --events              Stream real-time WFP drop/block alerts\n", prog_name);
    printf("    %s --block-app <path>    Block application outbound and inbound\n", prog_name);
    printf("    %s --allow-app <path>    Allow application\n", prog_name);
    printf("    %s --block-ip <ip>       Block IP address (IPv4 or IPv6)\n", prog_name);
    printf("    %s --block-port <p> [proto] Block port (TCP, UDP, or any)\n", prog_name);
    printf("    %s --del-rule <id>       Delete firewall rule by ID\n", prog_name);
    printf("====================================================================\n");
}

static void run_interactive_console(void) {
    print_banner();

    if (!is_admin()) {
        printf("\n====================================================================\n");
        printf(" [!] WARNING: RUNNING WITHOUT ADMINISTRATOR PRIVILEGES\n");
        printf(" Windows Filtering Platform (WFP) and WinDivert kernel driver require\n");
        printf(" elevated permissions (Run as administrator) to filter network traffic.\n");
        printf(" Running now in passive unprivileged mode.\n");
        printf("====================================================================\n\n");
    }

    LOG_INFO("Starting KPacketShield in Interactive Mode (Safe Dynamic Session)...");

    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    if (!app_core_start(true)) {
        LOG_ERROR("Failed to start core subsystems.");
        return;
    }

    printf("\nEngine is RUNNING. Type 'help' for commands, 'exit' or Ctrl+C to quit.\n\n");

    char line[512];
    while (g_cli_running) {
        printf("KPS> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }

        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';

        if (strlen(line) == 0) continue;

        if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            break;
        } else if (strcmp(line, "help") == 0) {
            printf("Commands:\n");
            printf("  status              - Show bandwidth and engine health\n");
            printf("  rules               - List current active rules\n");
            printf("  flows               - List active network connections, PIDs, and Tx/Rx\n");
            printf("  alerts [on|off|all] - Configure console drop alert display (default: on)\n");
            printf("  block app <path>    - Block application (e.g. block app C:\\test\\bad.exe)\n");
            printf("  allow app <path>    - Allow application\n");
            printf("  block ip <ip>       - Block IP address (e.g. block ip 31.57.184.48)\n");
            printf("  allow ip <ip>       - Allow IP address\n");
            printf("  block port <p> [t]  - Block port (e.g. block port 8645 tcp)\n");
            printf("  del <id>            - Delete rule by ID\n");
            printf("  clear               - Clear all rules\n");
            printf("  cls                 - Clear console screen\n");
            printf("  exit                - Stop engine and exit\n");
        } else if (strncmp(line, "alerts", 6) == 0) {
            char mode_str[16] = {0};
            sscanf(line, "%*s %15s", mode_str);
            if (stricmp(mode_str, "off") == 0) {
                service_set_alert_mode(0);
                printf("Console alerts MUTED.\n");
            } else if (stricmp(mode_str, "all") == 0) {
                service_set_alert_mode(2);
                printf("Console alerts set to ALL OS drops.\n");
            } else {
                service_set_alert_mode(1);
                printf("Console alerts set to KPacketShield rules only.\n");
            }
        } else if (strcmp(line, "cls") == 0) {
            system("cls");
            print_banner();
        } else if (strcmp(line, "status") == 0) {
            BandwidthStats s;
            monitor_get_stats(&s);
            printf("--- KPacketShield Status ---\n");
            printf("  Admin Privileges:%s\n", is_admin() ? " YES" : " NO (Run as administrator to enable WFP & Divert)");
            printf("  WFP Engine:      %s\n", wfp_engine_is_active() ? "ACTIVE" : "INACTIVE (Needs Admin)");
            printf("  WinDivert Sniff: %s\n", monitor_is_divert_active() ? "ACTIVE" : "INACTIVE (Needs Admin)");
            printf("  Active Rules:    %u\n", rule_store_get_count());
            printf("  Active Flows:    %u\n", s.active_flows);
            printf("  Download Speed:  %.2f KB/s (%llu B/s)\n", (double)s.rx_bytes_per_sec / 1024.0, s.rx_bytes_per_sec);
            printf("  Upload Speed:    %.2f KB/s (%llu B/s)\n", (double)s.tx_bytes_per_sec / 1024.0, s.tx_bytes_per_sec);
            printf("  Total Download:  %.2f MB (%llu packets)\n", (double)s.total_rx_bytes / (1024.0 * 1024.0), s.total_rx_packets);
            printf("  Total Upload:    %.2f MB (%llu packets)\n", (double)s.total_tx_bytes / (1024.0 * 1024.0), s.total_tx_packets);
        } else if (strcmp(line, "rules") == 0) {
            uint32_t count = rule_store_get_count();
            printf("--- Active Firewall Rules (%u) ---\n", count);
            printf("  ID  | ACTION | TYPE | DIR  | VALUE\n");
            printf("------+--------+------+------+-----------------------------------\n");
            for (uint32_t i = 0; i < count; i++) {
                FirewallRule r;
                if (rule_store_get_at(i, &r)) {
                    printf("  %-3u | %-6s | %-4s | %-4s | %s\n",
                        r.id,
                        (r.action == RULE_ACT_BLOCK ? "BLOCK" : "ALLOW"),
                        (r.type == RULE_TYPE_APP ? "APP" : (r.type == RULE_TYPE_IP ? "IP" : "PORT")),
                        (r.direction == RULE_DIR_OUTBOUND ? "OUT" : (r.direction == RULE_DIR_INBOUND ? "IN" : "BOTH")),
                        r.value);
                }
            }
        } else if (strcmp(line, "flows") == 0) {
            NetworkFlow flows[40];
            uint32_t count = monitor_get_flows(flows, 40);
            printf("--- Active Network Connections (%u) ---\n", count);
            printf("  PROTO | LOCAL ENDPOINT      | REMOTE ENDPOINT     | TX (KB)  | RX (KB)  | PID   | PROCESS\n");
            printf("--------+---------------------+---------------------+----------+----------+-------+------------------\n");
            for (uint32_t i = 0; i < count; i++) {
                char s_ip[64], d_ip[64];
                if (!flows[i].is_ipv6) {
                    struct in_addr sa, da;
                    sa.s_addr = flows[i].src_ip_v4;
                    da.s_addr = flows[i].dst_ip_v4;
                    inet_ntop(AF_INET, &sa, s_ip, sizeof(s_ip));
                    inet_ntop(AF_INET, &da, d_ip, sizeof(d_ip));
                } else {
                    inet_ntop(AF_INET6, flows[i].src_ip_v6, s_ip, sizeof(s_ip));
                    inet_ntop(AF_INET6, flows[i].dst_ip_v6, d_ip, sizeof(d_ip));
                }
                char s_end[128], d_end[128];
                snprintf(s_end, sizeof(s_end), "%s:%u", s_ip, flows[i].src_port);
                snprintf(d_end, sizeof(d_end), "%s:%u", d_ip, flows[i].dst_port);
                const char *pr = (flows[i].protocol == IPPROTO_TCP) ? "TCP" :
                                 (flows[i].protocol == IPPROTO_UDP) ? "UDP" : "OTHER";
                printf("  %-5s | %-19s | %-19s | %-8.1f | %-8.1f | %-5u | %s\n",
                    pr, s_end, d_end,
                    (double)flows[i].bytes_sent / 1024.0,
                    (double)flows[i].bytes_recv / 1024.0,
                    flows[i].pid, flows[i].process_name);
            }
        } else if (strncmp(line, "block app ", 10) == 0) {
            const char *path = line + 10;
            uint32_t id = rule_store_add_app(path, RULE_ACT_BLOCK, RULE_DIR_BOTH, "CLI Rule");
            printf("Added Block Rule ID: %u for '%s'\n", id, path);
        } else if (strncmp(line, "allow app ", 10) == 0) {
            const char *path = line + 10;
            uint32_t id = rule_store_add_app(path, RULE_ACT_ALLOW, RULE_DIR_BOTH, "CLI Rule");
            printf("Added Allow Rule ID: %u for '%s'\n", id, path);
        } else if (strncmp(line, "block ip ", 9) == 0) {
            const char *ip = line + 9;
            uint32_t id = rule_store_add_ip(ip, RULE_ACT_BLOCK, RULE_DIR_BOTH, "CLI Rule");
            printf("Added Block Rule ID: %u for IP '%s'\n", id, ip);
        } else if (strncmp(line, "block port ", 11) == 0) {
            uint16_t port = 0;
            char proto[16] = {0};
            sscanf(line + 11, "%hu %15s", &port, proto);
            uint8_t p = 0;
            if (stricmp(proto, "tcp") == 0) p = IPPROTO_TCP;
            else if (stricmp(proto, "udp") == 0) p = IPPROTO_UDP;
            uint32_t id = rule_store_add_port(port, p, RULE_ACT_BLOCK, RULE_DIR_BOTH, "CLI Rule");
            printf("Added Block Rule ID: %u for Port %u\n", id, port);
        } else if (strncmp(line, "del ", 4) == 0) {
            uint32_t id = (uint32_t)atoi(line + 4);
            if (rule_store_delete(id)) {
                printf("Deleted Rule ID: %u\n", id);
            } else {
                printf("Rule ID %u not found\n", id);
            }
        } else if (strcmp(line, "clear") == 0) {
            rule_store_clear_all();
            printf("All rules cleared.\n");
        } else {
            printf("Unknown command: '%s'. Type 'help' for available commands.\n", line);
        }
    }

    app_core_stop();
    LOG_INFO("Exited interactive console.");
}

static bool ensure_admin_or_elevate(int argc, char *argv[]) {
    if (IsUserAnAdmin()) return true;

    char exe_path[MAX_PATH_LEN];
    GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));

    char params[1024] = {0};
    bool is_hidden = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hidden") == 0 || strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--daemon") == 0) {
            is_hidden = true;
        }
        strcat(params, "\"");
        strcat(params, argv[i]);
        strcat(params, "\"");
        if (i < argc - 1) strcat(params, " ");
    }

    if (is_hidden) {
        HWND hWnd = GetConsoleWindow();
        if (hWnd) ShowWindow(hWnd, SW_HIDE);
    } else {
        printf("\n====================================================================\n");
        printf(" [!] ELEVATION REQUIRED: Attempting to launch as Administrator...\n");
        printf("     Please click 'Yes' on the Windows UAC elevation prompt.\n");
        printf("====================================================================\n\n");
    }

    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = exe_path;
    sei.lpParameters = params;
    sei.nShow = is_hidden ? SW_HIDE : SW_SHOWNORMAL;

    if (ShellExecuteExA(&sei)) {
        return false; // Elevated child process launched
    }

    DWORD err = GetLastError();
    if (err == ERROR_CANCELLED) {
        printf("[ERROR] UAC elevation was cancelled by user.\n");
    } else {
        printf("[ERROR] Failed to trigger UAC elevation prompt (Error: %lu).\n", err);
    }
    printf("\nTo run manually with Administrator privileges:\n");
    printf("  1. Right-click Command Prompt or PowerShell.\n");
    printf("  2. Select 'Run as administrator'.\n");
    printf("  3. Run: %s %s\n\n", exe_path, params);
    return false;
}

int main(int argc, char *argv[]) {
    // Ensure working directory is the folder where kpacketshield.exe lives
    char exe_dir[MAX_PATH_LEN];
    if (GetModuleFileNameA(NULL, exe_dir, sizeof(exe_dir)) > 0) {
        char *last_slash = strrchr(exe_dir, '\\');
        if (last_slash) {
            *last_slash = '\0';
            SetCurrentDirectoryA(exe_dir);
        }
    }

    // If no argument provided, default to --run (console engine)
    char default_arg[] = "--run";
    char *default_argv[] = { argv[0], default_arg, NULL };
    if (argc < 2) {
        argc = 2;
        argv = default_argv;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    // Windows Service Dispatcher (Runs under LocalSystem)
    if (strcmp(argv[1], "--service") == 0) {
        service_run();
        return 0;
    }

    bool hide_window = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--hidden") == 0 || strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--daemon") == 0) {
            hide_window = true;
            break;
        }
    }

    if (hide_window) {
        HWND hWnd = GetConsoleWindow();
        if (hWnd) ShowWindow(hWnd, SW_HIDE);
    }

    // Standalone Console Execution
    if (strcmp(argv[1], "--run") == 0 || strcmp(argv[1], "-r") == 0 || hide_window) {
        if (!ensure_admin_or_elevate(argc, argv)) return 1;

        if (hide_window) {
            HWND hWnd = GetConsoleWindow();
            if (hWnd) ShowWindow(hWnd, SW_HIDE);
        } else {
            print_banner();
            LOG_INFO("Running KPacketShield in console mode...");
        }
        SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
        if (!app_core_start(true)) {
            LOG_ERROR("Failed to start engine subsystems.");
            return 1;
        }
        printf("[Press Ctrl+C to stop engine]\n");
        while (g_cli_running) {
            Sleep(500);
        }
        app_core_stop();
        return 0;
    }

    // Interactive CLI Shell
    if (strcmp(argv[1], "--interactive") == 0 || strcmp(argv[1], "-i") == 0) {
        if (!ensure_admin_or_elevate(argc, argv)) return 1;

        run_interactive_console();
        return 0;
    }

    // Service Management (Requires Admin)
    if (strcmp(argv[1], "--install") == 0) {
        if (!ensure_admin_or_elevate(argc, argv)) return 1;
        return service_install() ? 0 : 1;
    }
    if (strcmp(argv[1], "--uninstall") == 0) {
        if (!ensure_admin_or_elevate(argc, argv)) return 1;
        return service_uninstall() ? 0 : 1;
    }
    if (strcmp(argv[1], "--start") == 0) {
        if (!ensure_admin_or_elevate(argc, argv)) return 1;
        return service_start() ? 0 : 1;
    }
    if (strcmp(argv[1], "--stop") == 0) {
        if (!ensure_admin_or_elevate(argc, argv)) return 1;
        return service_stop() ? 0 : 1;
    }
    if (strcmp(argv[1], "--svc-status") == 0) {
        return service_status() ? 0 : 1;
    }

    // Client Commands (Talking to running service via Named Pipe)
    if (strcmp(argv[1], "--status") == 0) {
        return client_send_cmd("STATUS", false) ? 0 : 1;
    }
    if (strcmp(argv[1], "--list") == 0) {
        return client_send_cmd("LIST_RULES", false) ? 0 : 1;
    }
    if (strcmp(argv[1], "--flows") == 0) {
        return client_send_cmd("GET_FLOWS", false) ? 0 : 1;
    }
    if (strcmp(argv[1], "--events") == 0) {
        SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
        return client_send_cmd("SUBSCRIBE", true) ? 0 : 1;
    }
    if (strcmp(argv[1], "--block-app") == 0 && argc >= 3) {
        char cmd[IPC_BUFFER_SIZE];
        snprintf(cmd, sizeof(cmd), "ADD_APP block %s %s", argv[2], argc >= 4 ? argv[3] : "");
        return client_send_cmd(cmd, false) ? 0 : 1;
    }
    if (strcmp(argv[1], "--allow-app") == 0 && argc >= 3) {
        char cmd[IPC_BUFFER_SIZE];
        snprintf(cmd, sizeof(cmd), "ADD_APP allow %s %s", argv[2], argc >= 4 ? argv[3] : "");
        return client_send_cmd(cmd, false) ? 0 : 1;
    }
    if (strcmp(argv[1], "--block-ip") == 0 && argc >= 3) {
        char cmd[IPC_BUFFER_SIZE];
        snprintf(cmd, sizeof(cmd), "ADD_IP block %s %s", argv[2], argc >= 4 ? argv[3] : "");
        return client_send_cmd(cmd, false) ? 0 : 1;
    }
    if (strcmp(argv[1], "--block-port") == 0 && argc >= 3) {
        char cmd[IPC_BUFFER_SIZE];
        snprintf(cmd, sizeof(cmd), "ADD_PORT block %s %s", argv[2], argc >= 4 ? argv[3] : "any");
        return client_send_cmd(cmd, false) ? 0 : 1;
    }
    if (strcmp(argv[1], "--del-rule") == 0 && argc >= 3) {
        char cmd[IPC_BUFFER_SIZE];
        snprintf(cmd, sizeof(cmd), "DEL_RULE %s", argv[2]);
        return client_send_cmd(cmd, false) ? 0 : 1;
    }

    print_usage(argv[0]);
    return 0;
}
