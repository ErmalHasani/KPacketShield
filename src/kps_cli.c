#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define KPACKETSHIELD_PIPE "\\\\.\\pipe\\KPacketShield"
#define IPC_BUFFER_SIZE 8192

static bool send_pipe_cmd(const char *cmd, bool stream_mode) {
    HANDLE hPipe = CreateFileA(
        KPACKETSHIELD_PIPE,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("Error: Could not connect to KPacketShield service at '%s'.\nIs the KPacketShield service or engine running?\n", KPACKETSHIELD_PIPE);
        return false;
    }

    DWORD written = 0;
    if (!WriteFile(hPipe, cmd, (DWORD)strlen(cmd), &written, NULL)) {
        printf("Error: Failed to write command to named pipe.\n");
        CloseHandle(hPipe);
        return false;
    }

    char buf[IPC_BUFFER_SIZE];
    DWORD read_bytes = 0;

    if (stream_mode) {
        printf("[Streaming live firewall events from KPacketShield. Press Ctrl+C to exit]\n\n");
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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("KPacketShield CLI Client (Unprivileged)\n");
        printf("Usage:\n");
        printf("  kps status                     - Query engine status and live bandwidth\n");
        printf("  kps list                       - List all active firewall rules\n");
        printf("  kps flows                      - Show active connections/flows and PIDs\n");
        printf("  kps events                     - Stream live block/drop alerts\n");
        printf("  kps block app <exe_path> [desc]- Add block rule for application\n");
        printf("  kps allow app <exe_path> [desc]- Add allow rule for application\n");
        printf("  kps block ip <ip_addr> [desc]  - Add block rule for IP address\n");
        printf("  kps block port <port> [proto]  - Add block rule for port (tcp/udp)\n");
        printf("  kps del <rule_id>              - Delete firewall rule\n");
        return 0;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "status") == 0) {
        return send_pipe_cmd("STATUS", false) ? 0 : 1;
    }
    if (strcmp(cmd, "list") == 0 || strcmp(cmd, "rules") == 0) {
        return send_pipe_cmd("LIST_RULES", false) ? 0 : 1;
    }
    if (strcmp(cmd, "flows") == 0) {
        return send_pipe_cmd("GET_FLOWS", false) ? 0 : 1;
    }
    if (strcmp(cmd, "events") == 0 || strcmp(cmd, "stream") == 0) {
        return send_pipe_cmd("SUBSCRIBE", true) ? 0 : 1;
    }
    if (strcmp(cmd, "block") == 0 && argc >= 4) {
        const char *sub = argv[2];
        char pipe_cmd[IPC_BUFFER_SIZE];
        if (strcmp(sub, "app") == 0) {
            snprintf(pipe_cmd, sizeof(pipe_cmd), "ADD_APP block %s %s", argv[3], argc >= 5 ? argv[4] : "");
            return send_pipe_cmd(pipe_cmd, false) ? 0 : 1;
        } else if (strcmp(sub, "ip") == 0) {
            snprintf(pipe_cmd, sizeof(pipe_cmd), "ADD_IP block %s %s", argv[3], argc >= 5 ? argv[4] : "");
            return send_pipe_cmd(pipe_cmd, false) ? 0 : 1;
        } else if (strcmp(sub, "port") == 0) {
            snprintf(pipe_cmd, sizeof(pipe_cmd), "ADD_PORT block %s %s", argv[3], argc >= 5 ? argv[4] : "any");
            return send_pipe_cmd(pipe_cmd, false) ? 0 : 1;
        }
    }
    if (strcmp(cmd, "allow") == 0 && argc >= 4) {
        const char *sub = argv[2];
        char pipe_cmd[IPC_BUFFER_SIZE];
        if (strcmp(sub, "app") == 0) {
            snprintf(pipe_cmd, sizeof(pipe_cmd), "ADD_APP allow %s %s", argv[3], argc >= 5 ? argv[4] : "");
            return send_pipe_cmd(pipe_cmd, false) ? 0 : 1;
        }
    }
    if (strcmp(cmd, "del") == 0 && argc >= 3) {
        char pipe_cmd[IPC_BUFFER_SIZE];
        snprintf(pipe_cmd, sizeof(pipe_cmd), "DEL_RULE %s", argv[2]);
        return send_pipe_cmd(pipe_cmd, false) ? 0 : 1;
    }
    if (strcmp(cmd, "stop") == 0 || strcmp(cmd, "exit") == 0) {
        return send_pipe_cmd("STOP", false) ? 0 : 1;
    }

    printf("Unknown command: %s\n", cmd);
    return 1;
}
