#include "service.h"
#include "proc_map.h"
#include "wfp_engine.h"
#include "rule_store.h"
#include "monitor.h"
#include "ipc_pipe.h"
#include <sddl.h>

static SERVICE_STATUS g_service_status = {0};
static SERVICE_STATUS_HANDLE g_status_handle = NULL;
static HANDLE g_stop_event = NULL;

static int g_alert_mode = 1; // 0 = off, 1 = kps rules only, 2 = all OS events

void service_set_alert_mode(int mode) {
    g_alert_mode = mode;
}

int service_get_alert_mode(void) {
    return g_alert_mode;
}

static void on_wfp_event(const char *event_type, const char *app_path, const char *remote_ip, uint16_t remote_port, uint8_t proto, uint64_t filter_id) {
    char rule_desc[128] = "System Default Rule";
    bool is_our_rule = rule_store_is_our_filter(filter_id, rule_desc, sizeof(rule_desc));

    char msg[1024];
    snprintf(msg, sizeof(msg),
        "{\"event\":\"%s\",\"is_kps_rule\":%s,\"rule\":\"%s\",\"app\":\"%s\",\"remote_ip\":\"%s\",\"port\":%u,\"proto\":%u,\"filter_id\":%llu}",
        event_type, is_our_rule ? "true" : "false", rule_desc, app_path, remote_ip, remote_port, proto, filter_id);

    // Broadcast over Named Pipe for GUI / IPC subscribers
    ipc_pipe_broadcast(msg);

    // Filter console output based on alert mode
    if (g_alert_mode == 0) {
        return; // Muted in console
    }

    if (g_alert_mode == 1) { // Default: only show KPacketShield rule enforcements
        if (is_our_rule) {
            LOG_WARN("[KPS ENFORCED] %s -> %s to %s:%u (Triggered by %s)",
                     event_type, app_path, remote_ip, remote_port, rule_desc);
        }
        return;
    }

    // Mode 2: Show all OS drops, but suppress router ICMP ping echo noise
    if (proto == 1) {
        return;
    }

    LOG_WARN("[%s] %s -> %s to %s:%u (Filter: %llu)",
             is_our_rule ? "KPS BLOCKED" : "OS DROP",
             event_type, app_path, remote_ip, remote_port, filter_id);
}

bool app_core_start(bool dynamic_session) {
    LOG_INFO("Starting KPacketShield Engine subsystems...");

    proc_map_init();

    if (!wfp_engine_init(dynamic_session)) {
        LOG_ERROR("WFP Engine initialization failed. Administrator privileges required!");
        proc_map_cleanup();
        return false;
    }

    wfp_engine_set_event_callback(on_wfp_event);

    rule_store_init();
    rule_store_load_and_apply(KPACKETSHIELD_RULE_FILE);

    monitor_start();

    if (!ipc_pipe_start()) {
        LOG_ERROR("Failed to start IPC Pipe server");
        return false;
    }

    LOG_INFO("All KPacketShield subsystems started successfully.");
    return true;
}

void app_core_stop(void) {
    LOG_INFO("Stopping KPacketShield Engine subsystems...");
    ipc_pipe_stop();
    monitor_stop();
    rule_store_cleanup();
    wfp_engine_shutdown();
    proc_map_cleanup();
    LOG_INFO("All subsystems stopped cleanly.");
}

static void WINAPI service_ctrl_handler(DWORD ctrl) {
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_service_status.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_status_handle, &g_service_status);
            if (g_stop_event) SetEvent(g_stop_event);
            break;
        default:
            break;
    }
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv) {
    (void)argc;
    (void)argv;

    g_status_handle = RegisterServiceCtrlHandlerW(L"KPacketShieldSvc", service_ctrl_handler);
    if (!g_status_handle) return;

    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwCurrentState = SERVICE_START_PENDING;
    g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_service_status.dwWin32ExitCode = 0;
    g_service_status.dwServiceSpecificExitCode = 0;
    g_service_status.dwCheckPoint = 0;
    g_service_status.dwWaitHint = 3000;
    SetServiceStatus(g_status_handle, &g_service_status);

    g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_stop_event) {
        g_service_status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_status_handle, &g_service_status);
        return;
    }

    if (!app_core_start(false)) { // Persistent session in Windows Service
        g_service_status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_status_handle, &g_service_status);
        return;
    }

    g_service_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_status_handle, &g_service_status);

    WaitForSingleObject(g_stop_event, INFINITE);

    app_core_stop();

    g_service_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_status_handle, &g_service_status);

    CloseHandle(g_stop_event);
    g_stop_event = NULL;
}

bool service_run(void) {
    SERVICE_TABLE_ENTRYW service_table[] = {
        { L"KPacketShieldSvc", (LPSERVICE_MAIN_FUNCTIONW)service_main },
        { NULL, NULL }
    };
    return (StartServiceCtrlDispatcherW(service_table) != 0);
}

bool service_install(void) {
    char exe_path[MAX_PATH_LEN];
    GetModuleFileNameA(NULL, exe_path, sizeof(exe_path));

    char cmd_line[MAX_PATH_LEN + 32];
    snprintf(cmd_line, sizeof(cmd_line), "\"%s\" --service", exe_path);

    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        LOG_ERROR("OpenSCManager failed: %lu (Administrator required)", GetLastError());
        return false;
    }

    SC_HANDLE svc = CreateServiceA(
        scm,
        KPACKETSHIELD_SERVICE_NAME,
        KPACKETSHIELD_SERVICE_DISPLAY,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        cmd_line,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            LOG_WARN("Service '%s' is already installed", KPACKETSHIELD_SERVICE_NAME);
            svc = OpenServiceA(scm, KPACKETSHIELD_SERVICE_NAME, SERVICE_ALL_ACCESS | WRITE_DAC);
        } else {
            LOG_ERROR("CreateService failed: %lu", err);
            CloseServiceHandle(scm);
            return false;
        }
    }

    if (svc) {
        // Grant Interactive Users (IU) permission to start and stop service without UAC
        PSECURITY_DESCRIPTOR pSD = NULL;
        const char *sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)";
        if (ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &pSD, NULL)) {
            SetServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION, pSD);
            LocalFree(pSD);
        }
        CloseServiceHandle(svc);
    }

    LOG_INFO("Service '%s' installed & configured successfully", KPACKETSHIELD_SERVICE_NAME);
    CloseServiceHandle(scm);
    return true;
}

bool service_uninstall(void) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        LOG_ERROR("OpenSCManager failed: %lu", GetLastError());
        return false;
    }

    SC_HANDLE svc = OpenServiceA(scm, KPACKETSHIELD_SERVICE_NAME, SERVICE_STOP | DELETE);
    if (!svc) {
        LOG_ERROR("OpenService failed: %lu", GetLastError());
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status);

    if (!DeleteService(svc)) {
        LOG_ERROR("DeleteService failed: %lu", GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    LOG_INFO("Service '%s' uninstalled successfully", KPACKETSHIELD_SERVICE_NAME);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

bool service_start(void) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, KPACKETSHIELD_SERVICE_NAME, SERVICE_START);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    bool ok = StartService(svc, 0, NULL);
    if (ok) {
        LOG_INFO("Service '%s' started successfully", KPACKETSHIELD_SERVICE_NAME);
    } else {
        LOG_ERROR("StartService failed: %lu", GetLastError());
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool service_stop(void) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, KPACKETSHIELD_SERVICE_NAME, SERVICE_STOP);
    if (!svc) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS status;
    bool ok = ControlService(svc, SERVICE_CONTROL_STOP, &status);
    if (ok) {
        LOG_INFO("Service '%s' stopped successfully", KPACKETSHIELD_SERVICE_NAME);
    } else {
        LOG_ERROR("ControlService stop failed: %lu", GetLastError());
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool service_status(void) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceA(scm, KPACKETSHIELD_SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!svc) {
        LOG_INFO("Service '%s' is NOT installed.", KPACKETSHIELD_SERVICE_NAME);
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) {
        const char *state_str = "UNKNOWN";
        switch (ssp.dwCurrentState) {
            case SERVICE_STOPPED: state_str = "STOPPED"; break;
            case SERVICE_START_PENDING: state_str = "STARTING"; break;
            case SERVICE_STOP_PENDING: state_str = "STOPPING"; break;
            case SERVICE_RUNNING: state_str = "RUNNING"; break;
            default: break;
        }
        LOG_INFO("Service '%s' status: %s (PID: %lu)", KPACKETSHIELD_SERVICE_NAME, state_str, ssp.dwProcessId);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}
