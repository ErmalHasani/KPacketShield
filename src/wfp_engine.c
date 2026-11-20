#include "wfp_engine.h"
#include "wfp_defs.h"

static HANDLE g_engine_handle = NULL;
static HANDLE g_event_handle = NULL;
static bool g_is_active = false;
static WfpEventCallback g_event_callback = NULL;

static void CALLBACK wfp_net_event_cb(void *context, const FWPM_NET_EVENT1 *event) {
    (void)context;
    if (!event) return;

    const char *event_type_str = "UNKNOWN";
    uint64_t filter_id = 0;

    if (event->type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) {
        event_type_str = "DROP";
        if (event->classifyDrop) {
            filter_id = event->classifyDrop->filterId;
        }
    } else {
        event_type_str = "EVENT";
    }

    char remote_ip[MAX_IP_STR] = "0.0.0.0";
    uint16_t remote_port = event->header.remotePort;
    uint8_t protocol = event->header.ipProtocol;

    if (event->header.ipVersion == FWP_IP_VERSION_V4) {
        struct in_addr addr;
        addr.s_addr = htonl(event->header.remoteAddrV4);
        inet_ntop(AF_INET, &addr, remote_ip, sizeof(remote_ip));
    } else if (event->header.ipVersion == FWP_IP_VERSION_V6) {
        inet_ntop(AF_INET6, &event->header.remoteAddrV6, remote_ip, sizeof(remote_ip));
    }

    char app_str[MAX_PATH_LEN] = "Unknown";
    if (event->header.appId.data && event->header.appId.size > 0) {
        wchar_t *wapp = (wchar_t *)event->header.appId.data;
        int wlen = event->header.appId.size / sizeof(wchar_t);
        // Ensure null-termination
        int conv = WideCharToMultiByte(CP_UTF8, 0, wapp, wlen, app_str, sizeof(app_str) - 1, NULL, NULL);
        if (conv > 0) {
            app_str[conv] = '\0';
        }
    }

    if (g_event_callback) {
        g_event_callback(event_type_str, app_str, remote_ip, remote_port, protocol, filter_id);
    }
}

bool wfp_engine_init(bool dynamic_session) {
    if (g_is_active) {
        return true;
    }

    FWPM_SESSION0 session = {0};
    if (dynamic_session) {
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    }
    session.displayData.name = L"KPacketShield Dynamic Session";
    session.displayData.description = L"Active session for KPacketShield Firewall Engine";

    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_engine_handle);
    if (result != ERROR_SUCCESS) {
        LOG_ERROR("FwpmEngineOpen0 failed: 0x%08lx (Are you running as Administrator?)", result);
        return false;
    }

    // Register Provider (without transaction so existing provider won't abort)
    FWPM_PROVIDER0 provider = {0};
    provider.providerKey = KPACKETSHIELD_PROVIDER_GUID;
    provider.displayData.name = L"KPacketShield Provider";
    provider.displayData.description = L"Provider for KPacketShield Firewall Service";
    result = FwpmProviderAdd0(g_engine_handle, &provider, NULL);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        LOG_WARN("FwpmProviderAdd0 returned 0x%08lx", result);
    }

    // Register Sublayer
    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.subLayerKey = KPACKETSHIELD_SUBLAYER_GUID;
    sublayer.displayData.name = L"KPacketShield Sublayer";
    sublayer.displayData.description = L"High-priority sublayer for KPacketShield rules";
    sublayer.providerKey = (GUID *)&KPACKETSHIELD_PROVIDER_GUID;
    sublayer.weight = 0x8000; // High weight so rules take precedence
    result = FwpmSubLayerAdd0(g_engine_handle, &sublayer, NULL);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        LOG_WARN("FwpmSubLayerAdd0 returned 0x%08lx", result);
    }

    // Subscribe to NetEvents (Drops and Blocks)
    FWPM_NET_EVENT_SUBSCRIPTION0 sub = {0};
    result = FwpmNetEventSubscribe0(g_engine_handle, &sub, wfp_net_event_cb, NULL, &g_event_handle);
    if (result != ERROR_SUCCESS) {
        LOG_WARN("FwpmNetEventSubscribe0 failed: 0x%08lx (Events won't be streamed)", result);
        g_event_handle = NULL;
    }

    g_is_active = true;
    LOG_INFO("WFP Engine initialized successfully (Dynamic Session: %s)", dynamic_session ? "YES" : "NO");
    return true;
}

void wfp_engine_shutdown(void) {
    if (!g_is_active) return;

    if (g_event_handle && g_engine_handle) {
        FwpmNetEventUnsubscribe0(g_engine_handle, g_event_handle);
        g_event_handle = NULL;
    }

    if (g_engine_handle) {
        FwpmEngineClose0(g_engine_handle);
        g_engine_handle = NULL;
    }

    g_is_active = false;
    LOG_INFO("WFP Engine shut down cleanly");
}

bool wfp_engine_is_active(void) {
    return g_is_active;
}

void wfp_engine_set_event_callback(WfpEventCallback cb) {
    g_event_callback = cb;
}

static DWORD add_filter_internal(const GUID *layer_key,
                                 FWPM_FILTER_CONDITION0 *conditions,
                                 UINT32 num_conditions,
                                 RuleAction action,
                                 const wchar_t *name,
                                 UINT64 *out_filter_id) {
    if (!g_engine_handle) return ERROR_INVALID_HANDLE;

    FWPM_FILTER0 filter = {0};
    filter.layerKey = *layer_key;
    filter.subLayerKey = KPACKETSHIELD_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF; // Max weight in sublayer
    filter.numFilterConditions = num_conditions;
    filter.filterCondition = conditions;
    filter.action.type = (action == RULE_ACT_BLOCK) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    filter.displayData.name = (wchar_t *)name;

    return FwpmFilterAdd0(g_engine_handle, &filter, NULL, out_filter_id);
}

bool wfp_add_app_rule(const char *app_path, RuleAction action, RuleDirection direction, FirewallRule *rule) {
    if (!g_is_active || !app_path || !rule) return false;

    wchar_t wpath[MAX_PATH_LEN] = {0};
    MultiByteToWideChar(CP_UTF8, 0, app_path, -1, wpath, MAX_PATH_LEN);

    FWP_BYTE_BLOB *app_id = NULL;
    DWORD res = FwpmGetAppIdFromFileName0(wpath, &app_id);
    if (res != ERROR_SUCCESS || !app_id) {
        LOG_ERROR("FwpmGetAppIdFromFileName0 failed for '%s': 0x%08lx", app_path, res);
        return false;
    }

    FWPM_FILTER_CONDITION0 cond = {0};
    cond.fieldKey = KPS_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = app_id;

    wchar_t filter_name[128];
    swprintf(filter_name, 128, L"KPS_App_%s", (action == RULE_ACT_BLOCK) ? L"Block" : L"Allow");

    rule->wfp_filter_v4_out = 0;
    rule->wfp_filter_v6_out = 0;
    rule->wfp_filter_v4_in = 0;
    rule->wfp_filter_v6_in = 0;

    // Outbound filters
    if (direction == RULE_DIR_OUTBOUND || direction == RULE_DIR_BOTH) {
        add_filter_internal(&KPS_LAYER_ALE_AUTH_CONNECT_V4, &cond, 1, action, filter_name, &rule->wfp_filter_v4_out);
        add_filter_internal(&KPS_LAYER_ALE_AUTH_CONNECT_V6, &cond, 1, action, filter_name, &rule->wfp_filter_v6_out);
    }

    // Inbound filters
    if (direction == RULE_DIR_INBOUND || direction == RULE_DIR_BOTH) {
        add_filter_internal(&KPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &cond, 1, action, filter_name, &rule->wfp_filter_v4_in);
        add_filter_internal(&KPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6, &cond, 1, action, filter_name, &rule->wfp_filter_v6_in);
    }

    FwpmFreeMemory0((void **)&app_id);
    LOG_INFO("Applied App Rule [%s] -> %s (v4_out: %llu, v6_out: %llu)",
             (action == RULE_ACT_BLOCK ? "BLOCK" : "ALLOW"), app_path,
             rule->wfp_filter_v4_out, rule->wfp_filter_v6_out);
    return true;
}

bool wfp_add_ip_rule(const char *ip_str, RuleAction action, RuleDirection direction, FirewallRule *rule) {
    if (!g_is_active || !ip_str || !rule) return false;

    struct in_addr addr4;
    struct in6_addr addr6;
    bool is_v4 = (inet_pton(AF_INET, ip_str, &addr4) == 1);
    bool is_v6 = (!is_v4 && inet_pton(AF_INET6, ip_str, &addr6) == 1);

    if (!is_v4 && !is_v6) {
        LOG_ERROR("Invalid IP address: %s", ip_str);
        return false;
    }

    wchar_t filter_name[128];
    swprintf(filter_name, 128, L"KPS_IP_%s", (action == RULE_ACT_BLOCK) ? L"Block" : L"Allow");

    FWPM_FILTER_CONDITION0 cond = {0};
    cond.fieldKey = KPS_CONDITION_IP_REMOTE_ADDRESS;
    cond.matchType = FWP_MATCH_EQUAL;

    if (is_v4) {
        cond.conditionValue.type = FWP_UINT32;
        cond.conditionValue.uint32 = ntohl(addr4.s_addr);

        if (direction == RULE_DIR_OUTBOUND || direction == RULE_DIR_BOTH) {
            add_filter_internal(&KPS_LAYER_ALE_AUTH_CONNECT_V4, &cond, 1, action, filter_name, &rule->wfp_filter_v4_out);
        }
        if (direction == RULE_DIR_INBOUND || direction == RULE_DIR_BOTH) {
            add_filter_internal(&KPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &cond, 1, action, filter_name, &rule->wfp_filter_v4_in);
        }
    } else {
        cond.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        cond.conditionValue.byteArray16 = (FWP_BYTE_ARRAY16 *)&addr6;

        if (direction == RULE_DIR_OUTBOUND || direction == RULE_DIR_BOTH) {
            add_filter_internal(&KPS_LAYER_ALE_AUTH_CONNECT_V6, &cond, 1, action, filter_name, &rule->wfp_filter_v6_out);
        }
        if (direction == RULE_DIR_INBOUND || direction == RULE_DIR_BOTH) {
            add_filter_internal(&KPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6, &cond, 1, action, filter_name, &rule->wfp_filter_v6_in);
        }
    }

    LOG_INFO("Applied IP Rule [%s] -> %s (v4_out: %llu, v6_out: %llu)",
             (action == RULE_ACT_BLOCK ? "BLOCK" : "ALLOW"), ip_str,
             rule->wfp_filter_v4_out, rule->wfp_filter_v6_out);
    return true;
}

bool wfp_add_port_rule(uint16_t port, uint8_t protocol, RuleAction action, RuleDirection direction, FirewallRule *rule) {
    if (!g_is_active || !rule) return false;

    FWPM_FILTER_CONDITION0 conds[2] = {0};
    UINT32 num_conds = 1;

    conds[0].fieldKey = KPS_CONDITION_IP_REMOTE_PORT;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type = FWP_UINT16;
    conds[0].conditionValue.uint16 = port;

    if (protocol != 0) {
        conds[1].fieldKey = KPS_CONDITION_IP_PROTOCOL;
        conds[1].matchType = FWP_MATCH_EQUAL;
        conds[1].conditionValue.type = FWP_UINT8;
        conds[1].conditionValue.uint8 = protocol;
        num_conds = 2;
    }

    wchar_t filter_name[128];
    swprintf(filter_name, 128, L"KPS_Port_%s_%u", (action == RULE_ACT_BLOCK) ? L"Block" : L"Allow", port);

    rule->wfp_filter_v4_out = 0;
    rule->wfp_filter_v6_out = 0;
    rule->wfp_filter_v4_in = 0;
    rule->wfp_filter_v6_in = 0;

    if (direction == RULE_DIR_OUTBOUND || direction == RULE_DIR_BOTH) {
        add_filter_internal(&KPS_LAYER_ALE_AUTH_CONNECT_V4, conds, num_conds, action, filter_name, &rule->wfp_filter_v4_out);
        add_filter_internal(&KPS_LAYER_ALE_AUTH_CONNECT_V6, conds, num_conds, action, filter_name, &rule->wfp_filter_v6_out);
    }
    if (direction == RULE_DIR_INBOUND || direction == RULE_DIR_BOTH) {
        add_filter_internal(&KPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4, conds, num_conds, action, filter_name, &rule->wfp_filter_v4_in);
        add_filter_internal(&KPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6, conds, num_conds, action, filter_name, &rule->wfp_filter_v6_in);
    }

    LOG_INFO("Applied Port Rule [%s] -> Port %u (Proto: %u)",
             (action == RULE_ACT_BLOCK ? "BLOCK" : "ALLOW"), port, protocol);
    return true;
}

bool wfp_remove_rule(FirewallRule *rule) {
    if (!g_engine_handle || !rule) return false;

    if (rule->wfp_filter_v4_out) {
        FwpmFilterDeleteById0(g_engine_handle, rule->wfp_filter_v4_out);
        rule->wfp_filter_v4_out = 0;
    }
    if (rule->wfp_filter_v6_out) {
        FwpmFilterDeleteById0(g_engine_handle, rule->wfp_filter_v6_out);
        rule->wfp_filter_v6_out = 0;
    }
    if (rule->wfp_filter_v4_in) {
        FwpmFilterDeleteById0(g_engine_handle, rule->wfp_filter_v4_in);
        rule->wfp_filter_v4_in = 0;
    }
    if (rule->wfp_filter_v6_in) {
        FwpmFilterDeleteById0(g_engine_handle, rule->wfp_filter_v6_in);
        rule->wfp_filter_v6_in = 0;
    }

    return true;
}
