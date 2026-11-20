#include "rule_store.h"
#include "wfp_engine.h"

static FirewallRule g_rules[MAX_RULES];
static uint32_t g_rule_count = 0;
static uint32_t g_next_rule_id = 1;
static CRITICAL_SECTION g_store_lock;
static bool g_initialized = false;
static char g_store_path[MAX_PATH_LEN] = KPACKETSHIELD_RULE_FILE;

void rule_store_init(void) {
    if (!g_initialized) {
        InitializeCriticalSection(&g_store_lock);
        memset(g_rules, 0, sizeof(g_rules));
        g_rule_count = 0;
        g_next_rule_id = 1;
        g_initialized = true;
    }
}

void rule_store_cleanup(void) {
    if (g_initialized) {
        rule_store_clear_all();
        DeleteCriticalSection(&g_store_lock);
        g_initialized = false;
    }
}

uint32_t rule_store_add_app(const char *app_path, RuleAction action, RuleDirection direction, const char *desc) {
    EnterCriticalSection(&g_store_lock);
    if (g_rule_count >= MAX_RULES) {
        LeaveCriticalSection(&g_store_lock);
        LOG_ERROR("Rule store limit reached (%d rules)", MAX_RULES);
        return 0;
    }

    FirewallRule rule = {0};
    rule.id = g_next_rule_id++;
    rule.action = action;
    rule.type = RULE_TYPE_APP;
    rule.direction = direction;
    strncpy(rule.value, app_path, sizeof(rule.value) - 1);
    rule.enabled = true;
    if (desc) {
        strncpy(rule.description, desc, sizeof(rule.description) - 1);
    }

    // Apply rule to WFP if engine is active
    if (wfp_engine_is_active()) {
        wfp_add_app_rule(app_path, action, direction, &rule);
    }

    g_rules[g_rule_count++] = rule;
    LeaveCriticalSection(&g_store_lock);

    rule_store_save(g_store_path);
    return rule.id;
}

uint32_t rule_store_add_ip(const char *ip_str, RuleAction action, RuleDirection direction, const char *desc) {
    EnterCriticalSection(&g_store_lock);
    if (g_rule_count >= MAX_RULES) {
        LeaveCriticalSection(&g_store_lock);
        LOG_ERROR("Rule store limit reached");
        return 0;
    }

    FirewallRule rule = {0};
    rule.id = g_next_rule_id++;
    rule.action = action;
    rule.type = RULE_TYPE_IP;
    rule.direction = direction;
    strncpy(rule.value, ip_str, sizeof(rule.value) - 1);
    rule.enabled = true;
    if (desc) {
        strncpy(rule.description, desc, sizeof(rule.description) - 1);
    }

    if (wfp_engine_is_active()) {
        wfp_add_ip_rule(ip_str, action, direction, &rule);
    }

    g_rules[g_rule_count++] = rule;
    LeaveCriticalSection(&g_store_lock);

    rule_store_save(g_store_path);
    return rule.id;
}

uint32_t rule_store_add_port(uint16_t port, uint8_t protocol, RuleAction action, RuleDirection direction, const char *desc) {
    EnterCriticalSection(&g_store_lock);
    if (g_rule_count >= MAX_RULES) {
        LeaveCriticalSection(&g_store_lock);
        LOG_ERROR("Rule store limit reached");
        return 0;
    }

    FirewallRule rule = {0};
    rule.id = g_next_rule_id++;
    rule.action = action;
    rule.type = RULE_TYPE_PORT;
    rule.direction = direction;
    rule.port = port;
    rule.protocol = protocol;
    snprintf(rule.value, sizeof(rule.value), "%u", port);
    rule.enabled = true;
    if (desc) {
        strncpy(rule.description, desc, sizeof(rule.description) - 1);
    }

    if (wfp_engine_is_active()) {
        wfp_add_port_rule(port, protocol, action, direction, &rule);
    }

    g_rules[g_rule_count++] = rule;
    LeaveCriticalSection(&g_store_lock);

    rule_store_save(g_store_path);
    return rule.id;
}

bool rule_store_delete(uint32_t rule_id) {
    EnterCriticalSection(&g_store_lock);
    int found_idx = -1;
    for (uint32_t i = 0; i < g_rule_count; i++) {
        if (g_rules[i].id == rule_id) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx == -1) {
        LeaveCriticalSection(&g_store_lock);
        return false;
    }

    // Remove from WFP
    if (wfp_engine_is_active()) {
        wfp_remove_rule(&g_rules[found_idx]);
    }

    // Shift remaining rules
    for (uint32_t i = found_idx; i < g_rule_count - 1; i++) {
        g_rules[i] = g_rules[i + 1];
    }
    g_rule_count--;

    LeaveCriticalSection(&g_store_lock);
    rule_store_save(g_store_path);
    return true;
}

uint32_t rule_store_get_count(void) {
    EnterCriticalSection(&g_store_lock);
    uint32_t count = g_rule_count;
    LeaveCriticalSection(&g_store_lock);
    return count;
}

bool rule_store_get_at(uint32_t index, FirewallRule *out_rule) {
    if (!out_rule) return false;
    EnterCriticalSection(&g_store_lock);
    if (index >= g_rule_count) {
        LeaveCriticalSection(&g_store_lock);
        return false;
    }
    *out_rule = g_rules[index];
    LeaveCriticalSection(&g_store_lock);
    return true;
}

bool rule_store_is_our_filter(uint64_t filter_id, char *out_desc, size_t desc_len) {
    if (filter_id == 0) return false;
    EnterCriticalSection(&g_store_lock);
    for (uint32_t i = 0; i < g_rule_count; i++) {
        FirewallRule *r = &g_rules[i];
        if (r->wfp_filter_v4_out == filter_id ||
            r->wfp_filter_v6_out == filter_id ||
            r->wfp_filter_v4_in == filter_id ||
            r->wfp_filter_v6_in == filter_id) {
            if (out_desc && desc_len > 0) {
                snprintf(out_desc, desc_len, "Rule #%u (%s %s)", r->id,
                         r->action == RULE_ACT_BLOCK ? "BLOCK" : "ALLOW", r->value);
            }
            LeaveCriticalSection(&g_store_lock);
            return true;
        }
    }
    LeaveCriticalSection(&g_store_lock);
    return false;
}

void rule_store_clear_all(void) {
    EnterCriticalSection(&g_store_lock);
    for (uint32_t i = 0; i < g_rule_count; i++) {
        if (wfp_engine_is_active()) {
            wfp_remove_rule(&g_rules[i]);
        }
    }
    g_rule_count = 0;
    LeaveCriticalSection(&g_store_lock);
    rule_store_save(g_store_path);
}

bool rule_store_save(const char *filename) {
    if (!filename) filename = g_store_path;

    EnterCriticalSection(&g_store_lock);
    FILE *f = fopen(filename, "w");
    if (!f) {
        LeaveCriticalSection(&g_store_lock);
        LOG_WARN("Failed to open rule file '%s' for writing", filename);
        return false;
    }

    fprintf(f, "# KPacketShield Rule Configuration File\n");
    fprintf(f, "# Format: ID|ACTION|TYPE|DIRECTION|PROTOCOL|PORT|VALUE|DESC\n");
    for (uint32_t i = 0; i < g_rule_count; i++) {
        FirewallRule *r = &g_rules[i];
        fprintf(f, "%u|%d|%d|%d|%u|%u|%s|%s\n",
                r->id, (int)r->action, (int)r->type, (int)r->direction,
                r->protocol, r->port, r->value, r->description);
    }

    fclose(f);
    LeaveCriticalSection(&g_store_lock);
    return true;
}

bool rule_store_load_and_apply(const char *filename) {
    if (!filename) filename = g_store_path;
    strncpy(g_store_path, filename, sizeof(g_store_path) - 1);

    FILE *f = fopen(filename, "r");
    if (!f) {
        LOG_INFO("No existing rule file found at '%s', starting fresh.", filename);
        return true;
    }

    char line[1024];
    EnterCriticalSection(&g_store_lock);

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\r' || line[0] == '\n' || strlen(line) < 5) {
            continue;
        }

        FirewallRule r = {0};
        int action_int = 0, type_int = 0, dir_int = 0;
        unsigned int proto_int = 0, port_int = 0;
        char val_buf[MAX_PATH_LEN] = {0};
        char desc_buf[MAX_NAME_LEN] = {0};

        char *token = strtok(line, "|\r\n");
        if (token) r.id = (uint32_t)atoi(token);
        token = strtok(NULL, "|\r\n");
        if (token) action_int = atoi(token);
        token = strtok(NULL, "|\r\n");
        if (token) type_int = atoi(token);
        token = strtok(NULL, "|\r\n");
        if (token) dir_int = atoi(token);
        token = strtok(NULL, "|\r\n");
        if (token) proto_int = (unsigned int)atoi(token);
        token = strtok(NULL, "|\r\n");
        if (token) port_int = (unsigned int)atoi(token);
        token = strtok(NULL, "|\r\n");
        if (token) strncpy(val_buf, token, sizeof(val_buf) - 1);
        token = strtok(NULL, "|\r\n");
        if (token) strncpy(desc_buf, token, sizeof(desc_buf) - 1);

        r.action = (RuleAction)action_int;
        r.type = (RuleType)type_int;
        r.direction = (RuleDirection)dir_int;
        r.protocol = (uint8_t)proto_int;
        r.port = (uint16_t)port_int;
        strncpy(r.value, val_buf, sizeof(r.value) - 1);
        strncpy(r.description, desc_buf, sizeof(r.description) - 1);
        r.enabled = true;

        if (r.id >= g_next_rule_id) {
            g_next_rule_id = r.id + 1;
        }

        // Apply to WFP
        if (wfp_engine_is_active()) {
            if (r.type == RULE_TYPE_APP) {
                wfp_add_app_rule(r.value, r.action, r.direction, &r);
            } else if (r.type == RULE_TYPE_IP) {
                wfp_add_ip_rule(r.value, r.action, r.direction, &r);
            } else if (r.type == RULE_TYPE_PORT) {
                wfp_add_port_rule(r.port, r.protocol, r.action, r.direction, &r);
            }
        }

        if (g_rule_count < MAX_RULES) {
            g_rules[g_rule_count++] = r;
        }
    }

    fclose(f);
    LeaveCriticalSection(&g_store_lock);
    LOG_INFO("Loaded %u rules from '%s'", g_rule_count, filename);
    return true;
}
