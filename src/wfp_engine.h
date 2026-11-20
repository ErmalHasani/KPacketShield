#ifndef WFP_ENGINE_H
#define WFP_ENGINE_H

#include "common.h"

typedef void (*WfpEventCallback)(const char *event_type, const char *app_path, const char *remote_ip, uint16_t remote_port, uint8_t protocol, uint64_t filter_id);

bool wfp_engine_init(bool dynamic_session);
void wfp_engine_shutdown(void);
bool wfp_engine_is_active(void);

// Register a callback to receive notifications when NetEvents arrive
void wfp_engine_set_event_callback(WfpEventCallback cb);

// Rule enforcement operations
bool wfp_add_app_rule(const char *app_path, RuleAction action, RuleDirection direction, FirewallRule *rule);
bool wfp_add_ip_rule(const char *ip_str, RuleAction action, RuleDirection direction, FirewallRule *rule);
bool wfp_add_port_rule(uint16_t port, uint8_t protocol, RuleAction action, RuleDirection direction, FirewallRule *rule);

// Delete all active WFP filters associated with a rule
bool wfp_remove_rule(FirewallRule *rule);

#endif // WFP_ENGINE_H
