#ifndef RULE_STORE_H
#define RULE_STORE_H

#include "common.h"

void rule_store_init(void);
void rule_store_cleanup(void);

// Load persisted rules and apply to WFP
bool rule_store_load_and_apply(const char *filename);

// Save rules to file
bool rule_store_save(const char *filename);

// Rule CRUD
uint32_t rule_store_add_app(const char *app_path, RuleAction action, RuleDirection direction, const char *desc);
uint32_t rule_store_add_ip(const char *ip_str, RuleAction action, RuleDirection direction, const char *desc);
uint32_t rule_store_add_port(uint16_t port, uint8_t protocol, RuleAction action, RuleDirection direction, const char *desc);

bool rule_store_delete(uint32_t rule_id);
uint32_t rule_store_get_count(void);
bool rule_store_get_at(uint32_t index, FirewallRule *out_rule);
void rule_store_clear_all(void);

// Check if a filter ID was created by KPacketShield and retrieve rule description
bool rule_store_is_our_filter(uint64_t filter_id, char *out_desc, size_t desc_len);

#endif // RULE_STORE_H
