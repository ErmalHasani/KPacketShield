#ifndef COMMON_H
#define COMMON_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "windivert.h"

// Provider and Sublayer GUIDs for KPacketShield
// {48b61e27-0fa8-48b4-b499-7a76e73e97f0}
static const GUID KPACKETSHIELD_PROVIDER_GUID = {
    0x48b61e27, 0x0fa8, 0x48b4, { 0xb4, 0x99, 0x7a, 0x76, 0xe7, 0x3e, 0x97, 0xf0 }
};

// {5a892b10-61f2-4ad5-9e63-c79dc6e7c10b}
static const GUID KPACKETSHIELD_SUBLAYER_GUID = {
    0x5a892b10, 0x61f2, 0x4ad5, { 0x9e, 0x63, 0xc7, 0x9d, 0xc6, 0xe7, 0xc1, 0x0b }
};

#define KPACKETSHIELD_PIPE_NAME "\\\\.\\pipe\\KPacketShield"
#define KPACKETSHIELD_SERVICE_NAME "KPacketShieldSvc"
#define KPACKETSHIELD_SERVICE_DISPLAY "KPacketShield Firewall and Network Monitor"
#define KPACKETSHIELD_RULE_FILE "kpacketshield_rules.conf"

#define MAX_PATH_LEN 512
#define MAX_IP_STR 64
#define MAX_NAME_LEN 128
#define MAX_RULES 256
#define MAX_FLOWS 1024
#define IPC_BUFFER_SIZE 8192

typedef enum {
    RULE_ACT_BLOCK = 0,
    RULE_ACT_ALLOW = 1
} RuleAction;

typedef enum {
    RULE_TYPE_APP = 0,
    RULE_TYPE_IP = 1,
    RULE_TYPE_PORT = 2
} RuleType;

typedef enum {
    RULE_DIR_OUTBOUND = 0,
    RULE_DIR_INBOUND = 1,
    RULE_DIR_BOTH = 2
} RuleDirection;

typedef struct {
    uint32_t id;
    RuleAction action;
    RuleType type;
    RuleDirection direction;
    uint8_t protocol; // IPPROTO_TCP, IPPROTO_UDP, or 0 (any)
    char value[MAX_PATH_LEN]; // App path, IP string, or Port string
    uint16_t port;
    bool enabled;
    uint64_t wfp_filter_v4_out;
    uint64_t wfp_filter_v6_out;
    uint64_t wfp_filter_v4_in;
    uint64_t wfp_filter_v6_in;
    char description[MAX_NAME_LEN];
} FirewallRule;

typedef struct {
    uint32_t src_ip_v4;
    uint32_t dst_ip_v4;
    uint8_t src_ip_v6[16];
    uint8_t dst_ip_v6[16];
    bool is_ipv6;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; // IPPROTO_TCP, IPPROTO_UDP, etc.
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t packets_sent;
    uint64_t packets_recv;
    uint32_t pid;
    char process_name[MAX_NAME_LEN];
    time_t last_seen;
    bool inbound;
} NetworkFlow;

typedef struct {
    uint64_t rx_bytes_per_sec;
    uint64_t tx_bytes_per_sec;
    uint64_t rx_packets_per_sec;
    uint64_t tx_packets_per_sec;
    uint64_t total_rx_bytes;
    uint64_t total_tx_bytes;
    uint64_t total_rx_packets;
    uint64_t total_tx_packets;
    uint32_t active_flows;
} BandwidthStats;

#define LOG_INFO(fmt, ...)  printf("[INFO]  " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  printf("[WARN]  " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)

#endif // COMMON_H
