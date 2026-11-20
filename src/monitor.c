#include "monitor.h"
#include "proc_map.h"

static HANDLE g_divert_handle = INVALID_HANDLE_VALUE;
static HANDLE h_sniff_thread = NULL;
static HANDLE h_stats_thread = NULL;
static volatile bool g_running = false;

static NetworkFlow g_flows[MAX_FLOWS];
static uint32_t g_flow_count = 0;
static CRITICAL_SECTION g_flow_lock;

static BandwidthStats g_stats = {0};
static CRITICAL_SECTION g_stats_lock;

static volatile uint64_t g_accum_rx_bytes = 0;
static volatile uint64_t g_accum_tx_bytes = 0;
static volatile uint64_t g_accum_rx_pkts = 0;
static volatile uint64_t g_accum_tx_pkts = 0;

static DWORD WINAPI monitor_stats_thread(LPVOID param) {
    (void)param;
    uint64_t last_rx_bytes = 0;
    uint64_t last_tx_bytes = 0;
    uint64_t last_rx_pkts = 0;
    uint64_t last_tx_pkts = 0;

    while (g_running) {
        Sleep(1000);

        uint64_t cur_rx_bytes = g_accum_rx_bytes;
        uint64_t cur_tx_bytes = g_accum_tx_bytes;
        uint64_t cur_rx_pkts = g_accum_rx_pkts;
        uint64_t cur_tx_pkts = g_accum_tx_pkts;

        EnterCriticalSection(&g_stats_lock);
        g_stats.rx_bytes_per_sec = (cur_rx_bytes >= last_rx_bytes) ? (cur_rx_bytes - last_rx_bytes) : 0;
        g_stats.tx_bytes_per_sec = (cur_tx_bytes >= last_tx_bytes) ? (cur_tx_bytes - last_tx_bytes) : 0;
        g_stats.rx_packets_per_sec = (cur_rx_pkts >= last_rx_pkts) ? (cur_rx_pkts - last_rx_pkts) : 0;
        g_stats.tx_packets_per_sec = (cur_tx_pkts >= last_tx_pkts) ? (cur_tx_pkts - last_tx_pkts) : 0;
        g_stats.total_rx_bytes = cur_rx_bytes;
        g_stats.total_tx_bytes = cur_tx_bytes;
        g_stats.total_rx_packets = cur_rx_pkts;
        g_stats.total_tx_packets = cur_tx_pkts;

        EnterCriticalSection(&g_flow_lock);
        g_stats.active_flows = g_flow_count;

        // Prune stale flows older than 60s
        time_t now = time(NULL);
        for (uint32_t i = 0; i < g_flow_count; ) {
            if (now - g_flows[i].last_seen > 60) {
                // Move last to i
                g_flows[i] = g_flows[g_flow_count - 1];
                g_flow_count--;
            } else {
                i++;
            }
        }
        LeaveCriticalSection(&g_flow_lock);
        LeaveCriticalSection(&g_stats_lock);

        last_rx_bytes = cur_rx_bytes;
        last_tx_bytes = cur_tx_bytes;
        last_rx_pkts = cur_rx_pkts;
        last_tx_pkts = cur_tx_pkts;
    }
    return 0;
}

static void record_flow(bool is_ipv6, const void *src_ip, const void *dst_ip,
                        uint16_t src_port, uint16_t dst_port, uint8_t proto,
                        bool outbound, uint32_t pkt_len) {
    EnterCriticalSection(&g_flow_lock);

    // Normalize flow key so local endpoint is always src and remote is dst
    const void *loc_ip = outbound ? src_ip : dst_ip;
    const void *rem_ip = outbound ? dst_ip : src_ip;
    uint16_t loc_port = outbound ? src_port : dst_port;
    uint16_t rem_port = outbound ? dst_port : src_port;

    int match_idx = -1;
    for (uint32_t i = 0; i < g_flow_count; i++) {
        NetworkFlow *f = &g_flows[i];
        if (f->protocol == proto && f->src_port == loc_port && f->dst_port == rem_port) {
            if (!is_ipv6 && !f->is_ipv6) {
                if (f->src_ip_v4 == *(const uint32_t *)loc_ip && f->dst_ip_v4 == *(const uint32_t *)rem_ip) {
                    match_idx = (int)i;
                    break;
                }
            } else if (is_ipv6 && f->is_ipv6) {
                if (memcmp(f->src_ip_v6, loc_ip, 16) == 0 && memcmp(f->dst_ip_v6, rem_ip, 16) == 0) {
                    match_idx = (int)i;
                    break;
                }
            }
        }
    }

    time_t now = time(NULL);
    if (match_idx != -1) {
        NetworkFlow *f = &g_flows[match_idx];
        if (outbound) {
            f->bytes_sent += pkt_len;
            f->packets_sent++;
        } else {
            f->bytes_recv += pkt_len;
            f->packets_recv++;
        }
        f->last_seen = now;

        // If PID was not resolved on creation, retry resolution
        if (f->pid == 0) {
            if (!is_ipv6) {
                f->pid = proc_map_lookup_socket_v4(proto, f->src_ip_v4, loc_port, f->dst_ip_v4, rem_port);
            } else {
                f->pid = proc_map_lookup_socket_v6(proto, f->src_ip_v6, loc_port, f->dst_ip_v6, rem_port);
            }
            if (f->pid > 0) {
                proc_map_get_by_pid(f->pid, f->process_name, sizeof(f->process_name), NULL, 0);
            }
        }
    } else {
        if (g_flow_count < MAX_FLOWS) {
            NetworkFlow *f = &g_flows[g_flow_count++];
            memset(f, 0, sizeof(NetworkFlow));
            f->is_ipv6 = is_ipv6;
            f->protocol = proto;
            f->src_port = loc_port; // Local port
            f->dst_port = rem_port; // Remote port
            f->inbound = !outbound;
            f->last_seen = now;

            if (outbound) {
                f->bytes_sent = pkt_len;
                f->packets_sent = 1;
            } else {
                f->bytes_recv = pkt_len;
                f->packets_recv = 1;
            }

            if (!is_ipv6) {
                f->src_ip_v4 = *(const uint32_t *)loc_ip;
                f->dst_ip_v4 = *(const uint32_t *)rem_ip;
                f->pid = proc_map_lookup_socket_v4(proto, f->src_ip_v4, loc_port, f->dst_ip_v4, rem_port);
            } else {
                memcpy(f->src_ip_v6, loc_ip, 16);
                memcpy(f->dst_ip_v6, rem_ip, 16);
                f->pid = proc_map_lookup_socket_v6(proto, (const uint8_t *)loc_ip, loc_port, (const uint8_t *)rem_ip, rem_port);
            }

            if (f->pid > 0) {
                proc_map_get_by_pid(f->pid, f->process_name, sizeof(f->process_name), NULL, 0);
            } else {
                strncpy(f->process_name, "-", sizeof(f->process_name));
            }
        }
    }

    LeaveCriticalSection(&g_flow_lock);
}

static DWORD WINAPI monitor_sniff_thread(LPVOID param) {
    (void)param;
    UINT8 packet[65535];
    UINT packet_len = 0;
    WINDIVERT_ADDRESS addr;

    LOG_INFO("WinDivert sniffing loop active");

    while (g_running) {
        if (!WinDivertRecv(g_divert_handle, packet, sizeof(packet), &packet_len, &addr)) {
            DWORD err = GetLastError();
            if (!g_running) break;
            if (err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE) {
                break;
            }
            Sleep(10);
            continue;
        }

        if (addr.Outbound) {
            InterlockedAdd64((LONG64 *)&g_accum_tx_bytes, packet_len);
            InterlockedIncrement64((LONG64 *)&g_accum_tx_pkts);
        } else {
            InterlockedAdd64((LONG64 *)&g_accum_rx_bytes, packet_len);
            InterlockedIncrement64((LONG64 *)&g_accum_rx_pkts);
        }

        // Parse packet for flow tracking
        PWINDIVERT_IPHDR ip_hdr = NULL;
        PWINDIVERT_IPV6HDR ipv6_hdr = NULL;
        PWINDIVERT_TCPHDR tcp_hdr = NULL;
        PWINDIVERT_UDPHDR udp_hdr = NULL;
        UINT8 proto = 0;

        if (WinDivertHelperParsePacket(packet, packet_len, &ip_hdr, &ipv6_hdr, &proto,
                                      NULL, NULL, &tcp_hdr, &udp_hdr, NULL, NULL, NULL, NULL)) {
            uint16_t src_port = 0, dst_port = 0;
            if (tcp_hdr) {
                src_port = ntohs(tcp_hdr->SrcPort);
                dst_port = ntohs(tcp_hdr->DstPort);
            } else if (udp_hdr) {
                src_port = ntohs(udp_hdr->SrcPort);
                dst_port = ntohs(udp_hdr->DstPort);
            }

            if (ip_hdr) {
                record_flow(false, &ip_hdr->SrcAddr, &ip_hdr->DstAddr, src_port, dst_port, proto, addr.Outbound, packet_len);
            } else if (ipv6_hdr) {
                record_flow(true, ipv6_hdr->SrcAddr, ipv6_hdr->DstAddr, src_port, dst_port, proto, addr.Outbound, packet_len);
            }
        }
    }

    LOG_INFO("WinDivert sniffing loop exited");
    return 0;
}

bool monitor_start(void) {
    if (g_running) return true;

    InitializeCriticalSection(&g_flow_lock);
    InitializeCriticalSection(&g_stats_lock);

    // Open WinDivert handle in SNIFF mode (read-only copy, zero traffic interference)
    g_divert_handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
    if (g_divert_handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        LOG_WARN("WinDivertOpen failed (Error: %lu). Bandwidth/packet sniffer running in passive mock mode.", err);
        // We still allow stats thread to run
    } else {
        LOG_INFO("WinDivert opened successfully (Layer: Network, Mode: SNIFF)");
    }

    g_running = true;

    if (g_divert_handle != INVALID_HANDLE_VALUE) {
        h_sniff_thread = CreateThread(NULL, 0, monitor_sniff_thread, NULL, 0, NULL);
    }
    h_stats_thread = CreateThread(NULL, 0, monitor_stats_thread, NULL, 0, NULL);

    return true;
}

void monitor_stop(void) {
    if (!g_running) return;
    g_running = false;

    if (g_divert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(g_divert_handle);
        g_divert_handle = INVALID_HANDLE_VALUE;
    }

    if (h_sniff_thread) {
        WaitForSingleObject(h_sniff_thread, 2000);
        CloseHandle(h_sniff_thread);
        h_sniff_thread = NULL;
    }

    if (h_stats_thread) {
        WaitForSingleObject(h_stats_thread, 2000);
        CloseHandle(h_stats_thread);
        h_stats_thread = NULL;
    }

    DeleteCriticalSection(&g_flow_lock);
    DeleteCriticalSection(&g_stats_lock);
    LOG_INFO("Monitor stopped cleanly");
}

bool monitor_is_running(void) {
    return g_running;
}

bool monitor_is_divert_active(void) {
    return (g_divert_handle != INVALID_HANDLE_VALUE);
}

void monitor_get_stats(BandwidthStats *out_stats) {
    if (!out_stats) return;
    EnterCriticalSection(&g_stats_lock);
    *out_stats = g_stats;
    LeaveCriticalSection(&g_stats_lock);
}

uint32_t monitor_get_flows(NetworkFlow *out_flows, uint32_t max_flows) {
    if (!out_flows || max_flows == 0) return 0;
    EnterCriticalSection(&g_flow_lock);
    uint32_t count = (g_flow_count < max_flows) ? g_flow_count : max_flows;
    memcpy(out_flows, g_flows, count * sizeof(NetworkFlow));
    LeaveCriticalSection(&g_flow_lock);
    return count;
}
