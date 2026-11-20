#ifndef MONITOR_H
#define MONITOR_H

#include "common.h"

bool monitor_start(void);
void monitor_stop(void);
bool monitor_is_running(void);
bool monitor_is_divert_active(void);

// Retrieve snapshot of live bandwidth statistics
void monitor_get_stats(BandwidthStats *out_stats);

// Retrieve copy of current active network flows
uint32_t monitor_get_flows(NetworkFlow *out_flows, uint32_t max_flows);

#endif // MONITOR_H
