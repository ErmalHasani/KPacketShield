#ifndef SERVICE_H
#define SERVICE_H

#include "common.h"

// Run service dispatcher
bool service_run(void);

// Service lifecycle commands (CLI driven)
bool service_install(void);
bool service_uninstall(void);
bool service_start(void);
bool service_stop(void);
bool service_status(void);

// App core life-cycle (shared between Service and interactive CLI mode)
bool app_core_start(bool dynamic_session);
void app_core_stop(void);

// Console alert mode: 0 = mute, 1 = KPS rules only (default), 2 = all OS events
void service_set_alert_mode(int mode);
int service_get_alert_mode(void);

#endif // SERVICE_H
