# KPacketShield

**KPacketShield** is a lightweight Windows personal firewall and real-time network monitor written in C, built completely without Visual Studio using **MinGW-w64 (GCC/Clang)**.

It pairs **user-mode Windows Filtering Platform (WFP)** for OS-kernel-enforced application, IP, and port filtering with **WinDivert** for real-time packet sniffing and bandwidth accounting. It operates either as an interactive foreground CLI console (with dynamic auto-cleanup on exit) or as a hardened background **Windows Service** communicating with unprivileged clients over a Windows Named Pipe (`\\.\pipe\KPacketShield`).

---

## Architecture & Layout

```
c:\KPacketShield\
├── Makefile                   # GNU make / mingw32-make build script
├── build.bat                  # Batch build script for CMD
├── build.ps1                  # PowerShell build script
├── bin\                       # Compiled binaries & WinDivert dependencies
│   ├── kpacketshield.exe      # Main engine and Windows service
│   ├── kpacketshield-ui.exe   # Standalone Go + Wails WebView2 modern GUI
│   ├── kps.exe                # Lightweight unprivileged CLI client
│   ├── WinDivert.dll          # WinDivert 2.2.2 64-bit library
│   └── WinDivert64.sys        # Signed WinDivert 64-bit driver
├── gui\                       # Go + Wails (WebView2) GUI source
│   ├── app.go / main.go       # Go backend bridging Named Pipe to frontend
│   └── frontend\              # HTML5, Tailwind CSS, Chart.js UI
├── deps\
│   └── windivert\             # WinDivert 2.2.2 headers and import libraries
└── src\
    ├── common.h               # Shared data structures, constants, and GUIDs
    ├── wfp_defs.h             # WFP layer and condition GUID definitions
    ├── wfp_engine.h / .c      # WFP engine, ALE layers, NetEvents & filters
    ├── monitor.h / .c         # WinDivert sniffer & bandwidth flow monitor
    ├── proc_map.h / .c        # PID <-> process image name & socket lookup
    ├── rule_store.h / .c      # In-memory and disk persistent rule store
    ├── ipc_pipe.h / .c        # Multi-client Named Pipe server
    ├── service.h / .c         # Windows Service Control Manager dispatcher
    ├── main.c                 # Service / Engine CLI entry point
    └── kps_cli.c              # Dedicated unprivileged client tool
```

---

## Key Technical Features

1. **Dual-Stack IPv4 & IPv6 Protection**:
   All application, IP, and port block rules apply to both `FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` / `_V6`, preventing IPv6 bypasses.

2. **Lockout Protection (Dynamic WFP Sessions)**:
   When running the console engine (`kpacketshield.exe --run` or `--interactive`), the session is created with `FWPM_SESSION_FLAG_DYNAMIC`. If the application crashes, exits, or is terminated with Ctrl+C, Windows BFE automatically clears all applied test rules, preventing loss of network connectivity.

3. **High-Priority Sublayer**:
   Rules are registered under a custom provider (`{48b61e27-...}`) and sublayer (`{5a892b10-...}`) with weight `0x8000` to take precedence over default Windows rules.

4. **Zero-Latency Sniffing with WinDivert**:
   The network monitor attaches to WinDivert using `WINDIVERT_FLAG_SNIFF`. Packets are inspected and counted in read-only mode without delaying or interfering with packet delivery.

5. **Privilege Separation via Named Pipe IPC**:
   The engine runs under `LocalSystem` as a Windows Service, exposing a Named Pipe (`\\.\pipe\KPacketShield`) configured with an open DACL. Desktop UIs, CLI scripts, and web dashboards can query live statistics and submit rule modifications without triggering UAC prompts.

---

## Building from the Command Line

No Visual Studio installation is required.

### Prerequisites
- MSYS2 with `gcc` (UCRT64 or MINGW64). If installed in `C:\msys64`, the build scripts will automatically detect it.

### Compile with PowerShell
```powershell
.\build.ps1
```

### Compile with CMD
```cmd
build.bat
```

### Compile with GNU Make
```cmd
make
```

---

## Usage Guide

### 1. Interactive Console Mode (Development & Testing)
Launch the firewall engine directly in an Administrator PowerShell or CMD window:
```powershell
.\bin\kpacketshield.exe --interactive
```
Interactive commands available:
- `status` : View live download/upload speeds and connection counts.
- `rules` : Display active firewall rules.
- `flows` : List active network flows, endpoints, and owning process names.
- `block app <path>` : Block an application (e.g. `block app C:\Windows\System32\notepad.exe`).
- `block ip <ip>` : Block an IP address (e.g. `block ip 198.51.100.1`).
- `block port <port> [tcp|udp]` : Block a port.
- `del <id>` : Remove a rule by ID.
- `exit` : Cleanly shut down engine and remove dynamic filters.

### 2. Windows Service Deployment
Run in an **Administrator** command prompt:
```powershell
# Install the Windows Service
.\bin\kpacketshield.exe --install

# Start the service
.\bin\kpacketshield.exe --start

# Check service status
.\bin\kpacketshield.exe --svc-status

# Stop the service
.\bin\kpacketshield.exe --stop

# Uninstall the service
.\bin\kpacketshield.exe --uninstall
```

### 3. Modern Desktop GUI (`kpacketshield-ui.exe`)
A modern dark-mode desktop GUI built with **Go + Wails (WebView2)**, Tailwind CSS, and Chart.js.
- Double-click `run.bat` to launch both the elevated engine and the GUI together, or:
- Launch `bin\kpacketshield-ui.exe` while `kpacketshield.exe` is running.

Features:
- Live real-time bandwidth charts (Download & Upload speeds)
- Searchable & sortable active connection flows with process names and PIDs
- 1-click IP and Port blocking directly from connection entries
- Firewall rules manager with creation modal
- Live security drop alerts feed

### 4. Unprivileged Client CLI (`kps.exe`)
Any standard user process, script, or UI can communicate with the running service:
```powershell
# Query status and bandwidth
.\bin\kps.exe status

# List active firewall rules
.\bin\kps.exe list

# Show active network flows
.\bin\kps.exe flows

# Stream real-time blocked connection alerts
.\bin\kps.exe events

# Add rules via IPC
.\bin\kps.exe block app "C:\Windows\System32\curl.exe" "Block curl"
.\bin\kps.exe block ip 1.1.1.1 "Block DNS"
.\bin\kps.exe block port 4444 tcp "Block reverse shell port"

# Delete a rule
.\bin\kps.exe del 1
```
