package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/getlantern/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed icon.ico
var trayIconBytes []byte

const pipeName = `\\.\pipe\KPacketShield`

// --- JSON response types from engine ---

type StatusResponse struct {
	Service        string  `json:"service"`
	WfpActive      bool    `json:"wfp_engine_active"`
	WinDivertActive bool   `json:"windivert_active"`
	ActiveRules    uint32  `json:"active_rules"`
	ActiveFlows    uint32  `json:"active_flows"`
	RxBytesPerSec  uint64  `json:"rx_bytes_sec"`
	TxBytesPerSec  uint64  `json:"tx_bytes_sec"`
	TotalRxMB      float64 `json:"total_rx_mb"`
	TotalTxMB      float64 `json:"total_tx_mb"`
}

type Rule struct {
	ID          uint32 `json:"id"`
	Action      string `json:"action"`
	Type        string `json:"type"`
	Direction   string `json:"dir"`
	Value       string `json:"value"`
	Description string `json:"desc"`
}

type RulesResponse struct {
	RuleCount uint32 `json:"rule_count"`
	Rules     []Rule `json:"rules"`
}

type Flow struct {
	Protocol  uint8  `json:"proto"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	BytesSent uint64 `json:"bytes_sent"`
	BytesRecv uint64 `json:"bytes_recv"`
	PID       uint32 `json:"pid"`
	Process   string `json:"proc"`
}

type FlowsResponse struct {
	FlowCount uint32 `json:"flow_count"`
	Flows     []Flow `json:"flows"`
}

type AddRuleResponse struct {
	Success bool   `json:"success"`
	RuleID  uint32 `json:"rule_id"`
	Action  string `json:"action"`
	App     string `json:"app,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    uint16 `json:"port,omitempty"`
}

type DeleteRuleResponse struct {
	Success bool   `json:"success"`
	RuleID  uint32 `json:"rule_id"`
}

// --- App struct ---

type App struct {
	ctx         context.Context
	cancel      context.CancelFunc
	subConn     net.Conn
	subMu       sync.Mutex
	connected   bool
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	subCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	go a.setupSystray()
	go a.subscriptionLoop(subCtx)
}

func (a *App) setupSystray() {
	systray.Run(func() {
		systray.SetTitle("KPacketShield")
		systray.SetTooltip("KPacketShield Firewall")
		if len(trayIconBytes) > 0 {
			systray.SetIcon(trayIconBytes)
		}

		mShow := systray.AddMenuItem("Show Dashboard", "Open KPacketShield Dashboard")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Quit KPacketShield", "Close KPacketShield completely")

		for {
			select {
			case <-mShow.ClickedCh:
				a.ShowWindow()
			case <-mQuit.ClickedCh:
				systray.Quit()
				runtime.Quit(a.ctx)
				return
			case <-a.ctx.Done():
				systray.Quit()
				return
			}
		}
	}, func() {})
}

func (a *App) ShowWindow() {
	if a.ctx != nil {
		runtime.WindowShow(a.ctx)
		runtime.WindowUnminimise(a.ctx)
	}
}

func (a *App) QuitApp() {
	if a.ctx != nil {
		systray.Quit()
		runtime.Quit(a.ctx)
	}
}

func (a *App) shutdown(ctx context.Context) {
	if a.cancel != nil {
		a.cancel()
	}
	a.subMu.Lock()
	if a.subConn != nil {
		a.subConn.Close()
	}
	a.subMu.Unlock()
}

// sendCommand opens a pipe, sends command, reads full response, closes pipe
func (a *App) sendCommand(cmd string) (string, error) {
	t := 3 * time.Second
	conn, err := winio.DialPipe(pipeName, &t)
	if err != nil {
		return "", fmt.Errorf("cannot connect to KPacketShield engine: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte(cmd + "\n"))
	if err != nil {
		return "", fmt.Errorf("write failed: %v", err)
	}

	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read failed: %v", err)
	}
	return string(buf[:n]), nil
}

// --- Exposed methods to frontend via Wails binding ---

func (a *App) GetStatus() (*StatusResponse, error) {
	resp, err := a.sendCommand("STATUS")
	if err != nil {
		return nil, err
	}
	var status StatusResponse
	if err := json.Unmarshal([]byte(resp), &status); err != nil {
		return nil, fmt.Errorf("parse error: %v (raw: %s)", err, resp)
	}
	return &status, nil
}

func (a *App) GetRules() (*RulesResponse, error) {
	resp, err := a.sendCommand("LIST_RULES")
	if err != nil {
		return nil, err
	}
	var rules RulesResponse
	if err := json.Unmarshal([]byte(resp), &rules); err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}
	return &rules, nil
}

func (a *App) GetFlows() (*FlowsResponse, error) {
	resp, err := a.sendCommand("GET_FLOWS")
	if err != nil {
		return nil, err
	}
	var flows FlowsResponse
	if err := json.Unmarshal([]byte(resp), &flows); err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}
	return &flows, nil
}

func (a *App) AddAppRule(action, appPath, desc string) (*AddRuleResponse, error) {
	cmd := fmt.Sprintf("ADD_APP %s %s %s", action, appPath, desc)
	resp, err := a.sendCommand(cmd)
	if err != nil {
		return nil, err
	}
	var result AddRuleResponse
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}
	return &result, nil
}

func (a *App) AddIPRule(action, ip, desc string) (*AddRuleResponse, error) {
	cmd := fmt.Sprintf("ADD_IP %s %s %s", action, ip, desc)
	resp, err := a.sendCommand(cmd)
	if err != nil {
		return nil, err
	}
	var result AddRuleResponse
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}
	return &result, nil
}

func (a *App) AddPortRule(action string, port uint16, proto, desc string) (*AddRuleResponse, error) {
	cmd := fmt.Sprintf("ADD_PORT %s %d %s %s", action, port, proto, desc)
	resp, err := a.sendCommand(cmd)
	if err != nil {
		return nil, err
	}
	var result AddRuleResponse
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}
	return &result, nil
}

func (a *App) DeleteRule(ruleID uint32) (*DeleteRuleResponse, error) {
	cmd := fmt.Sprintf("DEL_RULE %d", ruleID)
	resp, err := a.sendCommand(cmd)
	if err != nil {
		return nil, err
	}
	var result DeleteRuleResponse
	if err := json.Unmarshal([]byte(resp), &result); err != nil {
		return nil, fmt.Errorf("parse error: %v", err)
	}
	return &result, nil
}

func (a *App) StartEngine() error {
	cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", "Start-Process 'C:\\KPacketShield\\bin\\kpacketshield.exe' -ArgumentList '--run', '--hidden' -Verb RunAs -WindowStyle Hidden")
	return cmd.Start()
}

func (a *App) InstallService() error {
	cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", "Start-Process 'C:\\KPacketShield\\bin\\kpacketshield.exe' -ArgumentList '--install' -Verb RunAs -Wait; Start-Process 'C:\\KPacketShield\\bin\\kpacketshield.exe' -ArgumentList '--start' -Verb RunAs -Wait")
	return cmd.Run()
}

func (a *App) UninstallService() error {
	cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", "Start-Process 'C:\\KPacketShield\\bin\\kpacketshield.exe' -ArgumentList '--stop' -Verb RunAs -Wait; Start-Process 'C:\\KPacketShield\\bin\\kpacketshield.exe' -ArgumentList '--uninstall' -Verb RunAs -Wait")
	return cmd.Run()
}

func (a *App) StopEngine() error {
	_, err := a.sendCommand("STOP")
	return err
}

func (a *App) IsEngineConnected() bool {
	_, err := a.sendCommand("STATUS")
	return err == nil
}

// subscriptionLoop connects to the pipe with SUBSCRIBE and emits events to frontend
func (a *App) subscriptionLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		t := 3 * time.Second
		conn, err := winio.DialPipe(pipeName, &t)
		if err != nil {
			runtime.EventsEmit(a.ctx, "engine:status", map[string]interface{}{
				"connected": false,
				"error":     err.Error(),
			})
			time.Sleep(3 * time.Second)
			continue
		}

		a.subMu.Lock()
		a.subConn = conn
		a.connected = true
		a.subMu.Unlock()

		runtime.EventsEmit(a.ctx, "engine:status", map[string]interface{}{
			"connected": true,
		})

		_, err = conn.Write([]byte("SUBSCRIBE\n"))
		if err != nil {
			conn.Close()
			continue
		}

		scanner := bufio.NewScanner(conn)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				conn.Close()
				return
			default:
			}

			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			var event map[string]interface{}
			if err := json.Unmarshal([]byte(line), &event); err == nil {
				runtime.EventsEmit(a.ctx, "engine:event", event)
			}
		}

		// Connection lost
		conn.Close()
		a.subMu.Lock()
		a.subConn = nil
		a.connected = false
		a.subMu.Unlock()

		runtime.EventsEmit(a.ctx, "engine:status", map[string]interface{}{
			"connected": false,
			"error":     "connection lost",
		})

		time.Sleep(2 * time.Second)
	}
}
