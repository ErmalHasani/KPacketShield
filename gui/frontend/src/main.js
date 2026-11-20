// KPacketShield - Professional Cybersecurity Firewall & Network Monitor
// High Performance Single-Page Architecture

import { 
  GetStatus, GetRules, GetFlows, AddAppRule, AddIPRule, AddPortRule, 
  DeleteRule, StartEngine, StopEngine, IsEngineConnected,
  InstallService, UninstallService
} from '../wailsjs/go/main/App';
import { EventsOn } from '../wailsjs/runtime/runtime';
import { 
  Chart, LineController, LineElement, PointElement, LinearScale, 
  CategoryScale, Filler, Tooltip 
} from 'chart.js';

Chart.register(LineController, LineElement, PointElement, LinearScale, CategoryScale, Filler, Tooltip);

// ─── State ───
const state = {
  connected: false,
  status: null,
  rules: [],
  flows: [],
  alerts: [],
  bandwidthHistory: {
    labels: Array(30).fill(''),
    rx: Array(30).fill(0),
    tx: Array(30).fill(0),
  },
  activeTab: 'dashboard',
  flowSearch: '',
  flowSort: { key: 'bytes_recv', dir: 'desc' },
};

const MAX_BW_POINTS = 30;
const MAX_ALERTS = 100;
let bwChart = null;

// ─── Helpers ───
function formatBytes(bytes) {
  if (!bytes || isNaN(bytes) || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  if (bytes < k) return Math.round(bytes) + ' B';
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatBps(bytesPerSec) {
  return formatBytes(bytesPerSec) + '/s';
}

function protoName(proto) {
  switch (proto) {
    case 6: return 'TCP';
    case 17: return 'UDP';
    case 1: return 'ICMP';
    default: return proto > 0 ? `P${proto}` : 'OTHER';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function showToast(message, isError = false) {
  const toast = document.getElementById('toast');
  const toastMsg = document.getElementById('toast-msg');
  if (!toast || !toastMsg) return;

  toastMsg.textContent = message;
  toast.className = `fixed bottom-5 right-5 z-50 flex items-center gap-2.5 px-4 py-2.5 rounded-lg border shadow-xl text-xs font-medium transition-all duration-300 transform translate-y-0 opacity-100 ${
    isError 
      ? 'bg-red-950/90 border-red-800/80 text-red-200' 
      : 'bg-emerald-950/90 border-emerald-800/80 text-emerald-200'
  }`;

  setTimeout(() => {
    toast.className = 'fixed bottom-5 right-5 z-50 flex items-center gap-2.5 px-4 py-2.5 rounded-lg border shadow-xl text-xs font-medium transition-all duration-300 transform translate-y-3 opacity-0 pointer-events-none';
  }, 3200);
}

// ─── Initial DOM Layout ───
function initLayout() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <!-- Top Application Bar -->
    <header class="wails-drag flex items-center justify-between px-5 py-3 border-b border-zinc-800/80 bg-zinc-950/80 shrink-0">
      <div class="flex items-center gap-4">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center glow-emerald">
            <svg class="w-4 h-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <div>
            <div class="flex items-center gap-1.5">
              <span class="font-bold text-sm tracking-wide text-zinc-100">KPacketShield</span>
              <span class="text-[10px] font-mono px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-400 font-semibold">v1.2</span>
            </div>
            <div class="text-[10px] text-zinc-500 tracking-wider uppercase font-medium">WFP Firewall & Real-time Monitor</div>
          </div>
        </div>

        <!-- Connection Pill -->
        <div class="ml-4 flex items-center gap-2 px-3 py-1 rounded-full bg-zinc-900 border border-zinc-800">
          <div id="engine-dot" class="w-2 h-2 rounded-full bg-red-500"></div>
          <span id="engine-status-text" class="text-xs font-semibold text-red-400 tracking-wide uppercase">UNPROTECTED</span>
        </div>
      </div>

      <!-- Right action controls -->
      <div class="flex items-center gap-2.5">
        <button id="btn-start-engine" onclick="window.__startEngine()" 
          class="hidden items-center gap-1.5 px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold shadow-lg shadow-emerald-950/50 transition">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z" /></svg>
          Start Engine (Silent)
        </button>
        <button onclick="window.__openServiceModal()" 
          class="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded-lg text-xs font-medium text-zinc-300 transition">
          <svg class="w-3.5 h-3.5 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z" /></svg>
          Service Settings
        </button>
      </div>
    </header>

    <!-- Navigation Tabs -->
    <nav class="flex border-b border-zinc-800/80 bg-zinc-950 px-4 shrink-0">
      <button id="tab-btn-dashboard" onclick="window.__switchTab('dashboard')" 
        class="tab-btn flex items-center gap-2 px-4 py-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 border-emerald-400 text-emerald-400">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" /></svg>
        Overview Dashboard
      </button>
      <button id="tab-btn-flows" onclick="window.__switchTab('flows')" 
        class="tab-btn flex items-center gap-2 px-4 py-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 border-transparent text-zinc-400 hover:text-zinc-200">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" /></svg>
        Live Network Flows
        <span id="tab-flows-badge" class="ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-zinc-800 text-zinc-300">0</span>
      </button>
      <button id="tab-btn-rules" onclick="window.__switchTab('rules')" 
        class="tab-btn flex items-center gap-2 px-4 py-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 border-transparent text-zinc-400 hover:text-zinc-200">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z" /></svg>
        Firewall Rules
        <span id="tab-rules-badge" class="ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-zinc-800 text-zinc-300">0</span>
      </button>
      <button id="tab-btn-alerts" onclick="window.__switchTab('alerts')" 
        class="tab-btn flex items-center gap-2 px-4 py-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 border-transparent text-zinc-400 hover:text-zinc-200">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" /></svg>
        Security Drops & Alerts
        <span id="tab-alerts-badge" class="hidden ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-red-500/20 text-red-400 border border-red-500/30">0</span>
      </button>
    </nav>

    <!-- Main Content Panels -->
    <main class="p-5 flex-1 overflow-auto" style="height: calc(100vh - 98px);">

      <!-- ─── Panel 1: Dashboard ─── -->
      <section id="panel-dashboard" class="space-y-5">
        <!-- 4 Top Cards -->
        <div class="grid grid-cols-4 gap-4">
          <div class="glass-panel glass-panel-hover rounded-xl p-4.5">
            <div class="flex items-center justify-between text-xs text-zinc-400 mb-2">
              <span class="font-medium">WFP Kernel Subsystem</span>
              <span class="text-[10px] font-mono uppercase bg-zinc-800/80 px-1.5 py-0.5 rounded text-zinc-400">ALE Layer</span>
            </div>
            <div class="flex items-center gap-2.5">
              <div id="stat-wfp-dot" class="w-2.5 h-2.5 rounded-full bg-red-500"></div>
              <span id="stat-wfp-text" class="text-xl font-bold text-red-400 tracking-tight">Inactive</span>
            </div>
            <div class="text-[11px] text-zinc-500 mt-1.5">Dual-stack IPv4/IPv6 packet filter</div>
          </div>

          <div class="glass-panel glass-panel-hover rounded-xl p-4.5">
            <div class="flex items-center justify-between text-xs text-zinc-400 mb-2">
              <span class="font-medium">WinDivert Sniffer</span>
              <span class="text-[10px] font-mono uppercase bg-zinc-800/80 px-1.5 py-0.5 rounded text-zinc-400">Kernel v2.2</span>
            </div>
            <div class="flex items-center gap-2.5">
              <div id="stat-windivert-dot" class="w-2.5 h-2.5 rounded-full bg-red-500"></div>
              <span id="stat-windivert-text" class="text-xl font-bold text-red-400 tracking-tight">Inactive</span>
            </div>
            <div class="text-[11px] text-zinc-500 mt-1.5">Zero-latency non-blocking tap</div>
          </div>

          <div class="glass-panel glass-panel-hover rounded-xl p-4.5">
            <div class="flex items-center justify-between text-xs text-zinc-400 mb-2">
              <span class="font-medium">Active Policy Rules</span>
              <span class="text-[10px] font-mono uppercase bg-zinc-800/80 px-1.5 py-0.5 rounded text-zinc-400">Enforced</span>
            </div>
            <div class="text-2xl font-bold text-sky-400 tracking-tight">
              <span id="stat-rules-count">0</span>
            </div>
            <div class="text-[11px] text-zinc-500 mt-1.5">Custom App / IP / Port blocks</div>
          </div>

          <div class="glass-panel glass-panel-hover rounded-xl p-4.5">
            <div class="flex items-center justify-between text-xs text-zinc-400 mb-2">
              <span class="font-medium">Active Network Sessions</span>
              <span class="text-[10px] font-mono uppercase bg-zinc-800/80 px-1.5 py-0.5 rounded text-zinc-400">Tracked</span>
            </div>
            <div class="text-2xl font-bold text-purple-400 tracking-tight">
              <span id="stat-flows-count">0</span>
            </div>
            <div class="text-[11px] text-zinc-500 mt-1.5">Concurrent bidirectional flows</div>
          </div>
        </div>

        <!-- Bandwidth Monitor and Summary Card -->
        <div class="grid grid-cols-3 gap-4">
          <div class="col-span-2 glass-panel rounded-xl p-5 flex flex-col">
            <div class="flex justify-between items-center mb-3">
              <div>
                <h3 class="text-sm font-bold text-zinc-100 tracking-tight">Real-Time Throughput Monitor</h3>
                <p class="text-xs text-zinc-500">Live 30-second rolling upload & download rate</p>
              </div>
              <div class="flex gap-4 text-xs font-mono">
                <span class="flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse-dot"></span> 
                  ↓ <span id="speed-rx">0 B/s</span>
                </span>
                <span class="flex items-center gap-1.5 px-2.5 py-1 rounded bg-sky-500/10 border border-sky-500/20 text-sky-400">
                  <span class="w-2 h-2 rounded-full bg-sky-400 animate-pulse-dot"></span> 
                  ↑ <span id="speed-tx">0 B/s</span>
                </span>
              </div>
            </div>

            <!-- STRICT FIXED CONTAINER: Prevents any canvas resize feedback loops -->
            <div class="relative w-full h-[210px] overflow-hidden">
              <canvas id="bw-chart"></canvas>
            </div>
          </div>

          <!-- Cumulative Statistics -->
          <div class="space-y-3 flex flex-col justify-between">
            <div class="glass-panel rounded-xl p-4">
              <div class="flex items-center justify-between mb-1">
                <span class="text-xs text-zinc-400 font-medium">Session Downloaded</span>
                <span class="text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded">RX</span>
              </div>
              <div id="stat-total-rx" class="text-xl font-bold text-zinc-100 font-mono">0 B</div>
            </div>

            <div class="glass-panel rounded-xl p-4">
              <div class="flex items-center justify-between mb-1">
                <span class="text-xs text-zinc-400 font-medium">Session Uploaded</span>
                <span class="text-[10px] text-sky-400 bg-sky-500/10 px-1.5 py-0.5 rounded">TX</span>
              </div>
              <div id="stat-total-tx" class="text-xl font-bold text-zinc-100 font-mono">0 B</div>
            </div>

            <div class="glass-panel rounded-xl p-4">
              <div class="flex items-center justify-between mb-1">
                <span class="text-xs text-zinc-400 font-medium">Protection Status</span>
                <span id="stat-engine-state-badge" class="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400">OFFLINE</span>
              </div>
              <div id="stat-engine-state" class="text-sm font-semibold text-zinc-300">Engine Disconnected</div>
            </div>
          </div>
        </div>

        <!-- Silent Service Notification Banner -->
        <div class="glass-panel rounded-xl p-4 border-l-4 border-l-emerald-500 flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
              <svg class="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" /></svg>
            </div>
            <div>
              <div class="text-xs font-semibold text-zinc-100">Want zero CMD windows and zero UAC prompts on startup?</div>
              <div class="text-[11px] text-zinc-400">Install KPacketShield as a Windows Service to run completely in the background at boot.</div>
            </div>
          </div>
          <button onclick="window.__installService()" class="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold shadow transition shrink-0">
            Install Windows Service
          </button>
        </div>

        <!-- Quick Shield Actions -->
        <div class="glass-panel rounded-xl p-4.5">
          <h3 class="text-xs font-bold text-zinc-300 uppercase tracking-wider mb-3">Quick Shield Controls</h3>
          <div class="flex items-center gap-3">
            <button onclick="window.__quickBlockIP()" class="flex items-center gap-2 px-4 py-2 bg-red-600/15 hover:bg-red-600/25 border border-red-600/30 text-red-400 rounded-lg text-xs font-semibold transition">
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
              Block Remote IP
            </button>
            <button onclick="window.__quickBlockPort()" class="flex items-center gap-2 px-4 py-2 bg-orange-600/15 hover:bg-orange-600/25 border border-orange-600/30 text-orange-400 rounded-lg text-xs font-semibold transition">
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" /></svg>
              Block Port
            </button>
            <button onclick="window.__openModal()" class="flex items-center gap-2 px-4 py-2 bg-emerald-600/15 hover:bg-emerald-600/25 border border-emerald-600/30 text-emerald-400 rounded-lg text-xs font-semibold transition">
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15" /></svg>
              + Create Custom Filter
            </button>
          </div>
        </div>
      </section>

      <!-- ─── Panel 2: Flows ─── -->
      <section id="panel-flows" class="hidden space-y-4">
        <div class="flex justify-between items-center">
          <div>
            <h2 class="text-sm font-bold text-zinc-100 uppercase tracking-wider">Live Network Sessions</h2>
            <p class="text-xs text-zinc-500">Real-time socket mapping to system processes & transfer stats</p>
          </div>
          <div class="relative w-80">
            <input type="text" id="flow-search-input" placeholder="Filter by process, IP, port..."
              class="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-9 pr-3 py-2 text-xs text-zinc-200 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none transition"
              oninput="window.__flowSearch(this.value)" />
            <svg class="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" /></svg>
          </div>
        </div>

        <div class="glass-panel rounded-xl overflow-hidden">
          <div class="max-h-[calc(100vh-190px)] overflow-y-auto">
            <table class="w-full text-left text-xs">
              <thead class="sticky top-0 bg-zinc-950/95 border-b border-zinc-800 text-zinc-400 z-10 backdrop-blur">
                <tr class="uppercase text-[10px] tracking-wider font-semibold">
                  <th class="px-4 py-3 cursor-pointer hover:text-zinc-200" onclick="window.__flowSortBy('proto')">Protocol</th>
                  <th class="px-4 py-3 cursor-pointer hover:text-zinc-200" onclick="window.__flowSortBy('src')">Local Endpoint</th>
                  <th class="px-4 py-3 cursor-pointer hover:text-zinc-200" onclick="window.__flowSortBy('dst')">Remote Endpoint</th>
                  <th class="px-4 py-3 cursor-pointer hover:text-zinc-200 text-right" onclick="window.__flowSortBy('bytes_sent')">Transmitted (TX)</th>
                  <th class="px-4 py-3 cursor-pointer hover:text-zinc-200 text-right" onclick="window.__flowSortBy('bytes_recv')">Received (RX)</th>
                  <th class="px-4 py-3 cursor-pointer hover:text-zinc-200 text-right" onclick="window.__flowSortBy('pid')">PID</th>
                  <th class="px-4 py-3 cursor-pointer hover:text-zinc-200" onclick="window.__flowSortBy('proc')">Process Image</th>
                  <th class="px-4 py-3 text-center">Firewall Action</th>
                </tr>
              </thead>
              <tbody id="flows-tbody" class="divide-y divide-zinc-800/40">
                <tr><td colspan="8" class="px-4 py-12 text-center text-zinc-500">Connecting to engine flow monitor...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- ─── Panel 3: Rules ─── -->
      <section id="panel-rules" class="hidden space-y-4">
        <div class="flex justify-between items-center">
          <div>
            <h2 class="text-sm font-bold text-zinc-100 uppercase tracking-wider">Firewall Security Policies</h2>
            <p class="text-xs text-zinc-500">Active rules enforced by Windows Filtering Platform (WFP)</p>
          </div>
          <button onclick="window.__openModal()" class="flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold shadow transition">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4.5v15m7.5-7.5h-15" /></svg>
            Add New Rule
          </button>
        </div>

        <div id="rules-list" class="space-y-2.5">
          <div class="glass-panel rounded-xl p-12 text-center">
            <div class="w-12 h-12 rounded-full bg-zinc-800/60 border border-zinc-700/60 flex items-center justify-center mx-auto mb-3">
              <svg class="w-6 h-6 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" /></svg>
            </div>
            <h3 class="text-sm font-semibold text-zinc-200">No active firewall rules</h3>
            <p class="text-xs text-zinc-500 mt-1">Network traffic is currently operating under default pass-through.</p>
          </div>
        </div>
      </section>

      <!-- ─── Panel 4: Alerts ─── -->
      <section id="panel-alerts" class="hidden space-y-4">
        <div class="flex justify-between items-center">
          <div>
            <h2 class="text-sm font-bold text-zinc-100 uppercase tracking-wider">Live Security Audit Log</h2>
            <p class="text-xs text-zinc-500">Live dropped packets captured by WFP NetEvent subscriber</p>
          </div>
          <button onclick="window.__clearAlerts()" class="px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded-lg text-xs text-zinc-400 hover:text-zinc-200 transition">
            Clear Audit Log
          </button>
        </div>

        <div id="alerts-list" class="space-y-2 max-h-[calc(100vh-190px)] overflow-y-auto">
          <div class="glass-panel rounded-xl p-12 text-center text-zinc-500 text-xs">
            No drop events recorded. Live alerts appear as packet filters are enforced.
          </div>
        </div>
      </section>

    </main>

    <!-- Modal: Add Custom Rule -->
    <div id="modal-overlay" class="hidden fixed inset-0 modal-backdrop z-50 flex items-center justify-center p-4">
      <div class="glass-panel bg-zinc-950 border border-zinc-800 rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <div class="flex justify-between items-center mb-5">
          <div>
            <h3 class="text-base font-bold text-zinc-100">Create Firewall Filter</h3>
            <p class="text-xs text-zinc-500">Registers an OS-level WFP ALE sublayer filter</p>
          </div>
          <button onclick="window.__closeModal()" class="text-zinc-500 hover:text-zinc-200 transition p-1">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div class="space-y-4 text-xs">
          <div>
            <label class="block text-zinc-400 font-medium mb-1.5">Filter Type</label>
            <select id="rule-type" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-zinc-200 focus:border-emerald-500 focus:outline-none" onchange="window.__onRuleTypeChange()">
              <option value="ip">Remote IP Address (IPv4 / IPv6)</option>
              <option value="port">Port Number & Protocol</option>
              <option value="app">Executable Application Path</option>
            </select>
          </div>
          <div>
            <label class="block text-zinc-400 font-medium mb-1.5">Action</label>
            <select id="rule-action" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-zinc-200 focus:border-emerald-500 focus:outline-none">
              <option value="block">BLOCK Traffic (Drop packets)</option>
              <option value="allow">ALLOW Traffic (Permit packets)</option>
            </select>
          </div>
          <div id="rule-value-group">
            <label id="rule-value-label" class="block text-zinc-400 font-medium mb-1.5">IP Address</label>
            <input id="rule-value" type="text" placeholder="e.g. 192.168.1.100" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-zinc-200 focus:border-emerald-500 focus:outline-none font-mono" />
          </div>
          <div id="rule-proto-group" class="hidden">
            <label class="block text-zinc-400 font-medium mb-1.5">Protocol</label>
            <select id="rule-proto" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-zinc-200 focus:border-emerald-500 focus:outline-none">
              <option value="tcp">TCP (Transmission Control Protocol)</option>
              <option value="udp">UDP (User Datagram Protocol)</option>
            </select>
          </div>
          <div>
            <label class="block text-zinc-400 font-medium mb-1.5">Rule Description / Comment</label>
            <input id="rule-desc" type="text" placeholder="e.g. Block malicious C2 connection" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-zinc-200 focus:border-emerald-500 focus:outline-none" />
          </div>
          <div class="flex gap-2.5 pt-3">
            <button onclick="window.__submitRule()" class="flex-1 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2.5 rounded-lg transition">Apply Rule</button>
            <button onclick="window.__closeModal()" class="flex-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-300 font-medium py-2.5 rounded-lg transition">Cancel</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Modal: Service Settings -->
    <div id="modal-service-overlay" class="hidden fixed inset-0 modal-backdrop z-50 flex items-center justify-center p-4">
      <div class="glass-panel bg-zinc-950 border border-zinc-800 rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <div class="flex justify-between items-center mb-4">
          <div>
            <h3 class="text-base font-bold text-zinc-100">Windows Background Service</h3>
            <p class="text-xs text-zinc-500">Run permanently under LocalSystem (No UAC, No CMD)</p>
          </div>
          <button onclick="window.__closeServiceModal()" class="text-zinc-500 hover:text-zinc-200 transition p-1">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div class="space-y-4 text-xs text-zinc-400">
          <p>
            When installed as a Windows Service, KPacketShield starts automatically in the background on Windows boot without any console window or UAC dialog.
          </p>
          <div class="p-3.5 bg-zinc-900/80 rounded-xl border border-zinc-800 space-y-2">
            <div class="flex items-center justify-between">
              <span class="font-medium text-zinc-300">Service Name:</span>
              <span class="font-mono text-zinc-400">KPacketShieldSvc</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="font-medium text-zinc-300">Account:</span>
              <span class="font-mono text-zinc-400">NT AUTHORITY\\SYSTEM</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="font-medium text-zinc-300">Startup Type:</span>
              <span class="font-mono text-emerald-400">Automatic</span>
            </div>
          </div>
          <div class="flex gap-2.5 pt-2">
            <button onclick="window.__installService()" class="flex-1 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2.5 rounded-lg transition">Install & Start Service</button>
            <button onclick="window.__uninstallService()" class="flex-1 bg-red-950/40 hover:bg-red-900/40 border border-red-800/40 text-red-300 font-medium py-2.5 rounded-lg transition">Remove Service</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Toast Notification Container -->
    <div id="toast" class="fixed bottom-5 right-5 z-50 flex items-center gap-2.5 px-4 py-2.5 rounded-lg border shadow-xl text-xs font-medium transition-all duration-300 transform translate-y-3 opacity-0 pointer-events-none">
      <span id="toast-msg">Notification</span>
    </div>
  `;
}

// ─── Initialize Chart (ONCE) ───
function initBwChart() {
  const canvas = document.getElementById('bw-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  bwChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: state.bandwidthHistory.labels,
      datasets: [
        {
          label: 'Download',
          data: state.bandwidthHistory.rx,
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          fill: true,
          tension: 0.35,
          pointRadius: 0,
          borderWidth: 2,
        },
        {
          label: 'Upload',
          data: state.bandwidthHistory.tx,
          borderColor: '#0ea5e9',
          backgroundColor: 'rgba(14, 165, 233, 0.1)',
          fill: true,
          tension: 0.35,
          pointRadius: 0,
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: { intersect: false, mode: 'index' },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(9, 9, 11, 0.95)',
          borderColor: 'rgba(255, 255, 255, 0.1)',
          borderWidth: 1,
          padding: 8,
          titleFont: { size: 10, family: 'monospace' },
          bodyFont: { size: 11 },
          callbacks: {
            label: (ctx) => ` ${ctx.dataset.label}: ${formatBps(ctx.raw)}`,
          },
        },
      },
      scales: {
        x: { display: false },
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255, 255, 255, 0.04)' },
          ticks: {
            color: '#71717a',
            font: { size: 10, family: 'monospace' },
            callback: (v) => formatBps(v),
            maxTicksLimit: 5,
          },
        },
      },
    },
  });
}

// ─── In-Place Partial DOM Updates ───

function updateDashboardDOM(s) {
  const dot = document.getElementById('engine-dot');
  const txt = document.getElementById('engine-status-text');
  const btnStart = document.getElementById('btn-start-engine');
  const stateBadge = document.getElementById('stat-engine-state-badge');
  const stateDesc = document.getElementById('stat-engine-state');

  if (state.connected) {
    dot.className = 'w-2 h-2 rounded-full bg-emerald-400 animate-pulse-dot glow-emerald';
    txt.className = 'text-xs font-semibold text-emerald-400 tracking-wide uppercase';
    txt.textContent = 'PROTECTED';
    btnStart.classList.add('hidden');
    stateBadge.className = 'text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400';
    stateBadge.textContent = 'ACTIVE';
    stateDesc.textContent = 'Kernel Firewall Enforcing';
  } else {
    dot.className = 'w-2 h-2 rounded-full bg-red-500';
    txt.className = 'text-xs font-semibold text-red-400 tracking-wide uppercase';
    txt.textContent = 'UNPROTECTED';
    btnStart.classList.remove('hidden');
    stateBadge.className = 'text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400';
    stateBadge.textContent = 'OFFLINE';
    stateDesc.textContent = 'Engine Disconnected';
  }

  const wfpDot = document.getElementById('stat-wfp-dot');
  const wfpTxt = document.getElementById('stat-wfp-text');
  const isWfp = s && s.wfp_engine_active;
  wfpDot.className = `w-2.5 h-2.5 rounded-full ${isWfp ? 'bg-emerald-400 glow-emerald' : 'bg-red-500'}`;
  wfpTxt.className = `text-xl font-bold tracking-tight ${isWfp ? 'text-emerald-400' : 'text-red-400'}`;
  wfpTxt.textContent = isWfp ? 'Active' : 'Inactive';

  const divDot = document.getElementById('stat-windivert-dot');
  const divTxt = document.getElementById('stat-windivert-text');
  const isDiv = s && s.windivert_active;
  divDot.className = `w-2.5 h-2.5 rounded-full ${isDiv ? 'bg-emerald-400 glow-emerald' : 'bg-red-500'}`;
  divTxt.className = `text-xl font-bold tracking-tight ${isDiv ? 'text-emerald-400' : 'text-red-400'}`;
  divTxt.textContent = isDiv ? 'Sniffing' : 'Inactive';

  document.getElementById('stat-rules-count').textContent = s ? s.active_rules : '0';
  document.getElementById('stat-flows-count').textContent = s ? s.active_flows : '0';

  document.getElementById('speed-rx').textContent = formatBps(s ? s.rx_bytes_sec : 0);
  document.getElementById('speed-tx').textContent = formatBps(s ? s.tx_bytes_sec : 0);

  document.getElementById('stat-total-rx').textContent = formatBytes((s ? s.total_rx_mb : 0) * 1024 * 1024);
  document.getElementById('stat-total-tx').textContent = formatBytes((s ? s.total_tx_mb : 0) * 1024 * 1024);

  if (bwChart) {
    bwChart.data.labels = state.bandwidthHistory.labels;
    bwChart.data.datasets[0].data = state.bandwidthHistory.rx;
    bwChart.data.datasets[1].data = state.bandwidthHistory.tx;
    bwChart.update('none');
  }
}

function updateFlowsDOM() {
  document.getElementById('tab-flows-badge').textContent = state.flows.length;

  if (state.activeTab !== 'flows') return;

  let flows = [...state.flows];

  if (state.flowSearch) {
    const q = state.flowSearch.toLowerCase();
    flows = flows.filter(f =>
      (f.proc && f.proc.toLowerCase().includes(q)) ||
      (f.src && f.src.includes(q)) ||
      (f.dst && f.dst.includes(q)) ||
      protoName(f.proto).toLowerCase().includes(q)
    );
  }

  const { key, dir } = state.flowSort;
  flows.sort((a, b) => {
    let va = a[key], vb = b[key];
    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();
    if (va < vb) return dir === 'asc' ? -1 : 1;
    if (va > vb) return dir === 'asc' ? 1 : -1;
    return 0;
  });

  const tbody = document.getElementById('flows-tbody');
  if (flows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="px-4 py-12 text-center text-zinc-500">${state.flowSearch ? 'No active sessions match the query' : 'No network flows captured'}</td></tr>`;
    return;
  }

  tbody.innerHTML = flows.map(f => `
    <tr class="flow-row transition font-mono">
      <td class="px-4 py-2.5">
        <span class="px-2 py-0.5 rounded text-[11px] font-bold ${
          f.proto === 6 ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30' : 
          f.proto === 17 ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30' : 
          'bg-zinc-800 text-zinc-400'
        }">${protoName(f.proto)}</span>
      </td>
      <td class="px-4 py-2.5 text-zinc-400 text-xs">${escapeHtml(f.src)}</td>
      <td class="px-4 py-2.5 text-zinc-100 font-semibold text-xs">${escapeHtml(f.dst)}</td>
      <td class="px-4 py-2.5 text-right text-sky-400 text-xs">${formatBytes(f.bytes_sent)}</td>
      <td class="px-4 py-2.5 text-right text-emerald-400 text-xs">${formatBytes(f.bytes_recv)}</td>
      <td class="px-4 py-2.5 text-right text-zinc-500 text-xs">${f.pid}</td>
      <td class="px-4 py-2.5 text-zinc-200 font-sans text-xs font-medium">
        <span class="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800">${escapeHtml(f.proc || 'System')}</span>
      </td>
      <td class="px-4 py-2.5 text-center font-sans">
        <button onclick="window.__blockFlowIP('${escapeHtml(f.dst.split(':')[0])}')" 
          class="px-2.5 py-1 bg-red-600/15 hover:bg-red-600/35 border border-red-600/30 text-red-400 rounded-md text-[11px] font-semibold transition">
          Block IP
        </button>
      </td>
    </tr>
  `).join('');
}

function updateRulesDOM() {
  document.getElementById('tab-rules-badge').textContent = state.rules.length;

  if (state.activeTab !== 'rules') return;

  const list = document.getElementById('rules-list');
  if (state.rules.length === 0) {
    list.innerHTML = `
      <div class="glass-panel rounded-xl p-12 text-center">
        <div class="w-12 h-12 rounded-full bg-zinc-800/60 border border-zinc-700/60 flex items-center justify-center mx-auto mb-3">
          <svg class="w-6 h-6 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" /></svg>
        </div>
        <h3 class="text-sm font-semibold text-zinc-200">No active firewall rules</h3>
        <p class="text-xs text-zinc-500 mt-1">Network traffic is currently operating under default pass-through.</p>
      </div>
    `;
    return;
  }

  list.innerHTML = state.rules.map(r => `
    <div class="glass-panel rounded-xl p-4 flex items-center justify-between hover:border-zinc-700 transition">
      <div class="flex items-center gap-4 min-w-0">
        <span class="px-2.5 py-1 rounded text-xs font-bold tracking-wider ${
          r.action === 'BLOCK' 
            ? 'bg-red-500/20 text-red-400 border border-red-500/30' 
            : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
        }">${r.action}</span>
        <span class="px-2 py-0.5 rounded text-xs bg-zinc-900 border border-zinc-800 text-zinc-400 font-mono">${r.type}</span>
        <div class="truncate">
          <div class="font-mono text-xs text-zinc-100 font-semibold truncate">${escapeHtml(r.value)}</div>
          <div class="text-[11px] text-zinc-500 truncate">${escapeHtml(r.desc)} · Direction: ${r.dir} · Rule ID: #${r.id}</div>
        </div>
      </div>
      <button onclick="window.__deleteRule(${r.id})" class="p-2 text-zinc-500 hover:text-red-400 transition rounded-lg hover:bg-red-500/10 shrink-0" title="Delete filter rule">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" /></svg>
      </button>
    </div>
  `).join('');
}

function updateAlertsDOM() {
  const badge = document.getElementById('tab-alerts-badge');
  if (state.alerts.length > 0) {
    badge.textContent = state.alerts.length;
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }

  if (state.activeTab !== 'alerts') return;

  const list = document.getElementById('alerts-list');
  if (state.alerts.length === 0) {
    list.innerHTML = `
      <div class="glass-panel rounded-xl p-12 text-center text-zinc-500 text-xs">
        No drop events recorded. Live security alerts appear when rules block connections.
      </div>
    `;
    return;
  }

  list.innerHTML = state.alerts.map(a => `
    <div class="glass-panel rounded-xl p-3.5 flex items-center justify-between gap-4 text-xs hover:border-zinc-700 transition">
      <div class="flex items-center gap-3.5 min-w-0">
        <span class="text-[11px] text-zinc-500 font-mono whitespace-nowrap">${a.time}</span>
        <span class="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider shrink-0 ${
          a.isKps ? 'bg-red-500/20 text-red-400 border border-red-500/40 glow-red' : 'bg-zinc-800 text-zinc-400 border border-zinc-700/50'
        }">
          ${a.isKps ? 'KPS ENFORCED' : 'OS DROP'}
        </span>
        <div class="truncate">
          <div class="text-xs text-zinc-200 font-medium truncate">${escapeHtml(a.summary)}</div>
          <div class="text-[11px] text-zinc-500 font-mono">${escapeHtml(a.detail)}</div>
        </div>
      </div>
      ${a.remoteIp ? `
        <button onclick="window.__quickBlockIPFromAlert('${escapeHtml(a.remoteIp)}')" 
          class="shrink-0 px-2.5 py-1 bg-red-600/15 hover:bg-red-600/35 border border-red-600/30 text-red-400 rounded-md text-[11px] font-medium transition">
          Block IP
        </button>
      ` : ''}
    </div>
  `).join('');
}

// ─── Polling Loop ───
async function poll() {
  try {
    const [status, flows, rules] = await Promise.all([
      GetStatus().catch(() => null),
      GetFlows().catch(() => null),
      GetRules().catch(() => null),
    ]);

    if (status) {
      state.connected = true;
      state.status = status;

      const now = new Date();
      const label = now.getMinutes() + ':' + String(now.getSeconds()).padStart(2, '0');
      state.bandwidthHistory.labels.push(label);
      state.bandwidthHistory.rx.push(status.rx_bytes_sec || 0);
      state.bandwidthHistory.tx.push(status.tx_bytes_sec || 0);

      if (state.bandwidthHistory.labels.length > MAX_BW_POINTS) {
        state.bandwidthHistory.labels.shift();
        state.bandwidthHistory.rx.shift();
        state.bandwidthHistory.tx.shift();
      }
    } else {
      state.connected = false;
    }

    if (flows) {
      state.flows = flows.flows || [];
    }

    if (rules) {
      state.rules = rules.rules || [];
    }

    updateDashboardDOM(state.status);
    updateFlowsDOM();
    updateRulesDOM();
  } catch (err) {
    state.connected = false;
    updateDashboardDOM(null);
  }
}

// ─── Global Handlers ───
window.__switchTab = (tab) => {
  state.activeTab = tab;

  const tabs = ['dashboard', 'flows', 'rules', 'alerts'];
  tabs.forEach(t => {
    const panel = document.getElementById(`panel-${t}`);
    const btn = document.getElementById(`tab-btn-${t}`);
    if (t === tab) {
      panel.classList.remove('hidden');
      btn.className = 'tab-btn flex items-center gap-2 px-4 py-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 border-emerald-400 text-emerald-400';
    } else {
      panel.classList.add('hidden');
      btn.className = 'tab-btn flex items-center gap-2 px-4 py-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 border-transparent text-zinc-400 hover:text-zinc-200';
    }
  });

  if (tab === 'flows') updateFlowsDOM();
  if (tab === 'rules') updateRulesDOM();
  if (tab === 'alerts') updateAlertsDOM();
  if (tab === 'dashboard' && bwChart) bwChart.resize();
};

window.__startEngine = async () => {
  const btn = document.getElementById('btn-start-engine');
  btn.textContent = '⏳ Starting...';
  try {
    await StartEngine();
    showToast('Engine process requested (Silent Mode)');
    setTimeout(poll, 1500);
  } catch (e) {
    showToast('Failed to start engine: ' + e, true);
    btn.textContent = 'Start Engine (Silent)';
  }
};

window.__openServiceModal = () => {
  document.getElementById('modal-service-overlay').classList.remove('hidden');
};

window.__closeServiceModal = () => {
  document.getElementById('modal-service-overlay').classList.add('hidden');
};

window.__installService = async () => {
  window.__closeServiceModal();
  showToast('Installing and launching KPacketShield Windows Service...');
  try {
    await InstallService();
    showToast('Windows Service installed! Protection will start on boot.');
    setTimeout(poll, 2000);
  } catch (e) {
    showToast('Service install error: ' + e, true);
  }
};

window.__uninstallService = async () => {
  window.__closeServiceModal();
  showToast('Stopping and removing Windows Service...');
  try {
    await UninstallService();
    showToast('Windows Service uninstalled cleanly.');
    setTimeout(poll, 2000);
  } catch (e) {
    showToast('Service uninstall error: ' + e, true);
  }
};

window.__flowSearch = (val) => {
  state.flowSearch = val;
  updateFlowsDOM();
};

window.__flowSortBy = (key) => {
  if (state.flowSort.key === key) {
    state.flowSort.dir = state.flowSort.dir === 'asc' ? 'desc' : 'asc';
  } else {
    state.flowSort.key = key;
    state.flowSort.dir = 'desc';
  }
  updateFlowsDOM();
};

window.__openModal = () => {
  document.getElementById('modal-overlay').classList.remove('hidden');
};

window.__closeModal = () => {
  document.getElementById('modal-overlay').classList.add('hidden');
};

window.__onRuleTypeChange = () => {
  const type = document.getElementById('rule-type').value;
  const label = document.getElementById('rule-value-label');
  const input = document.getElementById('rule-value');
  const protoGroup = document.getElementById('rule-proto-group');

  if (type === 'ip') {
    label.textContent = 'IP Address';
    input.placeholder = 'e.g. 192.168.1.100';
    protoGroup.classList.add('hidden');
  } else if (type === 'port') {
    label.textContent = 'Port Number';
    input.placeholder = 'e.g. 8080';
    protoGroup.classList.remove('hidden');
  } else {
    label.textContent = 'Application Executable Path';
    input.placeholder = 'e.g. C:\\Windows\\System32\\curl.exe';
    protoGroup.classList.add('hidden');
  }
};

window.__submitRule = async () => {
  const type = document.getElementById('rule-type').value;
  const action = document.getElementById('rule-action').value;
  const value = document.getElementById('rule-value').value.trim();
  const desc = document.getElementById('rule-desc').value.trim();

  if (!value) return showToast('Please enter a target value', true);

  try {
    let result;
    if (type === 'ip') {
      result = await AddIPRule(action, value, desc || 'Custom IP Rule');
    } else if (type === 'port') {
      const proto = document.getElementById('rule-proto').value;
      result = await AddPortRule(action, parseInt(value), proto, desc || 'Custom Port Rule');
    } else {
      result = await AddAppRule(action, value, desc || 'Custom App Rule');
    }

    if (result && result.success) {
      window.__closeModal();
      document.getElementById('rule-value').value = '';
      document.getElementById('rule-desc').value = '';
      showToast(`Rule #${result.rule_id} created successfully!`);
      poll();
    } else {
      showToast('Failed to apply rule', true);
    }
  } catch (err) {
    showToast('Error applying rule: ' + err, true);
  }
};

window.__deleteRule = async (id) => {
  if (!confirm(`Delete firewall rule #${id}?`)) return;
  try {
    await DeleteRule(id);
    showToast(`Rule #${id} removed.`);
    poll();
  } catch (err) {
    showToast('Error: ' + err, true);
  }
};

window.__quickBlockIP = () => {
  const ip = prompt('Enter IP address to block:');
  if (ip && ip.trim()) {
    AddIPRule('block', ip.trim(), 'Quick block from GUI').then(res => {
      showToast(`Blocked ${ip.trim()}`);
      poll();
    });
  }
};

window.__quickBlockPort = () => {
  const port = prompt('Enter port number to block:');
  if (port && port.trim()) {
    const proto = prompt('Protocol? (tcp/udp)', 'tcp');
    AddPortRule('block', parseInt(port), proto || 'tcp', 'Quick block from GUI').then(res => {
      showToast(`Blocked port ${port}`);
      poll();
    });
  }
};

window.__blockFlowIP = (ip) => {
  if (confirm(`Block remote IP address ${ip}?`)) {
    AddIPRule('block', ip, `Blocked from active session (${ip})`).then(() => {
      showToast(`Remote IP ${ip} blocked!`);
      poll();
      window.__switchTab('rules');
    });
  }
};

window.__quickBlockIPFromAlert = (ip) => {
  if (confirm(`Block IP address ${ip}?`)) {
    AddIPRule('block', ip, `Blocked from Alert feed (${ip})`).then(() => {
      showToast(`Alert IP ${ip} blocked!`);
      poll();
      window.__switchTab('rules');
    });
  }
};

window.__clearAlerts = () => {
  state.alerts = [];
  updateAlertsDOM();
  showToast('Audit log cleared');
};

// ─── Event Listeners ───
EventsOn('engine:event', (event) => {
  if (!event || event.status === 'subscribed') return;

  // Real-time sub-second Throughput Push Event from Engine
  if (event.event === 'TICK') {
    state.connected = true;
    const now = new Date();
    const label = now.getMinutes() + ':' + String(now.getSeconds()).padStart(2, '0');
    state.bandwidthHistory.labels.push(label);
    state.bandwidthHistory.rx.push(event.rx_bytes_sec || 0);
    state.bandwidthHistory.tx.push(event.tx_bytes_sec || 0);

    if (state.bandwidthHistory.labels.length > MAX_BW_POINTS) {
      state.bandwidthHistory.labels.shift();
      state.bandwidthHistory.rx.shift();
      state.bandwidthHistory.tx.shift();
    }

    if (!state.status) {
      state.status = {
        wfp_engine_active: true,
        windivert_active: true,
        active_rules: event.active_rules || 0,
        active_flows: event.active_flows || 0,
        rx_bytes_sec: event.rx_bytes_sec || 0,
        tx_bytes_sec: event.tx_bytes_sec || 0,
        total_rx_mb: event.total_rx_mb || 0,
        total_tx_mb: event.total_tx_mb || 0,
      };
    } else {
      state.status.wfp_engine_active = true;
      state.status.windivert_active = true;
      state.status.active_rules = event.active_rules;
      state.status.active_flows = event.active_flows;
      state.status.rx_bytes_sec = event.rx_bytes_sec;
      state.status.tx_bytes_sec = event.tx_bytes_sec;
      state.status.total_rx_mb = event.total_rx_mb;
      state.status.total_tx_mb = event.total_tx_mb;
    }
    updateDashboardDOM(state.status);
    return;
  }

  const now = new Date();
  const timeStr = now.getHours().toString().padStart(2, '0') + ':' +
                  now.getMinutes().toString().padStart(2, '0') + ':' +
                  now.getSeconds().toString().padStart(2, '0');

  const isKps = event.is_kps_rule === true;
  const proto = protoName(event.proto);
  const target = event.remote_ip ? `${event.remote_ip}${event.port ? ':' + event.port : ''}` : 'Unknown Endpoint';

  let summary = '';
  if (isKps) {
    summary = `Blocked connection to ${target} (${event.app || 'App'}) by Rule: "${event.rule || 'KPS'}"`;
  } else {
    summary = `System Filter #${event.filter_id || 0} dropped ${proto} packet to ${target}`;
  }

  const detail = `Proto: ${proto} · Filter ID: ${event.filter_id || 0} · App: ${event.app || '-'}`;

  state.alerts.unshift({
    time: timeStr,
    isKps,
    summary,
    detail,
    remoteIp: event.remote_ip,
    raw: event,
  });

  if (state.alerts.length > MAX_ALERTS) {
    state.alerts.pop();
  }

  updateAlertsDOM();
});

EventsOn('engine:status', (data) => {
  state.connected = data.connected;
  updateDashboardDOM(state.status);
});

// ─── Startup Execution ───
initLayout();
initBwChart();
poll();
setInterval(poll, 1500);
