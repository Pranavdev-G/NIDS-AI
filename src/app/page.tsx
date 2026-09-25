"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Shield, Activity, Lock, Brain, Bell, MessageSquare, AlertTriangle,
  Search, Eye, Ban, CheckCircle, Send, Bot, User,
  ArrowRight, Zap, RefreshCw, X, Upload, FileText, Download
} from "lucide-react";
import {
  AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";

// ─── Types ───────────────────────────────────────────────────────────────────
interface ThreatEvent {
  id: string; timestamp: string; source_ip: string; destination_ip: string;
  source_port: number; destination_port: number; protocol: string;
  packet_size: number; is_threat: boolean; threat_type: string | null;
  severity: string; pattern_matched: string | null; description: string; status: string;
}

interface AlertItem {
  id: string; timestamp: string; type: string; severity: string;
  source_ip: string; message: string; status: string;
}

interface Stats {
  total_packets: number; threats_detected: number; connections_blocked: number;
  ai_analyses: number; uptime_seconds: number; threat_categories: Record<string, number>;
  traffic_history: { timestamp: string; packets_per_sec: number; threats: number }[];
  ollama_status: string;
}

interface ChatMsg { id: number; role: "user" | "assistant"; content: string; timestamp: string; }

const COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6", "#8b5cf6", "#ec4899", "#06b6d4"];
const SEV_COLORS: Record<string, string> = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6" };
const PROTO_COLORS: Record<string, string> = { TCP: "#3b82f6", UDP: "#22c55e", ICMP: "#f97316", HTTP: "#8b5cf6", HTTPS: "#06b6d4", DNS: "#eab308", SSH: "#ec4899", FTP: "#64748b" };

const POLL = 8000; // Increase poll interval since data is static unless uploaded

// ─── API ─────────────────────────────────────────────────────────────────────
async function apiFetch<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(path, opts);
  if (!r.ok) {
    const errorData = await r.json().catch(() => ({}));
    throw new Error(errorData.error || `HTTP error ${r.status}`);
  }
  return r.json();
}

// ─── Pages ───────────────────────────────────────────────────────────────────
type Page = "dashboard" | "threats" | "network" | "ai-analysis" | "alerts" | "chat";

const NAV: { id: Page; label: string; icon: React.ElementType }[] = [
  { id: "dashboard", label: "Dashboard", icon: Activity },
  { id: "threats", label: "Threat Log", icon: Shield },
  { id: "network", label: "Network Monitor", icon: Zap },
  { id: "ai-analysis", label: "AI Analysis", icon: Brain },
  { id: "alerts", label: "Alerts", icon: Bell },
  { id: "chat", label: "AI Assistant", icon: MessageSquare },
];

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════════════════════════════════════════
export default function NIDSApp() {
  const [page, setPage] = useState<Page>("dashboard");
  const [stats, setStats] = useState<Stats | null>(null);
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [cats, setCats] = useState<Record<string, number>>({});
  const [history, setHistory] = useState<any[]>([]);

  const refresh = useCallback(async () => {
    try {
      const [s, t, e, a, c, h] = await Promise.all([
        apiFetch<Stats>("/api/stats"),
        apiFetch<{ threats: ThreatEvent[] }>("/api/threats?limit=200"),
        apiFetch<{ events: ThreatEvent[] }>("/api/network-events?limit=200"),
        apiFetch<{ alerts: AlertItem[] }>("/api/alerts"),
        apiFetch<{ categories: Record<string, number> }>("/api/threat-categories"),
        apiFetch<{ history: any[] }>("/api/traffic-history"),
      ]);
      setStats(s); setThreats(t.threats); setEvents(e.events);
      setAlerts(a.alerts); setCats(c.categories); setHistory(h.history);
    } catch {}
  }, []);

  useEffect(() => {
    refresh();
    const i = setInterval(() => { refresh(); }, POLL);
    return () => clearInterval(i);
  }, [refresh]);

  const fmtUptime = (s: number) => `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m ${s%60}s`;

  return (
    <div className="flex flex-col h-screen bg-[#0a0e17] text-gray-200 overflow-hidden font-sans">
      {/* Header */}
      <header className="flex items-center justify-between h-14 px-4 bg-[#111827] border-b border-[#1e293b] shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="text-cyan-400" size={22} />
          <span className="font-bold text-lg bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">NIDS AI</span>
          <span className="text-[10px] text-gray-500 uppercase tracking-widest ml-1 hidden sm:inline font-mono">Dataset Intrusion Detection</span>
        </div>
        <div className="flex items-center gap-4 text-xs text-gray-400">
          {stats && stats.total_packets > 0 ? (
            <>
              <span className="flex items-center gap-1"><Activity size={13}/> {stats.total_packets.toLocaleString()} pkts</span>
              <span className="flex items-center gap-1 text-red-400"><Shield size={13}/> {stats.threats_detected} threats</span>
              <span className="flex items-center gap-1"><Lock size={13}/> {stats.connections_blocked} blocked</span>
            </>
          ) : (
            <span className="text-gray-500 font-medium italic">Awaiting dataset upload</span>
          )}
          <span className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium ${stats && stats.total_packets > 0 ? "bg-cyan-500/10 text-cyan-400" : "bg-yellow-500/10 text-yellow-400"}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${stats && stats.total_packets > 0 ? "bg-cyan-400 animate-pulse" : "bg-yellow-400"}`}/>
            {stats && stats.total_packets > 0 ? "Dataset Mode" : "Ready"}
          </span>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <nav className="w-[200px] bg-[#111827] border-r border-[#1e293b] p-2 flex flex-col gap-0.5 shrink-0">
          {NAV.map(n => {
            const Icon = n.icon;
            return (
              <button key={n.id} onClick={() => setPage(n.id)}
                className={`flex items-center gap-2.5 px-3 py-2.5 rounded-md text-sm font-medium transition-all w-full text-left
                  ${page === n.id ? "bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-400" : "text-gray-400 hover:bg-[#243044] hover:text-gray-200"}`}>
                <Icon size={17}/>{n.label}
              </button>
            );
          })}
          <div className="mt-auto pt-3 border-t border-[#1e293b] text-center text-[10px] text-gray-600">NIDS AI v1.2</div>
        </nav>

        {/* Main */}
        <main className="flex-1 overflow-y-auto p-5">
          {page === "dashboard" && (
            <DashboardPage
              stats={stats}
              threats={threats}
              cats={cats}
              history={history}
              onUploadSuccess={refresh}
            />
          )}
          {page === "threats" && <ThreatLog threats={threats} onAnalyze={() => setPage("ai-analysis")} />}
          {page === "network" && <NetworkMonitor events={events} />}
          {page === "ai-analysis" && <AIAnalysis threats={threats} />}
          {page === "alerts" && <Alerts alerts={alerts} onRefresh={refresh} />}
          {page === "chat" && <ChatAssistant stats={stats} />}
        </main>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATASET UPLOADER
// ═══════════════════════════════════════════════════════════════════════════════
function DatasetUploader({ onUploadSuccess }: { onUploadSuccess: () => void }) {
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [clearExisting, setClearExisting] = useState(true);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const uploadFile = async (file: File) => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setSuccess(null);

    const reader = new FileReader();
    reader.onload = async (e) => {
      const text = e.target?.result as string;
      try {
        const response = await fetch("/api/upload-dataset", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            filename: file.name,
            content: text,
            clearExisting
          })
        });

        const result = await response.json();
        if (response.ok) {
          setSuccess(`Imported dataset successfully! Processed ${result.parsed} packets. Found ${result.threats} threats.`);
          onUploadSuccess();
        } else {
          setError(result.error || "Failed to process dataset");
        }
      } catch (err: any) {
        setError(err.message || "Network error when uploading");
      } finally {
        setLoading(false);
      }
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      uploadFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      uploadFile(e.target.files[0]);
    }
  };

  const downloadTemplate = () => {
    const csvContent = "timestamp,source_ip,destination_ip,source_port,destination_port,protocol,packet_size,description,is_threat\n" +
      "2026-06-08T19:00:00Z,192.168.1.100,10.0.0.1,52140,80,HTTP,1024,\"GET /index.html HTTP/1.1\",false\n" +
      "2026-06-08T19:00:05Z,185.220.101.34,10.0.0.5,43921,80,HTTP,450,\"UNION SELECT username, password FROM users\",true\n" +
      "2026-06-08T19:00:10Z,192.168.1.102,10.0.0.2,49230,443,HTTPS,2048,\"Normal HTTP POST request\",false\n" +
      "2026-06-08T19:00:15Z,91.218.114.11,10.0.0.1,53200,22,SSH,120,\"SSH_BRUTE login attempt\",true\n" +
      "2026-06-08T19:00:20Z,192.168.1.105,10.0.0.3,51090,53,DNS,85,\"DNS query for secure-api.domain.com\",false\n" +
      "2026-06-08T19:00:25Z,45.33.32.156,10.0.0.1,59821,443,HTTPS,820,\"<script>alert('XSS')</script> Injection test\",true\n";
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", "nids_sample_dataset.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="bg-[#1a2332] border border-[#1e293b] rounded-xl p-5 mb-5 relative overflow-hidden">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-4">
        <div>
          <h3 className="text-sm font-semibold text-gray-200">Upload Traffic Log Dataset</h3>
          <p className="text-xs text-gray-500 mt-0.5">Upload a CSV or JSON file containing network packets details</p>
        </div>
        <div className="flex items-center gap-3 self-stretch md:self-auto justify-between md:justify-end">
          <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={clearExisting}
              onChange={(e) => setClearExisting(e.target.checked)}
              className="rounded bg-[#0a0e17] border-[#1e293b] text-cyan-500 focus:ring-0 focus:ring-offset-0"
            />
            Clear previous records
          </label>
          <button
            onClick={downloadTemplate}
            className="flex items-center gap-1 px-3 py-1.5 bg-[#0a0e17] border border-[#1e293b] hover:border-cyan-500/50 hover:text-cyan-400 rounded-lg text-xs transition-colors"
          >
            <Download size={13} /> Template CSV
          </button>
        </div>
      </div>

      <div
        onDragEnter={handleDrag}
        onDragOver={handleDrag}
        onDragLeave={handleDrag}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center text-center transition-all cursor-pointer relative min-h-[140px]
          ${dragActive ? "border-cyan-400 bg-cyan-500/5" : "border-[#1e293b] hover:border-[#334155] bg-[#0d131f]"}`}
      >
        <input
          type="file"
          accept=".csv,.json"
          onChange={handleFileInput}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          disabled={loading}
        />
        {loading ? (
          <div className="flex flex-col items-center gap-2">
            <RefreshCw className="animate-spin text-cyan-400" size={28} />
            <span className="text-xs text-gray-400 font-medium">Parsing and analyzing logs...</span>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2">
            <div className="w-10 h-10 rounded-full bg-cyan-500/10 flex items-center justify-center text-cyan-400">
              <Upload size={18} />
            </div>
            <p className="text-xs text-gray-300 font-medium">
              Drag and drop your dataset here, or <span className="text-cyan-400 underline">browse</span>
            </p>
            <p className="text-[10px] text-gray-500 font-mono">Supports CSV and JSON logs</p>
          </div>
        )}
      </div>

      {error && (
        <div className="mt-3 p-2.5 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-lg flex items-start gap-2">
          <AlertTriangle size={14} className="shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {success && (
        <div className="mt-3 p-2.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs rounded-lg flex items-start gap-2">
          <CheckCircle size={14} className="shrink-0 mt-0.5" />
          <span>{success}</span>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD PAGE
// ═══════════════════════════════════════════════════════════════════════════════
function DashboardPage({
  stats,
  threats,
  cats,
  history,
  onUploadSuccess
}: {
  stats: Stats | null;
  threats: ThreatEvent[];
  cats: Record<string, number>;
  history: any[];
  onUploadSuccess: () => void;
}) {
  const cards = [
    { title: "Total Packets", value: stats?.total_packets || 0, icon: Activity, color: "#3b82f6" },
    { title: "Threats Detected", value: stats?.threats_detected || 0, icon: Shield, color: "#ef4444" },
    { title: "Blocked", value: stats?.connections_blocked || 0, icon: Lock, color: "#f97316" },
    { title: "AI Analyses", value: stats?.ai_analyses || 0, icon: Brain, color: "#8b5cf6" },
  ];

  const catData = Object.entries(cats).map(([name, value], i) => ({ name, value, fill: COLORS[i % COLORS.length] }));
  const chartData = history.map(h => ({ ...h, time: new Date(h.timestamp).toLocaleTimeString() }));
  const recent = threats.slice(-5).reverse();

  return (
    <div>
      <h2 className="text-xl font-bold mb-0.5">Security Dashboard</h2>
      <p className="text-xs text-gray-500 mb-5 font-mono">Analyze custom network packet captures and traffic datasets</p>

      {/* Dataset Uploader */}
      <DatasetUploader onUploadSuccess={onUploadSuccess} />

      {stats && stats.total_packets > 0 ? (
        <>
          {/* Stat Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
            {cards.map((c, i) => {
              const Icon = c.icon;
              return (
                <div key={i} className="flex items-center gap-3 p-4 bg-[#1a2332] rounded-xl border border-[#1e293b] hover:-translate-y-0.5 transition-transform"
                  style={{ borderLeftWidth: 3, borderLeftColor: c.color }}>
                  <div className="flex items-center justify-center w-11 h-11 rounded-lg" style={{ background: c.color + "20", color: c.color }}>
                    <Icon size={20}/>
                  </div>
                  <div>
                    <div className="text-2xl font-bold">{c.value.toLocaleString()}</div>
                    <div className="text-[11px] text-gray-500 uppercase tracking-wider">{c.title}</div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 mb-5">
            <div className="lg:col-span-2 bg-[#1a2332] border border-[#1e293b] rounded-xl p-4">
              <h3 className="text-sm font-semibold mb-3">Network Traffic History</h3>
              <ResponsiveContainer width="100%" height={250}>
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="gPkt" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/><stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/></linearGradient>
                    <linearGradient id="gThr" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b"/>
                  <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10 }}/>
                  <YAxis stroke="#64748b" tick={{ fontSize: 10 }}/>
                  <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, fontSize: 12 }}/>
                  <Area type="monotone" dataKey="packets_per_sec" stroke="#3b82f6" fill="url(#gPkt)" name="Packets"/>
                  <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#gThr)" name="Threats"/>
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-[#1a2332] border border-[#1e293b] rounded-xl p-4 font-mono">
              <h3 className="text-sm font-semibold mb-3 font-sans">Threat Categories</h3>
              {catData.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-[200px] text-gray-500 text-xs">No threats found in dataset</div>
              ) : (
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie data={catData} cx="50%" cy="50%" innerRadius={50} outerRadius={85} paddingAngle={3} dataKey="value">
                      {catData.map((e, i) => <Cell key={i} fill={e.fill}/>)}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, fontSize: 12 }}/>
                    <Legend wrapperStyle={{ fontSize: 10, color: "#94a3b8" }}/>
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Recent Threats */}
          <div className="bg-[#1a2332] border border-[#1e293b] rounded-xl p-4">
            <h3 className="text-sm font-semibold text-amber-500 flex items-center gap-2 mb-3"><AlertTriangle size={16}/> Threats Detected in Dataset</h3>
            {recent.length === 0 ? <p className="text-gray-500 text-sm text-center py-8">Dataset is clean. No threats detected!</p> : (
              <div className="flex flex-col gap-2 font-mono">
                {recent.map((t, i) => (
                  <div key={i} className="flex justify-between items-center p-2.5 bg-[#0a0e17] rounded-lg border-l-3" style={{ borderLeftColor: SEV_COLORS[t.severity]||"#64748b" }}>
                    <div className="flex items-center gap-2.5">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase font-sans" style={{ background: SEV_COLORS[t.severity]+"25", color: SEV_COLORS[t.severity] }}>{t.severity}</span>
                      <span className="font-semibold text-sm text-gray-200 font-sans">{t.threat_type}</span>
                      <span className="text-[11px] text-gray-500">{t.source_ip} → {t.destination_ip}:{t.destination_port}</span>
                    </div>
                    <div className="flex items-center gap-2.5 text-[11px] text-gray-500">
                      <span>{new Date(t.timestamp).toLocaleTimeString()}</span>
                      <span className="px-2 py-0.5 rounded-full font-sans" style={{ background: t.status==="blocked"?"rgba(34,197,94,0.15)":t.status==="detected"?"rgba(249,115,22,0.15)":"rgba(59,130,246,0.15)", color: t.status==="blocked"?"#22c55e":t.status==="detected"?"#f97316":"#3b82f6" }}>{t.status}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="flex flex-col items-center justify-center p-12 bg-[#121924] border border-[#1e293b] rounded-xl text-center text-gray-400 min-h-[300px]">
          <FileText size={40} className="text-gray-600 mb-3" />
          <h3 className="text-sm font-semibold text-gray-300">No Dataset Loaded</h3>
          <p className="text-xs text-gray-500 mt-1 max-w-sm">Please import a network traffic log CSV/JSON using the upload panel above to activate the charts and metrics.</p>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT LOG
// ═══════════════════════════════════════════════════════════════════════════════
function ThreatLog({ threats, onAnalyze }: { threats: ThreatEvent[]; onAnalyze: () => void }) {
  const [sev, setSev] = useState("");
  const [type, setType] = useState("");
  const [search, setSearch] = useState("");

  const types = [...new Set(threats.map(t => t.threat_type).filter(Boolean))];
  const filtered = threats.filter(t => {
    if (sev && t.severity !== sev) return false;
    if (type && t.threat_type !== type) return false;
    if (search) { const s = search.toLowerCase(); return (t.source_ip+t.destination_ip+t.threat_type+t.description).toLowerCase().includes(s); }
    return true;
  });

  const blockIP = async (ip: string) => { await fetch("/api/block-ip", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip, reason: "Blocked from threat log" }) }); };

  return (
    <div>
      <h2 className="text-xl font-bold flex items-center gap-2 mb-0.5"><Shield size={20}/> Threat Log</h2>
      <p className="text-xs text-gray-500 mb-4">Detailed record of threats detected in the uploaded dataset</p>

      <div className="flex gap-2 mb-4 flex-wrap">
        <div className="flex items-center gap-1.5 px-3 py-2 bg-[#1a2332] border border-[#1e293b] rounded-lg flex-1 min-w-[200px]">
          <Search size={14} className="text-gray-500"/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search IP, type..." className="bg-transparent border-none outline-none text-sm text-gray-200 w-full"/>
        </div>
        <select value={sev} onChange={e => setSev(e.target.value)} className="px-3 py-2 bg-[#1a2332] border border-[#1e293b] rounded-lg text-sm text-gray-200 outline-none">
          <option value="">All Severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option>
        </select>
        <select value={type} onChange={e => setType(e.target.value)} className="px-3 py-2 bg-[#1a2332] border border-[#1e293b] rounded-lg text-sm text-gray-200 outline-none">
          <option value="">All Types</option>{types.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <button onClick={() => { setSev(""); setType(""); setSearch(""); }} className="flex items-center gap-1 px-3 py-2 bg-[#1a2332] border border-[#1e293b] rounded-lg text-sm text-gray-400 hover:text-gray-200"><RefreshCw size={13}/> Reset</button>
      </div>

      <div className="bg-[#1a2332] border border-[#1e293b] rounded-xl overflow-hidden font-mono">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-[#0a0e17] font-sans">
              <tr>
                {["Time","Severity","Type","Source","Dest","Port","Protocol","Pattern","Status","Actions"].map(h =>
                  <th key={h} className="px-3 py-2.5 text-left text-[10px] uppercase tracking-wider text-gray-500 font-semibold">{h}</th>
                )}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={10} className="text-center py-8 text-gray-500 font-sans">No threats found</td></tr>
              ) : [...filtered].reverse().slice(0, 100).map((t, i) => (
                <tr key={t.id+i} className={`border-t border-[#1e293b] hover:bg-[#243044] ${t.severity==="critical"?"bg-red-500/5":t.severity==="high"?"bg-orange-500/[0.03]":""}`}>
                  <td className="px-3 py-2 text-[11px] text-gray-400">{new Date(t.timestamp).toLocaleTimeString()}</td>
                  <td className="px-3 py-2"><span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-sans" style={{ background: SEV_COLORS[t.severity]+"25", color: SEV_COLORS[t.severity] }}>{t.severity}</span></td>
                  <td className="px-3 py-2 font-semibold font-sans text-gray-200">{t.threat_type}</td>
                  <td className="px-3 py-2 text-[11px] text-gray-400">{t.source_ip}</td>
                  <td className="px-3 py-2 text-[11px] text-gray-400">{t.destination_ip}</td>
                  <td className="px-3 py-2 text-[11px]">{t.destination_port}</td>
                  <td className="px-3 py-2 font-sans" style={{ color: PROTO_COLORS[t.protocol] }}>{t.protocol}</td>
                  <td className="px-3 py-2 text-[10px] text-amber-500">{t.pattern_matched}</td>
                  <td className="px-3 py-2 font-sans"><span className="text-[11px] font-semibold" style={{ color: t.status==="blocked"?"#22c55e":t.status==="detected"?"#f97316":"#3b82f6" }}>{t.status}</span></td>
                  <td className="px-3 py-2 flex gap-1">
                    <button onClick={onAnalyze} className="p-1.5 rounded border border-[#1e293b] hover:border-blue-500 hover:text-blue-400 text-gray-400 cursor-pointer" title="Analyze"><Eye size={12}/></button>
                    <button onClick={() => blockIP(t.source_ip)} className="p-1.5 rounded border border-[#1e293b] hover:border-red-500 hover:text-red-400 text-gray-400 cursor-pointer" title="Block"><Ban size={12}/></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="px-4 py-2 text-[11px] text-gray-500 border-t border-[#1e293b] font-sans">Showing {Math.min(filtered.length, 100)} of {filtered.length} threats</div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// NETWORK MONITOR
// ═══════════════════════════════════════════════════════════════════════════════
function NetworkMonitor({ events }: { events: ThreatEvent[] }) {
  const threatCount = events.filter(e => e.is_threat).length;
  const total = events.length;
  const ratio = total > 0 ? (threatCount / total * 100).toFixed(1) : "0.0";

  return (
    <div>
      <h2 className="text-xl font-bold flex items-center gap-2 mb-0.5"><Activity size={20}/> Network Monitor</h2>
      <p className="text-xs text-gray-500 mb-4 font-mono">Real-time packet logs in the imported dataset</p>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 mb-4">
        {[
          { label: "Connections", value: total, color: "#3b82f6" },
          { label: "Malicious", value: threatCount, color: "#ef4444" },
          { label: "Benign", value: total - threatCount, color: "#22c55e" },
          { label: "Threat Ratio", value: `${ratio}%`, color: "#f97316" },
        ].map((m, i) => (
          <div key={i} className="flex items-center gap-3 p-3 bg-[#1a2332] border border-[#1e293b] rounded-lg">
            <div>
              <div className="text-lg font-bold" style={{ color: m.color }}>{m.value}</div>
              <div className="text-[10px] text-gray-500 uppercase">{m.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="bg-[#1a2332] border border-[#1e293b] rounded-xl p-3 max-h-[calc(100vh-300px)] overflow-y-auto font-mono">
        {events.length === 0 ? (
          <div className="text-center py-12 text-gray-500 font-sans text-xs">No network logs loaded</div>
        ) : [...events].reverse().slice(0, 150).map((e, i) => (
          <div key={e.id+i} className={`flex items-start gap-2.5 py-2 px-2 border-b border-[#1e293b] last:border-0 ${e.is_threat ? "bg-red-500/5" : ""}`}>
            <div className={`w-1.5 h-1.5 rounded-full mt-2 shrink-0 ${e.is_threat ? "bg-red-500" : "bg-emerald-500"}`}/>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap text-xs">
                <span className="text-gray-500 text-[10px]">{new Date(e.timestamp).toLocaleTimeString()}</span>
                <span className="font-bold text-[11px] font-sans" style={{ color: PROTO_COLORS[e.protocol] }}>{e.protocol}</span>
                <span className="text-gray-400 text-[11px] flex items-center gap-0.5">{e.source_ip}:{e.source_port} <ArrowRight size={9}/> {e.destination_ip}:{e.destination_port}</span>
                <span className="text-gray-500 text-[10px]">{e.packet_size} B</span>
                {e.is_threat && <span className="flex items-center gap-1 font-semibold text-red-400 text-[11px] font-sans"><span className="w-1 h-1 rounded-full bg-red-400"/>{e.threat_type}</span>}
              </div>
              <div className="text-[10px] text-gray-500 mt-0.5 flex items-center gap-2">
                <span>Payload: <span className="text-gray-400">{e.description}</span></span>
                {e.is_threat && <>• Pattern: <span className="text-amber-500">{e.pattern_matched}</span></>}
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold font-sans ${e.status==="blocked"?"bg-emerald-500/15 text-emerald-400":e.status==="detected"?"bg-orange-500/15 text-orange-400":"bg-blue-500/15 text-blue-400"}`}>{e.status}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// AI ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════
function AIAnalysis({ threats }: { threats: ThreatEvent[] }) {
  const [sel, setSel] = useState<ThreatEvent | null>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [queryResult, setQueryResult] = useState<string | null>(null);
  
  // Dataset Report states
  const [datasetReport, setDatasetReport] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [activeMode, setActiveMode] = useState<"threat" | "dataset">("threat");

  const threatEvents = threats.filter(t => t.is_threat);

  const analyze = async (t: ThreatEvent) => {
    setActiveMode("threat");
    setSel(t); setLoading(true); setResult(null);
    try {
      const r = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ threat: t }) });
      setResult(await r.json());
    } catch (e: any) { setResult({ analysis: `Error: ${e.message}`, threat_data: t, model: "error" }); }
    setLoading(false);
  };

  const generateReport = async () => {
    setActiveMode("dataset");
    setReportLoading(true);
    setDatasetReport(null);
    try {
      const r = await fetch("/api/analyze-dataset", { method: "POST" });
      const d = await r.json();
      if (r.ok) {
        setDatasetReport(d.report);
      } else {
        setDatasetReport(`Error generating report: ${d.error}`);
      }
    } catch (err: any) {
      setDatasetReport(`Analysis failed: ${err.message}`);
    } finally {
      setReportLoading(false);
    }
  };

  const askQuery = async () => {
    if (!query.trim()) return;
    setLoading(true); setQueryResult(null);
    try {
      const r = await fetch("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message: query }) });
      const d = await r.json(); setQueryResult(d.response);
    } catch (e: any) { setQueryResult(`Error: ${e.message}`); }
    setLoading(false);
  };

  return (
    <div>
      <h2 className="text-xl font-bold flex items-center gap-2 mb-0.5"><Brain size={20}/> AI Threat Analysis</h2>
      <p className="text-xs text-gray-500 mb-4 font-mono">Run LLM security reviews on packets or full datasets</p>

      <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-4" style={{ height: "calc(100vh - 180px)" }}>
        {/* Left */}
        <div className="flex flex-col gap-3 overflow-y-auto pr-1">
          <div>
            <button
              onClick={generateReport}
              className={`w-full py-2.5 px-3 rounded-lg flex items-center justify-center gap-2 text-xs font-bold transition-all border
                ${activeMode === "dataset" ? "bg-gradient-to-r from-purple-500 to-cyan-500 text-white border-transparent shadow-lg shadow-purple-500/10" : "bg-[#1d273a] text-purple-400 border-purple-500/20 hover:border-purple-400/50"}`}
            >
              <Zap size={14} className={reportLoading ? "animate-pulse" : ""} />
              Generate Dataset AI Report
            </button>
          </div>

          <div>
            <h3 className="text-xs font-semibold mb-2 text-gray-400">Select Threat Event</h3>
            <div className="flex flex-col gap-1 max-h-[200px] overflow-y-auto pr-1 font-mono">
              {threatEvents.length === 0 ? <p className="text-gray-500 text-xs text-center py-4 font-sans">No threats available</p> :
                [...threatEvents].reverse().slice(0, 20).map((t, i) => (
                  <button key={t.id+i} onClick={() => analyze(t)}
                    className={`flex items-center gap-2 px-2.5 py-2 rounded-md text-left transition-all text-xs ${activeMode === "threat" && sel?.id === t.id ? "bg-cyan-500/10 border border-cyan-500/30 text-cyan-400" : "bg-[#1a2332] border border-[#1e293b] text-gray-300 hover:border-blue-500/50"}`}>
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background: SEV_COLORS[t.severity] }}/>
                    <div className="flex-1 min-w-0"><div className="font-semibold truncate font-sans text-gray-200">{t.threat_type}</div><div className="text-[10px] text-gray-500 truncate">{t.source_ip}→{t.destination_ip}</div></div>
                  </button>
                ))
              }
            </div>
          </div>

          <div className="bg-[#1a2332] border border-[#1e293b] rounded-lg p-3">
            <h3 className="text-xs font-semibold text-cyan-400 flex items-center gap-1 mb-2"><MessageSquare size={13}/> Quick Security Ask</h3>
            <textarea value={query} onChange={e => setQuery(e.target.value)} placeholder="Ask about threat signatures..." rows={2} className="w-full p-2 bg-[#0a0e17] border border-[#1e293b] rounded text-xs text-gray-200 outline-none resize-none focus:border-blue-500"/>
            <button onClick={askQuery} disabled={loading || !query.trim()} className="mt-1.5 w-full py-1.5 rounded bg-gradient-to-r from-blue-500 to-cyan-500 text-white text-xs font-semibold disabled:opacity-40 cursor-pointer">Analyze</button>
            {queryResult && <div className="mt-2 p-2 bg-[#0a0e17] rounded text-[11px] text-gray-300 whitespace-pre-wrap">{queryResult}</div>}
          </div>
        </div>

        {/* Right */}
        <div className="flex flex-col gap-3 overflow-y-auto pr-1">
          {activeMode === "dataset" ? (
            reportLoading ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500 gap-2 bg-[#1a2332] border border-[#1e293b] rounded-xl">
                <RefreshCw size={28} className="animate-spin text-purple-400"/><p className="text-xs">Aggregating and generating AI Security Summary report...</p>
              </div>
            ) : datasetReport ? (
              <div className="bg-[#1a2332] border border-[#1e293b] rounded-xl overflow-hidden shadow-xl">
                <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-purple-500/10 to-cyan-500/10 border-b border-[#1e293b]">
                  <Brain size={16} className="text-purple-400"/>
                  <h3 className="text-sm font-semibold flex-1">Dataset AI Analyst Report</h3>
                  <span className="text-[10px] px-2.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-400 font-mono">Full Capture Audit</span>
                </div>
                <div className="p-5 text-sm text-gray-300 whitespace-pre-wrap leading-relaxed max-w-none prose prose-invert font-sans">
                  {datasetReport}
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 bg-[#1a2332] border border-dashed border-[#334155] rounded-xl text-gray-500 gap-2">
                <Zap size={32} className="text-purple-400"/>
                <h3 className="text-sm text-gray-400">Request AI Dataset Report</h3>
                <p className="text-xs">Click the button in the left panel to scan the entire uploaded database and generate an executive report.</p>
              </div>
            )
          ) : (
            // Threat Mode
            loading ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500 gap-2 bg-[#1a2332] border border-[#1e293b] rounded-xl">
                <RefreshCw size={28} className="animate-spin text-cyan-400"/><p className="text-xs">Running security model threat evaluation...</p>
              </div>
            ) : result ? (
              <div className="bg-[#1a2332] border border-[#1e293b] rounded-xl overflow-hidden shadow-xl">
                <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-purple-500/10 to-cyan-500/10 border-b border-[#1e293b]">
                  <Brain size={16} className="text-cyan-400"/>
                  <h3 className="text-sm font-semibold flex-1">Single Alert AI Incident Report</h3>
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/15 text-purple-400 font-mono">{result.model}</span>
                </div>
                <div className="grid grid-cols-4 gap-2 px-4 py-3 border-b border-[#1e293b] text-xs font-mono">
                  {[
                    { l: "Threat", v: result.threat_data?.threat_type },
                    { l: "Severity", v: result.threat_data?.severity, c: SEV_COLORS[result.threat_data?.severity] },
                    { l: "Origin IP", v: result.threat_data?.source_ip },
                    { l: "Target", v: `${result.threat_data?.destination_ip}:${result.threat_data?.destination_port}` },
                  ].map((s, i) => (
                    <div key={i}><div className="text-[10px] text-gray-500 uppercase font-sans mb-0.5">{s.l}</div><div className="font-semibold text-gray-200" style={{ color: s.c || "inherit" }}>{s.v}</div></div>
                  ))}
                </div>
                <div className="p-5 text-sm text-gray-300 whitespace-pre-wrap leading-relaxed font-sans">{result.analysis}</div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 bg-[#1a2332] border border-dashed border-[#334155] rounded-xl text-gray-500 gap-2">
                <Brain size={32} className="text-cyan-400"/>
                <h3 className="text-sm text-gray-400 font-sans">Select a threat to analyze</h3>
                <p className="text-xs">Choose from the events list or generate the full dataset security audit report.</p>
              </div>
            )
          )}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALERTS
// ═══════════════════════════════════════════════════════════════════════════════
function Alerts({ alerts, onRefresh }: { alerts: AlertItem[]; onRefresh: () => void }) {
  const [filter, setFilter] = useState("all");
  const filtered = alerts.filter(a => {
    if (filter === "active") return a.status !== "resolved";
    if (filter === "resolved") return a.status === "resolved";
    if (filter === "critical") return a.severity === "critical";
    return true;
  });

  const resolve = async (id: string) => { await fetch("/api/resolve-alert", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }) }); onRefresh(); };
  const block = async (ip: string) => { await fetch("/api/block-ip", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip, reason: "Blocked via alert" }) }); };

  const activeCount = alerts.filter(a => a.status !== "resolved").length;
  const critCount = alerts.filter(a => a.severity === "critical").length;

  return (
    <div>
      <h2 className="text-xl font-bold flex items-center gap-2 mb-0.5"><Bell size={20}/> Security Alerts</h2>
      <p className="text-xs text-gray-500 mb-4">{activeCount} active, {critCount} critical alerts from dataset</p>

      <div className="flex gap-1.5 mb-4 flex-wrap">
        {[{ k: "all", l: `All (${alerts.length})` }, { k: "active", l: `Active (${activeCount})` }, { k: "critical", l: `Critical (${critCount})` }, { k: "resolved", l: "Resolved" }].map(f => (
          <button key={f.k} onClick={() => setFilter(f.k)} className={`px-3 py-1.5 rounded-full text-xs border transition-all cursor-pointer ${filter === f.k ? "bg-blue-500/15 border-blue-500 text-blue-400" : "bg-[#1a2332] border-[#1e293b] text-gray-400 hover:border-blue-500/50"}`}>{f.l}</button>
        ))}
      </div>

      <div className="flex flex-col gap-2 font-mono">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center py-12 text-gray-500 gap-2 font-sans"><CheckCircle size={36}/><h3 className="text-sm text-gray-400">No alerts found</h3><p className="text-xs">Dataset is secure</p></div>
        ) : [...filtered].reverse().map((a, i) => (
          <div key={a.id+i} className={`flex items-start gap-3 p-3.5 bg-[#1a2332] border border-[#1e293b] rounded-lg ${a.status==="resolved"?"opacity-50":""}`} style={{ borderLeftColor: SEV_COLORS[a.severity], borderLeftWidth: 3, background: SEV_COLORS[a.severity]+"08" }}>
            <AlertTriangle size={18} style={{ color: SEV_COLORS[a.severity] }} className="shrink-0 mt-0.5"/>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-bold text-sm font-sans" style={{ color: SEV_COLORS[a.severity] }}>{a.type}</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase font-sans" style={{ background: SEV_COLORS[a.severity]+"20", color: SEV_COLORS[a.severity] }}>{a.severity}</span>
                <span className="ml-auto text-[10px] text-gray-500">{new Date(a.timestamp).toLocaleTimeString()}</span>
              </div>
              <p className="text-xs text-gray-400 font-sans">{a.message}</p>
              <div className="flex gap-3 mt-1 text-[11px] text-gray-500 font-sans"><span>Source: {a.source_ip}</span><span>Status: <b className="text-gray-300">{a.status}</b></span></div>
            </div>
            {a.status !== "resolved" && (
              <div className="flex gap-1 shrink-0">
                <button onClick={() => resolve(a.id)} className="p-1.5 rounded border border-[#1e293b] text-emerald-400 hover:bg-emerald-500/10 hover:border-emerald-500 cursor-pointer" title="Resolve Alert"><CheckCircle size={13}/></button>
                <button onClick={() => block(a.source_ip)} className="p-1.5 rounded border border-[#1e293b] text-red-400 hover:bg-red-500/10 hover:border-red-500 cursor-pointer" title="Block source IP"><Shield size={13}/></button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHAT ASSISTANT
// ═══════════════════════════════════════════════════════════════════════════════
function ChatAssistant({ stats }: { stats: Stats | null }) {
  const [msgs, setMsgs] = useState<ChatMsg[]>([{ id: 1, role: "assistant", content: "Hello! I'm your AI Security Assistant. Ask me questions about the uploaded dataset, threat mitigations, SQL injection details, or DDoS strategies.", timestamp: new Date().toISOString() }]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const endRef = React.useRef<HTMLDivElement>(null);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs]);

  const send = async (text: string = input) => {
    if (!text.trim() || loading) return;
    const userMsg: ChatMsg = { id: Date.now(), role: "user", content: text, timestamp: new Date().toISOString() };
    setMsgs(p => [...p, userMsg]); setInput(""); setLoading(true);
    try {
      const ctx = `Threats: ${stats?.threats_detected || 0}. Categories: ${JSON.stringify(stats?.threat_categories || {})}`;
      const r = await fetch("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message: text, context: ctx }) });
      const d = await r.json();
      setMsgs(p => [...p, { id: Date.now()+1, role: "assistant", content: d.response, timestamp: d.timestamp || new Date().toISOString() }]);
    } catch (e: any) { setMsgs(p => [...p, { id: Date.now()+1, role: "assistant", content: `Error: ${e.message}`, timestamp: new Date().toISOString() }]); }
    setLoading(false);
  };

  const suggestions = ["What are the most critical threats?", "How to protect against SQL injection?", "DDoS mitigation strategies", "Best practices for network segmentation"];

  return (
    <div>
      <h2 className="text-xl font-bold flex items-center gap-2 mb-0.5"><MessageSquare size={20}/> AI Security Assistant</h2>
      <p className="text-xs text-gray-500 mb-4">Chat with the security assistant about target mitigations</p>

      <div className="flex flex-col bg-[#1a2332] border border-[#1e293b] rounded-xl overflow-hidden" style={{ height: "calc(100vh - 200px)" }}>
        <div className="flex gap-1.5 px-3 py-2 border-b border-[#1e293b] overflow-x-auto">
          {suggestions.map((s, i) => (
            <button key={i} onClick={() => send(s)} disabled={loading} className="flex items-center gap-1 px-2.5 py-1 bg-[#0a0e17] border border-[#1e293b] rounded-full text-[11px] text-gray-400 whitespace-nowrap hover:border-blue-500 hover:text-blue-400 disabled:opacity-40 cursor-pointer">
              <Shield size={10}/>{s}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-3">
          {msgs.map(m => (
            <div key={m.id} className={`flex gap-2.5 max-w-[85%] ${m.role === "user" ? "self-end flex-row-reverse" : "self-start"}`}>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${m.role === "assistant" ? "bg-gradient-to-br from-purple-500 to-cyan-500" : "bg-blue-500"} text-white`}>
                {m.role === "assistant" ? <Bot size={14}/> : <User size={14}/>}
              </div>
              <div className={`px-3 py-2.5 rounded-xl text-sm ${m.role === "assistant" ? "bg-[#0a0e17] border border-[#1e293b] text-gray-300" : "bg-blue-500/15 border border-blue-500/20 text-gray-200"}`}>
                <div className="text-[10px] text-gray-500 mb-1 font-medium">{m.role === "assistant" ? "AI Assistant" : "You"}</div>
                <div className="whitespace-pre-wrap leading-relaxed">{m.content}</div>
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex gap-2.5 self-start">
              <div className="w-8 h-8 rounded-full flex items-center justify-center bg-gradient-to-br from-purple-500 to-cyan-500 text-white"><Bot size={14}/></div>
              <div className="px-3 py-2.5 bg-[#0a0e17] border border-[#1e293b] rounded-xl text-xs text-gray-500 flex items-center gap-1.5"><RefreshCw size={12} className="animate-spin"/> Analyzing...</div>
            </div>
          )}
          <div ref={endRef}/>
        </div>

        <div className="px-3 py-2.5 border-t border-[#1e293b]">
          <div className="flex gap-2">
            <textarea value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
              placeholder="Ask about threats..." rows={1} className="flex-1 p-2.5 bg-[#0a0e17] border border-[#1e293b] rounded-lg text-sm text-gray-200 outline-none resize-none focus:border-blue-500"/>
            <button onClick={() => send()} disabled={loading || !input.trim()} className="px-3 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-lg text-white disabled:opacity-40 cursor-pointer"><Send size={16}/></button>
          </div>
        </div>
      </div>
    </div>
  );
}
