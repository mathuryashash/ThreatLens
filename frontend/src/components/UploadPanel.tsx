"use client";

import React, { useState, useRef } from "react";
import {
  UploadCloud, Play, Code, AlertCircle, FileText,
  CheckCircle, XCircle, Activity, Cpu, Zap, Shield,
  Server, Eye, Lock, Globe, X, ArrowRight
} from "lucide-react";

interface ParseSummary {
  total: number;
  parsed: number;
  failed: number;
  ruleMatches: number;
  aiMatches: number;
}

interface UploadPanelProps {
  onAnalyze: (logs: string[], sourceType: string) => void;
  isProcessing: boolean;
  jobProgress: {
    processed: number;
    failed: number;
    total: number;
    percent: number;
    status: string;
  } | null;
  logsRemaining: number;
  parseSummary: ParseSummary | null;
  apiConnected: boolean;
}

const SAMPLE_SCENARIOS = [
  {
    key: "auth_bruteforce",
    label: "SSH Brute Force",
    source: "auth",
    icon: Lock,
    color: "text-amber-400",
    bg: "hover:border-amber-500/40 bg-slate-900/30",
    desc: "10 failed sshd logins from one IP in 5 minutes.",
    detector: "Correlation Rule"
  },
  {
    key: "nginx_ssrf",
    label: "SSRF Probe",
    source: "nginx",
    icon: Globe,
    color: "text-rose-400",
    bg: "hover:border-rose-500/40 bg-slate-900/30",
    desc: "Metadata endpoint request targeting 169.254.169.254.",
    detector: "Regex Rule"
  },
  {
    key: "nginx_sqli",
    label: "SQL Injection",
    source: "nginx",
    icon: Server,
    color: "text-orange-400",
    bg: "hover:border-orange-500/40 bg-slate-900/30",
    desc: "UNION SELECT payload injected in URL query string.",
    detector: "Regex Rule"
  },
  {
    key: "auth_privesc",
    label: "Privilege Escalation",
    source: "auth",
    icon: Shield,
    color: "text-purple-400",
    bg: "hover:border-purple-500/40 bg-slate-900/30",
    desc: "Sudo authentication failures for root account.",
    detector: "Regex Rule"
  },
  {
    key: "mixed_attacks",
    label: "Mixed Scan Batch",
    source: "nginx",
    icon: Zap,
    color: "text-sky-400",
    bg: "hover:border-sky-500/40 bg-slate-900/30",
    desc: "Combination of SSRF, SQLi, traversal, and benign logs.",
    detector: "Hybrid Rules + LLM"
  },
] as const;

const SAMPLE_LOGS: Record<string, string[]> = {
  nginx_sqli: [
    '198.51.100.12 - - [23/May/2026:14:35:10 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 400 512 "-" "Mozilla/5.0"',
    '198.51.100.12 - - [23/May/2026:14:35:15 +0000] "GET /products?category=shoes%27%20OR%201=1-- HTTP/1.1" 400 324 "-" "Mozilla/5.0"',
    '198.51.100.12 - - [23/May/2026:14:35:20 +0000] "GET /search?q=normal%20search%20term HTTP/1.1" 200 4500 "-" "Mozilla/5.0"',
  ],
  nginx_ssrf: [
    '203.0.113.99 - - [23/May/2026:14:36:20 +0000] "GET /api/proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
    '203.0.113.99 - - [23/May/2026:14:36:25 +0000] "GET /fetch?url=http://metadata.google.internal/computeMetadata/v1/ HTTP/1.1" 200 488 "-" "Mozilla/5.0"',
    '203.0.113.99 - - [23/May/2026:14:36:30 +0000] "GET /api/proxy?url=https://legitimate-site.com/logo.png HTTP/1.1" 200 8500 "-" "Mozilla/5.0"',
  ],
  auth_bruteforce: [
    'May 23 14:33:01 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54321 ssh2',
    'May 23 14:33:02 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54322 ssh2',
    'May 23 14:33:03 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54323 ssh2',
    'May 23 14:33:04 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54324 ssh2',
    'May 23 14:33:05 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54325 ssh2',
    'May 23 14:33:06 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54326 ssh2',
    'May 23 14:33:07 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54327 ssh2',
    'May 23 14:33:08 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54328 ssh2',
    'May 23 14:33:09 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54329 ssh2',
    'May 23 14:33:10 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54330 ssh2',
    'May 23 14:33:15 server sshd[12345]: Accepted password for root from 192.168.1.100 port 12345 ssh2',
  ],
  auth_privesc: [
    'May 23 14:38:00 server sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 ruser=developer rhost=  user=root',
    'May 23 14:38:10 server su: pam_unix(su:auth): failed su for root by developer',
    'May 23 14:38:20 server sudo: developer : TTY=pts/1 ; PWD=/home/developer ; USER=root ; COMMAND=/bin/bash',
  ],
  mixed_attacks: [
    '127.0.0.1 - - [23/May/2026:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 4524 "-" "Mozilla/5.0"',
    'May 23 14:33:01 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54321 ssh2',
    'May 23 14:33:03 server sshd[12345]: Failed password for invalid user admin from 203.0.113.42 port 54322 ssh2',
    '198.51.100.12 - - [23/May/2026:14:35:10 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 400 512 "-" "Mozilla/5.0"',
    '203.0.113.99 - - [23/May/2026:14:36:20 +0000] "GET /api/proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
    '192.0.2.77 - - [23/May/2026:14:37:30 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 400 256 "-" "Mozilla/5.0"',
    'May 23 14:38:00 server sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 ruser=developer rhost=  user=root',
    '203.0.113.42 - - [23/May/2026:14:39:00 +0000] "GET /wp-login.php HTTP/1.1" 200 2345 "-" "Mozilla/5.0"',
  ],
};

const PIPELINE_STEPS = [
  { key: "parse", label: "Parse", desc: "Structure events" },
  { key: "redact", label: "Redact", desc: "Scrub PII" },
  { key: "rules", label: "Rules", desc: "Correlation engine" },
  { key: "llm", label: "LLM", desc: "Triage classification" },
  { key: "store", label: "Store", desc: "Commit findings" },
];

export const UploadPanel: React.FC<UploadPanelProps> = ({
  onAnalyze,
  isProcessing,
  jobProgress,
  logsRemaining,
  parseSummary,
  apiConnected,
}) => {
  const [inputText, setInputText] = useState("");
  const [sourceType, setSourceType] = useState("nginx");
  const [errorMsg, setErrorMsg] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const lineCount = inputText.split("\n").filter((l) => l.trim().length > 0).length;

  const handleAnalyzeClick = () => {
    setErrorMsg("");
    const lines = inputText.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
    if (lines.length === 0) { setErrorMsg("Paste or upload log lines first."); return; }
    if (lines.length > 500) { setErrorMsg("Maximum 500 lines per batch."); return; }
    if (lines.length > logsRemaining) { setErrorMsg(`Only ${logsRemaining} quota lines remaining.`); return; }
    onAnalyze(lines, sourceType);
  };

  const loadFile = (file: File) => {
    if (file.size > 3 * 1024 * 1024) { setErrorMsg("File exceeds 3 MB limit."); return; }
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      setInputText(text);
      setFileName(file.name);
      setSourceType(text.includes("sshd") || text.includes("sudo:") || text.includes("auth:") ? "auth" : "nginx");
    };
    reader.onerror = () => {
      setInputText("// Could not read file. Make sure it is a plain text log file.");
      setFileName(null);
    };
    reader.readAsText(file);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) loadFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) loadFile(file);
  };

  const handlePreload = (key: string, source: string) => {
    setErrorMsg("");
    setFileName(null);
    setSourceType(source);
    setInputText(SAMPLE_LOGS[key].join("\n"));
  };

  const clearInput = () => { setInputText(""); setFileName(null); setErrorMsg(""); };

  const isRunning = jobProgress?.status === "queued" || jobProgress?.status === "processing";

  // Calculate step state for pipeline visualization
  const getStepState = (stepIndex: number) => {
    if (!jobProgress) return "pending";
    if (jobProgress.status === "completed") return "completed";
    if (jobProgress.status === "failed") return "failed";

    const percent = jobProgress.percent;
    const thresh = [10, 30, 60, 85, 100];
    const prevThresh = [0, 10, 30, 60, 85];

    if (percent >= thresh[stepIndex]) return "completed";
    if (percent > prevThresh[stepIndex]) return "active";
    return "pending";
  };

  return (
    <div className="glass-panel rounded-sm border border-slate-800/80 bg-slate-950/40 shadow-xl flex flex-col overflow-hidden">

      {/* ── Panel header ── */}
      <div className="px-5 py-3.5 border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <UploadCloud className="w-4 h-4 text-sky-400" />
          <h2 className="text-xs font-bold tracking-widest text-slate-300 uppercase">Log Ingest Console</h2>
        </div>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded-sm border font-semibold ${
          logsRemaining < 50
            ? "bg-rose-500/10 border-rose-500/30 text-rose-400"
            : "bg-slate-800 border-slate-700/50 text-slate-400"
        }`}>
          {logsRemaining} lines left
        </span>
      </div>

      <div className="p-5 flex flex-col gap-4">

        {/* ── Format selector ── */}
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest shrink-0">Format</span>
          <div className="flex bg-slate-900/80 border border-slate-800 rounded-sm p-0.5 gap-0.5">
            {["nginx", "auth", "custom"].map((type) => (
              <button
                key={type}
                onClick={() => setSourceType(type)}
                disabled={isProcessing}
                className={`px-3 py-1 text-[11px] font-bold rounded-sm transition-all duration-150 cursor-pointer ${
                  sourceType === type
                    ? "bg-sky-500/20 text-sky-300 border border-sky-500/30"
                    : "text-slate-500 hover:text-slate-300 border border-transparent"
                }`}
              >
                {type.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* ── Textarea / drop zone ── */}
        <div
          className={`relative rounded-sm border transition-all duration-200 ${
            isDragging
              ? "border-sky-500/60 bg-sky-500/5 shadow-[0_0_20px_rgba(14,165,233,0.1)]"
              : "border-slate-800"
          }`}
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
        >
          <textarea
            value={inputText}
            onChange={(e) => { setInputText(e.target.value); setFileName(null); }}
            disabled={isProcessing || !apiConnected}
            placeholder={!apiConnected ? "Backend offline. Paste and analysis are disabled until the server is running." : `Paste ${sourceType === "nginx" ? "nginx access" : sourceType === "auth" ? "Linux auth / sshd / sudo" : "custom"} log lines here, or drag & drop a .log file…`}
            className="w-full h-44 p-4 bg-slate-950 text-xs font-mono text-slate-300 placeholder-slate-700 focus:outline-none resize-none block border-0 disabled:opacity-50"
            spellCheck={false}
          />

          {/* File name badge + clear */}
          {(fileName || inputText) && (
            <div className="absolute bottom-2.5 left-3 right-3 flex items-center justify-between">
              {fileName && (
                <span className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
                  <FileText className="w-3 h-3 text-sky-500" />
                  {fileName}
                  {lineCount > 0 && <span className="text-slate-600">· {lineCount} lines</span>}
                </span>
              )}
              {!fileName && lineCount > 0 && (
                <span className="text-[10px] font-mono text-slate-600 bg-slate-900/60 px-2 py-0.5 rounded">
                  {lineCount} lines
                </span>
              )}
              <button
                onClick={clearInput}
                className="flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 bg-slate-900 border border-slate-800 text-slate-500 hover:text-slate-300 rounded cursor-pointer transition-colors ml-auto"
              >
                <X className="w-2.5 h-2.5" /> Clear
              </button>
            </div>
          )}

          {isDragging && (
            <div className="absolute inset-0 flex items-center justify-center bg-slate-950/80 pointer-events-none">
              <p className="text-xs font-semibold text-sky-400">Drop file to load</p>
            </div>
          )}
        </div>

        {/* ── Pipeline Visualization Strip ── */}
        <div className="flex flex-col gap-1.5 p-3 rounded-sm border border-slate-800/80 bg-slate-950/40">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">Triage Pipeline Status</span>
          <div className="flex items-center justify-between gap-1">
            {PIPELINE_STEPS.map((step, idx) => {
              const state = getStepState(idx);
              let stateClass = "text-slate-600 border-slate-900 bg-slate-950/20";
              if (state === "completed") {
                stateClass = "text-emerald-400 border-emerald-500/20 bg-emerald-500/5";
              } else if (state === "active") {
                stateClass = "text-sky-400 border-sky-500/30 bg-sky-500/10 animate-pulse";
              } else if (state === "failed") {
                stateClass = "text-rose-400 border-rose-500/20 bg-rose-500/5";
              }
              
              return (
                <React.Fragment key={step.key}>
                  <div className={`flex flex-col items-center flex-1 py-1 rounded border text-center transition-all ${stateClass}`}>
                    <span className="text-[10px] font-bold uppercase tracking-wider font-mono">{step.label}</span>
                    <span className="text-[7px] text-slate-500 scale-90 hidden sm:inline truncate">{step.desc}</span>
                  </div>
                  {idx < PIPELINE_STEPS.length - 1 && (
                    <ArrowRight className={`w-3 h-3 flex-shrink-0 ${
                      state === "completed" ? "text-emerald-500" : "text-slate-800"
                    }`} />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>

        {/* ── Error / Offline Warnings ── */}
        {!apiConnected && (
          <div className="flex items-center gap-2 p-3 rounded-sm bg-rose-500/10 border border-rose-500/20 text-xs text-rose-400 font-mono">
            <AlertCircle className="w-4.5 h-4.5 shrink-0" />
            <span>API Server offline. Triage and upload features are disabled. Verify that the FastAPI backend is running at http://127.0.0.1:8000.</span>
          </div>
        )}
        {errorMsg && (
          <div className="flex items-center gap-2 p-3 rounded-sm bg-rose-500/10 border border-rose-500/20 text-xs text-rose-400 font-mono">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {errorMsg}
          </div>
        )}

        {/* ── Actions ── */}
        <div className="flex gap-2.5">
          <input type="file" ref={fileInputRef} onChange={handleFileChange} className="hidden" accept=".log,.txt" />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={isProcessing || !apiConnected}
            className="flex-1 flex items-center justify-center gap-2 py-2 px-3 border border-slate-700/60 hover:border-slate-600 bg-slate-900/60 hover:bg-slate-800/60 text-xs font-semibold text-slate-400 hover:text-slate-200 rounded-sm cursor-pointer transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <FileText className="w-3.5 h-3.5" />
            Upload File
          </button>
          <button
            onClick={handleAnalyzeClick}
            disabled={isProcessing || lineCount === 0 || !apiConnected}
            className="flex-[1.6] flex items-center justify-center gap-2 py-2 px-3 bg-sky-500 hover:bg-sky-400 text-xs font-bold text-slate-950 rounded-sm cursor-pointer transition-all hover:shadow-[0_0_15px_rgba(14,165,233,0.3)] disabled:opacity-40 disabled:shadow-none disabled:cursor-not-allowed"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            {isProcessing ? "Processing…" : "Analyze Logs"}
          </button>
        </div>

        {/* ── Progress bar ── */}
        {isRunning && jobProgress && (
          <div className="flex flex-col gap-2 p-3.5 rounded-sm border border-slate-800 bg-slate-950/70">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 font-semibold text-sky-400 animate-pulse">
                <Code className="w-3.5 h-3.5" />
                {jobProgress.status === "queued" ? "Queued in Pipeline" : "Executing Pipeline Steps"}
              </span>
              <span className="font-mono text-slate-500 tabular-nums">
                {jobProgress.processed}/{jobProgress.total} · {jobProgress.percent}%
              </span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-slate-900 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-sky-500 via-indigo-500 to-emerald-500 transition-all duration-500 ease-out"
                style={{ width: `${jobProgress.percent}%` }}
              />
            </div>
          </div>
        )}

        {/* ── Technical Scenario Cards ── */}
        <div className="flex flex-col gap-2.5 border-t border-slate-900 pt-4">
          <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">Select Incident Scenario</span>
          <div className="grid grid-cols-1 gap-2.5">
            {SAMPLE_SCENARIOS.map(({ key, label, source, icon: Icon, color, bg, desc, detector }) => (
              <div
                key={key}
                role="button"
                onClick={() => !isProcessing && apiConnected && handlePreload(key, source)}
                className={`flex gap-3 p-3 rounded-sm border border-slate-900 hover:border-slate-800/80 cursor-pointer transition-all duration-150 relative overflow-hidden group select-none ${bg} ${
                  isProcessing || !apiConnected ? "opacity-40 cursor-not-allowed pointer-events-none" : ""
                }`}
              >
                <div className={`p-2 rounded-sm bg-slate-950/60 flex items-center justify-center shrink-0 border border-slate-900 group-hover:border-slate-800/60 ${color}`}>
                  <Icon className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0 flex flex-col gap-0.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-slate-200 group-hover:text-slate-100 transition-colors">
                      {label}
                    </span>
                    <span className="text-[8px] font-mono font-semibold px-1.5 py-0.5 rounded bg-slate-950 text-slate-500 border border-slate-900">
                      {detector}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-500 group-hover:text-slate-400 transition-colors leading-relaxed">
                    {desc}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Parse summary (appears after job completes) ── */}
        {jobProgress?.status === "completed" && parseSummary && (
          <div className="rounded-sm border border-emerald-500/20 bg-emerald-500/5 overflow-hidden">
            {/* Header row */}
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-emerald-500/10">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-xs font-bold text-emerald-400">Log Triage Complete</span>
            </div>

            {/* Stats grid */}
            <div className="grid grid-cols-2 gap-px bg-slate-800/30">
              {[
                { label: "Lines Ingested", value: parseSummary.total,       icon: FileText,  color: "text-slate-300" },
                { label: "Parsed OK",      value: parseSummary.parsed,      icon: CheckCircle, color: "text-emerald-400" },
                { label: "Failed Lines",   value: parseSummary.failed,      icon: XCircle,   color: parseSummary.failed > 0 ? "text-rose-400" : "text-slate-500" },
                { label: "Threat Detections",  value: parseSummary.ruleMatches + parseSummary.aiMatches, icon: Eye, color: "text-amber-400" },
              ].map(({ label, value, icon: Icon, color }) => (
                <div key={label} className="flex items-center gap-2.5 px-4 py-3 bg-slate-950/40">
                  <Icon className={`w-3.5 h-3.5 shrink-0 ${color}`} />
                  <div>
                    <p className="text-[10px] text-slate-500">{label}</p>
                    <p className={`text-sm font-bold tabular-nums ${color}`}>{value}</p>
                  </div>
                </div>
              ))}
            </div>

            {/* Rule vs AI breakdown bar */}
            {(parseSummary.ruleMatches + parseSummary.aiMatches) > 0 && (
              <div className="px-4 py-3 border-t border-slate-800/40 flex flex-col gap-1.5">
                <div className="flex items-center justify-between text-[10px] font-semibold">
                  <span className="flex items-center gap-1 text-sky-400 font-mono"><Activity className="w-3 h-3" /> RULE ENGINE</span>
                  <span className="flex items-center gap-1 text-indigo-400 font-mono"><Cpu className="w-3 h-3" /> AI CLASSIFIED</span>
                </div>
                <div className="flex h-2 rounded-full overflow-hidden bg-slate-800">
                  {parseSummary.ruleMatches > 0 && (
                    <div
                      className="h-full bg-sky-500 transition-all duration-700"
                      style={{ width: `${(parseSummary.ruleMatches / (parseSummary.ruleMatches + parseSummary.aiMatches)) * 100}%` }}
                    />
                  )}
                  {parseSummary.aiMatches > 0 && (
                    <div
                      className="h-full bg-indigo-500 transition-all duration-700"
                      style={{ width: `${(parseSummary.aiMatches / (parseSummary.ruleMatches + parseSummary.aiMatches)) * 100}%` }}
                    />
                  )}
                </div>
                <div className="flex justify-between text-[10px] font-mono text-slate-500">
                  <span>{parseSummary.ruleMatches} rule hits</span>
                  <span>{parseSummary.aiMatches} AI hits</span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Failed job notice */}
        {jobProgress?.status === "failed" && (
          <div className="flex items-center gap-2 p-3 rounded-sm border border-rose-500/20 bg-rose-500/5 text-xs text-rose-400">
            <XCircle className="w-4 h-4 shrink-0" />
            Ingest pipeline failed — check backend logs for details.
          </div>
        )}
      </div>
    </div>
  );
};
