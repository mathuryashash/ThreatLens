"use client";

import React from "react";
import { ShieldCheck, Info, X, AlertTriangle, HelpCircle, Terminal, ClipboardList, Shield } from "lucide-react";

export interface ExplanationData {
  explanation: string;
  mitre_tactic: string;
  recommended_actions: string[];
  cached: boolean;
}

interface ExplainPanelProps {
  threat: {
    id: string;
    threat_type: string;
    severity: string;
    source_ip: string | null;
    summary: string;
    classification_source: string;
  } | null;
  explanation: ExplanationData | null;
  isLoading: boolean;
  error: string | null;
  onClose: () => void;
  onRetry: () => void;
  onUseDemoFallback?: () => void;
}

export const ExplainPanel: React.FC<ExplainPanelProps> = ({
  threat,
  explanation,
  isLoading,
  error,
  onClose,
  onRetry,
  onUseDemoFallback,
}) => {
  if (!threat) {
    return (
      <div className="glass-panel p-6 rounded-sm border border-slate-800 bg-slate-950/20 flex flex-col items-center justify-center text-center gap-3">
        <HelpCircle className="w-8 h-8 text-slate-600" />
        <div>
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">No Threat Selected</h3>
          <p className="text-[11px] text-slate-500 mt-1 max-w-[280px]">
            Click the &quot;Brief&quot; button on any threat in the triage queue to generate a full security analyst brief.
          </p>
        </div>
      </div>
    );
  }

  const getMitreTacticBadge = (tactic: string) => {
    const name = tactic.toLowerCase();
    if (name.includes("initial") || name.includes("access")) {
      return "bg-sky-500/10 text-sky-400 border border-sky-500/30";
    }
    if (name.includes("credential") || name.includes("privilege") || name.includes("escalation")) {
      return "bg-rose-500/10 text-rose-400 border border-rose-500/30";
    }
    if (name.includes("recon") || name.includes("discover")) {
      return "bg-amber-500/10 text-amber-400 border border-amber-500/30";
    }
    return "bg-indigo-500/10 text-indigo-400 border border-indigo-500/30";
  };

  return (
    <div className="glass-panel p-5 rounded-sm border border-slate-800 bg-slate-950/45 flex flex-col gap-4 relative">
      {/* Header */}
      <div className="flex items-start justify-between border-b border-slate-800/80 pb-3">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100 font-mono">
              Analyst Brief: {threat.threat_type.replaceAll("_", " ")}
            </h2>
            <div className="flex items-center gap-1.5">
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700/60 uppercase">
                Advisory
              </span>
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700/60">
                Redacted Logs
              </span>
              {explanation?.cached && (
                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-0.5">
                  <ShieldCheck className="w-2.5 h-2.5" />
                  Cached
                </span>
              )}
            </div>
          </div>
          <p className="text-[10px] text-slate-500 mt-1 font-mono">
            ID: {threat.id} · Scope: Session-level triage
          </p>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded hover:bg-slate-900 border border-transparent hover:border-slate-800 text-slate-400 hover:text-slate-200 transition-all cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Loading state */}
      {isLoading && (
        <div className="flex flex-col items-center justify-center text-center gap-3 py-10">
          <div className="w-7 h-7 rounded-full border-2 border-slate-800 border-t-sky-500 animate-spin" />
          <p className="text-[11px] text-slate-400">Querying Groq models for security briefing...</p>
        </div>
      )}

      {/* Error state */}
      {error && !isLoading && (
        <div className="flex flex-col items-center justify-center text-center gap-3 py-6">
          <div className="p-2 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-500">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-rose-400">Briefing Failed</h3>
            <p className="text-[11px] text-slate-500 mt-1 max-w-[280px] font-mono leading-relaxed">{error}</p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={onRetry}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-[10px] font-bold rounded text-slate-200 border border-slate-700 cursor-pointer transition-colors"
            >
              Retry Request
            </button>
            {onUseDemoFallback && (
              <button
                onClick={onUseDemoFallback}
                className="px-2.5 py-1 bg-sky-500 hover:bg-sky-400 text-[10px] font-bold rounded text-slate-950 border border-sky-600 cursor-pointer transition-colors"
              >
                Use Demo Briefing
              </button>
            )}
          </div>
        </div>
      )}

      {/* Render Analyst Brief Details */}
      {explanation && !isLoading && !error && (
        <div className="flex flex-col gap-4">
          
          {/* Incident Brief */}
          <div className="flex flex-col gap-1">
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
              <Shield className="w-3.5 h-3.5 text-rose-400" />
              Incident Brief (What Happened &amp; Why It Matters)
            </span>
            <div className="p-3.5 rounded-sm bg-slate-950/80 border border-slate-800/80">
              <p className="text-[11px] text-slate-300 leading-relaxed font-sans select-text whitespace-pre-wrap">
                {explanation.explanation}
              </p>
            </div>
          </div>

          {/* Evidence Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="flex flex-col gap-1">
              <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
                <Terminal className="w-3.5 h-3.5 text-sky-400" />
                Raw Evidence Context
              </span>
              <div className="p-2 rounded-sm bg-slate-950/40 border border-slate-900 font-mono text-[10px] text-slate-400 select-text break-all">
                IP Address: <span className="text-slate-300 font-semibold">{threat.source_ip || "Unknown"}</span>
                <br />
                Summary: <span className="text-slate-300">{threat.summary}</span>
              </div>
            </div>

            {/* MITRE ATT&CK */}
            <div className="flex flex-col gap-1">
              <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">
                MITRE ATT&CK Classification
              </span>
              <div className="p-2.5 rounded-sm bg-slate-950/40 border border-slate-900 flex items-center h-full min-h-[42px]">
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-sm ${getMitreTacticBadge(explanation.mitre_tactic)}`}>
                  {explanation.mitre_tactic}
                </span>
              </div>
            </div>
          </div>

          {/* Recommended Response */}
          <div className="flex flex-col gap-1.5">
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
              <ClipboardList className="w-3.5 h-3.5 text-indigo-400" />
              Recommended Response (SOC Runbook)
            </span>
            <ul className="flex flex-col gap-1.5">
              {explanation.recommended_actions.map((action, i) => (
                <li
                  key={i}
                  className="p-2.5 rounded-sm bg-slate-900/40 border border-slate-800/40 text-xs text-slate-300 flex items-start gap-2 select-text"
                >
                  <span className="w-4 h-4 rounded bg-sky-500/10 border border-sky-500/20 text-sky-400 flex items-center justify-center text-[10px] font-bold font-mono flex-shrink-0 mt-0.5">
                    {i + 1}
                  </span>
                  <span className="leading-relaxed text-[11px]">{action}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Advisory disclaimer */}
      <div className="border-t border-slate-900 pt-3 flex items-start gap-2 text-[9px] text-slate-500 leading-normal">
        <Info className="w-3.5 h-3.5 flex-shrink-0 text-slate-600" />
        <p>
          Advisory classification generated from redacted logs. This system is a triage tool and does not guarantee detection of all security incidents.
        </p>
      </div>
    </div>
  );
};
