"use client";

import React, { useState } from "react";
import { Terminal, Shield, ArrowRight, Activity, Cpu, ChevronDown, ChevronUp, Eye } from "lucide-react";

export interface ThreatItem {
  id: string;
  threat_type: string;
  severity: string;
  severity_score: number;
  confidence: number;
  source_ip: string | null;
  summary: string;
  classification_source: string;
  attack_pattern: string | null;
  evidence?: string[];
  detected_at: string;
}

interface ThreatFeedProps {
  threats: ThreatItem[];
  isLoading: boolean;
  onSelectThreat: (threatId: string) => void;
  selectedThreatId: string | null;
  explainQuota: number;
}

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-rose-950/40 text-rose-400 border border-rose-500/20",
  HIGH:     "bg-orange-950/40 text-orange-400 border border-orange-500/20",
  MEDIUM:   "bg-amber-950/40 text-amber-400 border border-amber-500/20",
  LOW:      "bg-sky-950/40 text-sky-400 border border-sky-500/20",
  INFO:     "bg-slate-900/50 text-slate-400 border border-slate-500/20",
};

const SEVERITY_LEFT_BORDER: Record<string, string> = {
  CRITICAL: "border-l-rose-500",
  HIGH:     "border-l-orange-500",
  MEDIUM:   "border-l-amber-500",
  LOW:      "border-l-sky-500",
  INFO:     "border-l-slate-700",
};

function formatThreatType(raw: string) {
  return raw.replaceAll("_", " ");
}

function formatRelativeTime(isoString: string) {
  try {
    const diff = Date.now() - new Date(isoString).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const dt = new Date(isoString);
    const pad = (n: number) => n.toString().padStart(2, "0");
    return `${pad(dt.getMonth() + 1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}`;
  } catch {
    return isoString;
  }
}

// Safely highlight threat keywords in log lines without using dangerouslySetInnerHTML
function highlightEvidenceSafe(text: string): React.ReactNode {
  const patterns = [
    /169\.254\.169\.254/i,
    /metadata\.google\.internal/i,
    /union\s+select/i,
    /or\s+1\s*=\s*1/i,
    /sleep\s*\(/i,
    /benchmark\s*\(/i,
    /information_schema/i,
    /drop\s+table/i,
    /etc\/passwd/i,
    /proc\/self\/environ/i,
    /win\.ini/i,
    /\.\.\//,
    /\.\.\\/,
    /<script[\s>]/i,
    /javascript:/i,
    /onerror\s*=/i,
    /onload\s*=/i,
    /<iframe[\s>]/i,
    /sudo:.*authentication failure/i,
    /su:.*failed su/i,
    /authentication failure for root/i,
    /Failed password/i,
    /invalid user/i
  ];

  let bestMatch: { index: number; length: number; text: string } | null = null;
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match && match.index !== undefined) {
      if (bestMatch === null || match.index < bestMatch.index) {
        bestMatch = { index: match.index, length: match[0].length, text: match[0] };
      }
    }
  }

  if (!bestMatch) {
    return <span>{text}</span>;
  }

  const before = text.substring(0, bestMatch.index);
  const matchedText = text.substring(bestMatch.index, bestMatch.index + bestMatch.length);
  const after = text.substring(bestMatch.index + bestMatch.length);

  return (
    <span>
      {before}
      <span className="bg-rose-500/25 text-rose-300 border border-rose-500/40 px-1 rounded-sm font-semibold font-mono">
        {matchedText}
      </span>
      {highlightEvidenceSafe(after)}
    </span>
  );
}

export const ThreatFeed: React.FC<ThreatFeedProps> = ({
  threats,
  isLoading,
  onSelectThreat,
  selectedThreatId,
  explainQuota,
}) => {
  const [expandedThreats, setExpandedThreats] = useState<Record<string, boolean>>({});

  const toggleExpand = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    setExpandedThreats((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  if (isLoading) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-3 text-center py-12">
        <div className="w-7 h-7 rounded-full border-2 border-slate-800 border-t-sky-500 animate-spin" />
        <p className="text-xs text-slate-500">Loading threat feed…</p>
      </div>
    );
  }

  if (threats.length === 0) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-4 text-center py-16">
        <div className="p-3 bg-slate-900 rounded-sm border border-slate-800 text-slate-600">
          <Shield className="w-8 h-8" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-400">No threats detected</h3>
          <p className="text-xs text-slate-600 mt-1 max-w-xs mx-auto">
            Upload logs or load a scenario to populate the feed.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-sm border border-slate-800/80 bg-slate-950/20 overflow-hidden flex flex-col">
      {/* Table Header */}
      <div className="hidden md:grid grid-cols-12 gap-2 px-4 py-2 bg-slate-900/60 border-b border-slate-800 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
        <div className="col-span-2">Severity</div>
        <div className="col-span-2">Threat Type</div>
        <div className="col-span-2">Source IP</div>
        <div className="col-span-3">Evidence</div>
        <div className="col-span-2 text-center">Detector</div>
        <div className="col-span-1 text-right">Actions</div>
      </div>

      {/* Table Body / Rows */}
      <div className="flex flex-col divide-y divide-slate-800/60">
        {threats.map((threat) => {
          const isSelected = selectedThreatId === threat.id;
          const isExpanded = !!expandedThreats[threat.id];
          const badge = SEVERITY_BADGE[threat.severity] ?? SEVERITY_BADGE.INFO;
          const leftBorder = SEVERITY_LEFT_BORDER[threat.severity] ?? "border-l-slate-700";
          const confidencePct = Math.round(threat.confidence * 100);

          return (
            <div
              key={threat.id}
              onClick={() => onSelectThreat(threat.id)}
              className={`flex flex-col transition-colors duration-150 border-l-2 cursor-pointer ${leftBorder} ${
                isSelected ? "bg-slate-900/30" : "hover:bg-slate-900/10"
              }`}
            >
              {/* Row Grid */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-2 items-center px-4 py-2.5 min-w-0">
                {/* Severity Badge */}
                <div className="col-span-1 md:col-span-2 flex items-center gap-2">
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-sm font-mono flex-shrink-0 tracking-wider ${badge}`}>
                    {threat.severity}
                  </span>
                  <span className="md:hidden text-[10px] text-slate-500">
                    {formatRelativeTime(threat.detected_at)}
                  </span>
                </div>

                {/* Threat Type */}
                <div className="col-span-1 md:col-span-2 font-mono text-xs font-semibold text-slate-200 uppercase tracking-wide truncate">
                  {formatThreatType(threat.threat_type)}
                </div>

                {/* Source IP */}
                <div className="col-span-1 md:col-span-2 text-xs text-slate-300 font-mono flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
                  {threat.source_ip || "Unknown"}
                </div>

                {/* Evidence Summary */}
                <div className="col-span-1 md:col-span-3 text-xs text-slate-400 truncate pr-2 flex items-center gap-1.5">
                  <button
                    onClick={(e) => toggleExpand(e, threat.id)}
                    className="p-1 rounded hover:bg-slate-800 text-slate-500 hover:text-slate-300 flex-shrink-0 transition-colors"
                    title="Toggle raw logs view"
                  >
                    {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                  <span className="truncate leading-tight font-sans">{threat.summary}</span>
                </div>

                {/* Detector & Confidence */}
                <div className="col-span-1 md:col-span-2 flex items-center justify-between md:justify-center gap-3">
                  <span className="md:hidden text-[10px] text-slate-500 font-bold uppercase">Detector:</span>
                  <div className="flex items-center gap-2">
                    {threat.classification_source === "rule" ? (
                      <span className="flex items-center gap-1 text-[10px] font-bold text-sky-400 bg-sky-500/5 px-2 py-0.5 rounded-sm border border-sky-500/10">
                        <Activity className="w-2.5 h-2.5" />
                        RULE
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-[10px] font-bold text-indigo-400 bg-indigo-500/5 px-2 py-0.5 rounded-sm border border-indigo-500/10">
                        <Cpu className="w-2.5 h-2.5" />
                        AI
                      </span>
                    )}
                    <span className="text-[10px] font-mono text-slate-500 font-bold">
                      {confidencePct}%
                    </span>
                  </div>
                </div>

                {/* Explain Button / Actions */}
                <div className="col-span-1 md:col-span-1 flex items-center justify-between md:justify-end gap-2 mt-2 md:mt-0">
                  <span className="md:hidden text-[10px] text-slate-500 font-bold uppercase">Actions:</span>
                  <button
                    aria-label={`Explain ${threat.threat_type}`}
                    disabled={explainQuota <= 0}
                    onClick={(e) => { e.stopPropagation(); onSelectThreat(threat.id); }}
                    className={`flex items-center gap-1.5 px-2.5 py-1 rounded-sm text-[10px] font-bold transition-all duration-150 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap border ${
                      isSelected
                        ? "bg-sky-500 border-sky-600 text-slate-950 font-black shadow-[0_0_10px_rgba(14,165,233,0.15)]"
                        : "bg-slate-900 border-slate-800 hover:bg-slate-800 text-slate-300"
                    }`}
                  >
                    Brief
                    <ArrowRight className="w-2.5 h-2.5" />
                  </button>
                </div>
              </div>

              {/* Collapsible Evidence Sub-Row */}
              {isExpanded && threat.evidence && threat.evidence.length > 0 && (
                <div
                  className="px-4 py-3 bg-slate-950/40 border-t border-slate-900 flex flex-col gap-2 cursor-default"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="flex items-center gap-1.5 text-[9px] font-bold text-slate-500 uppercase tracking-widest">
                    <Eye className="w-3.5 h-3.5 text-rose-500/70" />
                    Raw Event Evidence (Redacted)
                  </div>
                  <div className="flex flex-col gap-1 max-h-[150px] overflow-y-auto rounded-sm border border-slate-900 bg-slate-950 p-2 text-[11px] font-mono text-slate-400 leading-normal scrollbar-thin">
                    {threat.evidence.map((line, idx) => (
                      <div key={idx} className="flex gap-2 hover:bg-slate-900/50 py-0.5 px-1 rounded-sm">
                        <span className="text-slate-600 select-none">{idx + 1}.</span>
                        <pre className="whitespace-pre-wrap break-all select-text font-mono flex-1 text-slate-300">
                          {highlightEvidenceSafe(line)}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
