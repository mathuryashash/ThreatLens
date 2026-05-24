"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import { Header } from "@/components/Header";
import { StatsCards } from "@/components/StatsCards";
import { UploadPanel } from "@/components/UploadPanel";
import { ThreatFeed } from "@/components/ThreatFeed";
import { ExplainPanel } from "@/components/ExplainPanel";
import { getDemoExplanation } from "@/utils/demoExplanations";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

interface ThreatItem {
  id: string;
  threat_type: string;
  severity: string;
  severity_score: number;
  confidence: number;
  source_ip: string | null;
  summary: string;
  explanation: string | null;
  classification_source: string;
  attack_pattern: string | null;
  evidence?: string[];
  detected_at: string;
}

interface IngestionJob {
  processed: number;
  failed: number;
  total: number;
  percent: number;
  status: string;
}

interface ExplanationData {
  explanation: string;
  mitre_tactic: string;
  recommended_actions: string[];
  cached: boolean;
}

export default function Dashboard() {
  // Session States
  const [sessionId, setSessionId] = useState<string>("");
  const [sessionQuota, setSessionQuota] = useState<{ maxLogs: number; usedLogs: number; maxExplains: number; usedExplains: number }>({
    maxLogs: 500,
    usedLogs: 0,
    maxExplains: 10,
    usedExplains: 0,
  });
  
  // Connection states
  const [apiConnected, setApiConnected] = useState<boolean>(true);
  const [isResetting, setIsResetting] = useState<boolean>(false);
  
  // Threat Feed & Stats
  const [threats, setThreats] = useState<ThreatItem[]>([]);
  const [isThreatsLoading, setIsThreatsLoading] = useState<boolean>(false);
  
  // Ingest processing states
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [jobProgress, setJobProgress] = useState<IngestionJob | null>(null);
  
  // Explanation panel states
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const [explanation, setExplanation] = useState<ExplanationData | null>(null);
  const [explainLoading, setExplainLoading] = useState<boolean>(false);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [cachedExplains, setCachedExplains] = useState<Record<string, ExplanationData>>({});

  // References to handle polling loops without stale states
  const jobIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const sessionIdRef = useRef<string>("");
  const explainAbortRef = useRef<AbortController | null>(null);

  // Fetch session quota
  const fetchQuota = useCallback(async (sid: string) => {
    if (!sid) return;
    try {
      const res = await fetch(`${API_BASE}/api/session/${sid}/quota`);
      if (res.ok) {
        const data = await res.json();
        setSessionQuota({
          maxLogs: data.max_logs,
          usedLogs: data.used_logs,
          maxExplains: data.max_explain_calls,
          usedExplains: data.used_explain_calls,
        });
        setApiConnected(true);
      }
    } catch (err) {
      console.warn("Failed to fetch session quota:", err instanceof Error ? err.message : String(err));
      setApiConnected(false);
    }
  }, []);

  // 1. Load threats list
  const loadThreats = useCallback(async (sid: string) => {
    if (!sid) return;
    setIsThreatsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/threats?session_id=${sid}&limit=100`);
      if (!res.ok) {
        if (res.status === 401 || res.status === 404) {
          localStorage.removeItem("threatlens_session");
          setSessionId("");
          return;
        }
        throw new Error("Failed to load threats");
      }
      
      const data = await res.json();
      setThreats(data.threats);
      setApiConnected(true);
      
      // Fetch session quota to sync display
      await fetchQuota(sid);
    } catch (err) {
      console.warn("Failed to load threats:", err instanceof Error ? err.message : String(err));
      setApiConnected(false);
    } finally {
      setIsThreatsLoading(false);
    }
  }, [fetchQuota]);

  // 2. Fetch Session/Create Session
  const initSession = useCallback(async () => {
    setIsResetting(true);
    try {
      let activeSid = localStorage.getItem("threatlens_session") || "";
      
      let res;
      let shouldCreateNew = !activeSid;
      
      if (activeSid) {
        // Validate existing session
        res = await fetch(`${API_BASE}/api/threats?session_id=${activeSid}&limit=1`);
        if (!res.ok) {
          if (res.status === 401 || res.status === 404) {
            shouldCreateNew = true;
          } else {
            throw new Error("API Connection error");
          }
        }
      }
      
      if (shouldCreateNew) {
        // Create new session
        localStorage.removeItem("threatlens_session");
        res = await fetch(`${API_BASE}/api/session`, { method: "POST" });
        if (!res.ok) throw new Error("Session initialization failed");
        const data = await res.json();
        activeSid = data.session_id;
        localStorage.setItem("threatlens_session", activeSid);
      }
      
      setSessionId(activeSid);
      setApiConnected(true);
      
      // Load initial threats list (which will also call fetchQuota)
      await loadThreats(activeSid);
    } catch (err) {
      console.warn("API Connection error in initSession:", err instanceof Error ? err.message : String(err));
      setApiConnected(false);
    } finally {
      setIsResetting(false);
    }
  }, [loadThreats]);

  // 3. Reset Demo Handler
  const handleReset = async () => {
    localStorage.removeItem("threatlens_session");
    setThreats([]);
    setSelectedThreatId(null);
    setExplanation(null);
    setJobProgress(null);
    setIsProcessing(false);
    setCachedExplains({});

    if (jobIntervalRef.current) {
      clearInterval(jobIntervalRef.current);
      jobIntervalRef.current = null;
    }

    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }

    setSessionId("");
  };

  // 4. Ingest Logs Trigger
  const handleAnalyzeLogs = async (logs: string[], sourceType: string) => {
    if (!sessionId) return;
    setIsProcessing(true);
    setJobProgress({
      processed: 0,
      failed: 0,
      total: logs.length,
      percent: 0,
      status: "queued",
    });

    try {
      const res = await fetch(`${API_BASE}/api/ingest`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          source_type: sourceType,
          logs: logs,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        const detail = errData.detail?.detail || errData.detail || "Ingest request failed";
        throw new Error(detail);
      }

      const data = await res.json();
      const jobId = data.job_id;

      // Update sessionQuota with remaining logs
      setSessionQuota((prev) => ({
        ...prev,
        usedLogs: prev.maxLogs - data.remaining_quota,
      }));

      // Start polling the job status
      pollJobStatus(jobId);
    } catch (err: unknown) {
      let errMsg = "Log ingestion failed. Please try again.";
      if (err instanceof Error) {
        if (err.message.includes("Failed to fetch")) {
          errMsg = `API server offline. Log analysis is unavailable. Verify that the API backend is running at ${API_BASE}.`;
        } else {
          errMsg = err.message;
        }
      }
      console.warn("Log ingestion error:", errMsg);
      alert(errMsg);
      setApiConnected(false);
      setIsProcessing(false);
      setJobProgress(null);
    }
  };

  // 5. Poll Job Status
  const pollJobStatus = (jobId: string) => {
    if (jobIntervalRef.current) clearInterval(jobIntervalRef.current);

    jobIntervalRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/jobs/${jobId}?session_id=${sessionIdRef.current}`);
        if (!res.ok) throw new Error("Job status check failed");

        const data = await res.json();
        setJobProgress({
          processed: data.processed_logs,
          failed: data.failed_logs,
          total: data.total_logs,
          percent: data.percent_complete,
          status: data.status,
        });

        // Trigger threat list update dynamically as events get parsed
        loadThreats(sessionIdRef.current);

        if (data.status === "completed" || data.status === "failed") {
          if (jobIntervalRef.current) clearInterval(jobIntervalRef.current);
          setIsProcessing(false);
          
          // Clear progress alert banner after 5 seconds
          setTimeout(() => {
            setJobProgress(null);
          }, 6000);
        }
      } catch (err) {
        console.warn("Job status poll error:", err instanceof Error ? err.message : String(err));
        setApiConnected(false);
        if (jobIntervalRef.current) {
          clearInterval(jobIntervalRef.current);
          jobIntervalRef.current = null;
        }
        setIsProcessing(false);
      }
    }, 1500);
  };

  // 6. Threat Selection & Explain Trigger
  const handleSelectThreat = (threatId: string) => {
    setSelectedThreatId(threatId);
    const targetThreat = threats.find((t) => t.id === threatId) ?? null;

    if (targetThreat) {
      if (cachedExplains[threatId]) {
        setExplanation(cachedExplains[threatId]);
      } else if (targetThreat.explanation) {
        // If it was already cached on the server, fetch full details from explain endpoint
        fetchExplanation(threatId);
      } else {
        // Trigger a new explanation request
        fetchExplanation(threatId);
      }
    }
  };

  const fetchExplanation = async (threatId: string) => {
    if (explainAbortRef.current) explainAbortRef.current.abort();
    const controller = new AbortController();
    explainAbortRef.current = controller;

    setExplainLoading(true);
    setExplainError(null);
    setExplanation(null);

    try {
      const res = await fetch(`${API_BASE}/api/explain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          threat_id: threatId,
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        const detail = errData.detail?.detail || errData.detail || "";
        const isLLMError = res.status === 500 && detail.toLowerCase().includes("400");
        throw new Error(
          isLLMError
            ? "AI model temporarily unavailable. Please retry in a moment."
            : detail || "AI explanation query failed"
        );
      }

      const data = await res.json();
      setExplanation(data);
      
      // Save to client-side cache
      setCachedExplains((prev) => ({
        ...prev,
        [threatId]: data,
      }));
      
      // Update local quota directly to sync with server
      await fetchQuota(sessionId);

      // Reload threats to cache the explanation in client state
      loadThreats(sessionId);
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") return;
      let errMsg = "Failed calling AI model. Please retry.";
      if (err instanceof Error) {
        if (err.message.includes("Failed to fetch")) {
          errMsg = `API server offline. Explanation is unavailable. Verify that the API backend is running at ${API_BASE}.`;
        } else {
          errMsg = err.message;
        }
      }
      console.warn("Failed to fetch explanation:", errMsg);
      setExplainError(errMsg);
      setApiConnected(false);
    } finally {
      setExplainLoading(false);
    }
  };

  const handleUseDemoFallback = () => {
    if (!selectedThreat) return;
    const demoExplain = getDemoExplanation(selectedThreat.threat_type);
    setExplanation(demoExplain);
    
    // Save to client-side cache
    setCachedExplains((prev) => ({
      ...prev,
      [selectedThreat.id]: demoExplain,
    }));
    
    // Clear error
    setExplainError(null);
  };

  // Sync sessionIdRef whenever sessionId changes (Fix 2)
  useEffect(() => {
    sessionIdRef.current = sessionId;
  }, [sessionId]);

  // Health checks, polling, and auto-retry when backend is offline
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    if (!sessionId) {
      // Defer to next tick to avoid synchronous setState inside render/effect body
      timer = setTimeout(() => {
        initSession();
      }, 0);
    }

    pollingIntervalRef.current = setInterval(() => {
      const activeSid = localStorage.getItem("threatlens_session") || "";
      if (activeSid) {
        // Normal polling: refresh threat feed
        loadThreats(activeSid);
      } else if (!apiConnected) {
        // Backend was unreachable — keep retrying silently every 3s
        initSession();
      }
    }, 3000);

    return () => {
      if (timer) clearTimeout(timer);
      if (pollingIntervalRef.current) clearInterval(pollingIntervalRef.current);
    };
  }, [sessionId, apiConnected, initSession, loadThreats]);

  const selectedThreat = threats.find((t) => t.id === selectedThreatId) ?? null;

  return (
    <div className="flex flex-col h-screen overflow-hidden">
      {/* Header Bar */}
      <Header
        apiConnected={apiConnected}
        onReset={handleReset}
        isResetting={isResetting}
      />

      {/* Main Container — fills remaining viewport, no page scroll */}
      <main className="flex-1 min-h-0 max-w-7xl w-full mx-auto px-4 lg:px-8 pt-4 lg:pt-6 pb-3 flex flex-col gap-4 overflow-hidden">
        {/* Stats Cards — fixed height, never scrolls */}
        <section id="stats-section" className="flex-shrink-0">
          <StatsCards
            linesIngested={sessionQuota.usedLogs}
            maxLogs={sessionQuota.maxLogs}
            ruleHits={threats.filter(t => t.classification_source === "rule").length}
            aiHits={threats.filter(t => t.classification_source === "ai").length}
            criticalThreats={threats.filter(t => t.severity === "CRITICAL").length}
            explainsRemaining={Math.max(0, sessionQuota.maxExplains - sessionQuota.usedExplains)}
          />
        </section>

        {/* Workspace — takes all remaining height */}
        <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Upload panel — scrolls independently */}
          <div className="lg:col-span-5 min-h-0 overflow-y-auto pr-1">
            <UploadPanel
              onAnalyze={handleAnalyzeLogs}
              isProcessing={isProcessing}
              jobProgress={jobProgress}
              logsRemaining={Math.max(0, sessionQuota.maxLogs - sessionQuota.usedLogs)}
              parseSummary={jobProgress?.status === "completed" ? {
                total: jobProgress.total,
                parsed: jobProgress.processed,
                failed: jobProgress.failed,
                ruleMatches: threats.filter(t => t.classification_source === "rule").length,
                aiMatches: threats.filter(t => t.classification_source === "ai").length,
              } : null}
              apiConnected={apiConnected}
            />
          </div>

          {/* Right: Feed + Explain — internal layout, no page overflow */}
          <div className="lg:col-span-7 flex flex-col min-h-0 gap-3">
            {/* Feed header */}
            <div className="flex items-center justify-between flex-shrink-0">
              <h2 className="text-sm font-bold tracking-wider text-slate-400 uppercase">
                Threat Triage Queue
              </h2>
              {threats.length > 0 && (
                <span className="text-[10px] text-slate-500 font-mono">
                  {threats.length} threats detected
                </span>
              )}
            </div>

            {/* Threat list — this is the scroll region */}
            <div className="flex-1 min-h-0 overflow-y-auto">
              <ThreatFeed
                threats={threats}
                isLoading={isThreatsLoading}
                onSelectThreat={handleSelectThreat}
                selectedThreatId={selectedThreatId}
                explainQuota={Math.max(0, sessionQuota.maxExplains - sessionQuota.usedExplains)}
              />
            </div>

            {/* Analyst Brief Drawer — fixed-height drawer at the bottom */}
            <div className="flex-shrink-0 border-t border-slate-800/60 pt-3">
              <div className="flex items-center gap-2 mb-3">
                <h2 className="text-sm font-bold tracking-wider text-slate-400 uppercase">
                  Analyst Brief
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700/50">
                  {sessionQuota.maxExplains - sessionQuota.usedExplains} remaining
                </span>
              </div>
              <div className="max-h-[280px] overflow-y-auto rounded">
                <ExplainPanel
                  threat={selectedThreat}
                  explanation={explanation}
                  isLoading={explainLoading}
                  error={explainError}
                  onClose={() => {
                    setSelectedThreatId(null);
                    setExplanation(null);
                  }}
                  onRetry={() => selectedThreatId && fetchExplanation(selectedThreatId)}
                  onUseDemoFallback={handleUseDemoFallback}
                />
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
