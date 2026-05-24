"use client";

import React from "react";
import { ShieldAlert, RefreshCw, Wifi, WifiOff } from "lucide-react";

interface HeaderProps {
  apiConnected: boolean;
  onReset: () => void;
  isResetting: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  apiConnected,
  onReset,
  isResetting,
}) => {
  return (
    <header className="border-b border-slate-800/60 bg-slate-950/90 backdrop-blur-md sticky top-0 z-40 px-4 lg:px-8 py-3">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div className="relative p-2 bg-rose-500/10 rounded-xl border border-rose-500/20">
            <ShieldAlert className="w-5 h-5 text-rose-400 pulse-glow-red" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight text-slate-100">ThreatLens</h1>
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-slate-800 text-slate-500 border border-slate-700/40">v1.0</span>
            </div>
            <p className="text-[10px] text-slate-500 tracking-wide">Rules-first threat triage with AI explanations</p>
          </div>
        </div>

        {/* Right: status + action */}
        <div className="flex items-center gap-3">
          {/* API status — compact dot + label */}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
            apiConnected
              ? "bg-emerald-500/5 border-emerald-500/20 text-emerald-400"
              : "bg-rose-500/5 border-rose-500/20 text-rose-400"
          }`}>
            {apiConnected ? (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-50" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                </span>
                <Wifi className="w-3 h-3" />
                <span className="hidden sm:inline">Live</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3 h-3 animate-pulse" />
                <span>Offline</span>
              </>
            )}
          </div>

          {/* Reset */}
          <button
            onClick={onReset}
            disabled={isResetting}
            aria-label="Reset demo session"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg text-slate-300 bg-slate-800/70 hover:bg-slate-700 border border-slate-700/50 hover:border-slate-600 transition-all duration-150 disabled:opacity-40 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isResetting ? "animate-spin" : ""}`} />
            <span>Reset</span>
          </button>
        </div>
      </div>
    </header>
  );
};
