"use client";

import React from "react";
import { Server, Cpu, Brain, ShieldAlert, MessageSquareCode } from "lucide-react";

interface StatsCardsProps {
  linesIngested: number;
  maxLogs: number;
  ruleHits: number;
  aiHits: number;
  criticalThreats: number;
  explainsRemaining: number;
}

export const StatsCards: React.FC<StatsCardsProps> = ({
  linesIngested,
  maxLogs,
  ruleHits,
  aiHits,
  criticalThreats,
  explainsRemaining,
}) => {
  const cards = [
    {
      title: "Lines Ingested",
      value: `${linesIngested} / ${maxLogs}`,
      icon: Server,
      iconColor: "text-slate-400",
      bgClass: "bg-slate-900/40",
      topColor: "#64748b", // slate
      glowColor: "rgba(0,0,0,0)",
    },
    {
      title: "Rule Detections",
      value: ruleHits,
      icon: Cpu,
      iconColor: "text-emerald-400",
      bgClass: ruleHits > 0 ? "bg-emerald-950/10" : "bg-slate-900/40",
      topColor: "#10b981", // emerald
      glowColor: ruleHits > 0 ? "rgba(16,185,129,0.06)" : "rgba(0,0,0,0)",
    },
    {
      title: "AI Detections",
      value: aiHits,
      icon: Brain,
      iconColor: "text-sky-400",
      bgClass: aiHits > 0 ? "bg-sky-950/10" : "bg-slate-900/40",
      topColor: "#0ea5e9", // sky
      glowColor: aiHits > 0 ? "rgba(14,165,233,0.06)" : "rgba(0,0,0,0)",
    },
    {
      title: "Critical Threats",
      value: criticalThreats,
      icon: ShieldAlert,
      iconColor: "text-rose-400 animate-pulse",
      bgClass: criticalThreats > 0 ? "bg-rose-950/20" : "bg-slate-900/40",
      topColor: "#f43f5e", // rose
      glowColor: criticalThreats > 0 ? "rgba(244,63,94,0.12)" : "rgba(0,0,0,0)",
    },
    {
      title: "Explains Left",
      value: `${explainsRemaining} / 10`,
      icon: MessageSquareCode,
      iconColor: "text-indigo-400",
      bgClass: "bg-slate-900/40",
      topColor: "#6366f1", // indigo
      glowColor: "rgba(0,0,0,0)",
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
      {cards.map((card, i) => {
        const IconComponent = card.icon;
        return (
          <div
            key={i}
            className={`rounded-sm border border-slate-800 ${card.bgClass} flex items-center justify-between px-4 py-3 transition-colors duration-200`}
            style={{
              borderTopColor: card.topColor,
              borderTopWidth: "2px",
              boxShadow: `0 0 15px ${card.glowColor}`,
            }}
          >
            <div>
              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">
                {card.title}
              </p>
              <h3 className="text-xl font-bold mt-1 tracking-tight text-slate-100 font-mono">
                {card.value}
              </h3>
            </div>
            <div className={card.iconColor}>
              <IconComponent className="w-5 h-5" />
            </div>
          </div>
        );
      })}
    </div>
  );
};
