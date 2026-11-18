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
      // Neutral — count has no alert semantics
      topColor: "rgba(40,50,70,0.5)",
    },
    {
      title: "Rule Detections",
      value: ruleHits,
      icon: Cpu,
      iconColor: ruleHits > 0 ? "text-emerald-400" : "text-slate-500",
      bgClass: ruleHits > 0 ? "bg-emerald-950/10" : "bg-slate-900/40",
      // Green only when rules actually fired — means something
      topColor: ruleHits > 0 ? "#10b981" : "rgba(40,50,70,0.5)",
    },
    {
      title: "AI Detections",
      value: aiHits,
      icon: Brain,
      iconColor: aiHits > 0 ? "text-sky-400" : "text-slate-500",
      bgClass: aiHits > 0 ? "bg-sky-950/10" : "bg-slate-900/40",
      // Sky only when AI actually flagged something — means something
      topColor: aiHits > 0 ? "#0ea5e9" : "rgba(40,50,70,0.5)",
    },
    {
      title: "Critical Threats",
      value: criticalThreats,
      icon: ShieldAlert,
      iconColor: criticalThreats > 0 ? "text-rose-400" : "text-slate-500",
      bgClass: criticalThreats > 0 ? "bg-rose-950/20" : "bg-slate-900/40",
      // Red only when there are critical threats — highest urgency signal
      topColor: criticalThreats > 0 ? "#f43f5e" : "rgba(40,50,70,0.5)",
    },
    {
      title: "Explains Left",
      value: `${explainsRemaining} / 10`,
      icon: MessageSquareCode,
      iconColor: "text-slate-400",
      bgClass: "bg-slate-900/40",
      // Neutral — quota display, no alert semantics
      topColor: "rgba(40,50,70,0.5)",
    },
  ];

  return (
    <div className="grid grid-cols-3 sm:grid-cols-3 md:grid-cols-5 gap-3">
      {cards.map((card, i) => {
        const IconComponent = card.icon;
        return (
          <div
            key={i}
            className={`rounded border border-slate-800 ${card.bgClass} flex items-center justify-between px-4 py-3 transition-colors duration-200`}
            style={{
              borderTopColor: card.topColor,
              borderTopWidth: "2px",
            }}
          >
            <div>
              <p className="text-[11px] text-slate-500">
                {card.title}
              </p>
              <h3 className="text-xl font-semibold mt-1 tracking-tight text-slate-100 font-mono tabular-nums">
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
