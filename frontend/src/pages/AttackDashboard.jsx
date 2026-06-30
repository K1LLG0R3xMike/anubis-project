import React, { useEffect, useState, useCallback } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

const R = {
  primary:   '#FF3131',
  primaryDim: 'rgba(255,49,49,0.15)',
  primaryBorder: 'rgba(255,49,49,0.3)',
  card:      'rgba(45,15,15,0.5)',
  cardBorder: 'rgba(255,255,255,0.07)',
  bg:        '#0f0505',
};

function PulsingDot({ size = 'w-2 h-2' }) {
  return (
    <span
      className={`${size} rounded-full shrink-0`}
      style={{
        backgroundColor: R.primary,
        animation: 'pulse-red 2s infinite',
        boxShadow: `0 0 6px ${R.primary}`,
      }}
    />
  );
}

function StatCard({ label, value, sub, icon, pulse }) {
  return (
    <div
      className="rounded-xl p-6 relative overflow-hidden group"
      style={{
        background: R.primaryDim,
        border: `1px solid ${R.primaryBorder}`,
        animation: pulse ? 'neon-pulse 4s ease-in-out infinite' : undefined,
      }}
    >
      <p className="text-[11px] font-bold uppercase tracking-wider mb-2"
         style={{ color: 'rgba(255,255,255,0.4)' }}>
        {label}
      </p>
      <p className="text-5xl font-black text-white mb-1">{value}</p>
      <p className="text-xs" style={{ color: 'rgba(255,255,255,0.4)' }}>{sub}</p>
      <span
        className="material-symbols-outlined absolute -bottom-4 -right-4 text-[120px] opacity-[0.03]
                   group-hover:opacity-[0.06] transition-opacity duration-700 text-white"
      >
        {icon}
      </span>
    </div>
  );
}

function SeverityBar({ label, count, max, color }) {
  const pct = max > 0 ? Math.max(4, (count / max) * 100) : 4;
  return (
    <div className="flex-1 flex flex-col items-center group">
      <span className="text-white font-bold text-sm mb-2 opacity-0 group-hover:opacity-100 transition-opacity">
        {count}
      </span>
      <div
        className="w-full rounded-t-sm transition-all duration-500 hover:brightness-125"
        style={{
          height: `${Math.max(8, (pct / 100) * 200)}px`,
          background: color,
          border: `1px solid ${color}`,
          opacity: 0.8,
        }}
      />
      <p className="mt-4 text-[10px] font-bold uppercase tracking-wider"
         style={{ color: 'rgba(255,255,255,0.3)' }}>
        {label}
      </p>
      <p className="text-white font-black mt-1 text-sm">{count}</p>
    </div>
  );
}

export default function AttackDashboard() {
  const [targets, setTargets]   = useState([]);
  const [reports, setReports]   = useState([]);
  const [loading, setLoading]   = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [tRes, rRes] = await Promise.all([
        axios.get(`${BASE}/targets/`),
        axios.get(`${BASE}/reports/`),
      ]);
      setTargets(tRes.data || []);
      setReports(rRes.data || []);
    } catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Aggregate severity from most recent reports
  const sevAgg = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let totalFindings = 0;
  reports.forEach(r => {
    if (r.severity_counts) {
      Object.entries(r.severity_counts).forEach(([k, v]) => {
        if (k in sevAgg) sevAgg[k] += (v || 0);
      });
    }
    totalFindings += r.total_findings || 0;
  });
  // deduplicate: use latest report if multiple exist per scope
  const latestReport = reports[0];
  const globalSev = latestReport?.severity_counts || sevAgg;
  const globalFindings = latestReport?.total_findings || totalFindings;

  const maxSev = Math.max(...Object.values(globalSev), 1);

  const sevBars = [
    { label: 'Critical', key: 'critical', color: R.primary },
    { label: 'High',     key: 'high',     color: 'rgba(230,81,0,0.9)' },
    { label: 'Medium',   key: 'medium',   color: 'rgba(255,152,0,0.7)' },
    { label: 'Low',      key: 'low',      color: 'rgba(255,255,255,0.25)' },
    { label: 'Info',     key: 'info',     color: 'rgba(255,255,255,0.12)' },
  ];

  return (
    <div
      className="min-h-screen pb-20"
      style={{ backgroundColor: '#0a0505' }}
    >
      {/* Header row */}
      <div className="flex justify-between items-end px-8 pt-10 pb-8">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.3em] mb-1"
             style={{ color: 'rgba(255,255,255,0.3)' }}>
            Security_Overview
          </p>
          <h1 className="text-3xl font-black text-white">Security Overview</h1>
          <p className="text-xs mt-1 flex items-center gap-2" style={{ color: 'rgba(255,255,255,0.4)' }}>
            Status:{' '}
            <span className="font-bold" style={{ color: R.primary }}>Online</span>
          </p>
        </div>
        <div className="flex gap-3">
          <button
            className="px-5 py-2 rounded-xl text-xs font-bold text-white transition-all hover:brightness-125"
            style={{ border: '1px solid rgba(255,255,255,0.12)' }}
          >
            Export Reports
          </button>
          <button
            className="px-5 py-2 rounded-xl text-xs font-black italic tracking-tight text-black hover:scale-105 transition-all flex items-center gap-1.5"
            style={{ backgroundColor: R.primary, boxShadow: `0 0 16px ${R.primary}40` }}
          >
            <span className="material-symbols-outlined text-[16px]" style={{ fontVariationSettings: "'FILL' 1" }}>bolt</span>
            QUICK SCAN
          </button>
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-5 px-8 mb-8">
        <StatCard
          label="Targets Registrados"
          value={loading ? '—' : targets.length}
          sub="Endpoints monitorizados"
          icon="track_changes"
          pulse
        />
        <StatCard
          label="Vulnerabilidades"
          value={loading ? '—' : globalFindings}
          sub="En todos los sitios"
          icon="security"
        />
        <StatCard
          label="Estado del Sistema"
          value={loading ? '—' : 'OK'}
          sub="Backend Online"
          icon="bar_chart"
          pulse
        />
      </div>

      {/* Charts + Targets list */}
      <div className="grid grid-cols-12 gap-5 px-8 mb-8">
        {/* Severity chart */}
        <div
          className="col-span-8 rounded-xl p-8"
          style={{
            background: 'rgba(30,8,8,0.5)',
            border: `1px solid ${R.primaryBorder}`,
            animation: 'neon-pulse 4s ease-in-out infinite',
          }}
        >
          <div className="flex justify-between items-center mb-8">
            <div>
              <h3 className="text-lg font-bold text-white mb-1">Severity Distribution</h3>
              <p className="text-xs" style={{ color: 'rgba(255,255,255,0.35)' }}>
                {reports.length > 0 ? `Basado en ${reports.length} reporte(s)` : 'Sin reportes generados'}
              </p>
            </div>
            <div className="flex items-center gap-5 text-[10px] font-bold uppercase tracking-widest"
                 style={{ color: 'rgba(255,255,255,0.3)' }}>
              <span className="flex items-center gap-1.5">
                <PulsingDot size="w-2 h-2" /> Critical
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-white/20" /> High
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-white/10" /> Medium
              </span>
            </div>
          </div>

          {/* Bar chart */}
          <div className="h-56 flex items-end justify-between gap-4 px-6 relative">
            {/* Grid lines */}
            <div className="absolute inset-0 flex flex-col justify-between pointer-events-none opacity-5">
              {[0,1,2,3].map(i => (
                <div key={i} className="border-t border-white w-full" />
              ))}
            </div>
            {sevBars.map(bar => (
              <SeverityBar
                key={bar.key}
                label={bar.label}
                count={globalSev[bar.key] || 0}
                max={maxSev}
                color={bar.color}
              />
            ))}
          </div>
        </div>

        {/* Targets list */}
        <div
          className="col-span-4 rounded-xl flex flex-col"
          style={{
            background: 'rgba(30,8,8,0.5)',
            border: `1px solid ${R.primaryBorder}`,
            animation: 'neon-pulse 4s ease-in-out infinite',
          }}
        >
          <div className="p-5 border-b flex justify-between items-center"
               style={{ borderColor: 'rgba(255,49,49,0.15)' }}>
            <h3 className="text-base font-bold text-white">Targets</h3>
            <div className="flex items-center gap-2">
              <PulsingDot size="w-1.5 h-1.5" />
              <span className="text-[10px] font-bold uppercase tracking-widest"
                    style={{ color: 'rgba(255,255,255,0.3)' }}>Live</span>
            </div>
          </div>

          <div className="flex-grow overflow-y-auto px-3 py-2 space-y-0.5"
               style={{ maxHeight: 280, scrollbarWidth: 'thin' }}>
            {loading ? (
              <div className="flex items-center justify-center py-8">
                <span className="material-symbols-outlined text-sm animate-spin"
                      style={{ color: R.primary }}>sync</span>
              </div>
            ) : targets.length === 0 ? (
              <p className="text-center text-xs py-8" style={{ color: 'rgba(255,255,255,0.3)' }}>
                Sin targets registrados
              </p>
            ) : targets.map(t => (
              <div
                key={t.id}
                className="flex items-center justify-between p-3 rounded-xl cursor-pointer transition-all hover:bg-white/5"
              >
                <div className="min-w-0">
                  <p className="font-bold text-white text-sm truncate">{t.name}</p>
                  <p className="text-[10px] truncate" style={{ color: 'rgba(255,255,255,0.35)' }}>
                    {(t.url || '').substring(0, 32)}…
                  </p>
                </div>
                <span
                  className="shrink-0 ml-2 px-2 py-0.5 rounded text-[9px] font-bold"
                  style={{
                    background: 'rgba(255,255,255,0.06)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    color: 'rgba(255,255,255,0.4)',
                  }}
                >
                  {t.last_scan ? 'Scaneado' : 'Pendiente'}
                </span>
              </div>
            ))}
          </div>

          <div className="p-5">
            <button
              className="w-full py-2.5 rounded-xl text-xs font-bold transition-all hover:border-white hover:text-white"
              style={{
                border: '1px dashed rgba(255,49,49,0.3)',
                color: 'rgba(255,255,255,0.35)',
              }}
            >
              + Nuevo objetivo
            </button>
          </div>
        </div>
      </div>

      {/* Node map */}
      <div className="grid grid-cols-12 gap-5 px-8">
        {/* Last target card */}
        {targets.length > 0 && (
          <div className="col-span-3">
            <p className="text-[10px] font-bold uppercase tracking-[0.2em] mb-4"
               style={{ color: 'rgba(255,255,255,0.3)' }}>
              Último Target
            </p>
            <div
              className="rounded-xl p-6 group cursor-pointer transition-all hover:bg-white/5"
              style={{
                background: 'rgba(40,10,10,0.6)',
                borderWidth: '1px 1px 1px 4px',
                borderStyle: 'solid',
                borderColor: 'rgba(255,255,255,0.08) rgba(255,255,255,0.08) rgba(255,255,255,0.08) white',
              }}
            >
              <div className="mb-4">
                <p className="font-bold text-white text-base truncate">
                  {targets[targets.length - 1]?.name}
                </p>
                <p className="text-[11px] break-all" style={{ color: 'rgba(255,255,255,0.4)' }}>
                  {targets[targets.length - 1]?.url}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-sm transition-colors group-hover:text-white"
                      style={{ color: 'rgba(255,255,255,0.3)' }}>chevron_right</span>
                <span className="text-[10px] font-bold uppercase transition-colors group-hover:text-white"
                      style={{ color: 'rgba(255,255,255,0.3)' }}>Ver Detalles</span>
              </div>
            </div>
          </div>
        )}

        {/* Node vulnerability map */}
        <div
          className={`${targets.length > 0 ? 'col-span-9' : 'col-span-12'} rounded-xl overflow-hidden`}
          style={{
            background: 'rgba(30,8,8,0.5)',
            border: `1px solid ${R.primaryBorder}`,
            animation: 'neon-pulse 4s ease-in-out infinite',
          }}
        >
          <div
            className="px-6 py-4 border-b flex justify-between items-center"
            style={{ background: 'rgba(60,5,5,0.3)', borderColor: 'rgba(255,49,49,0.15)' }}
          >
            <h3 className="text-base font-bold text-white">Node Vulnerability Map</h3>
            <div className="flex gap-2">
              <span className="w-3 h-3 rounded-full bg-white/10 border border-white/20" />
              <span className="w-3 h-3 rounded-full bg-white/20 border border-white/40" />
              <PulsingDot size="w-3 h-3" />
            </div>
          </div>

          <div className="h-72 relative overflow-hidden" style={{ background: '#0f0303' }}>
            {/* Animated nodes */}
            {targets.slice(0, 8).map((t, i) => {
              const positions = [
                { top: '25%', left: '20%' }, { top: '50%', left: '60%' },
                { top: '70%', left: '35%' }, { top: '20%', left: '70%' },
                { top: '60%', left: '80%' }, { top: '40%', left: '45%' },
                { top: '80%', left: '65%' }, { top: '15%', left: '50%' },
              ];
              const pos = positions[i] || { top: `${20 + i * 10}%`, left: `${20 + i * 10}%` };
              return (
                <div
                  key={t.id}
                  className="absolute group cursor-pointer"
                  style={{ top: pos.top, left: pos.left }}
                >
                  <div
                    className="w-2.5 h-2.5 rounded-full transition-all group-hover:scale-150"
                    style={{
                      backgroundColor: i === 0 ? R.primary : 'rgba(255,255,255,0.3)',
                      boxShadow: i === 0 ? `0 0 8px ${R.primary}` : undefined,
                      animation: i === 0 ? 'pulse-red 2s infinite' : undefined,
                    }}
                  />
                  <div
                    className="absolute top-4 left-0 opacity-0 group-hover:opacity-100 transition-opacity
                               text-[9px] font-bold whitespace-nowrap px-1.5 py-0.5 rounded"
                    style={{ background: 'rgba(0,0,0,0.7)', color: 'white', zIndex: 10 }}
                  >
                    {t.name}
                  </div>
                </div>
              );
            })}

            {/* SVG connecting lines */}
            <svg className="absolute inset-0 w-full h-full opacity-10 pointer-events-none">
              <line stroke="white" strokeWidth="1" x1="20%" x2="60%" y1="25%" y2="50%" />
              <line stroke="white" strokeDasharray="4" strokeWidth="1" x1="60%" x2="35%" y1="50%" y2="70%" />
              <line stroke={R.primary} strokeWidth="0.5" strokeDasharray="6" x1="20%" x2="70%" y1="25%" y2="20%" />
            </svg>

            {/* Rotating ring */}
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div
                className="w-64 h-64 rounded-full border"
                style={{
                  borderColor: 'rgba(255,49,49,0.05)',
                  animation: 'spin 25s linear infinite',
                }}
              />
            </div>

            {/* Corner HUD elements */}
            <div
              className="absolute bottom-4 left-4 p-3 border-l border-b rounded-bl-xl backdrop-blur-sm"
              style={{ borderColor: 'rgba(255,49,49,0.2)', background: 'rgba(0,0,0,0.5)' }}
            >
              <p className="text-[10px] font-bold uppercase mb-1" style={{ color: R.primary }}>
                active_nodes: {targets.length}
              </p>
              <p className="text-[10px] font-mono" style={{ color: 'rgba(255,255,255,0.3)' }}>
                SCAN_MODE: PASSIVE
              </p>
            </div>

            <div
              className="absolute top-4 right-4 p-3 border-r border-t rounded-tr-xl backdrop-blur-sm"
              style={{ borderColor: 'rgba(255,49,49,0.2)', background: 'rgba(0,0,0,0.5)' }}
            >
              <p className="text-[10px] font-bold uppercase mb-1 text-white">
                threat_level: {(globalSev.critical || 0) > 0 ? 'critical' : (globalSev.high || 0) > 0 ? 'high' : 'normal'}
              </p>
              <div className="w-28 h-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.1)' }}>
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${Math.min(100, ((globalSev.critical || 0) * 30 + (globalSev.high || 0) * 15))}%`,
                    backgroundColor: R.primary,
                  }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Terminal FAB */}
      <button
        className="fixed bottom-8 right-8 w-14 h-14 rounded-full shadow-2xl hover:scale-110 active:scale-95
                   transition-all flex items-center justify-center z-50 text-white"
        style={{
          backgroundColor: R.primary,
          boxShadow: `0 0 24px ${R.primary}60`,
        }}
        title="Terminal"
      >
        <span className="material-symbols-outlined text-[26px]"
              style={{ fontVariationSettings: "'FILL' 1" }}>terminal</span>
      </button>
    </div>
  );
}
