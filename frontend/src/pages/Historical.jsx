import React, { useState, useEffect } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

const MODULE_COLORS = {
  waf:     { text: 'text-error',     bg: 'bg-error/15',     border: 'border-error/40',     dot: '#ff6e84' },
  whatweb: { text: 'text-primary',   bg: 'bg-primary/15',   border: 'border-primary/40',   dot: '#9aa8ff' },
  headers: { text: 'text-primary',   bg: 'bg-primary/15',   border: 'border-primary/40',   dot: '#9aa8ff' },
  certs:   { text: 'text-secondary', bg: 'bg-secondary/15', border: 'border-secondary/40', dot: '#ff8f06' },
  nikto:   { text: 'text-tertiary',  bg: 'bg-tertiary/15',  border: 'border-tertiary/40',  dot: '#b374f7' },
  zap:     { text: 'text-error',     bg: 'bg-error/15',     border: 'border-error/40',     dot: '#ff6e84' },
};

const SEV_COLORS = {
  critical: { text: 'text-[#ff6e84]', bg: 'bg-[#ff6e84]/15', border: 'border-[#ff6e84]/40' },
  high:     { text: 'text-error',     bg: 'bg-error/10',     border: 'border-error/30'     },
  medium:   { text: 'text-secondary', bg: 'bg-secondary/10', border: 'border-secondary/30' },
  low:      { text: 'text-tertiary',  bg: 'bg-tertiary/10',  border: 'border-tertiary/30'  },
  info:     { text: 'text-primary',   bg: 'bg-primary/10',   border: 'border-primary/30'   },
};

const modColor  = (m) => MODULE_COLORS[m] || MODULE_COLORS.waf;
const sevColor  = (s) => SEV_COLORS[(s || '').toLowerCase()] || SEV_COLORS.info;
const fmtDate   = (d) => new Date(d + 'T00:00:00').toLocaleDateString('es-ES', { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' });

export default function Historical() {
  const [sessions, setSessions]       = useState([]);
  const [loading, setLoading]         = useState(true);
  const [expanded, setExpanded]       = useState(null);   // key of open session
  const [filterTarget, setFilterTarget] = useState('');
  const [filterModule, setFilterModule] = useState('');

  // comparison
  const [cmpMode, setCmpMode]         = useState(false);
  const [cmpTarget, setCmpTarget]     = useState('');
  const [cmpModule, setCmpModule]     = useState('');
  const [cmpDateOld, setCmpDateOld]   = useState('');
  const [cmpDateNew, setCmpDateNew]   = useState('');
  const [cmpResult, setCmpResult]     = useState(null);
  const [cmpLoading, setCmpLoading]   = useState(false);

  useEffect(() => {
    axios.get(`${BASE}/findings/historical`)
      .then(r => setSessions(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const allTargets = [...new Set(sessions.map(s => s.target_name))].sort();
  const allModules = [...new Set(sessions.map(s => s.module))].sort();

  const filtered = sessions.filter(s =>
    (!filterTarget || s.target_name === filterTarget) &&
    (!filterModule || s.module === filterModule)
  );

  // group by date for timeline
  const byDate = filtered.reduce((acc, s) => {
    (acc[s.date] = acc[s.date] || []).push(s);
    return acc;
  }, {});
  const sortedDates = Object.keys(byDate).sort((a, b) => b.localeCompare(a));

  // available dates for the selected cmp target+module
  const cmpDates = [...new Set(
    sessions
      .filter(s => s.target_name === cmpTarget && s.module === cmpModule)
      .map(s => s.date)
  )].sort((a, b) => b.localeCompare(a));

  const handleCompare = async () => {
    if (!cmpTarget || !cmpModule || !cmpDateOld || !cmpDateNew) return;
    const targetId = sessions.find(s => s.target_name === cmpTarget)?.target_id;
    if (!targetId) return;
    setCmpLoading(true);
    setCmpResult(null);
    try {
      const r = await axios.get(`${BASE}/findings/compare`, {
        params: { target_id: targetId, module: cmpModule, date_old: cmpDateOld, date_new: cmpDateNew },
      });
      setCmpResult(r.data);
    } catch { setCmpResult({ error: true }); }
    finally { setCmpLoading(false); }
  };

  const sessionKey = (s) => `${s.target_id}-${s.module}-${s.date}`;

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto">

      {/* ── HEADER ── */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">scan_history</p>
          <h2 className="font-headline text-3xl font-bold text-on-background tracking-tight">Histórico de Escaneos</h2>
          <p className="text-sm text-on-surface-variant font-body mt-1">Timeline de hallazgos y comparación entre ejecuciones</p>
        </div>
        <button
          onClick={() => { setCmpMode(m => !m); setCmpResult(null); }}
          className={`flex items-center gap-1.5 px-4 py-2.5 rounded-lg text-xs font-bold uppercase tracking-[0.05em] transition-colors shrink-0
            ${cmpMode
              ? 'bg-secondary text-background'
              : 'bg-surface-container-high border border-outline-variant/30 text-on-surface hover:border-primary/40 hover:text-primary'}`}>
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>compare_arrows</span>
          {cmpMode ? 'Ver timeline' : 'Comparar escaneos'}
        </button>
      </div>

      {/* ══ COMPARISON MODE ══ */}
      {cmpMode && (
        <div className="space-y-5">
          <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6">
            <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-4">configurar_comparación</p>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-5">
              {/* Target */}
              <div>
                <label className="block font-mono text-[0.62rem] text-on-surface-variant uppercase tracking-[0.12em] mb-1.5">Objetivo</label>
                <select value={cmpTarget} onChange={e => { setCmpTarget(e.target.value); setCmpModule(''); setCmpDateOld(''); setCmpDateNew(''); setCmpResult(null); }}
                  className="w-full rounded-lg px-3 py-2.5 text-sm font-body text-on-surface bg-surface-container-lowest border border-outline-variant/30 focus:border-primary outline-none transition-colors">
                  <option value="">-- Seleccionar --</option>
                  {allTargets.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>

              {/* Module */}
              <div>
                <label className="block font-mono text-[0.62rem] text-on-surface-variant uppercase tracking-[0.12em] mb-1.5">Módulo</label>
                <select value={cmpModule} onChange={e => { setCmpModule(e.target.value); setCmpDateOld(''); setCmpDateNew(''); setCmpResult(null); }}
                  disabled={!cmpTarget}
                  className="w-full rounded-lg px-3 py-2.5 text-sm font-body text-on-surface bg-surface-container-lowest border border-outline-variant/30 focus:border-primary outline-none transition-colors disabled:opacity-40">
                  <option value="">-- Seleccionar --</option>
                  {[...new Set(sessions.filter(s => s.target_name === cmpTarget).map(s => s.module))].map(m =>
                    <option key={m} value={m}>{m}</option>
                  )}
                </select>
              </div>

              {/* Date old */}
              <div>
                <label className="block font-mono text-[0.62rem] text-on-surface-variant uppercase tracking-[0.12em] mb-1.5">Escaneo antiguo</label>
                <select value={cmpDateOld} onChange={e => { setCmpDateOld(e.target.value); setCmpResult(null); }}
                  disabled={!cmpModule}
                  className="w-full rounded-lg px-3 py-2.5 text-sm font-body text-on-surface bg-surface-container-lowest border border-outline-variant/30 focus:border-primary outline-none transition-colors disabled:opacity-40">
                  <option value="">-- Fecha --</option>
                  {cmpDates.map(d => <option key={d} value={d}>{fmtDate(d)}</option>)}
                </select>
              </div>

              {/* Date new */}
              <div>
                <label className="block font-mono text-[0.62rem] text-on-surface-variant uppercase tracking-[0.12em] mb-1.5">Escaneo reciente</label>
                <select value={cmpDateNew} onChange={e => { setCmpDateNew(e.target.value); setCmpResult(null); }}
                  disabled={!cmpModule}
                  className="w-full rounded-lg px-3 py-2.5 text-sm font-body text-on-surface bg-surface-container-lowest border border-outline-variant/30 focus:border-primary outline-none transition-colors disabled:opacity-40">
                  <option value="">-- Fecha --</option>
                  {cmpDates.map(d => <option key={d} value={d}>{fmtDate(d)}</option>)}
                </select>
              </div>
            </div>

            <button
              onClick={handleCompare}
              disabled={!cmpTarget || !cmpModule || !cmpDateOld || !cmpDateNew || cmpLoading}
              className="px-6 py-2.5 rounded-lg bg-primary text-on-primary font-bold text-xs uppercase tracking-[0.05em] hover:bg-primary-dim transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ boxShadow: '0 4px 12px rgba(154,168,255,0.2)' }}>
              {cmpLoading ? 'Comparando...' : '› Comparar'}
            </button>
          </div>

          {/* Comparison results */}
          {cmpResult && !cmpResult.error && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              {/* New */}
              <div className="bg-surface-container-low rounded-2xl border border-primary/30 p-5">
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-primary" style={{ fontSize: 18 }}>add_circle</span>
                  <p className="font-mono text-[0.65rem] text-primary uppercase tracking-[0.12em] font-bold">
                    Nuevos · {cmpResult.new.length}
                  </p>
                </div>
                {cmpResult.new.length === 0
                  ? <p className="font-mono text-xs text-outline">Sin hallazgos nuevos</p>
                  : cmpResult.new.map((f, i) => {
                      const c = sevColor(f.severity);
                      return (
                        <div key={i} className="mb-2 p-3 rounded-lg border border-primary/20 bg-primary/5">
                          <span className={`font-mono text-[0.55rem] uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border ${c.text} ${c.bg} ${c.border}`}>{f.severity}</span>
                          <p className="font-body text-xs text-on-surface font-medium mt-1.5">{f.title}</p>
                        </div>
                      );
                    })}
              </div>

              {/* Removed */}
              <div className="bg-surface-container-low rounded-2xl border border-error/30 p-5">
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-error" style={{ fontSize: 18 }}>remove_circle</span>
                  <p className="font-mono text-[0.65rem] text-error uppercase tracking-[0.12em] font-bold">
                    Resueltos · {cmpResult.removed.length}
                  </p>
                </div>
                {cmpResult.removed.length === 0
                  ? <p className="font-mono text-xs text-outline">Sin hallazgos resueltos</p>
                  : cmpResult.removed.map((f, i) => {
                      const c = sevColor(f.severity);
                      return (
                        <div key={i} className="mb-2 p-3 rounded-lg border border-error/20 bg-error/5 opacity-70">
                          <span className={`font-mono text-[0.55rem] uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border ${c.text} ${c.bg} ${c.border}`}>{f.severity}</span>
                          <p className="font-body text-xs text-on-surface font-medium mt-1.5 line-through">{f.title}</p>
                        </div>
                      );
                    })}
              </div>

              {/* Unchanged */}
              <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-5">
                <div className="flex items-center gap-2 mb-4">
                  <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: 18 }}>radio_button_unchecked</span>
                  <p className="font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.12em] font-bold">
                    Sin cambios · {cmpResult.unchanged.length}
                  </p>
                </div>
                {cmpResult.unchanged.length === 0
                  ? <p className="font-mono text-xs text-outline">—</p>
                  : cmpResult.unchanged.map((f, i) => {
                      const c = sevColor(f.severity);
                      return (
                        <div key={i} className="mb-2 p-3 rounded-lg border border-outline-variant/20 bg-surface-container-lowest">
                          <span className={`font-mono text-[0.55rem] uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border ${c.text} ${c.bg} ${c.border}`}>{f.severity}</span>
                          <p className="font-body text-xs text-on-surface-variant mt-1.5">{f.title}</p>
                        </div>
                      );
                    })}
              </div>
            </div>
          )}

          {cmpResult?.error && (
            <p className="font-mono text-xs text-error">Error al obtener la comparación.</p>
          )}
        </div>
      )}

      {/* ══ TIMELINE MODE ══ */}
      {!cmpMode && (
        <>
          {/* Filters */}
          <div className="flex gap-3 mb-6">
            <select value={filterTarget} onChange={e => setFilterTarget(e.target.value)}
              className="rounded-lg px-3 py-2 text-sm font-body text-on-surface bg-surface-container-low border border-outline-variant/30 focus:border-primary outline-none transition-colors">
              <option value="">Todos los objetivos</option>
              {allTargets.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <select value={filterModule} onChange={e => setFilterModule(e.target.value)}
              className="rounded-lg px-3 py-2 text-sm font-body text-on-surface bg-surface-container-low border border-outline-variant/30 focus:border-primary outline-none transition-colors">
              <option value="">Todos los módulos</option>
              {allModules.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            {(filterTarget || filterModule) && (
              <button onClick={() => { setFilterTarget(''); setFilterModule(''); }}
                className="px-3 py-2 rounded-lg border border-outline-variant/30 text-on-surface-variant text-xs font-mono hover:border-primary/40 hover:text-primary transition-colors">
                Limpiar
              </button>
            )}
          </div>

          {loading && (
            <div className="text-center py-20">
              <span className="material-symbols-outlined text-4xl text-outline animate-spin block mb-3">progress_activity</span>
              <p className="font-mono text-xs text-outline">Cargando histórico...</p>
            </div>
          )}

          {!loading && sortedDates.length === 0 && (
            <div className="text-center py-20 border-2 border-dashed border-outline-variant/20 rounded-2xl">
              <span className="material-symbols-outlined text-5xl text-outline mb-3 block">history</span>
              <p className="font-headline text-lg text-on-surface-variant">Sin historial disponible</p>
              <p className="text-xs text-outline mt-1">Los hallazgos aparecerán aquí tras ejecutar escaneos</p>
            </div>
          )}

          {/* Timeline */}
          <div className="space-y-8">
            {sortedDates.map(date => (
              <div key={date}>
                {/* Date separator */}
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-2.5 h-2.5 rounded-full bg-primary shrink-0" style={{ boxShadow: '0 0 8px #9aa8ff' }} />
                  <p className="font-mono text-sm font-bold text-on-surface">{fmtDate(date)}</p>
                  <div className="flex-1 h-px bg-outline-variant/20" />
                  <span className="font-mono text-[0.6rem] text-outline">{byDate[date].length} sesión{byDate[date].length > 1 ? 'es' : ''}</span>
                </div>

                {/* Sessions for this date */}
                <div className="ml-5 space-y-3 border-l-2 border-outline-variant/15 pl-5">
                  {byDate[date].map(s => {
                    const mc = modColor(s.module);
                    const key = sessionKey(s);
                    const isOpen = expanded === key;
                    return (
                      <div key={key} className="bg-surface-container-low rounded-xl border border-outline-variant/20 overflow-hidden">
                        {/* Session header */}
                        <button
                          className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-primary/5 transition-colors"
                          onClick={() => setExpanded(isOpen ? null : key)}>
                          <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: mc.dot }} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={`font-mono text-[0.6rem] font-bold uppercase tracking-[0.1em] px-2 py-0.5 rounded border ${mc.text} ${mc.bg} ${mc.border}`}>
                                {s.module}
                              </span>
                              <span className="font-headline text-sm font-bold text-on-surface">{s.target_name}</span>
                            </div>
                          </div>
                          <span className="font-mono text-[0.6rem] text-on-surface-variant shrink-0">{s.count} hallazgo{s.count !== 1 ? 's' : ''}</span>
                          <span className={`material-symbols-outlined text-on-surface-variant transition-transform ${isOpen ? 'rotate-180' : ''}`} style={{ fontSize: 18 }}>
                            expand_more
                          </span>
                        </button>

                        {/* Expanded findings */}
                        {isOpen && (
                          <div className="border-t border-outline-variant/15 divide-y divide-outline-variant/10">
                            {s.findings.map((f, fi) => {
                              const sc = sevColor(f.severity);
                              return (
                                <div key={fi} className="flex items-start gap-3 px-5 py-3 hover:bg-primary/5 transition-colors">
                                  <span className={`font-mono text-[0.55rem] uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border shrink-0 mt-0.5 ${sc.text} ${sc.bg} ${sc.border}`}>
                                    {f.severity}
                                  </span>
                                  <div className="min-w-0">
                                    <p className="font-body text-sm text-on-surface font-medium">{f.title}</p>
                                    {f.description && (
                                      <p className="font-mono text-[0.6rem] text-on-surface-variant mt-0.5 line-clamp-2">{f.description}</p>
                                    )}
                                  </div>
                                  <p className="font-mono text-[0.55rem] text-outline shrink-0 ml-auto">
                                    {f.scan_date ? new Date(f.scan_date).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' }) : ''}
                                  </p>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
