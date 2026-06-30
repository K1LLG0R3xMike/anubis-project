import React, { useState, useEffect } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

const R = {
  primary: '#FF3131',
  primaryDim: 'rgba(255,49,49,0.15)',
  primaryBorder: 'rgba(255,49,49,0.3)',
  card: 'rgba(30,8,8,0.5)',
  bg: '#0a0505',
};

const SEV_COLOR = {
  critical: '#FF3131',
  high:     '#e65100',
  medium:   '#ff9800',
  low:      'rgba(255,255,255,0.5)',
  info:     'rgba(255,255,255,0.2)',
};

const fmtDate = (d) =>
  new Date(d + 'T00:00:00').toLocaleDateString('es-ES', {
    weekday: 'short', day: 'numeric', month: 'short', year: 'numeric',
  });

function SevBadge({ sev }) {
  const s = (sev || 'info').toLowerCase();
  const c = SEV_COLOR[s] || SEV_COLOR.info;
  return (
    <span className="font-mono text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
      style={{ color: c, background: `${c}20`, border: `1px solid ${c}50` }}>
      {sev}
    </span>
  );
}

export default function AttackHistorical() {
  const [sessions, setSessions]     = useState([]);
  const [loading, setLoading]       = useState(true);
  const [expanded, setExpanded]     = useState(null);
  const [filterTarget, setFilter]   = useState('');
  const [filterModule, setFModule]  = useState('');
  const [cmpMode, setCmpMode]       = useState(false);
  const [cmpTarget, setCmpTarget]   = useState('');
  const [cmpModule, setCmpModule]   = useState('');
  const [cmpDateOld, setDateOld]    = useState('');
  const [cmpDateNew, setDateNew]    = useState('');
  const [cmpResult, setCmpResult]   = useState(null);
  const [cmpLoading, setCmpLoading] = useState(false);

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

  const byDate = filtered.reduce((acc, s) => {
    (acc[s.date] = acc[s.date] || []).push(s);
    return acc;
  }, {});
  const sortedDates = Object.keys(byDate).sort((a, b) => b.localeCompare(a));

  const cmpDates = [...new Set(
    sessions.filter(s => s.target_name === cmpTarget && s.module === cmpModule).map(s => s.date)
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

  const selectStyle = {
    background: 'rgba(255,255,255,0.05)',
    border: `1px solid rgba(255,49,49,0.25)`,
    color: 'white',
    borderRadius: 8,
    padding: '8px 12px',
    fontSize: 12,
    fontFamily: 'monospace',
    outline: 'none',
  };

  return (
    <div className="min-h-screen px-8 py-8 pb-24" style={{ backgroundColor: R.bg }}>

      {/* Header */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.25em] mb-1"
             style={{ color: 'rgba(255,255,255,0.3)' }}>scan_history</p>
          <h1 className="text-3xl font-black text-white">Histórico</h1>
          <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.35)' }}>
            Timeline de escaneos y comparación entre ejecuciones
          </p>
        </div>
        <button
          onClick={() => { setCmpMode(m => !m); setCmpResult(null); }}
          className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all"
          style={{
            background: cmpMode ? R.primary : R.primaryDim,
            border: `1px solid ${R.primaryBorder}`,
            color: 'white',
          }}>
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>compare_arrows</span>
          {cmpMode ? 'Ver timeline' : 'Comparar'}
        </button>
      </div>

      {/* COMPARISON MODE */}
      {cmpMode && (
        <div className="space-y-5">
          <div className="rounded-xl p-6" style={{ background: R.card, border: `1px solid ${R.primaryBorder}` }}>
            <p className="text-[10px] font-bold uppercase tracking-wider mb-5"
               style={{ color: 'rgba(255,255,255,0.35)' }}>configurar comparación</p>
            <div className="grid grid-cols-4 gap-4 mb-5">
              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider mb-2"
                       style={{ color: 'rgba(255,255,255,0.4)' }}>Objetivo</label>
                <select value={cmpTarget} onChange={e => { setCmpTarget(e.target.value); setCmpModule(''); setDateOld(''); setDateNew(''); }} style={selectStyle}>
                  <option value="">— Seleccionar —</option>
                  {allTargets.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider mb-2"
                       style={{ color: 'rgba(255,255,255,0.4)' }}>Módulo</label>
                <select value={cmpModule} onChange={e => { setCmpModule(e.target.value); setDateOld(''); setDateNew(''); }}
                  disabled={!cmpTarget} style={{ ...selectStyle, opacity: !cmpTarget ? 0.4 : 1 }}>
                  <option value="">— Seleccionar —</option>
                  {[...new Set(sessions.filter(s => s.target_name === cmpTarget).map(s => s.module))].map(m =>
                    <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider mb-2"
                       style={{ color: 'rgba(255,255,255,0.4)' }}>Escaneo antiguo</label>
                <select value={cmpDateOld} onChange={e => setDateOld(e.target.value)}
                  disabled={!cmpModule} style={{ ...selectStyle, opacity: !cmpModule ? 0.4 : 1 }}>
                  <option value="">— Fecha —</option>
                  {cmpDates.map(d => <option key={d} value={d}>{fmtDate(d)}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider mb-2"
                       style={{ color: 'rgba(255,255,255,0.4)' }}>Escaneo reciente</label>
                <select value={cmpDateNew} onChange={e => setDateNew(e.target.value)}
                  disabled={!cmpModule} style={{ ...selectStyle, opacity: !cmpModule ? 0.4 : 1 }}>
                  <option value="">— Fecha —</option>
                  {cmpDates.map(d => <option key={d} value={d}>{fmtDate(d)}</option>)}
                </select>
              </div>
            </div>
            <button onClick={handleCompare}
              disabled={!cmpTarget || !cmpModule || !cmpDateOld || !cmpDateNew || cmpLoading}
              className="px-6 py-2.5 rounded-xl text-xs font-black text-white uppercase tracking-wider transition-all hover:brightness-110 disabled:opacity-40"
              style={{ background: R.primary, boxShadow: `0 0 16px ${R.primary}40` }}>
              {cmpLoading ? 'Comparando...' : '› Comparar escaneos'}
            </button>
          </div>

          {cmpResult && !cmpResult.error && (
            <div className="grid grid-cols-3 gap-5">
              {[
                { key: 'new', label: 'Nuevos', icon: 'add_circle', color: R.primary },
                { key: 'removed', label: 'Resueltos', icon: 'remove_circle', color: '#4caf50' },
                { key: 'unchanged', label: 'Sin cambios', icon: 'radio_button_unchecked', color: 'rgba(255,255,255,0.4)' },
              ].map(({ key, label, icon, color }) => (
                <div key={key} className="rounded-xl p-5"
                     style={{ background: R.card, border: `1px solid rgba(255,49,49,0.2)` }}>
                  <div className="flex items-center gap-2 mb-4">
                    <span className="material-symbols-outlined text-sm" style={{ color }}>{icon}</span>
                    <p className="font-mono text-[10px] font-bold uppercase tracking-wider" style={{ color }}>
                      {label} · {cmpResult[key]?.length || 0}
                    </p>
                  </div>
                  {cmpResult[key]?.length === 0 ? (
                    <p className="font-mono text-xs" style={{ color: 'rgba(255,255,255,0.2)' }}>Sin hallazgos</p>
                  ) : cmpResult[key].map((f, i) => (
                    <div key={i} className="mb-2 p-3 rounded-lg"
                         style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)' }}>
                      <SevBadge sev={f.severity} />
                      <p className="font-bold text-xs text-white mt-1.5">{f.title}</p>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
          {cmpResult?.error && (
            <p className="font-mono text-xs" style={{ color: R.primary }}>Error al obtener la comparación.</p>
          )}
        </div>
      )}

      {/* TIMELINE MODE */}
      {!cmpMode && (
        <>
          <div className="flex gap-3 mb-6">
            {[
              { value: filterTarget, setter: setFilter, options: allTargets, placeholder: 'Todos los objetivos' },
              { value: filterModule, setter: setFModule, options: allModules, placeholder: 'Todos los módulos' },
            ].map((sel, i) => (
              <select key={i} value={sel.value} onChange={e => sel.setter(e.target.value)} style={selectStyle}>
                <option value="">{sel.placeholder}</option>
                {sel.options.map(o => <option key={o} value={o}>{o}</option>)}
              </select>
            ))}
            {(filterTarget || filterModule) && (
              <button onClick={() => { setFilter(''); setFModule(''); }}
                className="px-3 py-2 rounded-lg text-xs font-mono transition-all"
                style={{ border: `1px solid rgba(255,49,49,0.25)`, color: 'rgba(255,255,255,0.5)' }}>
                Limpiar
              </button>
            )}
          </div>

          {loading && (
            <div className="flex justify-center py-20">
              <span className="material-symbols-outlined animate-spin" style={{ fontSize: 32, color: R.primary }}>sync</span>
            </div>
          )}

          {!loading && sortedDates.length === 0 && (
            <div className="text-center py-24 rounded-xl border-2 border-dashed"
                 style={{ borderColor: 'rgba(255,49,49,0.15)' }}>
              <span className="material-symbols-outlined text-5xl mb-3 block" style={{ color: 'rgba(255,49,49,0.3)' }}>history</span>
              <p className="text-lg font-black text-white">Sin historial disponible</p>
              <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.3)' }}>
                Los hallazgos aparecerán aquí tras ejecutar escaneos
              </p>
            </div>
          )}

          <div className="space-y-8">
            {sortedDates.map(date => (
              <div key={date}>
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-2.5 h-2.5 rounded-full shrink-0"
                       style={{ backgroundColor: R.primary, boxShadow: `0 0 8px ${R.primary}` }} />
                  <p className="font-mono text-sm font-bold text-white">{fmtDate(date)}</p>
                  <div className="flex-1 h-px" style={{ background: 'rgba(255,49,49,0.15)' }} />
                  <span className="font-mono text-[10px]" style={{ color: 'rgba(255,255,255,0.3)' }}>
                    {byDate[date].length} sesión{byDate[date].length > 1 ? 'es' : ''}
                  </span>
                </div>

                <div className="ml-5 space-y-2 border-l-2 pl-5"
                     style={{ borderColor: 'rgba(255,49,49,0.15)' }}>
                  {byDate[date].map(s => {
                    const key = `${s.target_id}-${s.module}-${s.date}`;
                    const isOpen = expanded === key;
                    return (
                      <div key={key} className="rounded-xl overflow-hidden"
                           style={{ background: R.card, border: `1px solid rgba(255,49,49,0.15)` }}>
                        <button className="w-full flex items-center gap-3 px-5 py-4 text-left transition-all hover:bg-white/5"
                                onClick={() => setExpanded(isOpen ? null : key)}>
                          <div className="w-2 h-2 rounded-full shrink-0"
                               style={{ backgroundColor: R.primary }} />
                          <div className="flex-1 min-w-0 flex items-center gap-2">
                            <span className="font-mono text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded"
                              style={{ color: R.primary, background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>
                              {s.module}
                            </span>
                            <span className="font-bold text-sm text-white">{s.target_name}</span>
                          </div>
                          <span className="font-mono text-[10px] shrink-0"
                                style={{ color: 'rgba(255,255,255,0.35)' }}>
                            {s.count} hallazgo{s.count !== 1 ? 's' : ''}
                          </span>
                          <span className="material-symbols-outlined transition-transform"
                                style={{ fontSize: 18, color: 'rgba(255,255,255,0.4)',
                                         transform: isOpen ? 'rotate(180deg)' : 'none' }}>
                            expand_more
                          </span>
                        </button>

                        {isOpen && (
                          <div className="border-t divide-y"
                               style={{ borderColor: 'rgba(255,49,49,0.1)', '--tw-divide-opacity': 1 }}>
                            {s.findings.map((f, fi) => (
                              <div key={fi} className="flex items-start gap-3 px-5 py-3 hover:bg-white/5 transition-colors">
                                <SevBadge sev={f.severity} />
                                <div className="min-w-0 flex-1">
                                  <p className="font-bold text-sm text-white">{f.title}</p>
                                  {f.description && (
                                    <p className="font-mono text-[10px] mt-0.5 line-clamp-2"
                                       style={{ color: 'rgba(255,255,255,0.3)' }}>{f.description}</p>
                                  )}
                                </div>
                                <p className="font-mono text-[10px] shrink-0 ml-auto"
                                   style={{ color: 'rgba(255,255,255,0.2)' }}>
                                  {f.scan_date ? new Date(f.scan_date).toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' }) : ''}
                                </p>
                              </div>
                            ))}
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
