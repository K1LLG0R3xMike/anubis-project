import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

const R = {
  primary: '#FF3131',
  primaryDim: 'rgba(255,49,49,0.15)',
  primaryBorder: 'rgba(255,49,49,0.3)',
  card: 'rgba(30,8,8,0.5)',
  bg: '#0a0505',
};

function ModeBadge({ mode }) {
  const isQuick = mode === 'quick';
  return (
    <span className="font-mono text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded"
      style={{
        color: isQuick ? '#c4b5fd' : '#fb923c',
        background: isQuick ? 'rgba(139,92,246,0.12)' : 'rgba(251,146,60,0.1)',
        border: `1px solid ${isQuick ? 'rgba(139,92,246,0.3)' : 'rgba(251,146,60,0.25)'}`,
      }}>
      {isQuick ? 'PoC rápida' : 'Ejecución completa'}
    </span>
  );
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('es-ES', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function AttackFindings() {
  const [runs, setRuns]           = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(false);
  const [targetFilter, setTargetFilter] = useState('all');
  const [expanded, setExpanded]   = useState(null);

  useEffect(() => {
    axios.get(`${BASE}/attack/vector-runs?estado=explotable&nocache=${Date.now()}`)
      .then(r => setRuns(r.data))
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  const targets = useMemo(() => {
    const map = new Map();
    runs.forEach(r => { if (r.target_id != null) map.set(r.target_id, { id: r.target_id, name: r.target_name, url: r.target_url }); });
    return [...map.values()];
  }, [runs]);

  const visibleRuns = useMemo(() => {
    if (targetFilter === 'all') return runs;
    return runs.filter(r => String(r.target_id) === String(targetFilter));
  }, [runs, targetFilter]);

  return (
    <div className="min-h-screen flex" style={{ backgroundColor: R.bg }}>

      {/* ── SIDEBAR ── */}
      <aside className="w-72 shrink-0 border-r flex flex-col"
        style={{ borderColor: 'rgba(255,49,49,0.15)', background: 'rgba(20,5,5,0.6)' }}>
        <div className="px-5 pt-7 pb-5 border-b" style={{ borderColor: 'rgba(255,49,49,0.12)' }}>
          <p className="text-[10px] font-bold uppercase tracking-[0.25em] mb-1"
             style={{ color: 'rgba(255,255,255,0.3)' }}>attack_findings</p>
          <h1 className="text-2xl font-black text-white">Explotaciones</h1>
          <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.35)' }}>
            Vulnerabilidades confirmadas por el agente IA
          </p>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-3 space-y-1">
          <button onClick={() => setTargetFilter('all')}
            className="w-full text-left px-4 py-3 rounded-xl transition-all"
            style={{
              background: targetFilter === 'all' ? R.primaryDim : 'transparent',
              border: `1px solid ${targetFilter === 'all' ? R.primaryBorder : 'transparent'}`,
            }}>
            <div className="flex items-center gap-3">
              <span className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{ backgroundColor: targetFilter === 'all' ? R.primary : 'rgba(255,255,255,0.2)' }} />
              <p className="font-bold text-sm text-white">Todos los targets</p>
              <span className="ml-auto font-mono text-[10px]" style={{ color: 'rgba(255,255,255,0.3)' }}>{runs.length}</span>
            </div>
          </button>

          {!loading && targets.map(t => {
            const count = runs.filter(r => r.target_id === t.id).length;
            return (
              <button key={t.id} onClick={() => setTargetFilter(t.id)}
                className="w-full text-left px-4 py-3 rounded-xl transition-all"
                style={{
                  background: String(targetFilter) === String(t.id) ? R.primaryDim : 'transparent',
                  border: `1px solid ${String(targetFilter) === String(t.id) ? R.primaryBorder : 'transparent'}`,
                }}>
                <div className="flex items-center gap-3">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ backgroundColor: String(targetFilter) === String(t.id) ? R.primary : 'rgba(255,255,255,0.2)' }} />
                  <div className="min-w-0 flex-1">
                    <p className="font-bold text-sm text-white truncate">{t.name || `Target #${t.id}`}</p>
                    <p className="text-[10px] truncate" style={{ color: 'rgba(255,255,255,0.3)' }}>{t.url}</p>
                  </div>
                  <span className="font-mono text-[10px] shrink-0" style={{ color: 'rgba(255,255,255,0.3)' }}>{count}</span>
                </div>
              </button>
            );
          })}

          {loading && (
            <div className="py-8 flex justify-center">
              <span className="material-symbols-outlined text-sm animate-spin" style={{ color: R.primary }}>sync</span>
            </div>
          )}
        </div>
      </aside>

      {/* ── MAIN ── */}
      <div className="flex-1 overflow-y-auto px-8 py-8 pb-20">
        <div className="max-w-4xl">

          <div className="mb-6">
            <p className="text-[10px] font-bold uppercase tracking-[0.25em] mb-1"
               style={{ color: 'rgba(255,255,255,0.3)' }}>resultados del agente de vectores</p>
            <h2 className="text-3xl font-black text-white">
              {targetFilter === 'all' ? 'Todas las explotaciones' : (targets.find(t => String(t.id) === String(targetFilter))?.name || 'Target')}
            </h2>
            <p className="text-sm mt-1" style={{ color: 'rgba(255,255,255,0.35)' }}>
              Solo se listan vectores que el agente IA confirmó como <span style={{ color: R.primary }}>explotables</span>.
              Las pruebas inconclusas o no explotables no aparecen aquí.
            </p>
          </div>

          {loading ? (
            <div className="flex flex-col items-center justify-center py-32">
              <span className="material-symbols-outlined animate-spin mb-3" style={{ fontSize: 32, color: R.primary }}>sync</span>
              <p className="text-sm font-mono" style={{ color: 'rgba(255,255,255,0.4)' }}>Cargando explotaciones...</p>
            </div>
          ) : error ? (
            <div className="rounded-xl p-6 text-center" style={{ background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>
              <p className="text-sm font-bold text-white">No se pudo cargar el listado</p>
              <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.4)' }}>Verifica que el backend esté disponible</p>
            </div>
          ) : visibleRuns.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center py-32">
              <span className="material-symbols-outlined text-6xl mb-4" style={{ color: 'rgba(255,49,49,0.3)' }}>verified_user</span>
              <p className="text-xl font-black text-white mb-2">Sin explotaciones confirmadas</p>
              <p className="text-sm max-w-sm" style={{ color: 'rgba(255,255,255,0.3)' }}>
                Ejecuta vectores de ataque desde Targets — cuando el agente IA confirme un vector como explotable, aparecerá aquí.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {visibleRuns.map(run => {
                const isOpen = expanded === run.id;
                return (
                  <div key={run.id} className="rounded-xl overflow-hidden"
                       style={{ background: R.card, border: `1px solid ${R.primaryBorder}` }}>

                    {/* Header de la tarjeta — siempre visible */}
                    <button onClick={() => setExpanded(isOpen ? null : run.id)}
                      className="w-full text-left p-5 flex items-start gap-4 hover:bg-white/[0.02] transition-colors">
                      <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                           style={{ background: 'rgba(255,49,49,0.15)', border: `1px solid ${R.primaryBorder}` }}>
                        <span className="text-base font-black" style={{ color: R.primary }}>⚠</span>
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="font-black text-white text-sm">{run.vector_titulo || run.vector_name}</p>
                          <ModeBadge mode={run.mode} />
                        </div>
                        <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.4)' }}>
                          {run.target_name || `Target #${run.target_id}`} · <span className="font-mono">{run.target_url}</span>
                        </p>
                        <p className="text-xs mt-2 leading-relaxed" style={{ color: 'rgba(255,255,255,0.6)' }}>
                          {run.resumen}
                        </p>
                      </div>
                      <div className="text-right shrink-0">
                        <p className="text-[10px] font-mono" style={{ color: 'rgba(255,255,255,0.25)' }}>{fmtDate(run.completed_at)}</p>
                        <p className="text-[10px] font-mono mt-1" style={{ color: 'rgba(255,255,255,0.25)' }}>{run.iterations} iter.</p>
                        <span className="material-symbols-outlined text-sm mt-2 inline-block transition-transform"
                              style={{ color: 'rgba(255,255,255,0.3)', transform: isOpen ? 'rotate(180deg)' : 'none' }}>
                          expand_more
                        </span>
                      </div>
                    </button>

                    {/* Detalle expandido — mismos campos que el modal del vector */}
                    {isOpen && (
                      <div className="px-5 pb-5 space-y-3 border-t" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>

                        {run.evidencia_tecnica && (
                          <div className="space-y-1 pt-4">
                            <p className="text-[9px] font-bold uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.25)' }}>
                              evidencia técnica
                            </p>
                            <pre className="rounded-xl px-3 py-2.5 text-[10px] leading-relaxed overflow-x-auto font-mono whitespace-pre-wrap"
                                 style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.7)', maxHeight: 200, overflowY: 'auto' }}>
                              {run.evidencia_tecnica}
                            </pre>
                          </div>
                        )}

                        {run.comando_clave && (
                          <div className="space-y-1">
                            <p className="text-[9px] font-bold uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.25)' }}>
                              comando clave
                            </p>
                            <pre className="rounded-xl px-3 py-2 text-[10px] font-mono overflow-x-auto"
                                 style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(139,92,246,0.2)', color: '#c4b5fd' }}>
                              $ {run.comando_clave}
                            </pre>
                          </div>
                        )}

                        {run.impacto_negocio && (
                          <div className="space-y-1">
                            <p className="text-[9px] font-bold uppercase tracking-wider" style={{ color: 'rgba(255,255,255,0.25)' }}>
                              impacto de negocio
                            </p>
                            <p className="text-[11px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.55)' }}>
                              {run.impacto_negocio}
                            </p>
                          </div>
                        )}

                        {run.recomendacion && (
                          <div className="rounded-xl p-3 space-y-1"
                               style={{ background: 'rgba(74,222,128,0.05)', border: '1px solid rgba(74,222,128,0.15)' }}>
                            <p className="text-[9px] font-bold uppercase tracking-wider" style={{ color: 'rgba(74,222,128,0.5)' }}>
                              recomendación de mitigación
                            </p>
                            <p className="text-[11px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.6)' }}>
                              {run.recomendacion}
                            </p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
