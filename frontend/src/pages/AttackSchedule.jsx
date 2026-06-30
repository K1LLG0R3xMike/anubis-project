import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

const R = {
  primary: '#FF3131',
  primaryDim: 'rgba(255,49,49,0.15)',
  primaryBorder: 'rgba(255,49,49,0.3)',
  card: 'rgba(30,8,8,0.5)',
  bg: '#0a0505',
};

const FREQ_OPTS = [
  { value: 'once',    label: 'Una vez'   },
  { value: 'daily',   label: 'Diario'    },
  { value: 'weekly',  label: 'Semanal'   },
  { value: 'monthly', label: 'Mensual'   },
];

const STATUS_COLOR = {
  pending:   '#ff9800',
  running:   R.primary,
  completed: '#4caf50',
  failed:    '#FF3131',
};

function PulsingDot() {
  return (
    <span className="w-2 h-2 rounded-full shrink-0"
      style={{ backgroundColor: R.primary, animation: 'pulse-red 2s infinite', boxShadow: `0 0 6px ${R.primary}` }} />
  );
}

function SectionLabel({ children }) {
  return (
    <p className="text-[10px] font-bold uppercase tracking-[0.2em] mb-4"
       style={{ color: 'rgba(255,255,255,0.35)' }}>{children}</p>
  );
}

export default function AttackSchedule() {
  const [targets, setTargets]     = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading]     = useState(true);
  const [addOpen, setAddOpen]     = useState(false);
  const [saving, setSaving]       = useState(false);
  const [form, setForm]           = useState({
    target_id: '',
    frequency: 'weekly',
    time: '02:00',
    modules: ['waf', 'whatweb', 'headers', 'certs', 'nikto', 'zap'],
  });

  const ALL_MODULES = ['waf', 'whatweb', 'headers', 'certs', 'nikto', 'zap'];

  const fetchAll = useCallback(async () => {
    try {
      const [tr, sr] = await Promise.all([
        axios.get(`${BASE}/targets/?nocache=${Date.now()}`),
        axios.get(`${BASE}/schedules/?nocache=${Date.now()}`).catch(() => ({ data: [] })),
      ]);
      setTargets(tr.data);
      setSchedules(sr.data);
    } catch {}
  }, []);

  useEffect(() => {
    fetchAll().finally(() => setLoading(false));
    const iv = setInterval(fetchAll, 15000);
    return () => clearInterval(iv);
  }, [fetchAll]);

  const handleSave = async (e) => {
    e.preventDefault();
    if (!form.target_id) return;
    setSaving(true);
    try {
      await axios.post(`${BASE}/schedules/`, form);
      setAddOpen(false);
      setForm({ target_id: '', frequency: 'weekly', time: '02:00', modules: ALL_MODULES });
      fetchAll();
    } catch {}
    finally { setSaving(false); }
  };

  const handleDelete = async (id) => {
    if (!confirm('¿Eliminar esta tarea?')) return;
    try {
      await axios.delete(`${BASE}/schedules/${id}`);
      fetchAll();
    } catch {}
  };

  const toggleModule = (mod) => {
    setForm(f => ({
      ...f,
      modules: f.modules.includes(mod)
        ? f.modules.filter(m => m !== mod)
        : [...f.modules, mod],
    }));
  };

  const active   = schedules.filter(s => s.status === 'running').length;
  const pending  = schedules.filter(s => s.status === 'pending').length;

  return (
    <div className="min-h-screen" style={{ backgroundColor: R.bg }}>

      {/* Header */}
      <div className="flex items-end justify-between px-8 pt-10 pb-6">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.3em] mb-1"
             style={{ color: 'rgba(255,255,255,0.3)' }}>attack_automation</p>
          <h1 className="text-3xl font-black text-white">Programación</h1>
        </div>
        <div className="flex items-center gap-3">
          {active > 0 && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                 style={{ background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>
              <PulsingDot />
              <span className="font-mono text-[10px] font-bold" style={{ color: R.primary }}>
                {active} ACTIVO{active !== 1 ? 'S' : ''}
              </span>
            </div>
          )}
          <button onClick={() => setAddOpen(true)}
            className="px-5 py-2 rounded-xl text-xs font-black text-white transition-all hover:brightness-110 flex items-center gap-1.5"
            style={{ background: R.primary, boxShadow: `0 0 16px ${R.primary}40` }}>
            <span className="material-symbols-outlined text-sm">add</span>
            Nueva Tarea
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="flex gap-4 px-8 mb-8">
        {[
          { label: 'Total',      value: schedules.length, icon: 'calendar_month' },
          { label: 'Pendientes', value: pending,          icon: 'schedule'       },
          { label: 'Activos',    value: active,           icon: 'bolt'           },
          { label: 'Targets',    value: targets.length,   icon: 'radar'          },
        ].map(s => (
          <div key={s.label} className="flex-1 flex items-center gap-3 rounded-xl px-5 py-4"
               style={{ background: R.card, border: `1px solid ${R.primaryBorder}` }}>
            <span className="material-symbols-outlined" style={{ color: R.primary, fontSize: 22 }}>{s.icon}</span>
            <div>
              <p className="text-2xl font-black text-white">{s.value}</p>
              <p className="font-mono text-[10px] uppercase tracking-wider"
                 style={{ color: 'rgba(255,255,255,0.35)' }}>{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Schedule list */}
      <div className="px-8 pb-20">
        {loading ? (
          <div className="flex justify-center py-20">
            <span className="material-symbols-outlined animate-spin" style={{ fontSize: 32, color: R.primary }}>sync</span>
          </div>
        ) : schedules.length === 0 ? (
          <div className="text-center py-24 rounded-xl border-2 border-dashed"
               style={{ borderColor: 'rgba(255,49,49,0.2)' }}>
            <span className="material-symbols-outlined text-5xl mb-3 block" style={{ color: 'rgba(255,49,49,0.3)' }}>
              calendar_month
            </span>
            <p className="text-lg font-black text-white">Sin tareas programadas</p>
            <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.3)' }}>
              Programa escaneos automáticos para tus targets
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {schedules.map(s => {
              const tgt = targets.find(t => t.id === s.target_id);
              const sc = STATUS_COLOR[s.status] || 'rgba(255,255,255,0.3)';
              return (
                <div key={s.id} className="flex items-center gap-4 rounded-xl px-5 py-4"
                     style={{ background: R.card, border: `1px solid ${s.status === 'running' ? R.primary : 'rgba(255,49,49,0.15)'}` }}>

                  {/* Status dot */}
                  <span className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{
                      backgroundColor: sc,
                      boxShadow: s.status === 'running' ? `0 0 8px ${sc}` : undefined,
                      animation: s.status === 'running' ? 'pulse-red 2s infinite' : undefined,
                    }} />

                  {/* Target */}
                  <div className="flex-1 min-w-0">
                    <p className="font-bold text-white">{tgt?.name || `Target #${s.target_id}`}</p>
                    <p className="font-mono text-xs" style={{ color: 'rgba(255,255,255,0.35)' }}>
                      {tgt?.url}
                    </p>
                  </div>

                  {/* Freq */}
                  <div className="text-center">
                    <p className="font-mono text-xs font-bold text-white">{FREQ_OPTS.find(f => f.value === s.frequency)?.label || s.frequency}</p>
                    <p className="font-mono text-[10px]" style={{ color: 'rgba(255,255,255,0.3)' }}>frecuencia</p>
                  </div>

                  {/* Time */}
                  <div className="text-center">
                    <p className="font-mono text-sm font-black" style={{ color: R.primary }}>{s.time || '—'}</p>
                    <p className="font-mono text-[10px]" style={{ color: 'rgba(255,255,255,0.3)' }}>hora</p>
                  </div>

                  {/* Next run */}
                  <div className="text-center">
                    <p className="font-mono text-xs text-white">
                      {s.next_run ? new Date(s.next_run).toLocaleDateString('es-ES') : '—'}
                    </p>
                    <p className="font-mono text-[10px]" style={{ color: 'rgba(255,255,255,0.3)' }}>próximo</p>
                  </div>

                  {/* Modules */}
                  <div className="flex gap-1 flex-wrap max-w-[180px]">
                    {(s.modules || []).map(m => (
                      <span key={m} className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded"
                            style={{ color: R.primary, background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>
                        {m.toUpperCase()}
                      </span>
                    ))}
                  </div>

                  {/* Status badge */}
                  <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded shrink-0"
                        style={{ color: sc, background: `${sc}15`, border: `1px solid ${sc}40` }}>
                    {(s.status || 'pending').toUpperCase()}
                  </span>

                  <button onClick={() => handleDelete(s.id)}
                    className="w-7 h-7 rounded-lg flex items-center justify-center transition-all hover:bg-red-900/40 shrink-0"
                    style={{ color: 'rgba(255,255,255,0.3)' }}>
                    <span className="material-symbols-outlined" style={{ fontSize: 16 }}>delete</span>
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Add modal */}
      {addOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center"
             style={{ background: 'rgba(0,0,0,0.75)' }}
             onClick={e => { if (e.target === e.currentTarget) setAddOpen(false); }}>
          <div className="w-full max-w-lg rounded-2xl p-8"
               style={{ background: '#1a0505', border: `1px solid ${R.primaryBorder}` }}>
            <h2 className="text-xl font-black text-white mb-6">Nueva Tarea Programada</h2>
            <form onSubmit={handleSave} className="space-y-5">

              {/* Target */}
              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider mb-2"
                       style={{ color: 'rgba(255,255,255,0.4)' }}>Target</label>
                <select value={form.target_id} onChange={e => setForm(f => ({ ...f, target_id: e.target.value }))}
                  className="w-full px-4 py-3 rounded-xl font-mono text-sm text-white outline-none"
                  style={{ background: 'rgba(255,255,255,0.05)', border: `1px solid ${R.primaryBorder}` }}>
                  <option value="">Selecciona un target...</option>
                  {targets.map(t => (
                    <option key={t.id} value={t.id}>{t.name} — {t.url}</option>
                  ))}
                </select>
              </div>

              {/* Frequency + Time */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider mb-2"
                         style={{ color: 'rgba(255,255,255,0.4)' }}>Frecuencia</label>
                  <select value={form.frequency} onChange={e => setForm(f => ({ ...f, frequency: e.target.value }))}
                    className="w-full px-4 py-3 rounded-xl font-mono text-sm text-white outline-none"
                    style={{ background: 'rgba(255,255,255,0.05)', border: `1px solid ${R.primaryBorder}` }}>
                    {FREQ_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider mb-2"
                         style={{ color: 'rgba(255,255,255,0.4)' }}>Hora (24h)</label>
                  <input type="time" value={form.time} onChange={e => setForm(f => ({ ...f, time: e.target.value }))}
                    className="w-full px-4 py-3 rounded-xl font-mono text-sm text-white outline-none"
                    style={{ background: 'rgba(255,255,255,0.05)', border: `1px solid ${R.primaryBorder}`, colorScheme: 'dark' }} />
                </div>
              </div>

              {/* Modules */}
              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider mb-2"
                       style={{ color: 'rgba(255,255,255,0.4)' }}>Módulos</label>
                <div className="flex flex-wrap gap-2">
                  {ALL_MODULES.map(m => {
                    const active = form.modules.includes(m);
                    return (
                      <button key={m} type="button" onClick={() => toggleModule(m)}
                        className="px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider transition-all"
                        style={{
                          background: active ? R.primaryDim : 'rgba(255,255,255,0.05)',
                          border: `1px solid ${active ? R.primaryBorder : 'rgba(255,255,255,0.12)'}`,
                          color: active ? R.primary : 'rgba(255,255,255,0.4)',
                        }}>
                        {m}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="flex gap-3 pt-2">
                <button type="button" onClick={() => setAddOpen(false)}
                  className="flex-1 py-3 rounded-xl text-xs font-bold text-white"
                  style={{ border: `1px solid rgba(255,255,255,0.15)` }}>Cancelar</button>
                <button type="submit" disabled={saving || !form.target_id}
                  className="flex-1 py-3 rounded-xl text-xs font-black text-white transition-all hover:brightness-110 disabled:opacity-50"
                  style={{ background: R.primary }}>
                  {saving ? 'Guardando...' : 'Guardar Tarea'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
