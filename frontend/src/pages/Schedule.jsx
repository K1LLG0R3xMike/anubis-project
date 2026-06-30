import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

const SCAN_MODULES = [
  { id: 'waf',     label: 'WAF Detector',     icon: 'security',      color: '#ff6e84', bgCls: 'bg-error/20 border-error/40',         textCls: 'text-error'     },
  { id: 'whatweb', label: 'Stack Tecnológico', icon: 'terminal',      color: '#9aa8ff', bgCls: 'bg-primary/20 border-primary/40',     textCls: 'text-primary'   },
  { id: 'headers', label: 'HTTP Headers',      icon: 'verified_user', color: '#9aa8ff', bgCls: 'bg-primary/20 border-primary/40',     textCls: 'text-primary'   },
  { id: 'certs',   label: 'SSL Scan',          icon: 'radar',         color: '#ff8f06', bgCls: 'bg-secondary/20 border-secondary/40', textCls: 'text-secondary' },
  { id: 'nikto',   label: 'Nikto Vulns',       icon: 'bug_report',    color: '#b374f7', bgCls: 'bg-tertiary/20 border-tertiary/40',   textCls: 'text-tertiary'  },
  { id: 'zap',     label: 'OWASP ZAP',         icon: 'gpp_good',      color: '#ff6e84', bgCls: 'bg-error/20 border-error/40',         textCls: 'text-error'     },
];

const REPEAT_OPTIONS = [
  { value: 'once',    label: 'Una vez' },
  { value: 'daily',   label: 'Diario'  },
  { value: 'weekly',  label: 'Semanal' },
  { value: 'monthly', label: 'Mensual' },
];

const DAY_LABELS = ['Lun', 'Mar', 'Mié', 'Jue', 'Vie', 'Sáb', 'Dom'];
const HOURS = Array.from({ length: 16 }, (_, i) => i + 7); // 7:00 – 22:00
const HOUR_H = 64;
const START_HOUR = 7;

function getWeekStart(date) {
  const d = new Date(date);
  const dow = d.getDay();
  d.setDate(d.getDate() + (dow === 0 ? -6 : 1 - dow));
  d.setHours(0, 0, 0, 0);
  return d;
}

function addDays(date, n) {
  const d = new Date(date);
  d.setDate(d.getDate() + n);
  return d;
}

function isSameDay(a, b) {
  return a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate();
}

function toLocalISO(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

export default function Schedule() {
  const [weekStart, setWeekStart]   = useState(() => getWeekStart(new Date()));
  const [schedules, setSchedules]   = useState([]);
  const [targets, setTargets]       = useState([]);
  const [openModal, setOpenModal]   = useState(false);
  const [saving, setSaving]         = useState(false);
  const [form, setForm]             = useState({ target_ids: [], modules: [], date: '', time: '09:00', repeat: 'once' });
  const [tooltip, setTooltip]       = useState(null); // { ev, x, y }
  const gridRef = useRef(null);

  const fetchData = async () => {
    try {
      const [s, t] = await Promise.all([
        axios.get(`${BASE}/schedules/`),
        axios.get(`${BASE}/targets/`),
      ]);
      setSchedules(s.data);
      setTargets(t.data);
    } catch (e) { console.error(e); }
  };

  useEffect(() => { fetchData(); }, []);

  const today    = new Date();
  const weekDays = Array.from({ length: 7 }, (_, i) => addDays(weekStart, i));

  const getEventsForDay = (dayDate) =>
    schedules.filter(s => {
      const d = new Date(s.scheduled_at);
      switch (s.repeat) {
        case 'once':    return isSameDay(d, dayDate);
        case 'daily':   return true;
        case 'weekly':  return d.getDay() === dayDate.getDay();
        case 'monthly': return d.getDate() === dayDate.getDate();
        default:        return false;
      }
    });

  const toggleTarget = (id) => {
    setForm(f => ({
      ...f,
      target_ids: f.target_ids.includes(id)
        ? f.target_ids.filter(x => x !== id)
        : [...f.target_ids, id],
    }));
  };

  const toggleAllTargets = () => {
    setForm(f => ({
      ...f,
      target_ids: f.target_ids.length === targets.length ? [] : targets.map(t => t.id),
    }));
  };

  const toggleModule = (id) => {
    setForm(f => ({
      ...f,
      modules: f.modules.includes(id)
        ? f.modules.filter(x => x !== id)
        : [...f.modules, id],
    }));
  };

  const toggleAllModules = () => {
    setForm(f => ({
      ...f,
      modules: f.modules.length === SCAN_MODULES.length ? [] : SCAN_MODULES.map(m => m.id),
    }));
  };

  const openCreate = (dateStr = '') => {
    const def = dateStr || toLocalISO(new Date());
    setForm({ target_ids: [], modules: [], date: def, time: '09:00', repeat: 'once' });
    setTooltip(null);
    setOpenModal(true);
  };

  const handleCreate = async () => {
    if (form.target_ids.length === 0 || !form.date || !form.time) return alert('Selecciona al menos un objetivo y una fecha/hora');
    if (form.modules.length === 0) return alert('Selecciona al menos un módulo de escaneo');
    setSaving(true);
    try {
      await axios.post(`${BASE}/schedules/`, {
        target_ids:   form.target_ids,
        modules:      form.modules,
        scheduled_at: `${form.date}T${form.time}:00`,
        repeat:       form.repeat,
      });
      setOpenModal(false);
      fetchData();
    } catch { alert('Error al guardar el escaneo programado'); }
    finally { setSaving(false); }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('¿Eliminar este escaneo programado?')) return;
    setTooltip(null);
    await axios.delete(`${BASE}/schedules/${id}`);
    fetchData();
  };

  const weekRange = () => {
    const end  = addDays(weekStart, 6);
    const opts = { day: 'numeric', month: 'short' };
    return `${weekStart.toLocaleDateString('es-ES', opts)} – ${end.toLocaleDateString('es-ES', { ...opts, year: 'numeric' })}`;
  };

  const getMod = (id) => SCAN_MODULES.find(m => m.id === id) || SCAN_MODULES[0];
  const getFirstMod = (ev) => getMod(Array.isArray(ev.modules) ? ev.modules[0] : ev.modules);

  const repeatBadge = { once: 'Una vez', daily: 'Diario', weekly: 'Semanal', monthly: 'Mensual' };

  // ─── Upcoming list (next 7 days) ────────────────────────────
  const upcomingKeys = new Set();
  const upcoming = schedules
    .flatMap(s => {
      const results = [];
      for (let i = 0; i < 7; i++) {
        const day = addDays(today, i);
        const d = new Date(s.scheduled_at);
        let match = false;
        if (s.repeat === 'once'    && isSameDay(d, day))              match = true;
        if (s.repeat === 'daily')                                       match = true;
        if (s.repeat === 'weekly'  && d.getDay() === day.getDay())     match = true;
        if (s.repeat === 'monthly' && d.getDate() === day.getDate())   match = true;
        if (match) {
          const key = `${s.id}-${toLocalISO(day)}`;
          if (!upcomingKeys.has(key)) {
            upcomingKeys.add(key);
            results.push({ ...s, dayDate: day });
          }
        }
      }
      return results;
    })
    .sort((a, b) => {
      const da = new Date(a.scheduled_at), db = new Date(b.scheduled_at);
      const ta = a.dayDate.getTime() + da.getHours() * 3600000 + da.getMinutes() * 60000;
      const tb = b.dayDate.getTime() + db.getHours() * 3600000 + db.getMinutes() * 60000;
      return ta - tb;
    })
    .slice(0, 8);

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto" onClick={() => setTooltip(null)}>

      {/* ─── HEADER ─────────────────────────────────────────────── */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">scan_scheduler</p>
          <h2 className="font-headline text-3xl font-bold text-on-background tracking-tight">Programar Escaneos</h2>
          <p className="text-sm text-on-surface-variant font-body mt-1">Agenda módulos de análisis sobre tus objetivos registrados</p>
        </div>
        <button onClick={() => openCreate()}
          className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg bg-primary text-on-primary text-xs font-bold uppercase tracking-[0.05em] hover:bg-primary-dim transition-colors shrink-0"
          style={{ boxShadow: '0 4px 12px rgba(154,168,255,0.2)' }}>
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>add</span>
          Nuevo Escaneo
        </button>
      </div>

      <div className="flex gap-6">

        {/* ─── CALENDAR ────────────────────────────────────────────── */}
        <div className="flex-1 min-w-0">

          {/* Week nav */}
          <div className="flex items-center gap-2 mb-3">
            <button onClick={() => setWeekStart(w => addDays(w, -7))}
              className="w-8 h-8 rounded-lg border border-outline-variant/30 text-on-surface-variant hover:text-primary hover:border-primary/40 flex items-center justify-center transition-all">
              <span className="material-symbols-outlined" style={{ fontSize: 18 }}>chevron_left</span>
            </button>
            <button onClick={() => setWeekStart(getWeekStart(new Date()))}
              className="px-3 py-1.5 rounded-lg border border-outline-variant/30 font-mono text-xs text-on-surface-variant hover:border-primary/40 hover:text-primary transition-all">
              Hoy
            </button>
            <button onClick={() => setWeekStart(w => addDays(w, 7))}
              className="w-8 h-8 rounded-lg border border-outline-variant/30 text-on-surface-variant hover:text-primary hover:border-primary/40 flex items-center justify-center transition-all">
              <span className="material-symbols-outlined" style={{ fontSize: 18 }}>chevron_right</span>
            </button>
            <span className="font-mono text-sm text-on-surface font-semibold ml-1">{weekRange()}</span>
          </div>

          {/* Grid */}
          <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 overflow-hidden">

            {/* Day headers */}
            <div className="grid border-b border-outline-variant/20"
              style={{ gridTemplateColumns: '52px repeat(7, 1fr)' }}>
              <div className="border-r border-outline-variant/10" />
              {weekDays.map((day, i) => {
                const isToday = isSameDay(day, today);
                return (
                  <div key={i} className="py-3 text-center border-r border-outline-variant/10 last:border-r-0">
                    <p className={`font-mono text-[0.58rem] uppercase tracking-[0.12em] mb-0.5 ${isToday ? 'text-primary' : 'text-on-surface-variant'}`}>
                      {DAY_LABELS[i]}
                    </p>
                    <div className={`mx-auto w-7 h-7 rounded-full flex items-center justify-center ${isToday ? 'bg-primary' : ''}`}>
                      <span className={`font-headline text-sm font-bold ${isToday ? 'text-on-primary' : 'text-on-surface'}`}>
                        {day.getDate()}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Scrollable time grid */}
            <div className="overflow-y-auto" style={{ maxHeight: '62vh' }} ref={gridRef}>
              <div className="relative">

                {/* Hour rows */}
                <div className="grid" style={{ gridTemplateColumns: '52px repeat(7, 1fr)' }}>
                  {HOURS.map(hour => (
                    <React.Fragment key={hour}>
                      <div className="border-r border-b border-outline-variant/10 flex items-start justify-end pr-2 pt-1"
                        style={{ height: HOUR_H }}>
                        <span className="font-mono text-[0.58rem] text-outline select-none">
                          {String(hour).padStart(2, '0')}:00
                        </span>
                      </div>
                      {weekDays.map((day, di) => (
                        <div key={di}
                          onClick={() => openCreate(toLocalISO(day))}
                          title={`Programar el ${day.toLocaleDateString('es-ES')} a las ${String(hour).padStart(2,'0')}:00`}
                          className={`border-r border-b border-outline-variant/10 last:border-r-0 cursor-pointer transition-colors hover:bg-primary/5
                            ${isSameDay(day, today) ? 'bg-primary/[0.025]' : ''}`}
                          style={{ height: HOUR_H }}
                        />
                      ))}
                    </React.Fragment>
                  ))}
                </div>

                {/* Events overlay */}
                <div className="absolute inset-0 pointer-events-none"
                  style={{ display: 'grid', gridTemplateColumns: '52px repeat(7, 1fr)' }}>
                  <div />
                  {weekDays.map((day, di) => {
                    const events = getEventsForDay(day);
                    return (
                      <div key={di} className="relative">
                        {events.map((ev, ei) => {
                          const evDate = new Date(ev.scheduled_at);
                          const evH = evDate.getHours();
                          const evM = evDate.getMinutes();
                          if (evH < START_HOUR || evH >= START_HOUR + HOURS.length) return null;
                          const top = (evH - START_HOUR) * HOUR_H + (evM / 60) * HOUR_H;
                          const mod = getFirstMod(ev);
                          const evModules = Array.isArray(ev.modules) ? ev.modules : [ev.modules];
                          return (
                            <div key={`${ev.id}-${di}`}
                              className="absolute left-0.5 right-0.5 pointer-events-auto"
                              style={{ top: top + 2, height: HOUR_H - 6, zIndex: 10 + ei }}>
                              <div
                                className={`h-full rounded-lg border px-2 py-1 overflow-hidden cursor-pointer group transition-all hover:brightness-110 ${mod.bgCls}`}
                                style={{ borderLeftWidth: 3, borderLeftColor: mod.color }}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setTooltip(t => (t?.ev.id === ev.id && t?.di === di) ? null : { ev, di, top });
                                }}
                              >
                                <div className="flex items-center gap-0.5 flex-wrap">
                                  {evModules.slice(0, 3).map(mid => {
                                    const mm = getMod(mid);
                                    return <span key={mid} className={`material-symbols-outlined ${mm.textCls} shrink-0`} style={{ fontSize: 10 }}>{mm.icon}</span>;
                                  })}
                                  {evModules.length > 3 && <span className="font-mono text-[0.45rem] text-outline">+{evModules.length - 3}</span>}
                                </div>
                                <p className="font-body text-[0.6rem] text-on-surface truncate">{ev.target_name}</p>
                                <p className="font-mono text-[0.5rem] text-outline">
                                  {String(evH).padStart(2,'0')}:{String(evM).padStart(2,'0')}
                                  {ev.repeat !== 'once' && <span className="ml-1 opacity-70">↻</span>}
                                </p>
                              </div>

                              {/* Inline tooltip */}
                              {tooltip?.ev.id === ev.id && tooltip?.di === di && (
                                <div
                                  className="absolute left-full ml-1 z-50 w-48 rounded-xl border border-outline-variant/30 p-3 shadow-2xl pointer-events-auto"
                                  style={{ backgroundColor: '#1d1f2a', top: 0 }}
                                  onClick={e => e.stopPropagation()}>
                                  <div className="flex flex-wrap gap-1 mb-2">
                                    {evModules.map(mid => {
                                      const mm = getMod(mid);
                                      return (
                                        <span key={mid} className={`flex items-center gap-0.5 px-1.5 py-0.5 rounded-md border font-mono text-[0.52rem] uppercase ${mm.bgCls} ${mm.textCls}`}>
                                          <span className="material-symbols-outlined" style={{ fontSize: 9 }}>{mm.icon}</span>
                                          {mid}
                                        </span>
                                      );
                                    })}
                                  </div>
                                  <p className="font-body text-xs text-on-surface font-medium mb-1">{ev.target_name}</p>
                                  <p className="font-mono text-[0.6rem] text-on-surface-variant mb-1">
                                    {String(evH).padStart(2,'0')}:{String(evM).padStart(2,'0')} · {repeatBadge[ev.repeat]}
                                  </p>
                                  <button
                                    onClick={() => handleDelete(ev.id)}
                                    className="mt-2 w-full py-1.5 rounded-lg border border-error/30 text-error font-mono text-[0.6rem] uppercase tracking-[0.06em] hover:bg-error/10 transition-colors flex items-center justify-center gap-1">
                                    <span className="material-symbols-outlined" style={{ fontSize: 12 }}>delete_outline</span>
                                    Eliminar
                                  </button>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    );
                  })}
                </div>

              </div>
            </div>
          </div>
        </div>

        {/* ─── SIDEBAR: Upcoming ──────────────────────────────────── */}
        <div className="w-60 shrink-0 hidden lg:block">
          <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-3">próximos_7_días</p>

          {/* Module legend */}
          <div className="bg-surface-container-low rounded-xl border border-outline-variant/20 p-4 mb-4">
            <p className="font-mono text-[0.58rem] text-outline uppercase tracking-[0.12em] mb-2">módulos</p>
            <div className="space-y-1.5">
              {SCAN_MODULES.map(m => (
                <div key={m.id} className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ backgroundColor: m.color, opacity: 0.8 }} />
                  <span className="font-mono text-[0.6rem] text-on-surface-variant">{m.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Upcoming events list */}
          <div className="space-y-2">
            {upcoming.length === 0 && (
              <div className="text-center py-8 border-2 border-dashed border-outline-variant/20 rounded-xl">
                <span className="material-symbols-outlined text-3xl text-outline block mb-2">event_busy</span>
                <p className="font-mono text-[0.6rem] text-outline">Sin escaneos próximos</p>
              </div>
            )}
            {upcoming.map((ev, i) => {
              const evModules = Array.isArray(ev.modules) ? ev.modules : [ev.modules];
              const mod = getFirstMod(ev);
              const evDate = new Date(ev.scheduled_at);
              const isEv_today = isSameDay(ev.dayDate, today);
              return (
                <div key={i}
                  className="bg-surface-container-low rounded-xl border border-outline-variant/20 p-3 transition-all hover:border-outline-variant/40"
                  style={{ borderLeftWidth: 3, borderLeftColor: mod.color }}>
                  <div className="flex items-center gap-1 mb-1.5 flex-wrap">
                    {evModules.map(mid => {
                      const mm = getMod(mid);
                      return (
                        <span key={mid} className={`flex items-center gap-0.5 font-mono text-[0.52rem] font-bold uppercase ${mm.textCls}`}>
                          <span className="material-symbols-outlined" style={{ fontSize: 11 }}>{mm.icon}</span>
                          {mid}
                        </span>
                      );
                    })}
                    {ev.repeat !== 'once' && (
                      <span className="ml-auto font-mono text-[0.5rem] text-outline">↻</span>
                    )}
                  </div>
                  <p className="font-body text-xs text-on-surface font-medium truncate">{ev.target_name}</p>
                  <p className="font-mono text-[0.58rem] text-on-surface-variant mt-1">
                    {isEv_today ? 'Hoy' : ev.dayDate.toLocaleDateString('es-ES', { weekday: 'short', day: 'numeric', month: 'short' })}
                    {' · '}
                    {String(evDate.getHours()).padStart(2,'0')}:{String(evDate.getMinutes()).padStart(2,'0')}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

      </div>

      {/* ─── MODAL: NUEVO SCHEDULE ──────────────────────────────── */}
      {openModal && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
          onClick={() => setOpenModal(false)}>
          <div className="relative w-full max-w-sm rounded-2xl p-8"
            style={{ backgroundColor: '#1d1f2a', border: '1px solid rgba(70,71,81,0.25)', boxShadow: '0 24px 60px rgba(0,0,0,0.5)' }}
            onClick={e => e.stopPropagation()}>

            <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">new_schedule</p>
            <div className="flex items-center justify-between mb-6">
              <h3 className="font-headline text-xl font-bold text-on-surface">Programar Escaneo</h3>
              <button onClick={() => setOpenModal(false)} className="text-on-surface-variant hover:text-primary transition-colors">
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            <div className="space-y-4">

              {/* Targets multi-select */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em]">
                    Objetivos
                    {form.target_ids.length > 0 && (
                      <span className="ml-2 text-primary">({form.target_ids.length} seleccionados)</span>
                    )}
                  </label>
                  <button type="button" onClick={toggleAllTargets}
                    className="font-mono text-[0.58rem] text-on-surface-variant uppercase tracking-[0.08em] hover:text-primary transition-colors">
                    {form.target_ids.length === targets.length ? 'Ninguno' : 'Todos'}
                  </button>
                </div>
                <div className="max-h-36 overflow-y-auto rounded-lg border border-outline-variant/30 bg-surface-container-lowest divide-y divide-outline-variant/10">
                  {targets.length === 0 && (
                    <p className="px-4 py-3 font-mono text-xs text-outline">Sin objetivos registrados</p>
                  )}
                  {targets.map(t => {
                    const checked = form.target_ids.includes(t.id);
                    return (
                      <label key={t.id}
                        className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-colors hover:bg-primary/5 ${checked ? 'bg-primary/5' : ''}`}>
                        <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${
                          checked ? 'bg-primary border-primary' : 'border-outline-variant/50'}`}
                          onClick={() => toggleTarget(t.id)}>
                          {checked && <span className="material-symbols-outlined text-on-primary" style={{ fontSize: 12 }}>check</span>}
                        </div>
                        <div className="min-w-0" onClick={() => toggleTarget(t.id)}>
                          <p className="font-body text-sm text-on-surface font-medium leading-tight">{t.name}</p>
                          <p className="font-mono text-[0.6rem] text-outline truncate">{t.url}</p>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* Module selector */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em]">
                    Módulos de escaneo
                    {form.modules.length > 0 && (
                      <span className="ml-2 text-primary">({form.modules.length} seleccionados)</span>
                    )}
                  </label>
                  <button type="button" onClick={toggleAllModules}
                    className="font-mono text-[0.58rem] text-on-surface-variant uppercase tracking-[0.08em] hover:text-primary transition-colors">
                    {form.modules.length === SCAN_MODULES.length ? 'Ninguno' : 'Todos'}
                  </button>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  {SCAN_MODULES.map(m => {
                    const selected = form.modules.includes(m.id);
                    return (
                      <button key={m.id} type="button"
                        onClick={() => toggleModule(m.id)}
                        className={`flex flex-col items-center gap-1 p-2.5 rounded-lg border text-center transition-all
                          ${selected
                            ? `${m.bgCls}`
                            : 'border-outline-variant/20 bg-surface-container-lowest hover:border-outline-variant/40'}`}>
                        <span className={`material-symbols-outlined ${selected ? m.textCls : 'text-on-surface-variant'}`} style={{ fontSize: 18 }}>
                          {m.icon}
                        </span>
                        <span className={`font-mono text-[0.5rem] uppercase tracking-[0.06em] leading-tight ${selected ? m.textCls : 'text-on-surface-variant'}`}>
                          {m.id}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Date + Time */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em] mb-1.5">Fecha</label>
                  <input type="date" value={form.date} onChange={e => setForm(f => ({ ...f, date: e.target.value }))}
                    className="w-full rounded-lg px-3 py-3 text-sm font-body text-on-surface bg-surface-container-lowest border border-outline-variant/30 hover:border-outline-variant/60 focus:border-primary outline-none transition-colors" />
                </div>
                <div>
                  <label className="block font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em] mb-1.5">Hora</label>
                  <input type="time" value={form.time} onChange={e => setForm(f => ({ ...f, time: e.target.value }))}
                    className="w-full rounded-lg px-3 py-3 text-sm font-body text-on-surface bg-surface-container-lowest border border-outline-variant/30 hover:border-outline-variant/60 focus:border-primary outline-none transition-colors" />
                </div>
              </div>

              {/* Repeat */}
              <div>
                <label className="block font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em] mb-1.5">Repetición</label>
                <div className="grid grid-cols-4 gap-1.5">
                  {REPEAT_OPTIONS.map(r => (
                    <button key={r.value} type="button"
                      onClick={() => setForm(f => ({ ...f, repeat: r.value }))}
                      className={`py-2 rounded-lg border font-mono text-[0.58rem] uppercase tracking-[0.05em] transition-all
                        ${form.repeat === r.value
                          ? 'bg-primary/20 border-primary/50 text-primary'
                          : 'border-outline-variant/20 text-on-surface-variant hover:border-outline-variant/50'}`}>
                      {r.label}
                    </button>
                  ))}
                </div>
              </div>

              <button onClick={handleCreate} disabled={saving}
                className="w-full py-3 rounded-xl bg-primary text-on-primary font-bold text-sm uppercase tracking-[0.05em] hover:bg-primary-dim active:scale-[0.98] transition-all mt-2 disabled:opacity-50"
                style={{ boxShadow: '0 8px 24px rgba(154,168,255,0.2)' }}>
                {saving ? 'Guardando...' : '› Programar Escaneo'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
