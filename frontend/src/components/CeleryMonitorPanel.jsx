import React, { useEffect, useState } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

const QUEUE_LABEL = {
  light:  { label: 'Light',  desc: 'waf · whatweb · headers · certs', color: '#9aa8ff' },
  heavy:  { label: 'Heavy',  desc: 'zap · nikto',                     color: '#ff8f06' },
  attack: { label: 'Attack', desc: 'execute_attack_run',              color: '#ff6e84' },
  beat:   { label: 'Beat',   desc: 'scheduler',                       color: '#9aa8ff' },
};

const shortTaskName = (name = '') => name.split('.').pop();

const fmtElapsed = (s) => {
  if (s == null) return '—';
  if (s < 60) return `${Math.round(s)}s`;
  const m = Math.floor(s / 60);
  const rem = Math.round(s % 60);
  return `${m}m ${rem}s`;
};

export default function CeleryMonitorPanel({ onClose }) {
  const [data, setData]     = useState(null);
  const [error, setError]   = useState(false);

  const fetchStatus = async () => {
    try {
      const res = await axios.get(`${BASE}/system/celery-status?nocache=${Date.now()}`);
      setData(res.data);
      setError(false);
    } catch {
      setError(true);
    }
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchStatus();
    const iv = setInterval(fetchStatus, 3000);
    return () => clearInterval(iv);
  }, []);

  const totals = data?.totals;

  return (
    <div className="w-full lg:w-80 shrink-0 rounded-2xl border border-outline-variant/20 bg-surface-container-low p-5 h-fit lg:sticky lg:top-24">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-primary" style={{ fontSize: 18 }}>dns</span>
          <div>
            <p className="font-mono text-[0.58rem] text-on-surface-variant uppercase tracking-[0.18em] leading-none">celery_monitor</p>
            <p className="font-headline text-sm font-bold text-on-surface">Estado de Workers</p>
          </div>
        </div>
        {onClose && (
          <button onClick={onClose} className="text-on-surface-variant hover:text-primary transition-colors">
            <span className="material-symbols-outlined" style={{ fontSize: 18 }}>close</span>
          </button>
        )}
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg border border-error/30 bg-error/10 text-error text-xs font-mono mb-3">
          <span className="material-symbols-outlined" style={{ fontSize: 16 }}>error</span>
          No se pudo conectar con el backend
        </div>
      )}

      {!error && !data && (
        <p className="font-mono text-xs text-outline">// consultando workers...</p>
      )}

      {data && (
        <>
          <div className="grid grid-cols-3 gap-2 mb-5">
            <div className="rounded-xl bg-surface-container-lowest border border-outline-variant/20 p-3 text-center">
              <p className="font-headline text-lg font-bold text-primary">{totals.workers_online}</p>
              <p className="font-mono text-[0.55rem] text-on-surface-variant uppercase tracking-[0.1em]">workers</p>
            </div>
            <div className="rounded-xl bg-surface-container-lowest border border-outline-variant/20 p-3 text-center">
              <p className="font-headline text-lg font-bold text-secondary">{totals.active_tasks}</p>
              <p className="font-mono text-[0.55rem] text-on-surface-variant uppercase tracking-[0.1em]">activas</p>
            </div>
            <div className="rounded-xl bg-surface-container-lowest border border-outline-variant/20 p-3 text-center">
              <p className="font-headline text-lg font-bold text-on-surface-variant">{totals.reserved_tasks}</p>
              <p className="font-mono text-[0.55rem] text-on-surface-variant uppercase tracking-[0.1em]">en cola</p>
            </div>
          </div>

          <div className="space-y-3">
            {data.workers.length === 0 && (
              <p className="font-mono text-xs text-outline">// no hay workers respondiendo</p>
            )}
            {data.workers.map((w) => {
              const meta = QUEUE_LABEL[w.queue] || { label: w.queue, desc: '', color: '#9aa8ff' };
              const busy = w.active_tasks.length > 0;
              return (
                <div key={w.hostname}
                  className="rounded-xl border border-outline-variant/20 bg-surface-container-lowest p-3.5">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{ backgroundColor: busy ? meta.color : '#9aa8ff', boxShadow: `0 0 6px ${busy ? meta.color : '#9aa8ff'}` }} />
                      <p className="font-headline text-xs font-bold text-on-surface">{meta.label}</p>
                    </div>
                    <span className="font-mono text-[0.55rem] font-semibold uppercase tracking-[0.08em] px-1.5 py-0.5 rounded"
                      style={{ color: busy ? meta.color : '#9aa8ff', background: busy ? `${meta.color}1a` : 'rgba(154,168,255,0.1)' }}>
                      {busy ? 'ejecutando' : 'idle'}
                    </span>
                  </div>
                  <p className="font-mono text-[0.58rem] text-on-surface-variant mb-2">{meta.desc}</p>

                  {w.active_tasks.length === 0 && w.reserved_tasks.length === 0 ? (
                    <p className="font-mono text-[0.6rem] text-outline">sin tareas activas</p>
                  ) : (
                    <div className="space-y-1.5">
                      {w.active_tasks.map((t) => (
                        <div key={t.id} className="px-2 py-1.5 rounded-lg bg-primary/5 border border-primary/15">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-[0.62rem] text-primary font-semibold truncate">{t.tool || shortTaskName(t.name)}</span>
                            <span className="font-mono text-[0.55rem] text-on-surface-variant shrink-0">{fmtElapsed(t.elapsed_seconds)}</span>
                          </div>
                          {t.detail && (
                            <p className="font-mono text-[0.55rem] text-on-surface-variant truncate mt-0.5">{t.detail}</p>
                          )}
                        </div>
                      ))}
                      {w.reserved_tasks.map((t) => (
                        <div key={t.id} className="px-2 py-1.5 rounded-lg bg-surface-container-low border border-outline-variant/15">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-[0.62rem] text-on-surface-variant font-semibold truncate">{t.tool || shortTaskName(t.name)}</span>
                            <span className="font-mono text-[0.55rem] text-outline shrink-0 uppercase">en espera</span>
                          </div>
                          {t.detail && (
                            <p className="font-mono text-[0.55rem] text-outline truncate mt-0.5">{t.detail}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
