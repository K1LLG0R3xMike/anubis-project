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
  info:     'rgba(255,255,255,0.25)',
};

const HEADER_SEV = {
  'Strict-Transport-Security': 'HIGH',
  'Content-Security-Policy': 'MEDIUM',
  'X-Frame-Options': 'MEDIUM',
  'X-Content-Type-Options': 'LOW',
  'Referrer-Policy': 'LOW',
};

const SSL_SEV = { 'SSLv2': 'CRITICAL', 'SSLv3': 'HIGH', 'TLS 1.0': 'MEDIUM', 'TLS 1.1': 'LOW' };

function SevBadge({ sev }) {
  const s = (sev || 'info').toLowerCase();
  const color = SEV_COLOR[s] || SEV_COLOR.info;
  return (
    <span className="font-mono text-[0.6rem] font-bold uppercase tracking-wider px-2 py-0.5 rounded"
      style={{ color, background: `${color}20`, border: `1px solid ${color}50` }}>
      {sev}
    </span>
  );
}

function Card({ children, pulse }) {
  return (
    <div className="rounded-xl p-6"
      style={{
        background: R.card,
        border: `1px solid ${R.primaryBorder}`,
        animation: pulse ? 'neon-pulse 4s ease-in-out infinite' : undefined,
      }}>
      {children}
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <p className="text-[10px] font-bold uppercase tracking-[0.2em] mb-4"
       style={{ color: 'rgba(255,255,255,0.35)' }}>{children}</p>
  );
}

export default function AttackFindings() {
  const [targets, setTargets]       = useState([]);
  const [selected, setSelected]     = useState(null);
  const [loading, setLoading]       = useState(true);
  const [loadingDetail, setDetail]  = useState(false);
  const [waf, setWaf]               = useState(null);
  const [zap, setZap]               = useState(null);
  const [headers, setHeaders]       = useState(null);
  const [certs, setCerts]           = useState(null);
  const [whatweb, setWhatweb]       = useState(null);
  const [nikto, setNikto]           = useState(null);

  useEffect(() => {
    axios.get(`${BASE}/targets/?nocache=${Date.now()}`)
      .then(r => setTargets(r.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selected) return;
    setDetail(true);
    const fn = selected.name.toLowerCase().replace(/\s+/g, '_');
    const ts = Date.now();
    const get = (u, set) => axios.get(u).then(r => set(r.data)).catch(() => set(null));
    Promise.all([
      get(`${BASE}/reports/waf/${fn}.json?t=${ts}`,     setWaf),
      get(`${BASE}/reports/zap/${fn}.json?t=${ts}`,     setZap),
      get(`${BASE}/reports/headers/${fn}.json?t=${ts}`, setHeaders),
      get(`${BASE}/reports/certs/${fn}.json?t=${ts}`,   setCerts),
      get(`${BASE}/reports/whatweb/${fn}.json?t=${ts}`, setWhatweb),
      get(`${BASE}/reports/nikto/${fn}.json?t=${ts}`,   setNikto),
    ]).finally(() => setDetail(false));
  }, [selected?.name]);

  return (
    <div className="min-h-screen flex" style={{ backgroundColor: R.bg }}>

      {/* ── SIDEBAR ── */}
      <aside className="w-72 shrink-0 border-r flex flex-col"
        style={{ borderColor: 'rgba(255,49,49,0.15)', background: 'rgba(20,5,5,0.6)' }}>
        <div className="px-5 pt-7 pb-5 border-b" style={{ borderColor: 'rgba(255,49,49,0.12)' }}>
          <p className="text-[10px] font-bold uppercase tracking-[0.25em] mb-1"
             style={{ color: 'rgba(255,255,255,0.3)' }}>attack_recon</p>
          <h1 className="text-2xl font-black text-white">Findings</h1>
          <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.35)' }}>
            Selecciona un objetivo
          </p>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-3 space-y-1">
          {loading ? (
            <div className="py-8 flex justify-center">
              <span className="material-symbols-outlined text-sm animate-spin"
                    style={{ color: R.primary }}>sync</span>
            </div>
          ) : targets.map(t => (
            <button key={t.id} onClick={() => setSelected(t)}
              className="w-full text-left px-4 py-3 rounded-xl transition-all"
              style={{
                background: selected?.id === t.id ? R.primaryDim : 'transparent',
                border: `1px solid ${selected?.id === t.id ? R.primaryBorder : 'transparent'}`,
              }}>
              <div className="flex items-center gap-3">
                <span className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ backgroundColor: selected?.id === t.id ? R.primary : 'rgba(255,255,255,0.2)' }} />
                <div className="min-w-0">
                  <p className="font-bold text-sm text-white truncate">{t.name}</p>
                  <p className="text-[10px] truncate" style={{ color: 'rgba(255,255,255,0.3)' }}>{t.url}</p>
                </div>
              </div>
            </button>
          ))}
        </div>
      </aside>

      {/* ── MAIN ── */}
      <div className="flex-1 overflow-y-auto px-8 py-8 pb-20">

        {!selected ? (
          <div className="h-full flex flex-col items-center justify-center text-center py-32">
            <span className="material-symbols-outlined text-6xl mb-4"
                  style={{ color: 'rgba(255,49,49,0.3)' }}>security</span>
            <p className="text-xl font-black text-white mb-2">Selecciona un objetivo</p>
            <p className="text-sm" style={{ color: 'rgba(255,255,255,0.3)' }}>
              Elige un target del panel izquierdo para ver su análisis
            </p>
          </div>
        ) : loadingDetail ? (
          <div className="flex flex-col items-center justify-center py-32">
            <span className="material-symbols-outlined animate-spin mb-3"
                  style={{ fontSize: 32, color: R.primary }}>sync</span>
            <p className="text-sm font-mono" style={{ color: 'rgba(255,255,255,0.4)' }}>
              Cargando análisis...
            </p>
          </div>
        ) : (
          <div className="max-w-5xl space-y-6">

            {/* Header */}
            <div className="mb-2">
              <p className="text-[10px] font-bold uppercase tracking-[0.25em] mb-1"
                 style={{ color: 'rgba(255,255,255,0.3)' }}>target_analysis</p>
              <h2 className="text-3xl font-black text-white">{selected.name}</h2>
              <p className="font-mono text-sm mt-1" style={{ color: R.primary }}>{selected.url}</p>
            </div>

            {/* WAF */}
            <div className="rounded-xl p-5 flex items-center gap-5"
              style={{ background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>
              <div className="w-12 h-12 rounded-xl flex items-center justify-center"
                   style={{ background: 'rgba(255,49,49,0.2)', border: `1px solid ${R.primaryBorder}` }}>
                <span className="material-symbols-outlined" style={{ color: R.primary, fontSize: 26 }}>security</span>
              </div>
              <div>
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1"
                   style={{ color: 'rgba(255,255,255,0.35)' }}>firewall_status</p>
                <p className="text-xl font-black text-white">
                  {Array.isArray(waf) && waf.length > 0 ? (waf[0].firewall || 'WAF ACTIVE') : 'NO WAF DETECTED'}
                </p>
              </div>
            </div>

            {/* OWASP ZAP */}
            <Card pulse>
              <SectionLabel>owasp_zap — vulnerability scanner</SectionLabel>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b" style={{ borderColor: 'rgba(255,49,49,0.2)' }}>
                      {['Riesgo', 'Vulnerabilidad', 'Evidencia', 'OWASP ID'].map(h => (
                        <th key={h} className="font-mono text-[10px] uppercase tracking-wider text-left py-3 pr-4"
                            style={{ color: 'rgba(255,255,255,0.35)' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {zap?.vulnerabilities?.length > 0 ? zap.vulnerabilities.map((v, i) => (
                      <tr key={i} className="border-b transition-colors hover:bg-white/5"
                          style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                        <td className="py-3 pr-4"><SevBadge sev={v.severidad} /></td>
                        <td className="py-3 pr-4 font-bold text-sm text-white">{v.vulnerabilidad}</td>
                        <td className="py-3 pr-4 font-mono text-xs max-w-[200px] break-all"
                            style={{ color: 'rgba(255,255,255,0.4)' }}>{v.evidencia}</td>
                        <td className="py-3 font-mono text-xs font-bold" style={{ color: R.primary }}>{v.owasp_id}</td>
                      </tr>
                    )) : (
                      <tr><td colSpan={4} className="py-8 text-center font-mono text-xs"
                              style={{ color: 'rgba(255,255,255,0.2)' }}>// no hay reportes ZAP disponibles</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>

            {/* Headers + SSL */}
            <div className="grid grid-cols-2 gap-6">
              <Card>
                <SectionLabel>http_security_headers</SectionLabel>
                {headers?.security_headers ? (
                  <div className="space-y-2">
                    {Object.entries(headers.security_headers).map(([name, data]) => {
                      const missing = data.status !== 'Presente';
                      const sev = missing ? HEADER_SEV[name] : null;
                      return (
                        <div key={name} className="flex items-center justify-between p-3 rounded-lg"
                             style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}>
                          <p className="font-mono text-xs text-white">{name}</p>
                          <div className="flex items-center gap-2 shrink-0">
                            {sev && <span className="font-mono text-[9px] font-bold px-1.5 py-0.5 rounded"
                              style={{ color: R.primary, background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>{sev}</span>}
                            <span className="material-symbols-outlined text-sm"
                              style={{ color: missing ? R.primary : '#4caf50' }}>
                              {missing ? 'error' : 'check_circle'}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="font-mono text-xs" style={{ color: 'rgba(255,255,255,0.25)' }}>
                    // sin reporte de cabeceras
                  </p>
                )}
              </Card>

              <Card>
                <SectionLabel>ssl_tls_protocols</SectionLabel>
                {certs?.protocols ? (
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(certs.protocols).map(([p, s]) => {
                      const ok = s === 'Soportado';
                      const danger = ok && SSL_SEV[p];
                      return (
                        <div key={p} className="flex items-center justify-between px-3 py-2 rounded-lg"
                             style={{
                               background: danger ? R.primaryDim : ok ? 'rgba(76,175,80,0.1)' : 'rgba(255,255,255,0.04)',
                               border: `1px solid ${danger ? R.primaryBorder : ok ? 'rgba(76,175,80,0.3)' : 'rgba(255,255,255,0.08)'}`,
                             }}>
                          <span className="font-mono text-xs font-bold"
                                style={{ color: danger ? R.primary : ok ? '#4caf50' : 'rgba(255,255,255,0.3)' }}>{p}</span>
                          {danger && <span className="font-mono text-[9px] font-bold"
                                          style={{ color: R.primary }}>{SSL_SEV[p]}</span>}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="font-mono text-xs" style={{ color: 'rgba(255,255,255,0.25)' }}>
                    // sin reporte SSL
                  </p>
                )}
              </Card>
            </div>

            {/* Tech Stack */}
            <Card>
              <SectionLabel>stack_tecnológico — whatweb</SectionLabel>
              <div className="flex flex-wrap gap-2">
                {whatweb?.technologies?.length > 0 ? whatweb.technologies.map((t, i) => (
                  <span key={i} className="font-mono text-xs px-3 py-1 rounded"
                        style={{ color: R.primary, background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>
                    {t}
                  </span>
                )) : (
                  <p className="font-mono text-xs" style={{ color: 'rgba(255,255,255,0.25)' }}>
                    // no se detectaron tecnologías
                  </p>
                )}
              </div>
            </Card>

            {/* Nikto */}
            <Card>
              <SectionLabel>nikto — web server scan</SectionLabel>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b" style={{ borderColor: 'rgba(255,49,49,0.2)' }}>
                      {['Riesgo', 'Método', 'Hallazgo', 'URL'].map(h => (
                        <th key={h} className="font-mono text-[10px] uppercase tracking-wider text-left py-3 pr-4"
                            style={{ color: 'rgba(255,255,255,0.35)' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {nikto?.vulnerabilities?.length > 0 ? nikto.vulnerabilities.map((v, i) => (
                      <tr key={i} className="border-b transition-colors hover:bg-white/5"
                          style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
                        <td className="py-3 pr-4"><SevBadge sev={v.severity || 'low'} /></td>
                        <td className="py-3 pr-4 font-mono text-xs font-bold" style={{ color: R.primary }}>{v.method}</td>
                        <td className="py-3 pr-4 text-sm text-white">{v.msg}</td>
                        <td className="py-3 font-mono text-xs" style={{ color: 'rgba(255,255,255,0.35)' }}>{v.url}</td>
                      </tr>
                    )) : (
                      <tr><td colSpan={4} className="py-8 text-center font-mono text-xs"
                              style={{ color: 'rgba(255,255,255,0.2)' }}>// no hay reportes Nikto</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
