import React, { useEffect, useState, useCallback, useRef } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

const HEADER_SEV = {
  'Strict-Transport-Security': 'high',
  'Content-Security-Policy':   'medium',
  'X-Frame-Options':           'medium',
  'X-Content-Type-Options':    'low',
  'Referrer-Policy':           'low',
};

const SSL_SEV = {
  'SSLv2':   'critical',
  'SSLv3':   'high',
  'TLS 1.0': 'medium',
  'TLS 1.1': 'low',
};

function aggregateFindings(zap, nikto, hdrs, cert) {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  zap?.vulnerabilities?.forEach(v => {
    const s = (v.severidad || '').toLowerCase();
    if (s.includes('high'))   c.high++;
    else if (s.includes('medium')) c.medium++;
    else if (s.includes('low'))    c.low++;
  });
  nikto?.vulnerabilities?.forEach(v => {
    const s = (v.severity || '').toLowerCase();
    if (s === 'high')   c.high++;
    else if (s === 'medium') c.medium++;
    else if (s === 'low')    c.low++;
  });
  if (hdrs?.security_headers) {
    Object.entries(hdrs.security_headers).forEach(([name, data]) => {
      if (data.status === 'Faltante' && HEADER_SEV[name]) c[HEADER_SEV[name]]++;
    });
  }
  if (cert?.protocols) {
    Object.entries(cert.protocols).forEach(([proto, status]) => {
      if (status === 'Soportado' && SSL_SEV[proto]) c[SSL_SEV[proto]]++;
    });
  }
  return c;
}

const SCAN_TOOLS = {
  waf:     { label: 'WAF',     desc: 'Firewall fingerprint'       },
  whatweb: { label: 'WhatWeb', desc: 'Tech stack fingerprinting'  },
  headers: { label: 'Headers', desc: 'HTTP security headers'      },
  certs:   { label: 'SSLScan', desc: 'TLS/SSL config analysis'    },
  nikto:   { label: 'Nikto',   desc: 'Web server vuln scan'       },
  zap:     { label: 'ZAP',     desc: 'OWASP active web app scan'  },
};

const SEVERITY_BARS = [
  { key: 'critical', label: 'Critical', bg: '#ff6e84', dim: 'rgba(255,110,132,0.15)', text: '#ff6e84' },
  { key: 'high',     label: 'High',     bg: '#ff8f06', dim: 'rgba(255,143,6,0.15)',   text: '#ff8f06' },
  { key: 'medium',   label: 'Medium',   bg: '#ff7161', dim: 'rgba(255,113,97,0.15)',  text: '#ff7161' },
  { key: 'low',      label: 'Low',      bg: '#9aa8ff', dim: 'rgba(154,168,255,0.15)', text: '#9aa8ff' },
];

export default function Dashboard() {
  const [backendStatus, setBackendStatus] = useState('Checking...');
  const [isModalOpen, setIsModalOpen]     = useState(false);
  const [targetName, setTargetName]       = useState('');
  const [targetUrl, setTargetUrl]         = useState('');
  const [launching, setLaunching]         = useState(false);
  const [targets, setTargets]             = useState([]);
  const [scanConfig, setScanConfig]       = useState({
    waf: true, whatweb: true, headers: true, certs: true, nikto: false, zap: false,
  });
  const [stats, setStats] = useState({ total_targets: 0 });
  const [selectedChartTarget, setSelectedChartTarget] = useState(null);
  const [chartDist, setChartDist]   = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [loadingChart, setLoadingChart] = useState(false);
  const prevTargetsLen = useRef(0);

  const loadChartData = useCallback(async (targetList, selTarget) => {
    if (!targetList.length) return;
    setLoadingChart(true);
    const tryFetch = async (url) => { try { return (await axios.get(url)).data; } catch { return null; } };
    const list = selTarget ? [selTarget] : targetList;
    const totals = { critical: 0, high: 0, medium: 0, low: 0 };
    await Promise.all(list.map(async (t) => {
      const fn = t.name.toLowerCase().trim().replace(/\s+/g, '_');
      const ts = Date.now();
      const [zap, nikto, hdrs, cert] = await Promise.all([
        tryFetch(`${BASE}/reports/zap/${fn}.json?t=${ts}`),
        tryFetch(`${BASE}/reports/nikto/${fn}.json?t=${ts}`),
        tryFetch(`${BASE}/reports/headers/${fn}.json?t=${ts}`),
        tryFetch(`${BASE}/reports/certs/${fn}.json?t=${ts}`),
      ]);
      const d = aggregateFindings(zap, nikto, hdrs, cert);
      totals.critical += d.critical;
      totals.high     += d.high;
      totals.medium   += d.medium;
      totals.low      += d.low;
    }));
    setChartDist({ ...totals });
    setLoadingChart(false);
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const res = await axios.get(`${BASE}/targets/?nocache=${Date.now()}`);
      const tgts = res.data;
      setTargets(tgts);
      setBackendStatus('Online');
      setStats({ total_targets: tgts.length });
    } catch {
      setBackendStatus('Offline');
    }
  }, []);

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 5000);
    return () => clearInterval(iv);
  }, [fetchData]);

  // Reload chart when targets count changes or selected target changes
  useEffect(() => {
    if (targets.length > 0 && targets.length !== prevTargetsLen.current) {
      prevTargetsLen.current = targets.length;
      loadChartData(targets, selectedChartTarget);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targets.length]);

  useEffect(() => {
    if (targets.length > 0) loadChartData(targets, selectedChartTarget);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedChartTarget]);

  const handleLaunch = async (e) => {
    e?.preventDefault();
    if (!targetName || !targetUrl) return;
    setLaunching(true);
    try {
      await axios.post(`${BASE}/targets/`, { name: targetName, url: targetUrl });
      const selected = Object.entries(scanConfig).filter(([, v]) => v).map(([k]) => k);
      for (const mod of selected) {
        await axios.post(`${BASE}/run-${mod}`);
      }
      setIsModalOpen(false);
      setTargetName('');
      setTargetUrl('');
      fetchData();
    } catch (err) {
      alert('Error: ' + (err.response?.data?.detail || err.message));
    } finally {
      setLaunching(false);
    }
  };

  const totalVulns = chartDist.critical + chartDist.high + chartDist.medium + chartDist.low;
  const maxVal = Math.max(chartDist.critical, chartDist.high, chartDist.medium, chartDist.low, 1);
  const isOnline = backendStatus === 'Online';

  return (
    <div style={{ padding: '2rem 2rem 6rem', maxWidth: 1280, margin: '0 auto' }}>

      {/* ─── MODAL ─────────────────────────────────────────────── */}
      {isModalOpen && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 200,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(8px)', padding: '1rem',
        }}>
          <div style={{
            background: '#1d1f2a', border: '1px solid rgba(70,71,81,0.4)',
            borderRadius: '1rem', padding: '2rem', width: '100%', maxWidth: 480,
            maxHeight: '90vh', overflowY: 'auto',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <h3 style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: '1.25rem', fontWeight: 700, color: '#e4e4f0', margin: 0 }}>
                Nuevo Objetivo + Escaneo
              </h3>
              <button onClick={() => setIsModalOpen(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#aaaab5' }}>
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>
            <form onSubmit={handleLaunch} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {[
                { label: 'Nombre del objetivo', value: targetName, setter: setTargetName, placeholder: 'mi_objetivo' },
                { label: 'URL o IP',             value: targetUrl,  setter: setTargetUrl,  placeholder: 'https://example.com' },
              ].map(({ label, value, setter, placeholder }) => (
                <div key={label}>
                  <label style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: '#aaaab5', textTransform: 'uppercase', letterSpacing: '0.15em', display: 'block', marginBottom: '0.4rem' }}>
                    {label}
                  </label>
                  <input type="text" value={value} onChange={e => setter(e.target.value)} placeholder={placeholder} required
                    style={{
                      width: '100%', boxSizing: 'border-box',
                      background: '#11131c', border: '1px solid rgba(70,71,81,0.4)',
                      borderRadius: '0.5rem', padding: '0.75rem 1rem',
                      color: '#e4e4f0', fontSize: '0.875rem', outline: 'none',
                      fontFamily: "'JetBrains Mono', monospace",
                    }} />
                </div>
              ))}
              <div>
                <label style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: '#aaaab5', textTransform: 'uppercase', letterSpacing: '0.15em', display: 'block', marginBottom: '0.5rem' }}>
                  Módulos
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  {Object.entries(SCAN_TOOLS).map(([key, meta]) => (
                    <label key={key} style={{
                      display: 'flex', alignItems: 'center', gap: '0.75rem',
                      padding: '0.75rem', borderRadius: '0.75rem', cursor: 'pointer',
                      border: scanConfig[key] ? '1px solid rgba(154,168,255,0.4)' : '1px solid rgba(70,71,81,0.3)',
                      background: scanConfig[key] ? 'rgba(154,168,255,0.08)' : 'transparent',
                    }}>
                      <input type="checkbox" checked={scanConfig[key]}
                        onChange={() => setScanConfig(prev => ({ ...prev, [key]: !prev[key] }))}
                        style={{ accentColor: '#9aa8ff', width: 14, height: 14 }} />
                      <div>
                        <p style={{ margin: 0, fontSize: '0.7rem', fontWeight: 700, color: scanConfig[key] ? '#9aa8ff' : '#e4e4f0', textTransform: 'uppercase', fontFamily: "'JetBrains Mono', monospace" }}>{meta.label}</p>
                        <p style={{ margin: 0, fontSize: '0.6rem', color: '#aaaab5' }}>{meta.desc}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
              <button type="submit" disabled={launching} style={{
                background: '#9aa8ff', color: '#122479', padding: '0.75rem',
                borderRadius: '0.5rem', border: 'none', fontWeight: 700, fontSize: '0.875rem',
                cursor: launching ? 'not-allowed' : 'pointer', opacity: launching ? 0.6 : 1,
                fontFamily: "'Space Grotesk', sans-serif",
              }}>
                {launching ? 'Registrando...' : 'Registrar y Lanzar Escaneos'}
              </button>
            </form>
          </div>
        </div>
      )}

      {/* ─── HEADER ────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '2rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6rem', color: '#aaaab5', textTransform: 'uppercase', letterSpacing: '0.18em', margin: '0 0 0.25rem' }}>
            security_overview
          </p>
          <h2 style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: '2rem', fontWeight: 700, color: '#e4e4f0', margin: '0 0 0.25rem', letterSpacing: '-0.02em' }}>
            Security Overview
          </h2>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: '#aaaab5', margin: 0 }}>
            Status:{' '}
            <span style={{ color: isOnline ? '#9aa8ff' : '#ff6e84', fontWeight: 600 }}>
              {backendStatus}
            </span>
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button style={{
            background: 'rgba(154,168,255,0.08)', border: '1px solid rgba(154,168,255,0.2)',
            color: '#9aa8ff', padding: '0.5rem 1rem', borderRadius: '0.5rem',
            fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer',
            fontFamily: "'Inter', sans-serif",
          }}>
            Export Reports
          </button>
          <button onClick={() => setIsModalOpen(true)} style={{
            background: '#9aa8ff', color: '#122479', padding: '0.5rem 1.25rem',
            borderRadius: '0.5rem', border: 'none', fontWeight: 700, fontSize: '0.8rem',
            cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem',
            boxShadow: '0 4px 20px rgba(154,168,255,0.25)',
            fontFamily: "'Inter', sans-serif",
          }}>
            <span className="material-symbols-outlined" style={{ fontSize: 16 }}>add_circle</span>
            Quick Scan
          </button>
        </div>
      </div>

      {/* ─── KPI CARDS ─────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.5rem', marginBottom: '2rem' }}>
        {/* Targets */}
        <div style={{
          background: '#171923', border: '1px solid rgba(154,168,255,0.2)',
          borderLeft: '4px solid #9aa8ff', borderRadius: '0.75rem',
          padding: '1.5rem', position: 'relative', overflow: 'hidden',
          boxShadow: '0 2px 12px rgba(0,0,0,0.3)',
        }}>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: '#aaaab5', textTransform: 'uppercase', letterSpacing: '0.15em', margin: '0 0 0.5rem' }}>
            Targets Registrados
          </p>
          <p style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: '3rem', fontWeight: 700, color: '#e4e4f0', margin: '0 0 0.5rem', lineHeight: 1 }}>
            {stats.total_targets}
          </p>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.7rem', color: '#9aa8ff', margin: 0 }}>
            Endpoints monitorizados
          </p>
          <span className="material-symbols-outlined" style={{ position: 'absolute', right: -8, bottom: -8, fontSize: 80, color: 'rgba(154,168,255,0.06)' }}>radar</span>
        </div>

        {/* Vulnerabilidades */}
        <div style={{
          background: '#171923', border: '1px solid rgba(255,110,132,0.2)',
          borderLeft: '4px solid #ff6e84', borderRadius: '0.75rem',
          padding: '1.5rem', position: 'relative', overflow: 'hidden',
          boxShadow: '0 2px 12px rgba(0,0,0,0.3)',
        }}>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: '#aaaab5', textTransform: 'uppercase', letterSpacing: '0.15em', margin: '0 0 0.5rem' }}>
            Vulnerabilidades
          </p>
          <p style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: '3rem', fontWeight: 700, color: '#e4e4f0', margin: '0 0 0.5rem', lineHeight: 1 }}>
            {totalVulns > 0 ? totalVulns : '—'}
          </p>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.7rem', color: '#ff6e84', margin: 0 }}>
            {totalVulns > 0
              ? (selectedChartTarget ? `En ${selectedChartTarget.name}` : 'En todos los sitios')
              : 'Ejecuta un escaneo'}
          </p>
          <span className="material-symbols-outlined" style={{ position: 'absolute', right: -8, bottom: -8, fontSize: 80, color: 'rgba(255,110,132,0.06)' }}>security</span>
        </div>

        {/* Estado del Sistema */}
        <div style={{
          background: '#171923',
          border: `1px solid ${isOnline ? 'rgba(154,168,255,0.2)' : 'rgba(255,110,132,0.2)'}`,
          borderLeft: `4px solid ${isOnline ? '#9aa8ff' : '#ff6e84'}`,
          borderRadius: '0.75rem', padding: '1.5rem',
          position: 'relative', overflow: 'hidden',
          boxShadow: '0 2px 12px rgba(0,0,0,0.3)',
        }}>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: '#aaaab5', textTransform: 'uppercase', letterSpacing: '0.15em', margin: '0 0 0.5rem' }}>
            Estado del Sistema
          </p>
          <p style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: '3rem', fontWeight: 700, color: isOnline ? '#9aa8ff' : '#ff6e84', margin: '0 0 0.5rem', lineHeight: 1 }}>
            {isOnline ? 'OK' : 'ERR'}
          </p>
          <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.7rem', color: isOnline ? '#9aa8ff' : '#ff6e84', margin: 0 }}>
            Backend {backendStatus}
          </p>
          <span className="material-symbols-outlined" style={{ position: 'absolute', right: -8, bottom: -8, fontSize: 80, color: isOnline ? 'rgba(154,168,255,0.06)' : 'rgba(255,110,132,0.06)' }}>assessment</span>
        </div>
      </div>

      {/* ─── CHART + TARGETS PANEL ─────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>

        {/* Severity Distribution Chart */}
        <div style={{
          background: '#171923', border: '1px solid rgba(70,71,81,0.35)',
          borderRadius: '0.75rem', padding: '1.75rem',
          boxShadow: '0 2px 12px rgba(0,0,0,0.3)',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div>
              <h4 style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: '1.1rem', fontWeight: 700, color: '#e4e4f0', margin: '0 0 0.25rem' }}>
                Severity Distribution
              </h4>
              <p style={{ fontFamily: "'Inter', sans-serif", fontSize: '0.8rem', color: '#aaaab5', margin: 0 }}>
                {loadingChart ? 'Cargando datos...' : selectedChartTarget ? `Sitio: ${selectedChartTarget.name}` : 'Todos los sitios'}
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
              <select
                value={selectedChartTarget?.id || ''}
                onChange={e => {
                  const t = targets.find(t => String(t.id) === e.target.value);
                  setSelectedChartTarget(t || null);
                }}
                style={{
                  background: '#11131c',
                  border: '1px solid rgba(70,71,81,0.5)',
                  borderRadius: '0.4rem',
                  color: '#e4e4f0',
                  fontSize: '0.7rem',
                  padding: '0.3rem 0.6rem',
                  cursor: 'pointer',
                  fontFamily: "'JetBrains Mono', monospace",
                  outline: 'none',
                }}
              >
                <option value="">Todos los sitios</option>
                {targets.map(t => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
              {SEVERITY_BARS.map(s => (
                <span key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 4, fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6rem', color: '#aaaab5' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: s.bg, display: 'inline-block' }} />
                  {s.label}
                </span>
              ))}
            </div>
          </div>

          {/* Chart bars */}
          <div style={{ height: 180, display: 'flex', alignItems: 'flex-end', gap: 12, padding: '0 0.5rem', position: 'relative' }}>
            {/* Grid lines */}
            {[25, 50, 75, 100].map(pct => (
              <div key={pct} style={{
                position: 'absolute', left: 8, right: 8,
                bottom: `${pct}%`, borderTop: '1px dashed rgba(70,71,81,0.25)',
                pointerEvents: 'none',
              }} />
            ))}

            {SEVERITY_BARS.map((s) => {
              const rawPct = (chartDist[s.key] / maxVal) * 100;
              const pct = chartDist[s.key] > 0 ? Math.max(rawPct, 8) : 0;
              return (
                <div key={s.key} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, height: '100%', justifyContent: 'flex-end' }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.7rem', color: s.text, fontWeight: 700 }}>
                    {chartDist[s.key]}
                  </span>
                  <div style={{
                    width: '100%', height: pct > 0 ? `${pct}%` : 12,
                    background: pct > 0 ? s.bg : s.dim,
                    borderRadius: '4px 4px 0 0',
                    minHeight: 12,
                    transition: 'height 0.6s ease',
                    border: `1px solid ${s.bg}`,
                    opacity: pct > 0 ? 1 : 0.5,
                  }} />
                </div>
              );
            })}
          </div>

          {/* Chart footer */}
          <div style={{ marginTop: '1.5rem', paddingTop: '1rem', borderTop: '1px solid rgba(70,71,81,0.2)', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', textAlign: 'center' }}>
            {SEVERITY_BARS.map(s => (
              <div key={s.key}>
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6rem', color: '#aaaab5', margin: '0 0 0.25rem', textTransform: 'uppercase' }}>{s.label}</p>
                <p style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, color: s.text, margin: 0 }}>{chartDist[s.key]}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Registered Targets Panel */}
        <div style={{
          background: '#171923', border: '1px solid rgba(70,71,81,0.35)',
          borderRadius: '0.75rem', padding: '1.5rem',
          boxShadow: '0 2px 12px rgba(0,0,0,0.3)',
          display: 'flex', flexDirection: 'column',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <h4 style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: '1rem', fontWeight: 700, color: '#e4e4f0', margin: 0 }}>
              Targets
            </h4>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6rem', color: '#9aa8ff', animation: 'pulse 2s infinite' }}>
              ● LIVE
            </span>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', maxHeight: 220 }}>
            {targets.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '2rem 0', opacity: 0.5 }}>
                <span className="material-symbols-outlined" style={{ fontSize: 36, color: '#aaaab5', display: 'block', marginBottom: '0.5rem' }}>inventory_2</span>
                <p style={{ fontFamily: "'Inter', sans-serif", fontSize: '0.8rem', color: '#aaaab5', margin: 0, fontStyle: 'italic' }}>Sin targets registrados</p>
              </div>
            ) : (
              targets.map(t => (
                <div key={t.id} style={{ marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
                    <div>
                      <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', fontWeight: 700, color: '#9aa8ff', margin: 0, maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {t.name}
                      </p>
                      <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6rem', color: '#aaaab5', margin: 0, maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {t.url}
                      </p>
                    </div>
                    <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.55rem', padding: '2px 8px', borderRadius: 4, background: 'rgba(154,168,255,0.1)', color: '#9aa8ff', border: '1px solid rgba(154,168,255,0.2)', whiteSpace: 'nowrap' }}>
                      {t.status}
                    </span>
                  </div>
                  <div style={{ height: 1, background: 'rgba(70,71,81,0.3)' }} />
                </div>
              ))
            )}
          </div>

          <button onClick={() => setIsModalOpen(true)} style={{
            marginTop: '1rem', width: '100%', padding: '0.6rem',
            background: 'transparent', border: '1px solid rgba(154,168,255,0.25)',
            borderRadius: '0.5rem', color: '#9aa8ff', fontSize: '0.8rem',
            fontWeight: 500, cursor: 'pointer', fontFamily: "'Inter', sans-serif",
          }}>
            + Nuevo objetivo
          </button>
        </div>
      </div>

      {/* ─── BOTTOM SECTION ────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 3fr', gap: '1.5rem' }}>

        {/* Info cards column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Último target */}
          <div style={{
            background: '#171923', border: '1px solid rgba(70,71,81,0.35)',
            borderRadius: '0.75rem', padding: '1rem',
            boxShadow: '0 2px 12px rgba(0,0,0,0.3)',
          }}>
            <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6rem', color: '#aaaab5', textTransform: 'uppercase', letterSpacing: '0.15em', margin: '0 0 0.75rem' }}>
              Último Target
            </p>
            {targets.length > 0 ? (
              <div style={{ borderLeft: '2px solid #9aa8ff', paddingLeft: '0.75rem', background: 'rgba(154,168,255,0.06)', borderRadius: '0 0.5rem 0.5rem 0', padding: '0.75rem 0.75rem 0.75rem 0.75rem' }}>
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', fontWeight: 700, color: '#9aa8ff', margin: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {targets[targets.length - 1].name}
                </p>
                <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6rem', color: '#aaaab5', margin: '0.25rem 0 0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {targets[targets.length - 1].url}
                </p>
              </div>
            ) : (
              <p style={{ fontFamily: "'Inter', sans-serif", fontSize: '0.75rem', color: '#aaaab5', margin: 0, fontStyle: 'italic' }}>Sin targets</p>
            )}
          </div>

          {/* Sistema */}
          <div style={{
            background: '#171923', border: '1px solid rgba(70,71,81,0.35)',
            borderRadius: '0.75rem', padding: '1rem',
            boxShadow: '0 2px 12px rgba(0,0,0,0.3)',
          }}>
            <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6rem', color: '#aaaab5', textTransform: 'uppercase', letterSpacing: '0.15em', margin: '0 0 0.75rem' }}>
              Sistema
            </p>
            {[
              { label: 'Backend', val: backendStatus, ok: isOnline },
              { label: 'Targets', val: `${stats.total_targets} reg.`, ok: true },
              { label: 'Modules', val: '6 disponibles', ok: true },
            ].map(({ label, val, ok }) => (
              <div key={label} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: '#aaaab5' }}>{label}</span>
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: ok ? '#9aa8ff' : '#ff6e84', fontWeight: 600 }}>{val}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Node Vulnerability Map */}
        <div style={{
          background: '#171923', border: '1px solid rgba(70,71,81,0.35)',
          borderRadius: '0.75rem', overflow: 'hidden',
          boxShadow: '0 2px 12px rgba(0,0,0,0.3)',
        }}>
          <div style={{ padding: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <h4 style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: '1.1rem', fontWeight: 700, color: '#e4e4f0', margin: 0 }}>
                Node Vulnerability Map
              </h4>
              <div style={{ display: 'flex', gap: 6 }}>
                {['#ff6e84', '#ff8f06', '#ff7161'].map((c, i) => (
                  <span key={i} style={{ width: 10, height: 10, borderRadius: '50%', background: c, display: 'inline-block', boxShadow: i === 0 ? '0 0 8px rgba(255,110,132,0.6)' : 'none' }} />
                ))}
              </div>
            </div>
            <div style={{
              height: 200, background: '#080a10', borderRadius: '0.75rem',
              overflow: 'hidden', position: 'relative',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              {/* Background glows */}
              <div style={{ position: 'absolute', top: 20, left: 20, width: 100, height: 100, background: 'rgba(154,168,255,0.06)', filter: 'blur(40px)', pointerEvents: 'none' }} />
              <div style={{ position: 'absolute', bottom: 20, right: 40, width: 120, height: 120, background: 'rgba(255,110,132,0.04)', filter: 'blur(40px)', pointerEvents: 'none' }} />

              {/* Icons grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '2rem', opacity: 0.7, position: 'relative' }}>
                {[
                  { icon: 'hub',              color: '#74757f' },
                  { icon: 'dns',              color: '#ff6e84' },
                  { icon: 'cloud_queue',      color: '#74757f' },
                  { icon: 'router',           color: '#ff8f06' },
                  { icon: 'storage',          color: '#74757f' },
                  { icon: 'laptop_chromebook',color: '#ff7161' },
                ].map(({ icon, color }, i) => (
                  <span key={i} className="material-symbols-outlined" style={{ fontSize: 32, color }}>
                    {icon}
                  </span>
                ))}
              </div>

              {/* Footer text */}
              <div style={{ position: 'absolute', bottom: 10, left: 12, fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6rem', color: '#aaaab5', textTransform: 'uppercase' }}>
                {targets.length > 0
                  ? `TARGETS: ${targets.length} | SYSTEM_${backendStatus.toUpperCase()}`
                  : 'NO TARGETS REGISTERED | AWAITING DATA'}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
