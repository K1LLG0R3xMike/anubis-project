import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import CeleryMonitorPanel from '../components/CeleryMonitorPanel';

const BASE = 'http://127.0.0.1:8000';

const getSeverityColor = (sev = '') => {
  const s = sev.toLowerCase();
  if (s.includes('high'))   return { text: 'text-error',     bg: 'bg-error/10',     border: 'border-error/30' };
  if (s.includes('medium')) return { text: 'text-secondary', bg: 'bg-secondary/10', border: 'border-secondary/30' };
  if (s.includes('low'))    return { text: 'text-tertiary',  bg: 'bg-tertiary/10',  border: 'border-tertiary/30' };
  return { text: 'text-primary', bg: 'bg-primary/10', border: 'border-primary/30' };
};

const PanelHead = ({ icon, sub, title, color = 'text-primary', iconBg = 'bg-primary/10 border-primary/20' }) => (
  <div className="flex items-center gap-3 mb-5">
    <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${iconBg}`}>
      <span className={`material-symbols-outlined ${color}`} style={{ fontSize: 18 }}>{icon}</span>
    </div>
    <div>
      <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em]">{sub}</p>
      <p className="font-headline text-base font-bold text-on-surface leading-tight">{title}</p>
    </div>
  </div>
);

const SCAN_MODULES = [
  { id: 'waf',     label: 'WAF Detector',     icon: 'security',      sub: 'firewall_fingerprint', topColor: '#ff6e84', btnCls: 'bg-error hover:brightness-110',     iconBg: 'bg-error/10 border-error/20',         iconColor: 'text-error'     },
  { id: 'whatweb', label: 'Stack Tecnológico', icon: 'terminal',      sub: 'whatweb_engine',       topColor: '#9aa8ff', btnCls: 'bg-primary hover:brightness-110',   iconBg: 'bg-primary/10 border-primary/20',     iconColor: 'text-primary'   },
  { id: 'headers', label: 'HTTP Headers',      icon: 'verified_user', sub: 'security_headers',     topColor: '#9aa8ff', btnCls: 'bg-primary hover:brightness-110',   iconBg: 'bg-primary/10 border-primary/20',     iconColor: 'text-primary'   },
  { id: 'certs',   label: 'SSL Scan',          icon: 'radar',         sub: 'tls_protocols',        topColor: '#ff8f06', btnCls: 'bg-secondary hover:brightness-110', iconBg: 'bg-secondary/10 border-secondary/20', iconColor: 'text-secondary' },
  { id: 'nikto',   label: 'Nikto Vulns',       icon: 'bug_report',    sub: 'web_server_scan',      topColor: '#ff7161', btnCls: 'bg-tertiary hover:brightness-110',  iconBg: 'bg-tertiary/10 border-tertiary/20',   iconColor: 'text-tertiary'  },
  { id: 'zap',     label: 'OWASP ZAP',         icon: 'gpp_good',      sub: 'owasp_top_10',         topColor: '#ff6e84', btnCls: 'bg-error hover:brightness-110',     iconBg: 'bg-error/10 border-error/20',         iconColor: 'text-error'     },
];

export default function Targets() {
  const navigate = useNavigate();

  const [view, setView]                     = useState('radar');
  const [openModal, setOpenModal]           = useState(false);
  const [targets, setTargets]               = useState([]);
  const [selectedTarget, setSelectedTarget] = useState(null);
  const [name, setName]                     = useState('');
  const [url, setUrl]                       = useState('');
  const [loading, setLoading]               = useState(false);
  const [scanModal, setScanModal]           = useState(null);
  const [launchedModules, setLaunchedModules] = useState({});
  const [selectedScanModules, setSelectedScanModules] = useState([]);
  const [viewMode, setViewMode]             = useState('grid');
  const [showMonitor, setShowMonitor]       = useState(false);
  const [modalTab, setModalTab]             = useState('manual');
  const [bulkEntries, setBulkEntries]       = useState([]);
  const [bulkImporting, setBulkImporting]   = useState(false);
  const [scriptModal, setScriptModal]       = useState(false);
  const [scriptFile, setScriptFile]         = useState(null);
  const [scriptDest, setScriptDest]         = useState('individual');
  const [scriptUploading, setScriptUploading] = useState(false);
  const [scriptResult, setScriptResult]     = useState(null);

  // detail panels
  const [wafDetails, setWafDetails]       = useState(null);
  const [zapDetails, setZapDetails]       = useState(null);
  const [headerDetails, setHeaderDetails] = useState(null);
  const [certDetails, setCertDetails]     = useState(null);
  const [jsonDetails, setJsonDetails]     = useState(null);
  const [niktoDetails, setNiktoDetails]   = useState(null);

  // ─── data fetching ─────────────────────────────────────────
  const fetchTargets = async () => {
    try {
      const res = await axios.get(`${BASE}/targets/?nocache=${Date.now()}`);
      setTargets(res.data);
      if (selectedTarget) {
        const updated = res.data.find(t => t.id === selectedTarget.id);
        if (updated) setSelectedTarget(updated);
      }
    } catch (e) { console.error('Error al refrescar datos:', e); }
  };

  const fetchJsonFiles = async (targetName) => {
    const fileName = targetName.toLowerCase().trim().replace(/\s+/g, '_');
    const ts = Date.now();
    const tryGet = async (u, setter) => {
      try { setter((await axios.get(u)).data); } catch { setter(null); }
    };
    await Promise.all([
      tryGet(`${BASE}/reports/waf/${fileName}.json?t=${ts}`,     setWafDetails),
      tryGet(`${BASE}/reports/zap/${fileName}.json?t=${ts}`,     setZapDetails),
      tryGet(`${BASE}/reports/headers/${fileName}.json?t=${ts}`, setHeaderDetails),
      tryGet(`${BASE}/reports/certs/${fileName}.json?t=${ts}`,   setCertDetails),
      tryGet(`${BASE}/reports/whatweb/${fileName}.json?t=${ts}`, setJsonDetails),
      tryGet(`${BASE}/reports/nikto/${fileName}.json?t=${ts}`,   setNiktoDetails),
    ]);
  };

  useEffect(() => {
    fetchTargets();
    const iv = setInterval(fetchTargets, 5000);
    return () => clearInterval(iv);
  }, [selectedTarget?.id]);

  useEffect(() => {
    if (selectedTarget) fetchJsonFiles(selectedTarget.name);
  }, [selectedTarget?.name]);

  // ─── actions ───────────────────────────────────────────────
  const handleRunScan = async (type) => {
    setLoading(true);
    try {
      await axios.post(`${BASE}/run-${type}`);
      alert(`Misión enviada a la cola: ${type.toUpperCase()}`);
    } catch { alert('Error al conectar con el worker.'); }
    finally { setLoading(false); }
  };

  const handleRunScanFromModal = async (type, targetUrl) => {
    setLaunchedModules(prev => ({ ...prev, [type]: 'loading' }));
    try {
      await axios.post(`${BASE}/run-individual/${type}`, { url: targetUrl });
      setLaunchedModules(prev => ({ ...prev, [type]: 'done' }));
    } catch {
      setLaunchedModules(prev => ({ ...prev, [type]: 'error' }));
    }
  };

  const openScanModal = (t) => {
    setLaunchedModules({});
    setSelectedScanModules([]);
    setScanModal(t);
  };

  const toggleScanModule = (id) => {
    if (launchedModules[id]) return;
    setSelectedScanModules(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const handleLaunchSelected = async () => {
    if (selectedScanModules.length === 0) return;
    const targetUrl = scanModal.url;
    setScanModal(null);
    setViewMode('list');
    setShowMonitor(true);
    for (const modId of selectedScanModules) {
      await handleRunScanFromModal(modId, targetUrl);
    }
  };

  const openScriptModal = () => {
    setScriptFile(null);
    setScriptDest('individual');
    setScriptResult(null);
    setScriptModal(true);
  };

  const handleScriptUpload = async () => {
    if (!scriptFile) return;
    setScriptUploading(true);
    setScriptResult(null);
    try {
      const fd = new FormData();
      fd.append('file', scriptFile);
      fd.append('destination', scriptDest);
      const r = await axios.post(`${BASE}/upload-script`, fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setScriptResult({ ok: true, msg: r.data.message });
    } catch (e) {
      setScriptResult({ ok: false, msg: e.response?.data?.detail || 'Error al subir el script' });
    } finally {
      setScriptUploading(false);
    }
  };

  const openAddModal = () => {
    setModalTab('manual');
    setBulkEntries([]);
    setBulkImporting(false);
    setName(''); setUrl('');
    setOpenModal(true);
  };

  const handleRegister = async () => {
    if (!name || !url) return alert('Rellena los campos');
    try {
      await axios.post(`${BASE}/targets/`, { name, url });
      setName(''); setUrl('');
      setOpenModal(false);
      fetchTargets();
    } catch { alert('Error al registrar.'); }
  };

  const handleFileLoad = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const entries = ev.target.result
        .split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
        .map(rawUrl => {
          const fullUrl = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
          let name = rawUrl;
          try { name = new URL(fullUrl).hostname.replace(/^www\./, ''); } catch {}
          return { url: fullUrl, name, status: 'pending' };
        });
      setBulkEntries(entries);
    };
    reader.readAsText(file);
  };

  const handleBulkImport = async () => {
    setBulkImporting(true);
    for (let i = 0; i < bulkEntries.length; i++) {
      const entry = bulkEntries[i];
      setBulkEntries(prev => prev.map((e, idx) => idx === i ? { ...e, status: 'loading' } : e));
      try {
        await axios.post(`${BASE}/targets/`, { name: entry.name, url: entry.url });
        setBulkEntries(prev => prev.map((e, idx) => idx === i ? { ...e, status: 'done' } : e));
      } catch {
        setBulkEntries(prev => prev.map((e, idx) => idx === i ? { ...e, status: 'error' } : e));
      }
    }
    setBulkImporting(false);
    fetchTargets();
  };

  const deleteTarget = async (id) => {
    if (window.confirm('¿Eliminar este objetivo del radar?')) {
      await axios.delete(`${BASE}/targets/${id}`);
      if (selectedTarget?.id === id) setSelectedTarget(null);
      fetchTargets();
    }
  };

  // ─── render ────────────────────────────────────────────────
  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto">

      {/* ─── TABS + HEADER ───────────────────────────────────── */}
      <div className="flex items-center gap-1 border-b border-outline-variant/20 pb-0 mb-8">
        {[
          { id: 'radar',  label: 'Radar',       icon: 'radar'       },
          { id: 'engine', label: 'Scan Engine',  icon: 'play_circle' },
        ].map(tab => (
          <button key={tab.id} onClick={() => { setView(tab.id); setSelectedTarget(null); }}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-all -mb-px ${
              view === tab.id ? 'text-primary border-primary' : 'text-on-surface/60 border-transparent hover:text-on-surface/90'
            }`}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 16 }}>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
        <div className="flex-1" />
        <button onClick={openAddModal}
          className="flex items-center gap-1.5 px-4 py-2 mb-2 rounded-lg bg-primary text-on-primary text-xs font-bold uppercase tracking-[0.05em] hover:bg-primary-dim transition-colors"
          style={{ boxShadow: '0 4px 12px rgba(154,168,255,0.2)' }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>add_link</span>
          Nuevo Objetivo
        </button>
      </div>

      {/* ═══ RADAR: target list ═════════════════════════════════ */}
      {view === 'radar' && !selectedTarget && (
        <>
          <div className="flex items-end justify-between mb-6">
            <div>
              <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">radar_targets</p>
              <h2 className="font-headline text-3xl font-bold text-on-background tracking-tight">Objetivos en Radar</h2>
              <p className="text-sm text-on-surface-variant mt-1">Gestiona y monitorea tus endpoints de infraestructura</p>
            </div>
            <div className="flex gap-1 p-1 rounded-lg bg-surface-container-low border border-outline-variant/20">
              {[
                { mode: 'grid', icon: 'grid_view'   },
                { mode: 'list', icon: 'view_agenda'  },
              ].map(({ mode, icon }) => (
                <button key={mode} onClick={() => setViewMode(mode)}
                  title={mode === 'grid' ? 'Vista cuadrícula' : 'Vista lista'}
                  className={`w-8 h-8 rounded-md flex items-center justify-center transition-all
                    ${viewMode === mode
                      ? 'bg-primary/20 text-primary'
                      : 'text-on-surface-variant hover:text-on-surface'}`}>
                  <span className="material-symbols-outlined" style={{ fontSize: 18 }}>{icon}</span>
                </button>
              ))}
            </div>
          </div>

          {/* ── Grid view ── */}
          {viewMode === 'grid' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
              {targets.map((t) => (
                <div key={t.id}
                  className="bg-surface-container-low rounded-2xl border border-outline-variant/20 border-l-2 border-l-primary/40
                    transition-all duration-200 hover:-translate-y-0.5 hover:border-outline-variant/40 hover:border-l-primary"
                >
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-4">
                      <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
                        <span className="material-symbols-outlined text-primary" style={{ fontSize: 18 }}>language</span>
                      </div>
                      <span className="font-mono text-[0.6rem] tracking-[0.1em] font-semibold text-primary bg-primary/10 border border-primary/20 rounded px-2 py-0.5">
                        {t.status || 'ACTIVE'}
                      </span>
                    </div>
                    <h3 className="font-headline font-bold text-lg text-on-surface mb-1">{t.name}</h3>
                    <p className="font-mono text-xs text-on-surface-variant truncate">{t.url}</p>
                  </div>
                  <div className="px-5 pb-5 flex gap-2">
                    <button onClick={() => setSelectedTarget(t)}
                      className="flex-1 py-2 rounded-lg bg-surface-container-highest text-on-surface font-bold text-xs uppercase tracking-[0.05em] hover:bg-surface-bright transition-colors">
                      Detalles
                    </button>
                    <button onClick={() => navigate('/findings', { state: { targetName: t.name } })}
                      className="flex-1 py-2 rounded-lg bg-primary text-on-primary font-bold text-xs uppercase tracking-[0.05em] hover:bg-primary-dim transition-colors">
                      Findings
                    </button>
                    <button onClick={() => openScanModal(t)}
                      className="w-9 h-9 rounded-lg border border-primary/30 text-primary flex items-center justify-center hover:bg-primary/10 transition-colors"
                      title="Lanzar escaneo">
                      <span className="material-symbols-outlined" style={{ fontSize: 18 }}>rocket_launch</span>
                    </button>
                    <button onClick={() => deleteTarget(t.id)}
                      className="w-9 h-9 rounded-lg border border-error/30 text-error flex items-center justify-center hover:bg-error/10 transition-colors">
                      <span className="material-symbols-outlined" style={{ fontSize: 18 }}>delete_outline</span>
                    </button>
                  </div>
                </div>
              ))}
              {targets.length === 0 && (
                <div className="col-span-3 py-20 text-center border-2 border-dashed border-outline-variant/20 rounded-2xl">
                  <span className="material-symbols-outlined text-5xl text-outline mb-3 block">radar</span>
                  <p className="font-headline text-lg text-on-surface-variant">Sin objetivos en radar</p>
                  <p className="text-xs text-outline mt-1">Añade un objetivo para comenzar</p>
                </div>
              )}
            </div>
          )}

          {/* ── List view ── */}
          {viewMode === 'list' && (
          <div className="flex flex-col lg:flex-row gap-5 items-start">
            <div className="flex-1 min-w-0 w-full rounded-2xl border border-outline-variant/20 overflow-hidden">
              {targets.length === 0 && (
                <div className="py-20 text-center border-2 border-dashed border-outline-variant/20 rounded-2xl">
                  <span className="material-symbols-outlined text-5xl text-outline mb-3 block">radar</span>
                  <p className="font-headline text-lg text-on-surface-variant">Sin objetivos en radar</p>
                  <p className="text-xs text-outline mt-1">Añade un objetivo para comenzar</p>
                </div>
              )}
              {targets.map((t, i) => (
                <div key={t.id}
                  className={`flex items-center gap-4 px-5 py-4 border-l-2 border-l-primary/40 transition-all
                    hover:bg-primary/5 hover:border-l-primary
                    ${i < targets.length - 1 ? 'border-b border-outline-variant/15' : ''}
                    ${i === 0 ? 'bg-surface-container-low' : 'bg-surface-container-low'}`}>
                  {/* Icon */}
                  <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
                    <span className="material-symbols-outlined text-primary" style={{ fontSize: 16 }}>language</span>
                  </div>
                  {/* Name + URL */}
                  <div className="min-w-0 flex-1">
                    <p className="font-headline font-bold text-sm text-on-surface leading-tight">{t.name}</p>
                    <p className="font-mono text-[0.65rem] text-on-surface-variant truncate">{t.url}</p>
                  </div>
                  {/* Status badge */}
                  <span className="font-mono text-[0.55rem] tracking-[0.1em] font-semibold text-primary bg-primary/10 border border-primary/20 rounded px-2 py-0.5 shrink-0 hidden sm:block">
                    {t.status || 'ACTIVE'}
                  </span>
                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={() => setSelectedTarget(t)}
                      className="px-3 py-1.5 rounded-lg bg-surface-container-highest text-on-surface font-bold text-xs uppercase tracking-[0.05em] hover:bg-surface-bright transition-colors">
                      Detalles
                    </button>
                    <button onClick={() => navigate('/findings', { state: { targetName: t.name } })}
                      className="px-3 py-1.5 rounded-lg bg-primary text-on-primary font-bold text-xs uppercase tracking-[0.05em] hover:bg-primary-dim transition-colors">
                      Findings
                    </button>
                    <button onClick={() => openScanModal(t)}
                      className="w-8 h-8 rounded-lg border border-primary/30 text-primary flex items-center justify-center hover:bg-primary/10 transition-colors"
                      title="Lanzar escaneo">
                      <span className="material-symbols-outlined" style={{ fontSize: 16 }}>rocket_launch</span>
                    </button>
                    <button onClick={() => deleteTarget(t.id)}
                      className="w-8 h-8 rounded-lg border border-error/30 text-error flex items-center justify-center hover:bg-error/10 transition-colors">
                      <span className="material-symbols-outlined" style={{ fontSize: 16 }}>delete_outline</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
            {showMonitor && <CeleryMonitorPanel onClose={() => setShowMonitor(false)} />}
          </div>
          )}
        </>
      )}

      {/* ═══ RADAR: target detail ════════════════════════════════ */}
      {view === 'radar' && selectedTarget && (
        <div>
          <button onClick={() => setSelectedTarget(null)}
            className="flex items-center gap-1.5 font-mono text-xs text-on-surface-variant uppercase tracking-[0.1em] hover:text-primary transition-colors mb-6">
            <span className="material-symbols-outlined" style={{ fontSize: 16 }}>arrow_back</span>
            back_to_radar
          </button>

          <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">target_analysis</p>
          <h2 className="font-headline text-4xl font-bold text-on-background tracking-tight">{selectedTarget.name}</h2>
          <p className="font-mono text-sm text-primary mt-1 mb-8">{selectedTarget.url}</p>

          <div className="space-y-5">
            {/* WAF */}
            <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 border-l-4 border-l-error p-6 flex items-center gap-5">
              <div className="w-14 h-14 rounded-xl bg-error/10 border border-error/20 flex items-center justify-center">
                <span className="material-symbols-outlined text-error" style={{ fontSize: 30 }}>security</span>
              </div>
              <div>
                <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">firewall_status</p>
                <p className="font-headline text-2xl font-bold text-on-surface">
                  {Array.isArray(wafDetails) && wafDetails.length > 0
                    ? (wafDetails[0].firewall || 'WAF ACTIVE')
                    : 'DETECTOR OFF'}
                </p>
              </div>
            </div>

            {/* ZAP */}
            <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6">
              <PanelHead icon="gpp_good" sub="vulnerability_scanner" title="OWASP Top 10 · ZAP Engine"
                color="text-error" iconBg="bg-error/10 border-error/20" />
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-outline-variant/20">
                      {['Riesgo', 'Vulnerabilidad', 'Evidencia', 'OWASP ID'].map(h => (
                        <th key={h} className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] text-left py-3 pr-4">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {zapDetails?.vulnerabilities?.length > 0 ? zapDetails.vulnerabilities.map((v, i) => {
                      const c = getSeverityColor(v.severidad);
                      return (
                        <tr key={i} className="border-b border-outline-variant/10 hover:bg-primary/5 transition-colors">
                          <td className="py-3 pr-4">
                            <span className={`font-mono text-[0.6rem] font-semibold tracking-[0.08em] px-2 py-0.5 rounded border ${c.text} ${c.bg} ${c.border}`}>{v.severidad}</span>
                          </td>
                          <td className="py-3 pr-4 font-body text-sm text-on-surface font-medium">{v.vulnerabilidad}</td>
                          <td className="py-3 pr-4 font-mono text-xs text-on-surface-variant max-w-xs break-all">{v.evidencia}</td>
                          <td className="py-3 font-mono text-xs font-semibold text-primary">{v.owasp_id}</td>
                        </tr>
                      );
                    }) : (
                      <tr><td colSpan={4} className="py-8 text-center font-mono text-xs text-outline">// no zap reports available</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Headers + SSL */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6">
                <PanelHead icon="verified_user" sub="http_security" title="Security Headers" />
                {headerDetails?.security_headers ? (
                  <div className="space-y-2">
                    {Object.entries(headerDetails.security_headers).map(([hName, data]) => (
                      <div key={hName} className="flex items-center justify-between p-3 bg-surface-container-lowest rounded-lg border border-outline-variant/20">
                        <div className="min-w-0 mr-3">
                          <p className="font-mono text-xs font-semibold text-on-surface">{hName}</p>
                          {data.value && <p className="font-mono text-[0.65rem] text-on-surface-variant break-all mt-0.5">{data.value}</p>}
                        </div>
                        {data.status === 'Presente'
                          ? <span className="material-symbols-outlined text-primary shrink-0" style={{ fontSize: 20 }}>check_circle</span>
                          : <span className="material-symbols-outlined text-error shrink-0" style={{ fontSize: 20 }}>error</span>}
                      </div>
                    ))}
                  </div>
                ) : <p className="font-mono text-xs text-outline">// esperando reporte de cabeceras...</p>}
              </div>
              <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6">
                <PanelHead icon="radar" sub="cryptography" title="SSL / TLS Protocols"
                  color="text-secondary" iconBg="bg-secondary/10 border-secondary/20" />
                {certDetails?.protocols ? (
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(certDetails.protocols).map(([p, s]) => {
                      const ok = s === 'Soportado';
                      return (
                        <div key={p} className={`flex items-center justify-between px-3 py-2 rounded-lg border ${ok ? 'bg-primary/10 border-primary/30' : 'bg-surface-container-lowest border-outline-variant/20'}`}>
                          <span className={`font-mono text-xs font-semibold ${ok ? 'text-primary' : 'text-outline'}`}>{p}</span>
                          <span className={`w-1.5 h-1.5 rounded-full ${ok ? 'bg-primary' : 'bg-outline'}`}
                            style={ok ? { boxShadow: '0 0 6px #9aa8ff' } : {}} />
                        </div>
                      );
                    })}
                  </div>
                ) : <p className="font-mono text-xs text-outline">// cargando protocolos...</p>}
              </div>
            </div>

            {/* Tech Stack */}
            <div className="bg-surface-container-lowest rounded-2xl border border-outline-variant/20 p-6">
              <PanelHead icon="terminal" sub="fingerprinting" title="Stack Tecnológico" />
              <div className="flex flex-wrap gap-2">
                {jsonDetails?.technologies?.length > 0 ? jsonDetails.technologies.map((tech, i) => (
                  <span key={i} className="font-mono text-xs text-primary bg-primary/10 border border-primary/20 rounded-md px-3 py-1">{tech}</span>
                )) : <p className="font-mono text-xs text-outline">// no se detectaron tecnologías aún</p>}
              </div>
            </div>

            {/* Nikto */}
            <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6">
              <PanelHead icon="bug_report" sub="web_server_scanner" title="Vulnerabilities · Nikto Scan"
                color="text-secondary" iconBg="bg-secondary/10 border-secondary/20" />
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-outline-variant/20">
                      {['Método', 'Hallazgo / Mensaje', 'URL'].map(h => (
                        <th key={h} className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] text-left py-3 pr-4">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {niktoDetails?.vulnerabilities?.length > 0 ? niktoDetails.vulnerabilities.map((v, i) => (
                      <tr key={i} className="border-b border-outline-variant/10 hover:bg-primary/5 transition-colors">
                        <td className="py-3 pr-4 font-mono text-xs font-semibold text-primary">{v.method}</td>
                        <td className="py-3 pr-4 font-body text-sm text-on-surface">{v.msg}</td>
                        <td className="py-3 font-mono text-xs text-on-surface-variant">{v.url}</td>
                      </tr>
                    )) : (
                      <tr><td colSpan={3} className="py-8 text-center font-mono text-xs text-outline">// no hay reportes disponibles</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ═══ SCAN ENGINE ════════════════════════════════════════ */}
      {view === 'engine' && (
        <div>
          <div className="flex items-end justify-between mb-8">
            <div>
              <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">execution_layer</p>
              <h2 className="font-headline text-3xl font-bold text-on-background tracking-tight">Motores de Escaneos</h2>
              <p className="text-sm text-on-surface-variant font-body mt-1">Lanza un módulo de análisis sobre los objetivos registrados</p>
            </div>
            <button onClick={openScriptModal}
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg border border-outline-variant/30 text-on-surface text-xs font-bold uppercase tracking-[0.05em] hover:border-primary/40 hover:text-primary transition-colors shrink-0">
              <span className="material-symbols-outlined" style={{ fontSize: 14 }}>upload_file</span>
              Añadir Script
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {SCAN_MODULES.map((mod) => (
              <div key={mod.id}
                className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6 border-t-2 transition-all duration-200 hover:-translate-y-0.5"
                style={{ borderTopColor: mod.topColor }}
              >
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center border mb-5 ${mod.iconBg}`}>
                  <span className={`material-symbols-outlined ${mod.iconColor}`} style={{ fontSize: 26 }}>{mod.icon}</span>
                </div>
                <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">{mod.sub}</p>
                <h3 className="font-headline text-lg font-bold text-on-surface mb-5">{mod.label}</h3>
                <button disabled={loading} onClick={() => handleRunScan(mod.id)}
                  className={`w-full py-2.5 rounded-lg font-bold text-xs text-background uppercase tracking-[0.08em] transition-all ${mod.btnCls} disabled:opacity-50 disabled:cursor-not-allowed`}
                  style={{ boxShadow: `0 6px 16px ${mod.topColor}33` }}
                >
                  › Lanzar
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── MODAL: SCAN OBJETIVO ─────────────────────────────── */}
      {scanModal && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-lg rounded-2xl p-8"
            style={{ backgroundColor: '#1d1f2a', border: '1px solid rgba(70,71,81,0.25)', boxShadow: '0 24px 60px rgba(0,0,0,0.5)' }}>

            {/* header */}
            <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">launch_scan</p>
            <div className="flex items-center justify-between mb-5">
              <h3 className="font-headline text-xl font-bold text-on-surface">Lanzar Escaneo</h3>
              <button onClick={() => setScanModal(null)} className="text-on-surface-variant hover:text-primary transition-colors">
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            {/* target info */}
            <div className="flex items-center gap-3 p-4 rounded-xl bg-surface-container-lowest border border-outline-variant/20 mb-6">
              <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
                <span className="material-symbols-outlined text-primary" style={{ fontSize: 18 }}>language</span>
              </div>
              <div className="min-w-0">
                <p className="font-headline font-bold text-sm text-on-surface">{scanModal.name}</p>
                <p className="font-mono text-xs text-on-surface-variant truncate">{scanModal.url}</p>
              </div>
            </div>

            {/* módulos */}
            <div className="flex items-center justify-between mb-3">
              <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em]">módulos disponibles</p>
              {selectedScanModules.length > 0 && (
                <span className="font-mono text-[0.58rem] text-primary">{selectedScanModules.length} seleccionado{selectedScanModules.length > 1 ? 's' : ''}</span>
              )}
            </div>
            <div className="grid grid-cols-2 gap-3">
              {SCAN_MODULES.map((mod) => {
                const runState = launchedModules[mod.id];
                const selected = selectedScanModules.includes(mod.id);
                return (
                  <button
                    key={mod.id}
                    disabled={runState === 'loading'}
                    onClick={() => toggleScanModule(mod.id)}
                    className={`flex items-center gap-3 p-3 rounded-xl border text-left transition-all
                      ${runState === 'done'    ? 'border-primary/40 bg-primary/10 cursor-default' :
                        runState === 'error'   ? 'border-error/40 bg-error/10 cursor-default' :
                        runState === 'loading' ? 'border-outline-variant/20 bg-surface-container-lowest opacity-60 cursor-wait' :
                        selected               ? 'border-primary/50 bg-primary/10 ring-1 ring-primary/30' :
                        'border-outline-variant/20 bg-surface-container-lowest hover:border-primary/30 hover:bg-primary/5'}`}
                  >
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center border shrink-0 ${mod.iconBg}`}>
                      {runState === 'loading'
                        ? <span className="material-symbols-outlined text-on-surface-variant animate-spin" style={{ fontSize: 16 }}>progress_activity</span>
                        : runState === 'done'
                        ? <span className="material-symbols-outlined text-primary" style={{ fontSize: 16 }}>check_circle</span>
                        : runState === 'error'
                        ? <span className="material-symbols-outlined text-error" style={{ fontSize: 16 }}>error</span>
                        : <span className={`material-symbols-outlined ${mod.iconColor}`} style={{ fontSize: 16 }}>{mod.icon}</span>
                      }
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.12em] leading-none mb-0.5">{mod.sub}</p>
                      <p className="font-headline text-xs font-bold text-on-surface">{mod.label}</p>
                    </div>
                    {!runState && (
                      <div className={`w-4 h-4 rounded border shrink-0 flex items-center justify-center transition-colors
                        ${selected ? 'bg-primary border-primary' : 'border-outline-variant/50'}`}>
                        {selected && <span className="material-symbols-outlined text-on-primary" style={{ fontSize: 11 }}>check</span>}
                      </div>
                    )}
                  </button>
                );
              })}
            </div>

            <button
              onClick={handleLaunchSelected}
              disabled={selectedScanModules.length === 0 || Object.values(launchedModules).some(s => s === 'loading')}
              className="w-full mt-4 py-3 rounded-xl bg-primary text-on-primary font-bold text-sm uppercase tracking-[0.05em] hover:bg-primary-dim active:scale-[0.98] transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ boxShadow: '0 8px 24px rgba(154,168,255,0.2)' }}>
              {Object.values(launchedModules).some(s => s === 'loading')
                ? 'Ejecutando...'
                : selectedScanModules.length === 0
                ? 'Selecciona módulos'
                : `› Lanzar ${selectedScanModules.length} módulo${selectedScanModules.length > 1 ? 's' : ''}`}
            </button>

            <button onClick={() => setScanModal(null)}
              className="w-full mt-2 py-2 rounded-xl border border-outline-variant/30 text-on-surface-variant font-bold text-xs uppercase tracking-[0.05em] hover:border-outline-variant/60 hover:text-on-surface transition-all">
              Cerrar
            </button>
          </div>
        </div>
      )}

      {/* ─── MODAL: NUEVO OBJETIVO ─────────────────────────────── */}
      {openModal && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
          onClick={() => setOpenModal(false)}>
          <div className="relative w-full max-w-md rounded-2xl p-8"
            style={{ backgroundColor: '#1d1f2a', border: '1px solid rgba(70,71,81,0.25)', boxShadow: '0 24px 60px rgba(0,0,0,0.5)' }}
            onClick={e => e.stopPropagation()}>

            <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">new_target</p>
            <div className="flex items-center justify-between mb-5">
              <h3 className="font-headline text-xl font-bold text-on-surface">Nuevo Objetivo</h3>
              <button onClick={() => setOpenModal(false)} className="text-on-surface-variant hover:text-primary transition-colors">
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 p-1 rounded-lg bg-surface-container-lowest border border-outline-variant/20 mb-5">
              {[
                { id: 'manual', label: 'Manual',      icon: 'edit'        },
                { id: 'bulk',   label: 'Desde .txt',  icon: 'upload_file' },
              ].map(tab => (
                <button key={tab.id} type="button" onClick={() => setModalTab(tab.id)}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-md font-mono text-[0.6rem] uppercase tracking-[0.08em] transition-all
                    ${modalTab === tab.id
                      ? 'bg-primary/20 text-primary border border-primary/40'
                      : 'text-on-surface-variant hover:text-on-surface'}`}>
                  <span className="material-symbols-outlined" style={{ fontSize: 14 }}>{tab.icon}</span>
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab: Manual */}
            {modalTab === 'manual' && (
              <div className="space-y-4">
                <div>
                  <label className="block font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em] mb-1.5">Nombre</label>
                  <input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="mi_objetivo"
                    className="w-full rounded-lg px-4 py-3 text-sm font-body text-on-surface bg-surface-container-lowest outline-none border border-outline-variant/30 hover:border-outline-variant/60 focus:border-primary transition-colors" />
                </div>
                <div>
                  <label className="block font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em] mb-1.5">URL</label>
                  <input type="text" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com"
                    className="w-full rounded-lg px-4 py-3 text-sm font-body text-on-surface bg-surface-container-lowest outline-none border border-outline-variant/30 hover:border-outline-variant/60 focus:border-primary transition-colors" />
                </div>
                <button onClick={handleRegister}
                  className="w-full py-3 rounded-xl bg-primary text-on-primary font-bold text-sm uppercase tracking-[0.05em] hover:bg-primary-dim active:scale-[0.98] transition-all mt-2"
                  style={{ boxShadow: '0 8px 24px rgba(154,168,255,0.2)' }}>
                  › Añadir
                </button>
              </div>
            )}

            {/* Tab: Bulk desde .txt */}
            {modalTab === 'bulk' && (
              <div className="space-y-4">
                <label className="flex flex-col items-center justify-center gap-2 p-6 rounded-xl border-2 border-dashed border-outline-variant/30 bg-surface-container-lowest cursor-pointer hover:border-primary/50 hover:bg-primary/5 transition-all">
                  <span className="material-symbols-outlined text-outline" style={{ fontSize: 32 }}>upload_file</span>
                  <div className="text-center">
                    <p className="font-mono text-xs text-on-surface-variant">
                      {bulkEntries.length > 0
                        ? `${bulkEntries.length} URL${bulkEntries.length > 1 ? 's' : ''} detectada${bulkEntries.length > 1 ? 's' : ''} — clic para cambiar`
                        : 'Selecciona un archivo .txt'}
                    </p>
                    <p className="font-mono text-[0.58rem] text-outline mt-0.5">Una URL por línea · se ignoran líneas con #</p>
                  </div>
                  <input type="file" accept=".txt" className="hidden" onChange={handleFileLoad} />
                </label>

                {bulkEntries.length > 0 && (
                  <>
                    <div className="max-h-52 overflow-y-auto rounded-lg border border-outline-variant/20 divide-y divide-outline-variant/10">
                      {bulkEntries.map((entry, i) => (
                        <div key={i} className="flex items-center gap-3 px-3 py-2.5">
                          <span className={`material-symbols-outlined shrink-0 ${
                            entry.status === 'done'    ? 'text-primary' :
                            entry.status === 'error'   ? 'text-error'   :
                            entry.status === 'loading' ? 'text-on-surface-variant animate-spin' :
                            'text-outline'
                          }`} style={{ fontSize: 15 }}>
                            {entry.status === 'done'    ? 'check_circle'       :
                             entry.status === 'error'   ? 'error'              :
                             entry.status === 'loading' ? 'progress_activity'  :
                             'radio_button_unchecked'}
                          </span>
                          <div className="min-w-0">
                            <p className="font-mono text-[0.62rem] text-on-surface font-semibold truncate">{entry.name}</p>
                            <p className="font-mono text-[0.56rem] text-outline truncate">{entry.url}</p>
                          </div>
                        </div>
                      ))}
                    </div>

                    <button
                      onClick={handleBulkImport}
                      disabled={bulkImporting || bulkEntries.every(e => e.status === 'done')}
                      className="w-full py-3 rounded-xl bg-primary text-on-primary font-bold text-sm uppercase tracking-[0.05em] hover:bg-primary-dim active:scale-[0.98] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                      style={{ boxShadow: '0 8px 24px rgba(154,168,255,0.2)' }}>
                      {bulkImporting
                        ? `Importando...`
                        : bulkEntries.every(e => e.status === 'done')
                        ? '✓ Importación completada'
                        : `› Importar ${bulkEntries.length} objetivo${bulkEntries.length > 1 ? 's' : ''}`}
                    </button>
                  </>
                )}
              </div>
            )}

          </div>
        </div>
      )}

      {/* ─── MODAL: UPLOAD SCRIPT ─────────────────────────────── */}
      {scriptModal && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
          onClick={() => setScriptModal(false)}>
          <div className="relative w-full max-w-sm rounded-2xl p-8"
            style={{ backgroundColor: '#1d1f2a', border: '1px solid rgba(70,71,81,0.25)', boxShadow: '0 24px 60px rgba(0,0,0,0.5)' }}
            onClick={e => e.stopPropagation()}>

            <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">upload_script</p>
            <div className="flex items-center justify-between mb-6">
              <h3 className="font-headline text-xl font-bold text-on-surface">Añadir Script</h3>
              <button onClick={() => setScriptModal(false)} className="text-on-surface-variant hover:text-primary transition-colors">
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>

            <div className="space-y-5">
              {/* File picker */}
              <div>
                <label className="block font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em] mb-1.5">Archivo .py</label>
                <label className="flex flex-col items-center justify-center gap-2 p-5 rounded-xl border-2 border-dashed border-outline-variant/30 bg-surface-container-lowest cursor-pointer hover:border-primary/50 hover:bg-primary/5 transition-all">
                  <span className="material-symbols-outlined text-outline" style={{ fontSize: 28 }}>code</span>
                  <p className="font-mono text-xs text-on-surface-variant text-center">
                    {scriptFile ? scriptFile.name : 'Selecciona un archivo .py'}
                  </p>
                  <input type="file" accept=".py" className="hidden"
                    onChange={e => { setScriptFile(e.target.files[0] || null); setScriptResult(null); }} />
                </label>
              </div>

              {/* Destination */}
              <div>
                <label className="block font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em] mb-2">Destino</label>
                <div className="space-y-2">
                  {[
                    { value: 'individual', label: 'script_induvidual/', desc: 'Escaneos sobre un target individual' },
                    { value: 'full',       label: 'scripts/',           desc: 'Escaneos sobre todos los targets'   },
                  ].map(opt => (
                    <label key={opt.value}
                      className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-all
                        ${scriptDest === opt.value
                          ? 'border-primary/50 bg-primary/10'
                          : 'border-outline-variant/25 bg-surface-container-lowest hover:border-outline-variant/50'}`}>
                      <div className={`w-4 h-4 rounded-full border-2 mt-0.5 shrink-0 flex items-center justify-center transition-colors
                        ${scriptDest === opt.value ? 'border-primary' : 'border-outline-variant/50'}`}>
                        {scriptDest === opt.value && <div className="w-2 h-2 rounded-full bg-primary" />}
                      </div>
                      <input type="radio" className="hidden" value={opt.value}
                        checked={scriptDest === opt.value}
                        onChange={() => setScriptDest(opt.value)} />
                      <div>
                        <p className={`font-mono text-xs font-bold ${scriptDest === opt.value ? 'text-primary' : 'text-on-surface'}`}>{opt.label}</p>
                        <p className="font-mono text-[0.58rem] text-on-surface-variant mt-0.5">{opt.desc}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {/* Result */}
              {scriptResult && (
                <div className={`flex items-center gap-2 p-3 rounded-lg border text-xs font-mono
                  ${scriptResult.ok
                    ? 'border-primary/30 bg-primary/10 text-primary'
                    : 'border-error/30 bg-error/10 text-error'}`}>
                  <span className="material-symbols-outlined" style={{ fontSize: 16 }}>
                    {scriptResult.ok ? 'check_circle' : 'error'}
                  </span>
                  {scriptResult.msg}
                </div>
              )}

              <button
                onClick={handleScriptUpload}
                disabled={!scriptFile || scriptUploading}
                className="w-full py-3 rounded-xl bg-primary text-on-primary font-bold text-sm uppercase tracking-[0.05em] hover:bg-primary-dim active:scale-[0.98] transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                style={{ boxShadow: '0 8px 24px rgba(154,168,255,0.2)' }}>
                {scriptUploading ? 'Subiendo...' : '› Subir Script'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
