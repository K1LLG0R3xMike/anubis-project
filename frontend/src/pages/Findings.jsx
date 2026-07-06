import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useLocation } from 'react-router-dom';

// ─── severity color helper ───────────────────────────────────────
const getSeverityColor = (sev = '') => {
  const s = sev.toLowerCase();
  if (s.includes('critical')) return { text: 'text-[#ff6e84]', bg: 'bg-[#ff6e84]/15', border: 'border-[#ff6e84]/40' };
  if (s.includes('high'))     return { text: 'text-error',      bg: 'bg-error/10',      border: 'border-error/30' };
  if (s.includes('medium'))   return { text: 'text-secondary',  bg: 'bg-secondary/10',  border: 'border-secondary/30' };
  if (s.includes('low'))      return { text: 'text-tertiary',   bg: 'bg-tertiary/10',   border: 'border-tertiary/30' };
  return { text: 'text-primary', bg: 'bg-primary/10', border: 'border-primary/30' };
};

const HEADER_SEVERITY = {
  'Strict-Transport-Security': 'High',
  'Content-Security-Policy':   'Medium',
  'X-Frame-Options':           'Medium',
  'X-Content-Type-Options':    'Low',
  'Referrer-Policy':           'Low',
};

const SSL_SEVERITY = {
  'SSLv2':   'Critical',
  'SSLv3':   'High',
  'TLS 1.0': 'Medium',
  'TLS 1.1': 'Low',
};

// ─── low-priority severities (Low / Informational) get collapsed ─
const isMinorSeverity = (sev = '') => {
  const s = sev.toLowerCase();
  return s === 'low' || s === 'informational' || s === 'info';
};

const SeverityToggleRow = ({ count, expanded, onToggle, colSpan }) => (
  <tr>
    <td colSpan={colSpan} className="pt-2 pb-1">
      <button
        onClick={onToggle}
        className="flex items-center gap-1.5 font-mono text-[0.65rem] text-on-surface-variant hover:text-primary transition-colors"
      >
        <span className="material-symbols-outlined" style={{ fontSize: 14 }}>
          {expanded ? 'expand_less' : 'expand_more'}
        </span>
        {expanded ? 'Ocultar' : 'Ver'} {count} hallazgo{count !== 1 ? 's' : ''} de severidad baja / informativa
      </button>
    </td>
  </tr>
);

// Módulos con tabla a medida más abajo — cualquier otro módulo detectado en
// Scan Engine que tenga findings se renderiza con la sección genérica.
const KNOWN_MODULES = ['waf', 'whatweb', 'headers', 'certs', 'nikto', 'zap'];

// ─── panel heading shared component ─────────────────────────────
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

// ─── empty state: spinner si escaneo activo, info si sin datos ───
const ModuleEmpty = ({ scanning, label = '// sin datos — lanza un escaneo', rows = false }) => {
  const content = scanning ? (
    <div className="flex items-center gap-3 py-4">
      <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin shrink-0" />
      <p className="font-mono text-xs text-on-surface-variant animate-pulse">
        Escaneo en progreso · actualizando cada 30 s
      </p>
    </div>
  ) : (
    <div className="flex items-center gap-2 py-4">
      <span className="material-symbols-outlined text-outline" style={{ fontSize: 16 }}>info</span>
      <p className="font-mono text-xs text-outline">{label}</p>
    </div>
  );
  if (rows) return <tr><td colSpan={4} className="px-2">{content}</td></tr>;
  return content;
};

export default function Findings() {
  const location = useLocation();

  const [targets, setTargets]               = useState([]);
  const [selectedTarget, setSelectedTarget] = useState(null);
  const [loadingTargets, setLoadingTargets] = useState(true);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [targetStatus, setTargetStatus]     = useState(null);

  const [wafDetails, setWafDetails]       = useState(null);
  const [zapDetails, setZapDetails]       = useState(null);
  const [headerDetails, setHeaderDetails] = useState(null);
  const [certDetails, setCertDetails]     = useState(null);
  const [jsonDetails, setJsonDetails]     = useState(null);
  const [niktoDetails, setNiktoDetails]   = useState(null);

  const [showLowZap, setShowLowZap]       = useState(false);
  const [showLowNikto, setShowLowNikto]   = useState(false);

  // ─── módulos auto-detectados sin tabla a medida (ej. fuzz_dirb, kiterunner) ──
  const [scanModules, setScanModules]         = useState([]);
  const [genericFindings, setGenericFindings] = useState({});
  const [showLowExtra, setShowLowExtra]       = useState({});
  const toggleLowExtra = (id) => setShowLowExtra(s => ({ ...s, [id]: !s[id] }));
  const extraModules = scanModules.filter(m => !KNOWN_MODULES.includes(m.id));

  // ─── fetch target list ────────────────────────────────────────
  useEffect(() => {
    axios.get(`http://127.0.0.1:8000/targets/?nocache=${Date.now()}`)
      .then(r => setTargets(r.data))
      .catch(() => {})
      .finally(() => setLoadingTargets(false));
    axios.get(`http://127.0.0.1:8000/system/scan-modules`)
      .then(r => setScanModules(r.data))
      .catch(() => {});
  }, []);

  // ─── auto-select if navigated with state ─────────────────────
  useEffect(() => {
    if (location.state?.targetName && targets.length > 0) {
      const found = targets.find(t => t.name === location.state.targetName);
      if (found) setSelectedTarget(found);
    }
  }, [targets, location.state]);

  // ─── fetch report files for selected target ──────────────────
  useEffect(() => {
    if (!selectedTarget) return;
    setTargetStatus(selectedTarget.status);
    setShowLowZap(false);
    setShowLowNikto(false);
    setShowLowExtra({});
    const fetch = async () => {
      setLoadingDetails(true);
      const fileName = selectedTarget.name.toLowerCase().trim().replace(/\s+/g, '_');
      const ts = Date.now();
      const BASE = 'http://127.0.0.1:8000/reports';
      const tryGet = async (u, setter) => {
        try { setter((await axios.get(u)).data); } catch { setter(null); }
      };
      await Promise.all([
        tryGet(`${BASE}/waf/${fileName}.json?t=${ts}`,     setWafDetails),
        tryGet(`${BASE}/zap/${fileName}.json?t=${ts}`,     setZapDetails),
        tryGet(`${BASE}/headers/${fileName}.json?t=${ts}`, setHeaderDetails),
        tryGet(`${BASE}/certs/${fileName}.json?t=${ts}`,   setCertDetails),
        tryGet(`${BASE}/whatweb/${fileName}.json?t=${ts}`, setJsonDetails),
        tryGet(`${BASE}/nikto/${fileName}.json?t=${ts}`,   setNiktoDetails),
      ]);
      try {
        const { data } = await axios.get(`http://127.0.0.1:8000/findings/target/${selectedTarget.id}?t=${ts}`);
        setGenericFindings(data);
      } catch { setGenericFindings({}); }
      setLoadingDetails(false);
    };
    fetch();
  }, [selectedTarget?.name]);

  // ─── polling: refresca estado + módulos faltantes cada 30s ───
  useEffect(() => {
    if (!selectedTarget) return;
    const allLoaded = wafDetails && zapDetails && headerDetails && certDetails && jsonDetails && niktoDetails;
    const scanning  = targetStatus === 'Escaneando';
    if (allLoaded && !scanning) return;

    const tick = async () => {
      try {
        const { data } = await axios.get(`http://127.0.0.1:8000/targets/?nocache=${Date.now()}`);
        const updated = data.find(t => t.id === selectedTarget.id);
        if (updated) setTargetStatus(updated.status);
      } catch {}

      const fileName = selectedTarget.name.toLowerCase().trim().replace(/\s+/g, '_');
      const ts = Date.now();
      const BASE = 'http://127.0.0.1:8000/reports';
      const tryGet = async (u) => { try { return (await axios.get(u)).data; } catch { return null; } };

      const [waf, zap, hdr, cert, web, nkt] = await Promise.all([
        tryGet(`${BASE}/waf/${fileName}.json?t=${ts}`),
        tryGet(`${BASE}/zap/${fileName}.json?t=${ts}`),
        tryGet(`${BASE}/headers/${fileName}.json?t=${ts}`),
        tryGet(`${BASE}/certs/${fileName}.json?t=${ts}`),
        tryGet(`${BASE}/whatweb/${fileName}.json?t=${ts}`),
        tryGet(`${BASE}/nikto/${fileName}.json?t=${ts}`),
      ]);
      if (waf)  setWafDetails(waf);
      if (zap)  setZapDetails(zap);
      if (hdr)  setHeaderDetails(hdr);
      if (cert) setCertDetails(cert);
      if (web)  setJsonDetails(web);
      if (nkt)  setNiktoDetails(nkt);

      try {
        const { data } = await axios.get(`http://127.0.0.1:8000/findings/target/${selectedTarget.id}?t=${ts}`);
        setGenericFindings(data);
      } catch {}
    };

    const id = setInterval(tick, 30_000);
    return () => clearInterval(id);
  }, [selectedTarget?.id, targetStatus, wafDetails, zapDetails, headerDetails, certDetails, jsonDetails, niktoDetails]);

  const scanning = targetStatus === 'Escaneando';

  return (
    <div className="pt-8 pb-32 px-0 md:px-0 flex flex-col md:flex-row min-h-[calc(100vh-64px)]">

      {/* ─── LEFT: TARGET SELECTOR ───────────────────────────── */}
      <aside className="w-full md:w-72 shrink-0 border-b md:border-b-0 md:border-r border-outline-variant/15 flex flex-col">
        <div className="px-5 pt-6 pb-4 border-b border-outline-variant/15">
          <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">security_registry</p>
          <h1 className="font-headline text-2xl font-bold tracking-tight text-on-background">Findings</h1>
          <p className="text-xs text-on-surface-variant mt-1">Selecciona un objetivo para ver su análisis</p>
        </div>

        <div className="flex-1 overflow-y-auto px-3 py-3 space-y-1">
          {loadingTargets ? (
            <div className="py-8 text-center">
              <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-2" />
              <p className="font-mono text-xs text-on-surface-variant">Cargando...</p>
            </div>
          ) : targets.length === 0 ? (
            <div className="py-10 text-center px-3">
              <span className="material-symbols-outlined text-3xl text-outline block mb-2">radar</span>
              <p className="font-mono text-xs text-outline">Sin objetivos registrados</p>
            </div>
          ) : (
            targets.map((t) => (
              <button
                key={t.id}
                onClick={() => setSelectedTarget(t)}
                className={`w-full text-left px-4 py-3 rounded-xl transition-all duration-200 border ${
                  selectedTarget?.id === t.id
                    ? 'bg-surface-container-high border-primary/40 text-on-surface'
                    : 'border-transparent hover:bg-surface-container-high text-on-surface/70'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className={`material-symbols-outlined shrink-0 ${selectedTarget?.id === t.id ? 'text-primary' : 'text-on-surface-variant'}`}
                    style={{ fontSize: 18 }}>language</span>
                  <div className="min-w-0">
                    <p className={`text-sm font-semibold truncate ${selectedTarget?.id === t.id ? 'text-primary' : ''}`}>{t.name}</p>
                    <p className="font-mono text-[0.6rem] text-on-surface-variant truncate mt-0.5">{t.url}</p>
                  </div>
                </div>
              </button>
            ))
          )}
        </div>
      </aside>

      {/* ─── RIGHT: DETAIL PANELS ────────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-5 md:px-8 py-6 md:py-8">

        {!selectedTarget ? (
          <div className="h-full flex flex-col items-center justify-center text-center py-20">
            <div className="w-16 h-16 rounded-2xl bg-surface-container-high border border-outline-variant/20 flex items-center justify-center mb-5">
              <span className="material-symbols-outlined text-outline" style={{ fontSize: 32 }}>security</span>
            </div>
            <h2 className="font-headline text-xl font-bold text-on-surface mb-2">Selecciona un objetivo</h2>
            <p className="text-sm text-on-surface-variant max-w-xs">
              Elige un target del panel izquierdo para ver el análisis completo de seguridad.
            </p>
          </div>
        ) : loadingDetails ? (
          <div className="flex flex-col items-center justify-center py-20">
            <div className="w-10 h-10 border-4 border-primary border-t-transparent rounded-full animate-spin mb-4" />
            <p className="font-mono text-xs text-on-surface-variant animate-pulse">Cargando análisis...</p>
          </div>
        ) : (
          <div className="space-y-5 max-w-5xl">

            {/* Target header */}
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">target_analysis</p>
                <h2 className="font-headline text-3xl font-bold text-on-background tracking-tight">{selectedTarget.name}</h2>
                <p className="font-mono text-sm text-primary mt-1">{selectedTarget.url}</p>
              </div>
              {scanning && (
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/30 shrink-0 mt-1">
                  <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                  <span className="font-mono text-[0.6rem] text-primary uppercase tracking-widest">Escaneando</span>
                </div>
              )}
            </div>

            {/* ── WAF Status ─────────────────────────────────── */}
            <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 border-l-4 border-l-error p-6 flex items-center gap-5">
              <div className="w-14 h-14 rounded-xl bg-error/10 border border-error/20 flex items-center justify-center">
                {wafDetails === null && scanning
                  ? <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  : <span className="material-symbols-outlined text-error" style={{ fontSize: 30 }}>security</span>
                }
              </div>
              <div>
                <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">firewall_status</p>
                <p className="font-headline text-2xl font-bold text-on-surface">
                  {wafDetails === null
                    ? (scanning ? 'Detectando...' : 'SIN ESCANEO')
                    : Array.isArray(wafDetails) && wafDetails.length > 0
                      ? (wafDetails[0].firewall || 'WAF ACTIVE')
                      : 'NO DETECTADO'}
                </p>
              </div>
            </div>

            {/* ── OWASP ZAP Table ────────────────────────────── */}
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
                    {zapDetails?.vulnerabilities?.length > 0 ? (() => {
                      const renderZapRow = (v, i) => {
                        const c = getSeverityColor(v.severidad);
                        return (
                          <tr key={i} className="border-b border-outline-variant/10 hover:bg-primary/5 transition-colors">
                            <td className="py-3 pr-4">
                              <span className={`font-mono text-[0.6rem] font-semibold tracking-[0.08em] px-2 py-0.5 rounded border ${c.text} ${c.bg} ${c.border}`}>
                                {v.severidad}
                              </span>
                            </td>
                            <td className="py-3 pr-4 font-body text-sm text-on-surface font-medium">{v.vulnerabilidad}</td>
                            <td className="py-3 pr-4 font-mono text-xs text-on-surface-variant max-w-[220px] break-all">{v.evidencia}</td>
                            <td className="py-3 font-mono text-xs font-semibold text-primary">{v.owasp_id}</td>
                          </tr>
                        );
                      };
                      const important = zapDetails.vulnerabilities.filter(v => !isMinorSeverity(v.severidad));
                      const minor     = zapDetails.vulnerabilities.filter(v => isMinorSeverity(v.severidad));
                      return (
                        <>
                          {important.map(renderZapRow)}
                          {minor.length > 0 && (
                            <SeverityToggleRow
                              count={minor.length}
                              expanded={showLowZap}
                              onToggle={() => setShowLowZap(s => !s)}
                              colSpan={4}
                            />
                          )}
                          {showLowZap && minor.map(renderZapRow)}
                        </>
                      );
                    })() : (
                      <ModuleEmpty scanning={scanning} label="// sin reportes de ZAP disponibles" rows />
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* ── HTTP Headers + SSL side by side ─────────────── */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              {/* HTTP Headers */}
              <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6">
                <PanelHead icon="verified_user" sub="http_security" title="Security Headers" />
                {headerDetails?.security_headers ? (
                  <div className="space-y-2">
                    {Object.entries(headerDetails.security_headers).map(([hName, data]) => {
                      const missing = data.status !== 'Presente';
                      const sev = missing ? HEADER_SEVERITY[hName] : null;
                      const c = sev ? getSeverityColor(sev) : null;
                      return (
                        <div key={hName} className="flex items-center justify-between p-3 bg-surface-container-lowest rounded-lg border border-outline-variant/20">
                          <div className="min-w-0 mr-3">
                            <p className="font-mono text-xs font-semibold text-on-surface">{hName}</p>
                            {data.value && (
                              <p className="font-mono text-[0.65rem] text-on-surface-variant break-all mt-0.5">{data.value}</p>
                            )}
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            {missing && c && (
                              <span className={`font-mono text-[0.55rem] font-semibold tracking-[0.08em] px-1.5 py-0.5 rounded border ${c.text} ${c.bg} ${c.border}`}>
                                {sev.toUpperCase()}
                              </span>
                            )}
                            {missing
                              ? <span className="material-symbols-outlined text-error" style={{ fontSize: 20 }}>error</span>
                              : <span className="material-symbols-outlined text-primary" style={{ fontSize: 20 }}>check_circle</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <ModuleEmpty scanning={scanning} label="// sin reporte de cabeceras" />
                )}
              </div>

              {/* SSL/TLS */}
              <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6">
                <PanelHead icon="radar" sub="cryptography" title="SSL / TLS Protocols"
                  color="text-secondary" iconBg="bg-secondary/10 border-secondary/20" />
                {certDetails?.protocols ? (
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(certDetails.protocols).map(([p, s]) => {
                      const ok = s === 'Soportado';
                      const dangerous = ok && SSL_SEVERITY[p];
                      const sev = dangerous ? SSL_SEVERITY[p] : null;
                      const c = sev ? getSeverityColor(sev) : null;
                      return (
                        <div key={p}
                          className={`flex items-center justify-between px-3 py-2 rounded-lg border ${
                            dangerous
                              ? 'bg-error/10 border-error/30'
                              : ok
                              ? 'bg-primary/10 border-primary/30'
                              : 'bg-surface-container-lowest border-outline-variant/20'
                          }`}
                        >
                          <span className={`font-mono text-xs font-semibold ${dangerous ? 'text-error' : ok ? 'text-primary' : 'text-outline'}`}>{p}</span>
                          <div className="flex items-center gap-1.5">
                            {c && (
                              <span className={`font-mono text-[0.5rem] font-semibold px-1 py-0.5 rounded border ${c.text} ${c.bg} ${c.border}`}>
                                {sev.toUpperCase()}
                              </span>
                            )}
                            <span
                              className={`w-1.5 h-1.5 rounded-full ${dangerous ? 'bg-error' : ok ? 'bg-primary' : 'bg-outline'}`}
                              style={ok ? { boxShadow: `0 0 6px ${dangerous ? '#ff6e84' : '#9aa8ff'}` } : {}}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <ModuleEmpty scanning={scanning} label="// sin reporte SSL/TLS" />
                )}
              </div>
            </div>

            {/* ── Tech Stack ────────────────────────────────────── */}
            <div className="bg-surface-container-lowest rounded-2xl border border-outline-variant/20 p-6">
              <PanelHead icon="terminal" sub="fingerprinting" title="Stack Tecnológico" />
              <div className="flex flex-wrap gap-2">
                {jsonDetails?.technologies?.length > 0 ? jsonDetails.technologies.map((tech, i) => (
                  <span key={i} className="font-mono text-xs text-primary bg-primary/10 border border-primary/20 rounded-md px-3 py-1">
                    {tech}
                  </span>
                )) : (
                  <ModuleEmpty scanning={scanning} label="// sin datos de fingerprinting" />
                )}
              </div>
            </div>

            {/* ── Nikto Table ───────────────────────────────────── */}
            <div className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6">
              <PanelHead icon="bug_report" sub="web_server_scanner" title="Vulnerabilities · Nikto Scan"
                color="text-secondary" iconBg="bg-secondary/10 border-secondary/20" />
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-outline-variant/20">
                      {['Riesgo', 'Método', 'Hallazgo / Mensaje', 'URL'].map(h => (
                        <th key={h} className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] text-left py-3 pr-4">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {niktoDetails?.vulnerabilities?.length > 0 ? (() => {
                      const renderNiktoRow = (v, i) => {
                        const c = getSeverityColor(v.severity || 'low');
                        return (
                          <tr key={i} className="border-b border-outline-variant/10 hover:bg-primary/5 transition-colors">
                            <td className="py-3 pr-4">
                              <span className={`font-mono text-[0.6rem] font-semibold tracking-[0.08em] px-2 py-0.5 rounded border ${c.text} ${c.bg} ${c.border}`}>
                                {(v.severity || 'low').toUpperCase()}
                              </span>
                            </td>
                            <td className="py-3 pr-4 font-mono text-xs font-semibold text-primary">{v.method}</td>
                            <td className="py-3 pr-4 font-body text-sm text-on-surface">{v.msg}</td>
                            <td className="py-3 font-mono text-xs text-on-surface-variant">{v.url}</td>
                          </tr>
                        );
                      };
                      const important = niktoDetails.vulnerabilities.filter(v => !isMinorSeverity(v.severity || 'low'));
                      const minor     = niktoDetails.vulnerabilities.filter(v => isMinorSeverity(v.severity || 'low'));
                      return (
                        <>
                          {important.map(renderNiktoRow)}
                          {minor.length > 0 && (
                            <SeverityToggleRow
                              count={minor.length}
                              expanded={showLowNikto}
                              onToggle={() => setShowLowNikto(s => !s)}
                              colSpan={4}
                            />
                          )}
                          {showLowNikto && minor.map(renderNiktoRow)}
                        </>
                      );
                    })() : (
                      <ModuleEmpty scanning={scanning} label="// sin reportes de Nikto" rows />
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* ── Módulos auto-detectados (Scan Engine) ─────────── */}
            {extraModules.map((mod) => {
              const findings = genericFindings[mod.id] || [];
              return (
                <div key={mod.id} className="bg-surface-container-low rounded-2xl border border-outline-variant/20 p-6">
                  <PanelHead icon="extension" sub={mod.id} title={mod.label}
                    color="text-on-surface-variant" iconBg="bg-outline-variant/10 border-outline-variant/20" />
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-outline-variant/20">
                          {['Riesgo', 'Hallazgo', 'Descripción'].map(h => (
                            <th key={h} className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] text-left py-3 pr-4">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {findings.length > 0 ? (() => {
                          const renderRow = (f, i) => {
                            const c = getSeverityColor(f.severity);
                            return (
                              <tr key={f.id ?? i} className="border-b border-outline-variant/10 hover:bg-primary/5 transition-colors">
                                <td className="py-3 pr-4">
                                  <span className={`font-mono text-[0.6rem] font-semibold tracking-[0.08em] px-2 py-0.5 rounded border ${c.text} ${c.bg} ${c.border}`}>
                                    {(f.severity || 'info').toUpperCase()}
                                  </span>
                                </td>
                                <td className="py-3 pr-4 font-body text-sm text-on-surface font-medium">{f.title}</td>
                                <td className="py-3 font-mono text-xs text-on-surface-variant max-w-[320px] break-all">{f.description}</td>
                              </tr>
                            );
                          };
                          const important = findings.filter(f => !isMinorSeverity(f.severity));
                          const minor     = findings.filter(f => isMinorSeverity(f.severity));
                          return (
                            <>
                              {important.map(renderRow)}
                              {minor.length > 0 && (
                                <SeverityToggleRow
                                  count={minor.length}
                                  expanded={!!showLowExtra[mod.id]}
                                  onToggle={() => toggleLowExtra(mod.id)}
                                  colSpan={3}
                                />
                              )}
                              {showLowExtra[mod.id] && minor.map(renderRow)}
                            </>
                          );
                        })() : (
                          <ModuleEmpty scanning={scanning} label={`// sin reportes de ${mod.label}`} rows />
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              );
            })}

          </div>
        )}
      </div>
    </div>
  );
}
