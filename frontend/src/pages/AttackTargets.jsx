import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import AttackPlanViewer from '../components/AttackPlanViewer';
import LiveTerminal from '../components/LiveTerminal';
import EvidenceGallery from '../components/EvidenceGallery';

const BASE = 'http://127.0.0.1:8000';

const R = {
  primary:       '#FF3131',
  primaryDim:    'rgba(255,49,49,0.15)',
  primaryBorder: 'rgba(255,49,49,0.3)',
  card:          'rgba(30,8,8,0.5)',
  bg:            '#0a0505',
};

const STATUS_COLOR = {
  Completado: '#4caf50',
  Escaneando: '#ff9800',
  Error:      '#FF3131',
  Pendiente:  'rgba(255,255,255,0.3)',
};

const RUN_STATUS_COLOR = {
  completed: '#4ade80',
  running:   '#facc15',
  planned:   '#facc15',
  failed:    '#FF3131',
  aborted:   '#fb923c',
};

function PulsingDot() {
  return (
    <span className="w-2 h-2 rounded-full shrink-0"
      style={{ backgroundColor: R.primary, animation: 'pulse-red 2s infinite', boxShadow: `0 0 6px ${R.primary}` }} />
  );
}

// Small inline status check for target data loaded from backend
function DataStatusBar({ target, findings, loading }) {
  const hasData  = target.status === 'Completado' || findings > 0;
  const scanning = target.status === 'Escaneando';

  const dotColor = scanning ? '#ff9800' : hasData ? '#4ade80' : 'rgba(255,255,255,0.2)';
  const label    = scanning ? 'Escaneando...' : hasData ? 'Datos disponibles' : 'Sin datos de escaneo';
  const labelClr = scanning ? '#ff9800'       : hasData ? '#4ade80'           : 'rgba(255,255,255,0.3)';

  return (
    <div className="rounded-lg px-4 py-2.5 flex items-center gap-4 flex-wrap"
         style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.07)' }}>
      {/* main status */}
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-full shrink-0"
              style={{ backgroundColor: dotColor, boxShadow: hasData || scanning ? `0 0 5px ${dotColor}` : undefined,
                       animation: scanning ? 'pulse-red 1.5s infinite' : undefined }} />
        <span className="text-[10px] font-bold" style={{ color: labelClr }}>{label}</span>
      </div>

      <span style={{ width: 1, height: 12, background: 'rgba(255,255,255,0.1)', display: 'inline-block' }} />

      {/* WAF */}
      <div className="flex items-center gap-1.5">
        <span className="material-symbols-outlined"
              style={{ fontSize: 11, color: target.waf_detected ? '#ff9800' : 'rgba(255,255,255,0.2)' }}>
          security
        </span>
        <span className="text-[10px] font-mono"
              style={{ color: target.waf_detected ? '#ff9800' : 'rgba(255,255,255,0.25)' }}>
          {target.waf_detected ? `WAF: ${target.waf_detected}` : 'Sin WAF detectado'}
        </span>
      </div>

      <span style={{ width: 1, height: 12, background: 'rgba(255,255,255,0.1)', display: 'inline-block' }} />

      {/* findings */}
      <div className="flex items-center gap-1.5">
        <span className="material-symbols-outlined"
              style={{ fontSize: 11, color: findings > 0 ? '#facc15' : 'rgba(255,255,255,0.2)',
                       animation: loading ? 'spin 1s linear infinite' : undefined }}>
          {loading ? 'sync' : 'crisis_alert'}
        </span>
        <span className="text-[10px] font-mono"
              style={{ color: findings > 0 ? '#facc15' : 'rgba(255,255,255,0.25)' }}>
          {loading ? 'cargando...' : findings > 0 ? `${findings} finding${findings !== 1 ? 's' : ''}` : '0 findings'}
        </span>
      </div>

      {/* last scan */}
      {target.last_scan && (
        <>
          <span style={{ width: 1, height: 12, background: 'rgba(255,255,255,0.1)', display: 'inline-block' }} />
          <span className="text-[10px] font-mono" style={{ color: 'rgba(255,255,255,0.25)' }}>
            {new Date(target.last_scan).toLocaleDateString('es-ES', {
              day: '2-digit', month: '2-digit', year: '2-digit',
              hour: '2-digit', minute: '2-digit',
            })}
          </span>
        </>
      )}

      {/* no-data hint */}
      {!hasData && !scanning && (
        <>
          <span style={{ width: 1, height: 12, background: 'rgba(255,255,255,0.1)', display: 'inline-block' }} />
          <span className="text-[9px]" style={{ color: 'rgba(255,255,255,0.2)' }}>
            Ejecuta un escaneo desde Anubis Scan primero
          </span>
        </>
      )}
    </div>
  );
}

export default function AttackTargets() {
  // ── Targets ───────────────────────────────────────────────────────────────
  const [targets, setTargets]     = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading]     = useState(true);

  // derivado — siempre en sync con targets sin setSelected extra
  const selected = targets.find(t => t.id === selectedId) ?? null;
  const [name, setName]         = useState('');
  const [url, setUrl]           = useState('');
  const [addOpen, setAddOpen]   = useState(false);
  const [adding, setAdding]     = useState(false);

  // ── Target findings ───────────────────────────────────────────────────────
  const [targetFindings, setTargetFindings]   = useState(0);
  const [targetSeverity, setTargetSeverity]   = useState({});
  const [findingsLoading, setFindingsLoading] = useState(false);

  // ── AI Attack Plan ────────────────────────────────────────────────────────
  const [aiPlan, setAiPlan]               = useState(null);
  const [aiPlanLoading, setAiPlanLoading] = useState(false);
  const [vectorModal, setVectorModal]     = useState(null);   // vector obj | null
  const [vectorInstructions, setVectorInstructions] = useState('');
  const [vectorRunPhase, setVectorRunPhase] = useState('idle'); // idle|running|done
  const [vectorRunId, setVectorRunId]       = useState(null);
  const [vectorRunResult, setVectorRunResult] = useState(null);

  const WS_BASE = 'ws://127.0.0.1:8000';

  const launchVectorRun = useCallback(async (mode) => {
    if (!selected || !vectorModal) return;
    setVectorRunPhase('running');
    setVectorRunId(null);
    setVectorRunResult(null);
    try {
      const res = await axios.post(`${BASE}/attack/vector-run`, {
        target_id: selected.id,
        vector: vectorModal,
        mode,
        instructions: vectorInstructions,
      });
      const runId = res.data.run_id;
      setVectorRunId(runId);
      // Poll until completed
      const poll = setInterval(async () => {
        try {
          const r = await axios.get(`${BASE}/attack/vector-run/${runId}`);
          if (r.data.status === 'completed' || r.data.status === 'failed') {
            clearInterval(poll);
            setVectorRunResult(r.data);
            setVectorRunPhase('done');
          }
        } catch {}
      }, 2500);
    } catch (e) {
      setVectorRunPhase('idle');
    }
  }, [selected, vectorModal, vectorInstructions]);

  // ── Attack Run ────────────────────────────────────────────────────────────
  const [authorizations, setAuthorizations]               = useState([]);
  const [activeRun, setActiveRun]                         = useState(null);
  const [runResults, setRunResults]                       = useState([]);
  const [selectedIntrusiveness, setSelectedIntrusiveness] = useState('active');
  const [selectedAuthId, setSelectedAuthId]               = useState('');
  const [attackLaunching, setAttackLaunching]             = useState(false);
  const [showAuthForm, setShowAuthForm]                   = useState(false);
  const [authForm, setAuthForm] = useState({
    domain_pattern: '', valid_from: '', valid_until: '',
    authorized_by: 'admin', allowed_intrusiveness: 'active', notes: '',
  });

  // ── Fetch ─────────────────────────────────────────────────────────────────
  // Sin dependencia en `selected` — el intervalo se crea una sola vez.
  // setTargets actualiza targets y `selected` se re-deriva automáticamente.
  const fetchTargets = useCallback(async () => {
    try {
      const r = await axios.get(`${BASE}/targets/?nocache=${Date.now()}`);
      setTargets(r.data);
    } catch {}
  }, []);

  const fetchAuthorizations = useCallback(async () => {
    try {
      const r = await axios.get(`${BASE}/authorized-targets`);
      setAuthorizations(r.data || []);
    } catch {}
  }, []);

  useEffect(() => {
    fetchTargets().finally(() => setLoading(false));
    fetchAuthorizations();
    const iv = setInterval(fetchTargets, 8000);
    return () => clearInterval(iv);
  }, [fetchTargets, fetchAuthorizations]);

  // ── Fetch findings + plan guardado cuando cambia el target ───────────────
  useEffect(() => {
    setAiPlan(null);
    if (!selected) { setTargetFindings(0); setTargetSeverity({}); return; }

    setFindingsLoading(true);
    Promise.all([
      axios.get(`${BASE}/findings/historical`),
      axios.get(`${BASE}/attack/ai-plan/${selectedId}`).catch(() => ({ data: null })),
    ]).then(([findingsRes, planRes]) => {
      const groups = (findingsRes.data || []).filter(g => g.target_id === selectedId);
      const total  = groups.reduce((sum, g) => sum + (g.count || 0), 0);
      const sev = {};
      groups.forEach(g => (g.findings || []).forEach(f => {
        const s = (f.severity || 'info').toLowerCase();
        sev[s] = (sev[s] || 0) + 1;
      }));
      setTargetFindings(total);
      setTargetSeverity(sev);
      if (planRes.data) setAiPlan(planRes.data);
    }).catch(() => { setTargetFindings(0); setTargetSeverity({}); })
      .finally(() => setFindingsLoading(false));
  }, [selectedId]);

  // ── Poll run while active ─────────────────────────────────────────────────
  useEffect(() => {
    if (!activeRun || ['completed', 'aborted', 'failed'].includes(activeRun.status)) return;
    const interval = setInterval(async () => {
      try {
        const [runRes, resultsRes] = await Promise.all([
          axios.get(`${BASE}/attack/runs/${activeRun.id}`),
          axios.get(`${BASE}/attack/runs/${activeRun.id}/results`),
        ]);
        setActiveRun(runRes.data);
        setRunResults(resultsRes.data || []);
      } catch {}
    }, 4000);
    return () => clearInterval(interval);
  }, [activeRun]);

  // ── Handlers ──────────────────────────────────────────────────────────────
  const handleAdd = async (e) => {
    e.preventDefault();
    if (!name.trim() || !url.trim()) return;
    setAdding(true);
    try {
      await axios.post(`${BASE}/targets/`, { name: name.trim(), url: url.trim() });
      setName(''); setUrl(''); setAddOpen(false);
      fetchTargets();
    } catch {}
    finally { setAdding(false); }
  };

  const handleDelete = async (id) => {
    if (!confirm('¿Eliminar este target?')) return;
    try {
      await axios.delete(`${BASE}/targets/${id}`);
      if (selectedId === id) { setSelectedId(null); setActiveRun(null); setRunResults([]); }
      fetchTargets();
    } catch {}
  };

  const launchAttack = async () => {
    if (!selected) return;
    setAttackLaunching(true);
    try {
      const res = await axios.post(`${BASE}/attack/runs`, {
        target_id: selected.id,
        intrusiveness: selectedIntrusiveness,
        authorized_target_id: selectedAuthId ? parseInt(selectedAuthId) : undefined,
        confidence_threshold: 0.4,
      });
      setActiveRun(res.data);
      setRunResults([]);
    } catch (e) {
      alert(e.response?.data?.detail || 'Error lanzando attack run');
    } finally {
      setAttackLaunching(false);
    }
  };

  const abortRun = async () => {
    if (!activeRun) return;
    try {
      await axios.post(`${BASE}/attack/runs/${activeRun.id}/abort`);
      setActiveRun(r => ({ ...r, status: 'aborted' }));
    } catch (e) {
      alert(e.response?.data?.detail || 'Error al abortar');
    }
  };

  const registerAuthorization = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${BASE}/authorized-targets`, {
        ...authForm,
        valid_from:  new Date(authForm.valid_from).toISOString(),
        valid_until: new Date(authForm.valid_until).toISOString(),
      });
      setShowAuthForm(false);
      setAuthForm({ domain_pattern: '', valid_from: '', valid_until: '', authorized_by: 'admin', allowed_intrusiveness: 'active', notes: '' });
      fetchAuthorizations();
    } catch (err) {
      alert(err.response?.data?.detail || 'Error registrando autorización');
    }
  };

  const generateAiPlan = async () => {
    if (!selected) return;
    setAiPlanLoading(true);
    setAiPlan(null);
    try {
      const res = await axios.post(`${BASE}/attack/ai-plan/${selected.id}`);
      setAiPlan(res.data);
    } catch (e) {
      alert(e.response?.data?.detail || 'Error generando plan con IA');
    } finally {
      setAiPlanLoading(false);
    }
  };

  const runBelongsToSelected = activeRun && selected && activeRun.target_id === selected.id;

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen" style={{ backgroundColor: R.bg }}>

      {/* Header */}
      <div className="flex items-end justify-between px-8 pt-10 pb-6">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.3em] mb-1"
             style={{ color: 'rgba(255,255,255,0.3)' }}>attack_targets</p>
          <h1 className="text-3xl font-black text-white">Targets</h1>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
               style={{ background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>
            <PulsingDot />
            <span className="font-mono text-[10px] font-bold" style={{ color: R.primary }}>
              {targets.length} TARGETS
            </span>
          </div>
          <button onClick={() => setAddOpen(true)}
            className="px-5 py-2 rounded-xl text-xs font-black text-white transition-all hover:brightness-110 flex items-center gap-1.5"
            style={{ background: R.primary, boxShadow: `0 0 16px ${R.primary}40` }}>
            <span className="material-symbols-outlined text-sm">add</span>
            Nuevo Target
          </button>
        </div>
      </div>

      {/* Main layout */}
      <div className="flex px-8 gap-6 pb-8">

        {/* Target list — ancho fijo, tarjetas angostas */}
        <div className="w-[400px] shrink-0 space-y-3">
          {loading ? (
            <div className="flex justify-center py-16">
              <span className="material-symbols-outlined animate-spin"
                    style={{ fontSize: 32, color: R.primary }}>sync</span>
            </div>
          ) : targets.length === 0 ? (
            <div className="text-center py-24 rounded-xl border-2 border-dashed"
                 style={{ borderColor: 'rgba(255,49,49,0.2)' }}>
              <span className="material-symbols-outlined text-5xl mb-3 block"
                    style={{ color: 'rgba(255,49,49,0.3)' }}>radar</span>
              <p className="text-lg font-black text-white">Sin targets registrados</p>
              <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,0.3)' }}>
                Añade un objetivo para comenzar
              </p>
            </div>
          ) : targets.map(t => (
            <div key={t.id}
              className="rounded-xl overflow-hidden transition-all cursor-pointer"
              style={{
                background: selected?.id === t.id ? 'rgba(45,10,10,0.7)' : R.card,
                border: `1px solid ${selected?.id === t.id ? R.primary : 'rgba(255,49,49,0.15)'}`,
                animation: selected?.id === t.id ? 'neon-pulse 4s ease-in-out infinite' : undefined,
              }}
              onClick={() => setSelectedId(selectedId === t.id ? null : t.id)}>

              {/* Target row */}
              <div className="flex items-center gap-4 px-5 py-4">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                     style={{ background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>
                  <span className="material-symbols-outlined"
                        style={{ color: R.primary, fontSize: 20 }}>language</span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-bold text-white">{t.name}</p>
                  <p className="font-mono text-xs truncate"
                     style={{ color: 'rgba(255,255,255,0.4)' }}>{t.url}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded"
                        style={{
                          color: STATUS_COLOR[t.status] || 'rgba(255,255,255,0.3)',
                          background: `${STATUS_COLOR[t.status] || 'rgba(255,255,255,0.1)'}20`,
                          border: `1px solid ${STATUS_COLOR[t.status] || 'rgba(255,255,255,0.1)'}50`,
                        }}>
                    {t.status || 'Pendiente'}
                  </span>
                  {t.waf_detected && (
                    <span className="font-mono text-[10px] px-2 py-0.5 rounded"
                          style={{ color: '#ff9800', background: 'rgba(255,152,0,0.1)', border: '1px solid rgba(255,152,0,0.3)' }}>
                      WAF
                    </span>
                  )}
                  <button onClick={e => { e.stopPropagation(); handleDelete(t.id); }}
                    className="w-7 h-7 rounded-lg flex items-center justify-center transition-all hover:bg-red-900/40"
                    style={{ color: 'rgba(255,255,255,0.3)' }}>
                    <span className="material-symbols-outlined" style={{ fontSize: 16 }}>delete</span>
                  </button>
                </div>
              </div>

              {/* Expanded section */}
              {selected?.id === t.id && (
                <div className="border-t px-5 py-4 space-y-4"
                     style={{ borderColor: 'rgba(255,49,49,0.15)' }}
                     onClick={e => e.stopPropagation()}>

                  {/* ── Data status check ─────────────────────────────────── */}
                  <div>
                    <p className="text-[9px] font-bold uppercase tracking-[0.2em] mb-2"
                       style={{ color: 'rgba(255,255,255,0.25)' }}>datos_objetivo</p>
                    <DataStatusBar
                      target={t}
                      findings={targetFindings}
                      loading={findingsLoading}
                    />
                  </div>

                  {/* ── Attack Run controls ────────────────────────────────── */}
                  <div>
                    <p className="text-[9px] font-bold uppercase tracking-[0.2em] mb-2"
                       style={{ color: 'rgba(255,255,255,0.25)' }}>attack_run</p>

                    <div className="rounded-xl overflow-hidden"
                         style={{ border: '1px solid rgba(255,49,49,0.2)' }}>

                      {/* Controls row */}
                      <div className="px-4 py-3 flex flex-wrap items-end gap-3"
                           style={{ background: 'rgba(20,4,4,0.5)' }}>

                        <div className="flex flex-col gap-1">
                          <label className="text-[9px] font-bold uppercase tracking-wider"
                                 style={{ color: 'rgba(255,255,255,0.3)' }}>Intrusividad</label>
                          <select value={selectedIntrusiveness}
                                  onChange={e => setSelectedIntrusiveness(e.target.value)}
                                  style={{ background: '#1a0505', border: '1px solid rgba(255,49,49,0.25)', color: 'white', borderRadius: 8, padding: '5px 9px', fontSize: 11 }}>
                            <option value="passive">Passive</option>
                            <option value="active">Active</option>
                            <option value="exploitive">Exploitive</option>
                          </select>
                        </div>

                        <div className="flex flex-col gap-1">
                          <label className="text-[9px] font-bold uppercase tracking-wider"
                                 style={{ color: 'rgba(255,255,255,0.3)' }}>Autorización</label>
                          <select value={selectedAuthId}
                                  onChange={e => setSelectedAuthId(e.target.value)}
                                  style={{ background: '#1a0505', border: '1px solid rgba(255,49,49,0.25)', color: 'white', borderRadius: 8, padding: '5px 9px', fontSize: 11 }}>
                            <option value="">Sin autorización</option>
                            {authorizations.filter(a => a.is_active).map(a => (
                              <option key={a.id} value={a.id}>
                                {a.domain_pattern} · {(a.valid_until || '').substring(0, 10)}
                              </option>
                            ))}
                          </select>
                        </div>

                        <button onClick={launchAttack} disabled={attackLaunching}
                          className="px-5 py-2 rounded-xl text-xs font-black text-black transition-all hover:scale-105 disabled:opacity-40 flex items-center gap-1.5"
                          style={{ backgroundColor: R.primary, boxShadow: `0 0 12px ${R.primary}40` }}>
                          <span className="material-symbols-outlined text-[13px]"
                                style={{ fontVariationSettings: "'FILL' 1" }}>bolt</span>
                          {attackLaunching ? 'Lanzando...' : 'LAUNCH'}
                        </button>

                        {runBelongsToSelected && activeRun && ['planned', 'running'].includes(activeRun.status) && (
                          <button onClick={abortRun}
                            className="px-4 py-2 rounded-xl text-xs font-bold text-white transition-all hover:brightness-125"
                            style={{ border: '1px solid rgba(255,49,49,0.4)' }}>
                            ■ Abort
                          </button>
                        )}
                      </div>

                      {/* Run status strip */}
                      {runBelongsToSelected && activeRun && (
                        <div className="px-4 py-2 flex items-center gap-3"
                             style={{ background: 'rgba(0,0,0,0.2)', borderTop: '1px solid rgba(255,49,49,0.1)' }}>
                          <span className="w-1.5 h-1.5 rounded-full"
                                style={{ backgroundColor: RUN_STATUS_COLOR[activeRun.status] || 'white',
                                         animation: ['planned','running'].includes(activeRun.status) ? 'pulse-red 1.5s infinite' : undefined }} />
                          <span className="text-[9px] font-bold uppercase"
                                style={{ color: 'rgba(255,255,255,0.3)' }}>Run #{activeRun.id}</span>
                          <span className="text-[10px] font-black"
                                style={{ color: RUN_STATUS_COLOR[activeRun.status] || 'white' }}>
                            {(activeRun.status || '').toUpperCase()}
                          </span>
                          <span className="text-[9px] ml-auto" style={{ color: 'rgba(255,255,255,0.25)' }}>
                            {activeRun.node_count} nodos · {activeRun.intrusiveness}
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Register auth shortcut */}
                    <div className="mt-2">
                      <button onClick={() => setShowAuthForm(f => !f)}
                        className="text-[9px] font-bold transition-all hover:text-white"
                        style={{ color: 'rgba(255,255,255,0.25)' }}>
                        {showAuthForm ? '✕ cancelar' : '+ registrar autorización'}
                      </button>

                      {showAuthForm && (
                        <form className="mt-2 rounded-xl p-3 space-y-1.5"
                              style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,49,49,0.15)' }}
                              onSubmit={registerAuthorization}>
                          <div className="grid grid-cols-2 gap-1.5">
                            <input type="text" placeholder="*.ejemplo.com" required
                              value={authForm.domain_pattern}
                              onChange={e => setAuthForm(f => ({ ...f, domain_pattern: e.target.value }))}
                              style={{ background: '#1a0505', border: '1px solid rgba(255,49,49,0.2)', color: 'white', borderRadius: 6, padding: '4px 8px', fontSize: 10 }} />
                            <input type="text" placeholder="Autorizado por" required
                              value={authForm.authorized_by}
                              onChange={e => setAuthForm(f => ({ ...f, authorized_by: e.target.value }))}
                              style={{ background: '#1a0505', border: '1px solid rgba(255,49,49,0.2)', color: 'white', borderRadius: 6, padding: '4px 8px', fontSize: 10 }} />
                            <input type="datetime-local" required
                              value={authForm.valid_from}
                              onChange={e => setAuthForm(f => ({ ...f, valid_from: e.target.value }))}
                              style={{ background: '#1a0505', border: '1px solid rgba(255,49,49,0.2)', color: 'white', borderRadius: 6, padding: '4px 8px', fontSize: 10 }} />
                            <input type="datetime-local" required
                              value={authForm.valid_until}
                              onChange={e => setAuthForm(f => ({ ...f, valid_until: e.target.value }))}
                              style={{ background: '#1a0505', border: '1px solid rgba(255,49,49,0.2)', color: 'white', borderRadius: 6, padding: '4px 8px', fontSize: 10 }} />
                          </div>
                          <div className="flex gap-1.5">
                            <select value={authForm.allowed_intrusiveness}
                              onChange={e => setAuthForm(f => ({ ...f, allowed_intrusiveness: e.target.value }))}
                              style={{ flex: 1, background: '#1a0505', border: '1px solid rgba(255,49,49,0.2)', color: 'white', borderRadius: 6, padding: '4px 8px', fontSize: 10 }}>
                              <option value="passive">Passive</option>
                              <option value="active">Active</option>
                              <option value="exploitive">Exploitive</option>
                            </select>
                            <button type="submit"
                              className="px-4 py-1 rounded-lg text-[10px] font-black text-black"
                              style={{ backgroundColor: R.primary }}>Registrar</button>
                          </div>
                        </form>
                      )}
                    </div>
                  </div>

                </div>
              )}
            </div>
          ))}
        </div>

        {/* Right panel — siempre visible, ocupa el espacio restante */}
        <div className="flex-1 min-w-0">
          <div className="rounded-2xl overflow-hidden h-full"
               style={{ background: R.card, border: `1px solid ${R.primaryBorder}`, animation: 'neon-pulse 4s ease-in-out infinite' }}>

            {!selected ? (
              /* ── Sin selección ──────────────────────────────────────────── */
              <div className="flex flex-col items-center justify-center h-full min-h-[340px] gap-4"
                   style={{ color: 'rgba(255,255,255,0.15)' }}>
                <span className="material-symbols-outlined" style={{ fontSize: 56, color: 'rgba(255,49,49,0.15)' }}>
                  ads_click
                </span>
                <p className="text-sm font-bold" style={{ color: 'rgba(255,255,255,0.2)' }}>
                  Selecciona un target
                </p>
                <p className="text-[10px]" style={{ color: 'rgba(255,255,255,0.12)' }}>
                  Haz clic en cualquier objetivo de la lista
                </p>
              </div>
            ) : (
              /* ── Target seleccionado ────────────────────────────────────── */
              <div className="flex flex-col h-full">

                {/* Cabecera del target */}
                <div className="px-8 pt-8 pb-6"
                     style={{ borderBottom: '1px solid rgba(255,49,49,0.12)' }}>
                  <p className="text-[9px] font-bold uppercase tracking-[0.25em] mb-3"
                     style={{ color: 'rgba(255,255,255,0.25)' }}>target_info</p>
                  <div className="flex items-start gap-4">
                    <div className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0"
                         style={{ background: R.primaryDim, border: `1px solid ${R.primaryBorder}` }}>
                      <span className="material-symbols-outlined"
                            style={{ color: R.primary, fontSize: 22 }}>language</span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <h2 className="text-xl font-black text-white leading-tight mb-1 truncate">
                        {selected.name}
                      </h2>
                      <p className="font-mono text-xs break-all"
                         style={{ color: 'rgba(255,255,255,0.35)' }}>{selected.url}</p>
                    </div>
                    <span className="shrink-0 font-mono text-[10px] font-bold px-2.5 py-1 rounded-lg"
                          style={{
                            color: STATUS_COLOR[selected.status] || 'rgba(255,255,255,0.3)',
                            background: `${STATUS_COLOR[selected.status] || 'rgba(255,255,255,0.08)'}18`,
                            border: `1px solid ${STATUS_COLOR[selected.status] || 'rgba(255,255,255,0.1)'}40`,
                          }}>
                      {selected.status || 'Pendiente'}
                    </span>
                  </div>
                </div>

                {/* Cuerpo */}
                <div className="px-8 py-6 flex-1 space-y-6">

                  {/* Data status */}
                  <div>
                    <p className="text-[9px] font-bold uppercase tracking-[0.2em] mb-2"
                       style={{ color: 'rgba(255,255,255,0.25)' }}>datos_objetivo</p>
                    <DataStatusBar
                      target={selected}
                      findings={targetFindings}
                      loading={findingsLoading}
                    />
                  </div>

                  {/* Detalles */}
                  <div>
                    <p className="text-[9px] font-bold uppercase tracking-[0.2em] mb-3"
                       style={{ color: 'rgba(255,255,255,0.25)' }}>detalles</p>
                    <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                      {[
                        { label: 'WAF',         value: selected.waf_detected || 'No detectado',
                          color: selected.waf_detected ? '#ff9800' : undefined },
                        { label: 'ID',          value: `#${selected.id}` },
                        { label: 'Último scan', value: selected.last_scan
                            ? new Date(selected.last_scan).toLocaleString('es-ES', { day:'2-digit', month:'2-digit', year:'2-digit', hour:'2-digit', minute:'2-digit' })
                            : '—', span: true },
                      ].map(({ label, value, color, span }) => (
                        <div key={label} className={span ? 'col-span-2' : ''}>
                          <p className="text-[9px] font-bold uppercase tracking-wider mb-0.5"
                             style={{ color: 'rgba(255,255,255,0.25)' }}>{label}</p>
                          <p className="font-mono text-sm font-bold"
                             style={{ color: color || 'rgba(255,255,255,0.75)' }}>{value}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Findings por severidad */}
                  {targetFindings > 0 && (
                    <div>
                      <div className="flex items-center justify-between mb-3">
                        <p className="text-[9px] font-bold uppercase tracking-[0.2em]"
                           style={{ color: 'rgba(255,255,255,0.25)' }}>findings</p>
                        <span className="text-[10px] font-black"
                              style={{ color: 'rgba(255,255,255,0.4)' }}>{targetFindings} total</span>
                      </div>
                      <div className="space-y-2">
                        {[
                          { key: 'critical', label: 'Critical', color: '#FF3131' },
                          { key: 'high',     label: 'High',     color: '#e65100' },
                          { key: 'medium',   label: 'Medium',   color: '#ff9800' },
                          { key: 'low',      label: 'Low',      color: 'rgba(255,255,255,0.45)' },
                          { key: 'info',     label: 'Info',     color: 'rgba(255,255,255,0.2)' },
                        ].filter(s => targetSeverity[s.key] > 0).map(({ key, label, color }) => {
                          const count = targetSeverity[key] || 0;
                          const pct   = Math.round((count / targetFindings) * 100);
                          return (
                            <div key={key} className="flex items-center gap-3">
                              <span className="text-[9px] font-bold uppercase w-14 shrink-0"
                                    style={{ color }}>
                                {label}
                              </span>
                              <div className="flex-1 h-1.5 rounded-full overflow-hidden"
                                   style={{ background: 'rgba(255,255,255,0.06)' }}>
                                <div className="h-full rounded-full transition-all duration-700"
                                     style={{ width: `${pct}%`, backgroundColor: color,
                                              boxShadow: count > 0 ? `0 0 6px ${color}60` : undefined }} />
                              </div>
                              <span className="text-[10px] font-black w-5 text-right shrink-0"
                                    style={{ color }}>
                                {count}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Botón IA */}
                  <div>
                    <button
                      onClick={generateAiPlan}
                      disabled={aiPlanLoading}
                      className="w-full py-2.5 rounded-xl text-xs font-black flex items-center justify-center gap-2 transition-all hover:brightness-110 disabled:opacity-50"
                      style={{
                        background: 'linear-gradient(135deg, rgba(139,92,246,0.25), rgba(255,49,49,0.15))',
                        border: '1px solid rgba(139,92,246,0.4)',
                        color: aiPlanLoading ? 'rgba(255,255,255,0.4)' : '#c4b5fd',
                      }}>
                      <span className="material-symbols-outlined text-[15px]"
                            style={{ animation: aiPlanLoading ? 'spin 1s linear infinite' : undefined }}>
                        {aiPlanLoading ? 'sync' : 'auto_awesome'}
                      </span>
                      {aiPlanLoading ? 'Generando plan con IA...' : 'Planear con IA'}
                    </button>
                  </div>

                  {/* AI Attack Plan */}
                  {aiPlan && (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <p className="text-[9px] font-bold uppercase tracking-[0.2em]"
                           style={{ color: 'rgba(139,92,246,0.7)' }}>plan_ia</p>
                        <span className="text-[9px]" style={{ color: 'rgba(255,255,255,0.2)' }}>
                          {aiPlan.vectores?.length || 0} vectores
                        </span>
                      </div>

                      {/* Resumen */}
                      <div className="rounded-xl p-4"
                           style={{ background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.2)' }}>
                        <p className="text-xs text-white leading-relaxed">{aiPlan.resumen}</p>
                      </div>

                      {/* Razonamiento */}
                      {aiPlan.razonamiento && (
                        <div className="rounded-xl p-3"
                             style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.06)' }}>
                          <p className="text-[10px] leading-relaxed"
                             style={{ color: 'rgba(255,255,255,0.45)' }}>{aiPlan.razonamiento}</p>
                        </div>
                      )}

                      {/* Vectores */}
                      {(aiPlan.vectores || []).map((v, i) => {
                        const prioColor = {
                          critica: '#FF3131', alta: '#e65100',
                          media: '#ff9800',   baja: 'rgba(255,255,255,0.4)',
                        }[v.prioridad] || 'rgba(255,255,255,0.4)';
                        const intrColor = {
                          exploitive: '#FF3131', active: '#fb923c', passive: 'rgba(255,255,255,0.4)',
                        }[v.intrusividad] || 'rgba(255,255,255,0.4)';
                        return (
                          <div key={i} className="rounded-xl p-4 space-y-2"
                               style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(139,92,246,0.15)' }}>
                            <div className="flex items-start gap-2">
                              <span className="text-[9px] font-black px-1.5 py-0.5 rounded shrink-0 mt-0.5"
                                    style={{ background: `${prioColor}20`, color: prioColor, border: `1px solid ${prioColor}40` }}>
                                {(v.prioridad || '').toUpperCase()}
                              </span>
                              <div className="flex-1 min-w-0">
                                <p className="text-xs font-bold text-white truncate">{v.titulo || v.nombre}</p>
                                <p className="font-mono text-[9px]" style={{ color: 'rgba(255,255,255,0.3)' }}>{v.nombre}</p>
                              </div>
                              <span className="text-[9px] font-bold shrink-0 mr-1"
                                    style={{ color: intrColor }}>{v.intrusividad}</span>
                              {/* Botón ejecutar vector */}
                              <button
                                onClick={() => { setVectorModal(v); setVectorInstructions(''); }}
                                className="shrink-0 w-8 h-8 rounded-xl flex items-center justify-center transition-all hover:brightness-125"
                                style={{ background: 'rgba(139,92,246,0.2)', border: '1px solid rgba(139,92,246,0.4)' }}
                                title="Ejecutar vector">
                                <span className="material-symbols-outlined"
                                      style={{ fontSize: 16, color: '#c4b5fd' }}>play_arrow</span>
                              </button>
                            </div>
                            <p className="text-[10px] leading-relaxed"
                               style={{ color: 'rgba(255,255,255,0.5)' }}>{v.justificacion}</p>
                            {v.finding_relacionado && (
                              <p className="text-[9px]" style={{ color: 'rgba(139,92,246,0.6)' }}>
                                ↳ {v.finding_relacionado}
                              </p>
                            )}
                            {v.depende_de?.length > 0 && (
                              <p className="text-[9px]" style={{ color: 'rgba(255,255,255,0.2)' }}>
                                espera: {v.depende_de.join(', ')}
                              </p>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* Run activo */}
                  {runBelongsToSelected && activeRun && (
                    <div>
                      <p className="text-[9px] font-bold uppercase tracking-[0.2em] mb-3"
                         style={{ color: 'rgba(255,255,255,0.25)' }}>run activo</p>
                      <div className="rounded-xl px-5 py-4 flex items-center gap-4"
                           style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid rgba(255,49,49,0.15)' }}>
                        <span className="w-2 h-2 rounded-full shrink-0"
                              style={{ backgroundColor: RUN_STATUS_COLOR[activeRun.status] || 'white',
                                       boxShadow: `0 0 6px ${RUN_STATUS_COLOR[activeRun.status] || 'white'}`,
                                       animation: ['planned','running'].includes(activeRun.status) ? 'pulse-red 1.5s infinite' : undefined }} />
                        <div>
                          <p className="text-sm font-black"
                             style={{ color: RUN_STATUS_COLOR[activeRun.status] || 'white' }}>
                            {(activeRun.status || '').toUpperCase()}
                          </p>
                          <p className="text-[10px] mt-0.5"
                             style={{ color: 'rgba(255,255,255,0.3)' }}>
                            Run #{activeRun.id} · {activeRun.node_count} nodos · {activeRun.intrusiveness}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Attack Plan + Terminal + Evidence */}
      {runBelongsToSelected && activeRun && (
        <div className="px-8 pb-20 space-y-5">
          <div className="flex items-center gap-3"
               style={{ borderTop: '1px solid rgba(255,49,49,0.12)', paddingTop: 20 }}>
            <span className="w-1 h-4 rounded-full" style={{ backgroundColor: R.primary }} />
            <p className="text-[10px] font-bold uppercase tracking-[0.2em]"
               style={{ color: 'rgba(255,255,255,0.25)' }}>
              attack run #{activeRun.id} — {selected?.name}
            </p>
          </div>

          <div className="grid grid-cols-12 gap-5">
            <div className="col-span-7">
              <p className="text-[10px] font-bold uppercase tracking-widest mb-2"
                 style={{ color: 'rgba(255,255,255,0.3)' }}>Attack Plan</p>
              <AttackPlanViewer
                plan={activeRun.plan_json
                  ? (() => { try { return JSON.parse(activeRun.plan_json); } catch { return { nodes: [], target_url: '' }; } })()
                  : { nodes: [], target_url: '' }}
                results={runResults}
              />
            </div>
            <div className="col-span-5">
              <p className="text-[10px] font-bold uppercase tracking-widest mb-2"
                 style={{ color: 'rgba(255,255,255,0.3)' }}>Live Terminal</p>
              <LiveTerminal runId={activeRun.id} />
            </div>
          </div>

          {runResults.length > 0 && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-widest mb-2"
                 style={{ color: 'rgba(255,255,255,0.3)' }}>Evidencias</p>
              <EvidenceGallery results={runResults} />
            </div>
          )}
        </div>
      )}

      {/* Vector execution modal */}
      {vectorModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
             style={{ background: 'rgba(0,0,0,0.85)' }}
             onClick={e => {
               if (e.target === e.currentTarget && vectorRunPhase !== 'running') {
                 setVectorModal(null); setVectorRunPhase('idle');
               }
             }}>
          <div className={`w-full rounded-2xl overflow-hidden flex flex-col ${vectorRunPhase === 'idle' ? 'max-w-2xl' : 'max-w-5xl'}`}
               style={{ background: '#0d0218', border: '1px solid rgba(139,92,246,0.35)', maxHeight: '90vh' }}>

            {/* Header — siempre visible */}
            <div className="px-6 py-4 flex items-start gap-3 shrink-0"
                 style={{ background: 'rgba(139,92,246,0.1)', borderBottom: '1px solid rgba(139,92,246,0.2)' }}>
              <span className="material-symbols-outlined mt-0.5"
                    style={{ fontSize: 18, color: '#c4b5fd' }}>security</span>
              <div className="flex-1 min-w-0">
                <h3 className="text-sm font-black text-white truncate">
                  {vectorModal.titulo || vectorModal.nombre}
                </h3>
                <p className="font-mono text-[10px] mt-0.5" style={{ color: 'rgba(139,92,246,0.7)' }}>
                  {vectorModal.nombre}
                  {vectorRunPhase === 'running' && (
                    <span className="ml-3 animate-pulse" style={{ color: '#facc15' }}>
                      ● ejecutando…
                    </span>
                  )}
                  {vectorRunPhase === 'done' && vectorRunResult && (
                    <span className="ml-3" style={{
                      color: { explotable: '#FF3131', no_explotable: '#4ade80', inconcluso: '#fb923c' }[vectorRunResult.estado] || '#fff'
                    }}>
                      ●{{explotable:'EXPLOTABLE', no_explotable:'NO EXPLOTABLE', inconcluso:'INCONCLUSO'}[vectorRunResult.estado]}
                    </span>
                  )}
                </p>
              </div>
              {vectorRunPhase !== 'running' && (
                <button onClick={() => { setVectorModal(null); setVectorRunPhase('idle'); }}
                        className="text-white/30 hover:text-white transition-colors shrink-0">
                  <span className="material-symbols-outlined" style={{ fontSize: 18 }}>close</span>
                </button>
              )}
            </div>

            <div className="overflow-y-auto flex-1">
              <div className="p-6 space-y-5">

                {/* ── FASE: idle (formulario) ── */}
                {vectorRunPhase === 'idle' && (<>
                  {/* Contexto del vector */}
                  <div className="rounded-xl p-4 space-y-2"
                       style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <p className="text-[9px] font-bold uppercase tracking-wider"
                       style={{ color: 'rgba(255,255,255,0.25)' }}>contexto del vector</p>
                    <p className="text-xs leading-relaxed" style={{ color: 'rgba(255,255,255,0.55)' }}>
                      {vectorModal.justificacion}
                    </p>
                    {vectorModal.finding_relacionado && (
                      <p className="text-[10px]" style={{ color: 'rgba(139,92,246,0.7)' }}>
                        ↳ Finding: {vectorModal.finding_relacionado}
                      </p>
                    )}
                  </div>

                  {/* Instrucciones adicionales */}
                  <div>
                    <label className="block text-[9px] font-bold uppercase tracking-wider mb-2"
                           style={{ color: 'rgba(255,255,255,0.35)' }}>
                      Instrucciones adicionales para la IA
                    </label>
                    <textarea
                      value={vectorInstructions}
                      onChange={e => setVectorInstructions(e.target.value)}
                      rows={4}
                      placeholder={'Ej: "Enfócate en el parámetro ?id= del endpoint /login. El WAF bloquea comillas simples, prueba con URL encoding. No más de 10 payloads."'}
                      className="w-full rounded-xl px-4 py-3 text-xs text-white outline-none resize-none font-mono leading-relaxed"
                      style={{
                        background: 'rgba(255,255,255,0.04)',
                        border: '1px solid rgba(139,92,246,0.25)',
                        color: 'rgba(255,255,255,0.8)',
                      }}
                    />
                    <p className="text-[9px] mt-1.5" style={{ color: 'rgba(255,255,255,0.2)' }}>
                      Aplica a ambos modos. La IA actuará siempre como hacker ético — solo evidenciará el riesgo sin comprometer el servicio.
                    </p>
                  </div>

                  {/* Aviso */}
                  <div className="rounded-xl px-4 py-3 flex items-start gap-2"
                       style={{ background: 'rgba(251,146,60,0.08)', border: '1px solid rgba(251,146,60,0.2)' }}>
                    <span className="material-symbols-outlined shrink-0 mt-0.5"
                          style={{ fontSize: 14, color: '#fb923c' }}>warning</span>
                    <p className="text-[10px] leading-relaxed" style={{ color: 'rgba(251,146,60,0.8)' }}>
                      Asegúrate de tener autorización escrita para este target antes de ejecutar cualquier prueba.
                    </p>
                  </div>

                  {/* Botones */}
                  <div className="flex gap-3 pt-1">
                    <button onClick={() => setVectorModal(null)}
                      className="px-4 py-2.5 rounded-xl text-xs font-bold transition-all hover:text-white"
                      style={{ border: '1px solid rgba(255,255,255,0.1)', color: 'rgba(255,255,255,0.4)' }}>
                      Cancelar
                    </button>
                    <button onClick={() => launchVectorRun('quick')}
                      className="flex-1 py-2.5 rounded-xl text-xs font-black flex items-center justify-center gap-2 transition-all hover:brightness-110"
                      style={{ background: 'rgba(250,204,21,0.12)', border: '1px solid rgba(250,204,21,0.35)', color: '#fbbf24' }}>
                      <span className="material-symbols-outlined text-[14px]">science</span>
                      Prueba Rápida
                    </button>
                    <button onClick={() => launchVectorRun('full')}
                      className="flex-1 py-2.5 rounded-xl text-xs font-black flex items-center justify-center gap-2 transition-all hover:brightness-110"
                      style={{ background: 'rgba(255,49,49,0.2)', border: `1px solid ${R.primaryBorder}`, color: R.primary }}>
                      <span className="material-symbols-outlined text-[14px]"
                            style={{ fontVariationSettings: "'FILL' 1" }}>bolt</span>
                      Ejecutar
                    </button>
                  </div>
                </>)}

                {/* ── FASE: running + done — layout de dos columnas ── */}
                {(vectorRunPhase === 'running' || vectorRunPhase === 'done') && (() => {
                  const estadoColors = {
                    explotable:    { bg: 'rgba(255,49,49,0.12)',   border: 'rgba(255,49,49,0.3)',   text: '#FF3131', label: 'EXPLOTABLE',    icon: '⚠' },
                    no_explotable: { bg: 'rgba(74,222,128,0.08)',  border: 'rgba(74,222,128,0.25)', text: '#4ade80', label: 'NO EXPLOTABLE', icon: '✓' },
                    inconcluso:    { bg: 'rgba(251,146,60,0.08)',  border: 'rgba(251,146,60,0.25)', text: '#fb923c', label: 'INCONCLUSO',    icon: '?' },
                  };
                  const ec = estadoColors[vectorRunResult?.estado] || estadoColors.inconcluso;
                  return (
                    <div className="flex gap-5" style={{ minHeight: 380 }}>

                      {/* ── Columna izquierda: terminal ── */}
                      <div className="flex flex-col gap-2" style={{ flex: '0 0 52%' }}>
                        <p className="text-[9px] font-bold uppercase tracking-wider"
                           style={{ color: 'rgba(255,255,255,0.3)' }}>
                          {vectorRunPhase === 'running' ? 'ejecución en curso' : 'logs de ejecución'}
                        </p>
                        {vectorRunId && (
                          <div style={{ flex: 1 }}>
                            <LiveTerminal
                              runId={vectorRunId}
                              wsUrl={`${WS_BASE}/ws/vector-run/${vectorRunId}`}
                            />
                          </div>
                        )}
                        {vectorRunPhase === 'running' && (
                          <p className="text-[9px] text-center animate-pulse" style={{ color: 'rgba(255,255,255,0.2)' }}>
                            La IA está analizando el vector…
                          </p>
                        )}
                      </div>

                      {/* ── Columna derecha: resultado ── */}
                      <div className="flex flex-col gap-3" style={{ flex: 1, minWidth: 0 }}>
                        {vectorRunPhase === 'running' ? (
                          /* Placeholder mientras corre */
                          <div className="flex flex-col items-center justify-center h-full gap-3 rounded-xl"
                               style={{ border: '1px dashed rgba(139,92,246,0.2)', background: 'rgba(0,0,0,0.2)' }}>
                            <div className="w-5 h-5 rounded-full border-2 border-purple-400 border-t-transparent animate-spin" />
                            <p className="text-[10px] font-mono animate-pulse" style={{ color: 'rgba(139,92,246,0.5)' }}>
                              esperando resultado…
                            </p>
                          </div>
                        ) : vectorRunResult ? (<>
                          <p className="text-[9px] font-bold uppercase tracking-wider"
                             style={{ color: 'rgba(255,255,255,0.3)' }}>resultado</p>

                          {/* Estado badge */}
                          <div className="rounded-xl p-4 flex items-start gap-3"
                               style={{ background: ec.bg, border: `1px solid ${ec.border}` }}>
                            <span className="text-lg font-black shrink-0" style={{ color: ec.text }}>{ec.icon}</span>
                            <div className="min-w-0">
                              <p className="text-sm font-black" style={{ color: ec.text }}>{ec.label}</p>
                              <p className="text-xs mt-0.5 leading-relaxed" style={{ color: 'rgba(255,255,255,0.6)' }}>
                                {vectorRunResult.resumen}
                              </p>
                            </div>
                            <span className="shrink-0 text-[9px] ml-auto" style={{ color: 'rgba(255,255,255,0.2)' }}>
                              {vectorRunResult.iterations} iter.
                            </span>
                          </div>

                          {/* Evidencia técnica */}
                          {vectorRunResult.evidencia_tecnica && (
                            <div className="space-y-1">
                              <p className="text-[9px] font-bold uppercase tracking-wider"
                                 style={{ color: 'rgba(255,255,255,0.25)' }}>evidencia técnica</p>
                              <pre className="rounded-xl px-3 py-2.5 text-[10px] leading-relaxed overflow-x-auto font-mono whitespace-pre-wrap"
                                   style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.7)', maxHeight: 120, overflowY: 'auto' }}>
                                {vectorRunResult.evidencia_tecnica}
                              </pre>
                            </div>
                          )}

                          {/* Comando clave */}
                          {vectorRunResult.comando_clave && (
                            <div className="space-y-1">
                              <p className="text-[9px] font-bold uppercase tracking-wider"
                                 style={{ color: 'rgba(255,255,255,0.25)' }}>comando clave</p>
                              <pre className="rounded-xl px-3 py-2 text-[10px] font-mono overflow-x-auto"
                                   style={{ background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(139,92,246,0.2)', color: '#c4b5fd' }}>
                                $ {vectorRunResult.comando_clave}
                              </pre>
                            </div>
                          )}

                          {/* Impacto */}
                          {vectorRunResult.impacto_negocio && (
                            <div className="space-y-1">
                              <p className="text-[9px] font-bold uppercase tracking-wider"
                                 style={{ color: 'rgba(255,255,255,0.25)' }}>impacto de negocio</p>
                              <p className="text-[10px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.55)' }}>
                                {vectorRunResult.impacto_negocio}
                              </p>
                            </div>
                          )}

                          {/* Recomendación */}
                          {vectorRunResult.recomendacion && (
                            <div className="rounded-xl p-3 space-y-1"
                                 style={{ background: 'rgba(74,222,128,0.05)', border: '1px solid rgba(74,222,128,0.15)' }}>
                              <p className="text-[9px] font-bold uppercase tracking-wider"
                                 style={{ color: 'rgba(74,222,128,0.5)' }}>recomendación de mitigación</p>
                              <p className="text-[10px] leading-relaxed" style={{ color: 'rgba(255,255,255,0.6)' }}>
                                {vectorRunResult.recomendacion}
                              </p>
                            </div>
                          )}

                          {/* Botones */}
                          <div className="flex gap-2 pt-1 mt-auto">
                            <button
                              onClick={() => { setVectorRunPhase('idle'); setVectorRunResult(null); setVectorRunId(null); }}
                              className="flex-1 py-2 rounded-xl text-xs font-bold transition-all hover:brightness-110"
                              style={{ background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.3)', color: '#c4b5fd' }}>
                              Nueva prueba
                            </button>
                            <button
                              onClick={() => { setVectorModal(null); setVectorRunPhase('idle'); setVectorRunResult(null); setVectorRunId(null); }}
                              className="flex-1 py-2 rounded-xl text-xs font-bold transition-all hover:text-white"
                              style={{ border: '1px solid rgba(255,255,255,0.1)', color: 'rgba(255,255,255,0.4)' }}>
                              Cerrar
                            </button>
                          </div>
                        </>) : null}
                      </div>

                    </div>
                  );
                })()}

              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add target modal */}
      {addOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center"
             style={{ background: 'rgba(0,0,0,0.7)' }}
             onClick={e => { if (e.target === e.currentTarget) setAddOpen(false); }}>
          <div className="w-full max-w-md rounded-2xl p-8"
               style={{ background: '#1a0505', border: `1px solid ${R.primaryBorder}` }}>
            <h2 className="text-xl font-black text-white mb-6">Nuevo Target</h2>
            <form onSubmit={handleAdd} className="space-y-4">
              {[
                { label: 'Nombre', value: name, setter: setName, placeholder: 'Mi Servidor' },
                { label: 'URL',    value: url,  setter: setUrl,  placeholder: 'https://ejemplo.com' },
              ].map(f => (
                <div key={f.label}>
                  <label className="block text-[10px] font-bold uppercase tracking-wider mb-2"
                         style={{ color: 'rgba(255,255,255,0.4)' }}>{f.label}</label>
                  <input value={f.value} onChange={e => f.setter(e.target.value)}
                    placeholder={f.placeholder}
                    className="w-full px-4 py-3 rounded-xl font-mono text-sm text-white outline-none"
                    style={{ background: 'rgba(255,255,255,0.05)', border: `1px solid ${R.primaryBorder}` }} />
                </div>
              ))}
              <div className="flex gap-3 pt-2">
                <button type="button" onClick={() => setAddOpen(false)}
                  className="flex-1 py-3 rounded-xl text-xs font-bold text-white"
                  style={{ border: `1px solid rgba(255,255,255,0.15)` }}>Cancelar</button>
                <button type="submit" disabled={adding}
                  className="flex-1 py-3 rounded-xl text-xs font-black text-white transition-all hover:brightness-110 disabled:opacity-50"
                  style={{ background: R.primary }}>
                  {adding ? 'Añadiendo...' : 'Añadir Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
