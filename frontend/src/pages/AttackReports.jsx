import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

/* ── Attack theme ───────────────────────────────────────────────────────── */
const P   = '#FF3131';
const PDim = (a) => `rgba(255,49,49,${a})`;

const SECTION_BG  = 'rgba(18,4,4,0.9)';
const SECTION_BD  = `rgba(255,49,49,0.15)`;
const CARD_BG     = 'rgba(15,3,3,0.5)';
const CARD_BG2    = 'rgba(15,3,3,0.6)';
const MODAL_BG    = '#100303';
const DIM_TEXT    = 'rgba(255,255,255,0.35)';
const DIM_BORDER  = 'rgba(255,255,255,0.12)';

const REPORT_TYPES = [
  { id: 'executive',  label: 'Ejecutivo',  icon: 'summarize',     desc: 'Resumen para stakeholders. Riesgo de negocio, score y top hallazgos críticos.'     },
  { id: 'technical',  label: 'Técnico',    icon: 'bug_report',    desc: 'Detalle completo por módulo: evidencias, CVEs y pasos de reproducción.'            },
  { id: 'compliance', label: 'Compliance', icon: 'verified_user', desc: 'Mapeo contra OWASP Top 10, NIST CSF y CIS Controls.'                               },
  { id: 'full',       label: 'Completo',   icon: 'library_books', desc: 'Incluye ejecutivo, técnico y compliance en un único documento.', highlight: true },
];

const TYPE_STYLE = {
  executive:  { color: '#FF3131', bg: PDim(0.1),  border: PDim(0.3)  },
  technical:  { color: '#ff8f06', bg: 'rgba(255,143,6,0.1)',   border: 'rgba(255,143,6,0.3)'   },
  compliance: { color: '#e91e63', bg: 'rgba(233,30,99,0.1)',   border: 'rgba(233,30,99,0.3)'   },
  full:       { color: '#ff6e84', bg: 'rgba(255,110,132,0.1)', border: 'rgba(255,110,132,0.3)' },
};

const TYPE_ICON  = { executive: 'summarize', technical: 'bug_report', compliance: 'verified_user', full: 'library_books' };
const TYPE_LABEL = { executive: 'Ejecutivo', technical: 'Técnico', compliance: 'Compliance', full: 'Completo' };

const SEV_STYLE = {
  critical: { color: '#ff6e84', bg: 'rgba(255,110,132,0.1)', border: 'rgba(255,110,132,0.3)' },
  high:     { color: '#ff8f06', bg: 'rgba(255,143,6,0.1)',   border: 'rgba(255,143,6,0.3)'   },
  medium:   { color: '#ff7161', bg: 'rgba(255,113,97,0.1)',  border: 'rgba(255,113,97,0.3)'  },
  low:      { color: PDim(0.8),  bg: PDim(0.08),             border: PDim(0.2)               },
  info:     { color: 'rgba(255,255,255,0.3)', bg: 'rgba(255,255,255,0.06)', border: 'rgba(255,255,255,0.12)' },
};

function riskColor(score) {
  if (score >= 70) return '#4caf50';
  if (score >= 40) return '#ff8f06';
  return '#ff6e84';
}

function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('es-ES', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

/* ════════════════════════════════════════════════════════════════════════════
   MAIN PAGE
════════════════════════════════════════════════════════════════════════════ */
export default function AttackReports() {
  const [targets, setTargets]               = useState([]);
  const [scope, setScope]                   = useState('all');
  const [selectedId, setSelectedId]         = useState('');
  const [reportType, setReportType]         = useState('executive');
  const [generating, setGenerating]         = useState(false);
  const [downloading, setDownloading]       = useState(null);
  const [downloadingDocx, setDownloadingDocx] = useState(null);
  const [analyzing, setAnalyzing]           = useState(null);
  const [reports, setReports]               = useState([]);
  const [loadingReports, setLoading]        = useState(true);
  const [viewingReport, setViewing]         = useState(null);
  const [error, setError]                   = useState('');

  const fetchTargets = useCallback(() => {
    axios.get(`${BASE}/targets/?nocache=${Date.now()}`)
      .then(r => {
        setTargets(r.data);
        if (r.data.length && !selectedId) setSelectedId(String(r.data[0].id));
      })
      .catch(() => {});
  }, [selectedId]);

  const fetchReports = useCallback(() => {
    setLoading(true);
    axios.get(`${BASE}/reports/`)
      .then(r => { setReports(r.data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => { fetchTargets(); fetchReports(); }, []);

  const handleGenerate = async () => {
    if (scope === 'single' && !selectedId) { setError('Selecciona un objetivo'); return; }
    setError('');
    setGenerating(true);
    try {
      await axios.post(`${BASE}/reports/generate`, {
        target_ids: scope === 'single' ? [parseInt(selectedId)] : [],
        report_type: reportType,
        scope,
      });
      await fetchReports();
    } catch (e) {
      setError(e.response?.data?.detail || 'Error al generar el reporte');
    } finally {
      setGenerating(false);
    }
  };

  const handleDelete = async (id) => {
    try {
      await axios.delete(`${BASE}/reports/${id}`);
      setReports(prev => prev.filter(r => r.id !== id));
      if (viewingReport?.id === id) setViewing(null);
    } catch { setError('Error eliminando reporte'); }
  };

  const handleAnalyze = async (id) => {
    setAnalyzing(id);
    try {
      await axios.post(`${BASE}/reports/${id}/ai-analyze`);
      let tries = 0;
      const poll = setInterval(async () => {
        tries++;
        try {
          const res = await axios.get(`${BASE}/reports/${id}`);
          if (res.data.ai_enhanced || tries >= 40) {
            clearInterval(poll);
            setAnalyzing(null);
            setReports(prev => prev.map(r => r.id === id ? res.data : r));
            if (viewingReport?.id === id) setViewing(res.data);
          }
        } catch { clearInterval(poll); setAnalyzing(null); }
      }, 3000);
    } catch (e) {
      setAnalyzing(null);
      setError(e.response?.data?.detail || 'Error iniciando análisis IA');
    }
  };

  const handleDownload = async (id, title) => {
    setDownloading(id);
    try {
      const res = await axios.get(`${BASE}/reports/${id}/download`, { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const a   = document.createElement('a');
      a.href    = url;
      a.download = `anubis_${(title || 'report').slice(0, 50).replace(/[^a-z0-9_\- ]/gi, '_')}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch { setError('Error descargando PDF'); }
    finally  { setDownloading(null); }
  };

  const handleDownloadDocx = async (id, title) => {
    setDownloadingDocx(id);
    try {
      const mime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
      const res  = await axios.get(`${BASE}/reports/${id}/download/docx`, { responseType: 'blob' });
      const url  = window.URL.createObjectURL(new Blob([res.data], { type: mime }));
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `anubis_${(title || 'report').slice(0, 50).replace(/[^a-z0-9_\- ]/gi, '_')}.docx`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch { setError('Error descargando DOCX'); }
    finally  { setDownloadingDocx(null); }
  };

  const selectedTarget = targets.find(t => String(t.id) === selectedId) || null;
  const activeType     = REPORT_TYPES.find(r => r.id === reportType);

  return (
    <div className="pt-8 pb-32 px-4 md:px-8 max-w-5xl mx-auto space-y-8"
         style={{ backgroundColor: '#0a0505' }}>

      {/* ── HEADER ──────────────────────────────────────────────────────── */}
      <div>
        <p className="font-mono text-[0.6rem] uppercase tracking-[0.18em] mb-1" style={{ color: DIM_TEXT }}>
          attack_reporting
        </p>
        <h1 className="font-headline text-4xl font-bold tracking-tight text-white">
          Security Reports
        </h1>
        <p className="mt-2 leading-relaxed" style={{ color: DIM_TEXT }}>
          Genera reportes ejecutivos, técnicos y de compliance. Análisis potenciado por agente IA.
        </p>
      </div>

      {/* ── 1. SCOPE ────────────────────────────────────────────────────── */}
      <section className="rounded-2xl p-6" style={{ background: SECTION_BG, border: `1px solid ${SECTION_BD}` }}>
        <SectionLabel icon="tune" label="Alcance del reporte" />

        <div className="flex flex-col sm:flex-row gap-3">
          {[
            { id: 'all',    label: 'Todos los objetivos', icon: 'hub',      sub: `${targets.length} targets en scope` },
            { id: 'single', label: 'Un objetivo',         icon: 'language', sub: 'Análisis individual' },
          ].map(s => {
            const active = scope === s.id;
            return (
              <button key={s.id} onClick={() => setScope(s.id)}
                className="flex-1 flex items-center gap-3 p-4 rounded-xl text-left transition-all"
                style={{
                  background: active ? PDim(0.08) : CARD_BG,
                  border: `1px solid ${active ? PDim(0.35) : DIM_BORDER}`,
                }}>
                <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
                  style={{
                    background: active ? PDim(0.18) : 'rgba(255,255,255,0.06)',
                    border: `1px solid ${active ? PDim(0.3) : 'rgba(255,255,255,0.1)'}`,
                  }}>
                  <span className="material-symbols-outlined"
                        style={{ fontSize: 18, color: active ? P : 'rgba(255,255,255,0.3)' }}>
                    {s.icon}
                  </span>
                </div>
                <div>
                  <p className="text-sm font-semibold" style={{ color: active ? P : '#e4e4f0' }}>{s.label}</p>
                  <p className="font-mono text-[0.6rem] mt-0.5" style={{ color: DIM_TEXT }}>{s.sub}</p>
                </div>
                {active && (
                  <span className="material-symbols-outlined ml-auto" style={{ fontSize: 16, color: P }}>check_circle</span>
                )}
              </button>
            );
          })}
        </div>

        {scope === 'single' && (
          <div className="mt-4">
            {targets.length === 0 ? (
              <div className="flex items-center gap-3 p-4 rounded-xl"
                   style={{ background: CARD_BG, border: `1px solid ${DIM_BORDER}` }}>
                <span className="material-symbols-outlined" style={{ color: DIM_TEXT }}>info</span>
                <p className="font-mono text-xs" style={{ color: DIM_TEXT }}>
                  No hay objetivos. Añade uno desde <span style={{ color: P }}>Targets</span>.
                </p>
              </div>
            ) : (
              <>
                <p className="font-mono text-[0.6rem] uppercase tracking-[0.15em] mb-2" style={{ color: DIM_TEXT }}>
                  Selecciona el objetivo
                </p>
                <div className="flex flex-wrap gap-2">
                  {targets.map(t => {
                    const active = selectedId === String(t.id);
                    return (
                      <button key={t.id} onClick={() => setSelectedId(String(t.id))}
                        className="flex items-center gap-2 px-3 py-2 rounded-xl text-sm transition-all"
                        style={{
                          background: active ? PDim(0.1) : CARD_BG,
                          border: `1px solid ${active ? PDim(0.35) : DIM_BORDER}`,
                        }}>
                        <span className="material-symbols-outlined shrink-0"
                              style={{ fontSize: 13, color: active ? P : 'rgba(255,255,255,0.3)' }}>
                          language
                        </span>
                        <span className="font-mono text-xs" style={{ color: active ? P : '#e4e4f0' }}>{t.name}</span>
                      </button>
                    );
                  })}
                </div>
                {selectedTarget && (
                  <p className="font-mono text-xs mt-3 flex items-center gap-1.5" style={{ color: P }}>
                    <span className="material-symbols-outlined" style={{ fontSize: 13 }}>link</span>
                    {selectedTarget.url}
                  </p>
                )}
              </>
            )}
          </div>
        )}
      </section>

      {/* ── 2. REPORT TYPE ──────────────────────────────────────────────── */}
      <section className="rounded-2xl p-6" style={{ background: SECTION_BG, border: `1px solid ${SECTION_BD}` }}>
        <SectionLabel icon="description" label="Tipo de reporte" />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {REPORT_TYPES.map(rt => {
            const ts     = TYPE_STYLE[rt.id];
            const active = reportType === rt.id;
            const isFull = rt.id === 'full';
            return (
              <button key={rt.id} onClick={() => setReportType(rt.id)}
                className="text-left p-4 rounded-xl transition-all relative overflow-hidden"
                style={{
                  background: active ? ts.bg : isFull ? 'rgba(255,110,132,0.04)' : CARD_BG,
                  border: active ? `1px solid ${ts.border}` : isFull ? '1px dashed rgba(255,110,132,0.25)' : `1px solid ${DIM_BORDER}`,
                }}>
                {isFull && !active && (
                  <span className="absolute top-2 right-2 font-mono text-[0.5rem] uppercase px-1.5 py-0.5 rounded"
                    style={{ color: '#ff6e84', background: 'rgba(255,110,132,0.1)', border: '1px solid rgba(255,110,132,0.2)' }}>
                    Todo en uno
                  </span>
                )}
                <div className="w-9 h-9 rounded-xl flex items-center justify-center mb-3"
                  style={{
                    background: active ? ts.bg : 'rgba(255,255,255,0.06)',
                    border: `1px solid ${active ? ts.border : 'rgba(255,255,255,0.1)'}`,
                  }}>
                  <span className="material-symbols-outlined"
                        style={{ fontSize: 18, color: active ? ts.color : 'rgba(255,255,255,0.3)' }}>
                    {rt.icon}
                  </span>
                </div>
                <p className="text-xs font-bold uppercase tracking-tight mb-1"
                   style={{ color: active ? ts.color : '#e4e4f0' }}>{rt.label}</p>
                <p className="text-[0.65rem] leading-snug" style={{ color: DIM_TEXT }}>{rt.desc}</p>
              </button>
            );
          })}
        </div>
      </section>

      {/* ── 3. GENERATE ─────────────────────────────────────────────────── */}
      <section className="rounded-2xl p-6"
        style={{ background: SECTION_BG, border: `1px solid ${SECTION_BD}`, borderLeftWidth: 4, borderLeftColor: P }}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <span className="font-mono text-[0.6rem] rounded px-2 py-0.5 uppercase tracking-[0.1em]"
              style={{ color: P, background: PDim(0.1), border: `1px solid ${PDim(0.2)}` }}>
              {scope === 'all' ? `${targets.length} targets` : (selectedTarget?.name || 'Sin objetivo')}
            </span>
            <h3 className="font-headline text-xl font-bold mt-2 text-white">{activeType?.label}</h3>
            <p className="font-mono text-xs mt-1" style={{ color: DIM_TEXT }}>
              {scope === 'all' ? 'Reporte global · todos los hallazgos' : `Reporte individual · ${selectedTarget?.url || '—'}`}
            </p>
          </div>
          <button
            onClick={handleGenerate}
            disabled={generating || (scope === 'single' && !selectedId) || targets.length === 0}
            className="flex items-center gap-2 px-6 py-3 rounded-xl font-bold text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
            style={{ background: P, color: '#fff', boxShadow: `0 6px 20px ${PDim(0.3)}` }}>
            <span className="material-symbols-outlined" style={{ fontSize: 17, animation: generating ? 'spin 1s linear infinite' : undefined }}>
              {generating ? 'sync' : 'picture_as_pdf'}
            </span>
            {generating ? 'Generando...' : 'Generar Reporte'}
          </button>
        </div>

        {error && (
          <div className="mt-4 flex items-center gap-2 p-3 rounded-lg"
               style={{ background: 'rgba(255,110,132,0.08)', border: '1px solid rgba(255,110,132,0.25)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: 16, color: '#ff6e84' }}>error</span>
            <p className="font-mono text-xs" style={{ color: '#ff6e84' }}>{error}</p>
          </div>
        )}

        <div className="mt-5 flex items-start gap-3 p-4 rounded-xl"
             style={{ background: CARD_BG2, border: `1px solid ${PDim(0.1)}` }}>
          <span className="material-symbols-outlined" style={{ fontSize: 18, color: P }}>smart_toy</span>
          <div>
            <p className="font-mono text-xs font-semibold text-white">Agente IA — análisis automático</p>
            <p className="font-mono text-[0.65rem] mt-1 leading-relaxed" style={{ color: DIM_TEXT }}>
              El reporte se genera con datos reales de hallazgos. El agente IA puede enriquecer
              cada sección: resúmenes ejecutivos, recomendaciones técnicas y análisis de compliance.
            </p>
          </div>
        </div>
      </section>

      {/* ── 4. ARCHIVE ──────────────────────────────────────────────────── */}
      <section className="rounded-2xl p-6" style={{ background: SECTION_BG, border: `1px solid ${SECTION_BD}` }}>
        <SectionLabel icon="history" label={`Archivo de reportes (${reports.length})`} />

        {loadingReports ? (
          <div className="flex items-center justify-center gap-3 py-12">
            <span className="material-symbols-outlined" style={{ fontSize: 20, color: P, animation: 'spin 1s linear infinite' }}>sync</span>
            <p className="font-mono text-xs" style={{ color: DIM_TEXT }}>Cargando reportes...</p>
          </div>
        ) : reports.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-14 gap-3">
            <span className="material-symbols-outlined" style={{ fontSize: 44, color: 'rgba(255,255,255,0.2)' }}>description</span>
            <p className="font-mono text-xs" style={{ color: 'rgba(255,255,255,0.2)' }}>Sin reportes generados todavía.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {reports.map(r => (
              <ReportCard
                key={r.id}
                report={r}
                onView={() => setViewing(r)}
                onDelete={() => handleDelete(r.id)}
                onDownload={() => handleDownload(r.id, r.title)}
                onDownloadDocx={() => handleDownloadDocx(r.id, r.title)}
                onAnalyze={() => handleAnalyze(r.id)}
                isDownloading={downloading === r.id}
                isDownloadingDocx={downloadingDocx === r.id}
                isAnalyzing={analyzing === r.id}
              />
            ))}
          </div>
        )}
      </section>

      {viewingReport && (
        <ReportModal
          report={viewingReport}
          onClose={() => setViewing(null)}
          onDownload={() => handleDownload(viewingReport.id, viewingReport.title)}
          onDownloadDocx={() => handleDownloadDocx(viewingReport.id, viewingReport.title)}
          onAnalyze={() => handleAnalyze(viewingReport.id)}
          isDownloading={downloading === viewingReport.id}
          isDownloadingDocx={downloadingDocx === viewingReport.id}
          isAnalyzing={analyzing === viewingReport.id}
        />
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   REPORT CARD
════════════════════════════════════════════════════════════════════════════ */
function ReportCard({ report, onView, onDelete, onDownload, onDownloadDocx, onAnalyze, isDownloading, isDownloadingDocx, isAnalyzing }) {
  const [confirmDel, setConfirmDel] = useState(false);
  const ts = TYPE_STYLE[report.report_type] || TYPE_STYLE.executive;
  const rc = riskColor(report.risk_score || 0);

  return (
    <div className="flex items-center gap-3 p-4 rounded-xl transition-colors"
         style={{ background: CARD_BG, border: `1px solid ${DIM_BORDER}` }}>
      <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
           style={{ background: ts.bg, border: `1px solid ${ts.border}` }}>
        <span className="material-symbols-outlined" style={{ fontSize: 20, color: ts.color }}>
          {TYPE_ICON[report.report_type] || 'description'}
        </span>
      </div>

      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-white truncate">{report.title}</p>
        <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
          <Badge color={ts.color} bg={ts.bg} border={ts.border}>
            {TYPE_LABEL[report.report_type] || report.report_type}
          </Badge>
          <Badge color="rgba(255,255,255,0.4)" bg="rgba(255,255,255,0.05)" border="rgba(255,255,255,0.12)">
            <span className="material-symbols-outlined" style={{ fontSize: 9, marginRight: 2 }}>
              {report.scope === 'all' ? 'hub' : 'language'}
            </span>
            {report.scope === 'all' ? 'Todos' : `${report.total_targets} target`}
          </Badge>
          {report.ai_enhanced && (
            <Badge color={P} bg={PDim(0.08)} border={PDim(0.2)}>
              <span className="material-symbols-outlined" style={{ fontSize: 9, marginRight: 2 }}>smart_toy</span>
              IA Enhanced
            </Badge>
          )}
          <span className="font-mono text-[0.55rem]" style={{ color: DIM_TEXT }}>{fmtDate(report.generated_at)}</span>
        </div>
      </div>

      <div className="hidden sm:flex items-center gap-5 shrink-0 mr-2">
        <StatPill label="findings" value={report.total_findings} color="#e4e4f0" />
        <StatPill label="risk"     value={report.risk_score || 0} color={rc} />
      </div>

      <div className="flex items-center gap-2 shrink-0">
        <button onClick={onView}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all"
          style={{ color: P, border: `1px solid ${PDim(0.2)}` }}>
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>open_in_full</span>
          Ver
        </button>

        <button onClick={onAnalyze} disabled={isAnalyzing || report.ai_enhanced}
          title={report.ai_enhanced ? 'Ya analizado con IA' : 'Analizar con IA'}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
          style={{ color: '#c8a2f5', border: '1px solid rgba(200,162,245,0.25)' }}>
          <span className="material-symbols-outlined"
                style={{ fontSize: 14, animation: isAnalyzing ? 'spin 1s linear infinite' : 'none' }}>
            {report.ai_enhanced ? 'check_circle' : 'smart_toy'}
          </span>
          {isAnalyzing ? 'IA...' : 'IA'}
        </button>

        <button onClick={onDownload} disabled={isDownloading} title="Descargar PDF"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
          style={{ color: '#4caf50', border: '1px solid rgba(76,175,80,0.25)' }}>
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>
            {isDownloading ? 'sync' : 'picture_as_pdf'}
          </span>
          PDF
        </button>

        <button onClick={onDownloadDocx} disabled={isDownloadingDocx} title="Descargar DOCX"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
          style={{ color: '#29b6f6', border: '1px solid rgba(41,182,246,0.25)' }}>
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>
            {isDownloadingDocx ? 'sync' : 'description'}
          </span>
          DOCX
        </button>

        {confirmDel ? (
          <div className="flex gap-1">
            <button onClick={() => { onDelete(); setConfirmDel(false); }}
              className="px-2 py-1.5 rounded-lg font-mono text-[0.6rem] font-bold transition-colors"
              style={{ color: '#ff6e84', border: '1px solid rgba(255,110,132,0.2)' }}>
              Borrar
            </button>
            <button onClick={() => setConfirmDel(false)}
              className="px-2 py-1.5 rounded-lg font-mono text-[0.6rem]"
              style={{ color: DIM_TEXT, border: `1px solid ${DIM_BORDER}` }}>
              No
            </button>
          </div>
        ) : (
          <button onClick={() => setConfirmDel(true)}
            className="w-8 h-8 rounded-lg flex items-center justify-center transition-colors"
            style={{ color: 'rgba(255,255,255,0.3)' }}>
            <span className="material-symbols-outlined" style={{ fontSize: 16 }}>delete</span>
          </button>
        )}
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   REPORT MODAL
════════════════════════════════════════════════════════════════════════════ */
function ReportModal({ report, onClose, onDownload, onDownloadDocx, onAnalyze, isDownloading, isDownloadingDocx, isAnalyzing }) {
  const ts        = TYPE_STYLE[report.report_type] || TYPE_STYLE.executive;
  const data      = report.data || {};
  const aiContent = report.ai_content || {};
  const sevCounts = data.severity_counts || {};
  const totalF    = data.total_findings || 0;
  const rs        = data.risk_score || 0;
  const rc        = riskColor(rs);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto py-8 px-4"
         style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(10px)' }}>
      <div className="relative w-full max-w-4xl rounded-2xl overflow-hidden"
           style={{ background: MODAL_BG, border: `1px solid ${PDim(0.2)}` }}>

        {/* Sticky header */}
        <div className="sticky top-0 z-10 flex items-center gap-3 p-5"
             style={{ background: 'rgba(16,3,3,0.97)', borderBottom: `1px solid ${PDim(0.15)}` }}>
          <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
               style={{ background: ts.bg, border: `1px solid ${ts.border}` }}>
            <span className="material-symbols-outlined" style={{ fontSize: 20, color: ts.color }}>
              {TYPE_ICON[report.report_type]}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-bold text-white truncate">{report.title}</p>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="font-mono text-[0.6rem] uppercase" style={{ color: ts.color }}>
                {TYPE_LABEL[report.report_type]}
              </span>
              <span className="text-xs" style={{ color: DIM_TEXT }}>·</span>
              <span className="font-mono text-[0.6rem]" style={{ color: DIM_TEXT }}>{fmtDate(report.generated_at)}</span>
              {aiContent.ai_generated && (
                <>
                  <span className="text-xs" style={{ color: DIM_TEXT }}>·</span>
                  <span className="font-mono text-[0.6rem] flex items-center gap-1" style={{ color: P }}>
                    <span className="material-symbols-outlined" style={{ fontSize: 10 }}>smart_toy</span>
                    IA Enhanced
                  </span>
                </>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 ml-2 shrink-0">
            <button onClick={onAnalyze} disabled={isAnalyzing || report.ai_enhanced}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
              style={{ color: '#c8a2f5', border: '1px solid rgba(200,162,245,0.25)', background: 'rgba(200,162,245,0.06)' }}>
              <span className="material-symbols-outlined"
                    style={{ fontSize: 15, animation: isAnalyzing ? 'spin 1s linear infinite' : 'none' }}>
                smart_toy
              </span>
              {isAnalyzing ? 'Analizando...' : report.ai_enhanced ? 'IA completada' : 'Analizar con IA'}
            </button>
            <button onClick={onDownload} disabled={isDownloading}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
              style={{ color: '#4caf50', border: '1px solid rgba(76,175,80,0.25)', background: 'rgba(76,175,80,0.06)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: 15 }}>
                {isDownloading ? 'sync' : 'picture_as_pdf'}
              </span>
              {isDownloading ? 'Generando...' : 'Descargar PDF'}
            </button>
            <button onClick={onDownloadDocx} disabled={isDownloadingDocx}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
              style={{ color: '#29b6f6', border: '1px solid rgba(41,182,246,0.25)', background: 'rgba(41,182,246,0.06)' }}>
              <span className="material-symbols-outlined" style={{ fontSize: 15 }}>
                {isDownloadingDocx ? 'sync' : 'description'}
              </span>
              {isDownloadingDocx ? 'Generando...' : 'Descargar DOCX'}
            </button>
            <button onClick={onClose}
              className="w-9 h-9 rounded-xl flex items-center justify-center transition-colors"
              style={{ border: `1px solid ${PDim(0.2)}` }}>
              <span className="material-symbols-outlined" style={{ fontSize: 18, color: DIM_TEXT }}>close</span>
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Targets',  value: data.total_targets || 0, icon: 'radar',    color: P          },
              { label: 'Findings', value: totalF,                   icon: 'security', color: '#ff8f06'  },
              { label: 'Risk',     value: rs,                       icon: 'shield',   color: rc         },
              { label: 'Críticos', value: sevCounts.critical || 0,  icon: 'warning',  color: '#ff6e84'  },
            ].map(k => (
              <div key={k.label} className="p-4 rounded-xl"
                   style={{ background: CARD_BG2, border: `1px solid ${DIM_BORDER}` }}>
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="material-symbols-outlined" style={{ fontSize: 13, color: k.color }}>{k.icon}</span>
                  <p className="font-mono text-[0.6rem] uppercase" style={{ color: DIM_TEXT }}>{k.label}</p>
                </div>
                <p className="font-mono text-2xl font-bold" style={{ color: k.color }}>{k.value}</p>
              </div>
            ))}
          </div>

          {totalF > 0 && <SeverityBar counts={sevCounts} total={totalF} />}

          {report.report_type === 'executive'  && <ExecutiveView  data={data} ai={aiContent} />}
          {report.report_type === 'technical'  && <TechnicalView  data={data} ai={aiContent} />}
          {report.report_type === 'compliance' && <ComplianceView data={data} ai={aiContent} />}
          {report.report_type === 'full'       && <FullView       data={data} ai={aiContent} />}
        </div>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   EXECUTIVE VIEW
════════════════════════════════════════════════════════════════════════════ */
function ExecutiveView({ data, ai }) {
  const criticalAndHigh = [];
  (data.targets || []).forEach(t => {
    Object.values(t.findings_by_module || {}).forEach(mf => {
      mf.forEach(f => {
        if (['critical', 'high'].includes((f.severity || '').toLowerCase()))
          criticalAndHigh.push({ ...f, target_name: t.name });
      });
    });
  });
  criticalAndHigh.sort((a, b) => (a.severity === 'critical' ? -1 : 1));

  return (
    <div className="space-y-5">
      {criticalAndHigh.length > 0 && (
        <ModalCard>
          <ModalCardHeader icon="priority_high" label="Top hallazgos críticos / altos" iconColor="#ff6e84" />
          <div className="space-y-2">
            {criticalAndHigh.slice(0, 6).map((f, i) => {
              const ss = SEV_STYLE[(f.severity || 'info').toLowerCase()] || SEV_STYLE.info;
              return (
                <div key={i} className="flex items-start gap-3 p-3 rounded-lg"
                     style={{ background: ss.bg, border: `1px solid ${ss.border}` }}>
                  <SevBadge sev={f.severity} />
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-white">{f.title}</p>
                    <p className="font-mono text-[0.6rem] mt-0.5" style={{ color: DIM_TEXT }}>{f.target_name}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </ModalCard>
      )}
      <AISlot title="Resumen ejecutivo" icon="summarize" content={ai.executive_summary}
        placeholder="El agente IA generará un resumen ejecutivo adaptado para stakeholders no técnicos, destacando el impacto de negocio y la urgencia de remediación." />
      <AISlot title="Impacto de negocio" icon="trending_down" content={ai.business_impact}
        placeholder="El agente IA describirá el impacto potencial en operaciones, reputación y cumplimiento regulatorio basado en los hallazgos detectados." />
      <AISlot title="Narrativa de riesgo" icon="shield" content={ai.risk_narrative}
        placeholder="Perfil de riesgo actual, superficie de ataque y prioridades de remediación con estimación de esfuerzo." />
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   TECHNICAL VIEW
════════════════════════════════════════════════════════════════════════════ */
function TechnicalView({ data, ai }) {
  const [openTarget, setOpenTarget] = useState(null);
  const [openMod, setOpenMod]       = useState(null);
  const MODULE_ICONS = {
    waf: 'shield', whatweb: 'travel_explore', headers: 'http',
    certs: 'lock', nikto: 'bug_report', zap: 'security',
  };

  return (
    <div className="space-y-5">
      {(data.targets || []).map(t => (
        <div key={t.id} className="rounded-xl overflow-hidden"
             style={{ border: `1px solid ${DIM_BORDER}`, background: CARD_BG }}>
          <button onClick={() => setOpenTarget(openTarget === t.id ? null : t.id)}
            className="w-full flex items-center gap-3 p-4 text-left transition-colors">
            <span className="material-symbols-outlined" style={{ fontSize: 18, color: P }}>language</span>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-white">{t.name}</p>
              <p className="font-mono text-[0.6rem]" style={{ color: DIM_TEXT }}>{t.url}</p>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <SevRow counts={t.severity_counts} />
              <span className="material-symbols-outlined" style={{ fontSize: 16, color: DIM_TEXT }}>
                {openTarget === t.id ? 'expand_less' : 'expand_more'}
              </span>
            </div>
          </button>

          {openTarget === t.id && (
            <div className="p-4 space-y-2" style={{ borderTop: `1px solid ${PDim(0.1)}` }}>
              {Object.keys(t.findings_by_module || {}).length === 0 ? (
                <p className="font-mono text-xs italic px-2" style={{ color: DIM_TEXT }}>Sin hallazgos registrados.</p>
              ) : Object.entries(t.findings_by_module).map(([mod, mf]) => {
                const modKey = `${t.id}-${mod}`;
                return (
                  <div key={mod} className="rounded-xl overflow-hidden"
                       style={{ border: `1px solid ${DIM_BORDER}`, background: CARD_BG2 }}>
                    <button onClick={() => setOpenMod(openMod === modKey ? null : modKey)}
                      className="w-full flex items-center gap-2 p-3 text-left transition-colors">
                      <span className="material-symbols-outlined" style={{ fontSize: 14, color: DIM_TEXT }}>
                        {MODULE_ICONS[mod] || 'circle'}
                      </span>
                      <span className="font-mono text-xs font-bold text-white uppercase">{mod}</span>
                      <span className="font-mono text-[0.6rem]" style={{ color: DIM_TEXT }}>({mf.length})</span>
                      <span className="material-symbols-outlined ml-auto" style={{ fontSize: 14, color: DIM_TEXT }}>
                        {openMod === modKey ? 'expand_less' : 'expand_more'}
                      </span>
                    </button>
                    {openMod === modKey && (
                      <div className="divide-y" style={{ borderTop: `1px solid ${PDim(0.1)}`, borderColor: PDim(0.1) }}>
                        {mf.map((f, i) => (
                          <div key={i} className="p-4 space-y-2">
                            <div className="flex items-start gap-3">
                              <SevBadge sev={f.severity} />
                              <p className="text-xs font-semibold text-white">{f.title}</p>
                            </div>
                            {f.description && (
                              <p className="text-[0.7rem] leading-relaxed pl-1" style={{ color: DIM_TEXT }}>
                                {f.description}
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ))}

      <AISlot title="Recomendaciones técnicas" icon="build"
        content={ai.recommendations?.length ? ai.recommendations.map((r, i) =>
          typeof r === 'string' ? r : `${r.finding_title || `#${i+1}`}: ${r.recommendation || ''}`
        ).join('\n\n') : null}
        placeholder="El agente IA generará recomendaciones técnicas por hallazgo: pasos de remediación, referencias CVE, configuraciones recomendadas y prioridad de corrección." />
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   COMPLIANCE VIEW
════════════════════════════════════════════════════════════════════════════ */
function ComplianceView({ data, ai }) {
  const owasp    = data.owasp_mapping || {};
  const affected = Object.values(owasp).filter(v => v.status === 'affected').length;

  return (
    <div className="space-y-5">
      <ModalCard>
        <div className="flex items-center justify-between mb-4">
          <ModalCardHeader icon="verified_user" label="OWASP Top 10 — 2021" iconColor="#e91e63" />
          <span className="font-mono text-[0.6rem]">
            <span style={{ color: '#ff6e84' }}>{affected}</span>
            <span style={{ color: DIM_TEXT }}> / 10 afectados</span>
          </span>
        </div>
        <div className="rounded-xl overflow-hidden divide-y"
             style={{ border: `1px solid ${DIM_BORDER}`, borderColor: DIM_BORDER }}>
          {Object.entries(owasp).map(([code, info]) => {
            const isAffected = info.status === 'affected';
            return (
              <div key={code} className="flex items-center gap-3 px-4 py-3"
                   style={{ background: isAffected ? 'rgba(255,110,132,0.04)' : 'transparent' }}>
                <div className="w-14 h-7 rounded flex items-center justify-center shrink-0"
                  style={{
                    background: isAffected ? 'rgba(255,110,132,0.12)' : 'rgba(255,255,255,0.04)',
                    border: `1px solid ${isAffected ? 'rgba(255,110,132,0.25)' : DIM_BORDER}`,
                  }}>
                  <span className="font-mono text-[0.6rem] font-bold"
                        style={{ color: isAffected ? '#ff6e84' : DIM_TEXT }}>{code}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold" style={{ color: isAffected ? '#fff' : DIM_TEXT }}>
                    {info.name}
                  </p>
                  {isAffected && (
                    <p className="font-mono text-[0.55rem] mt-0.5" style={{ color: DIM_TEXT }}>
                      {info.count} hallazgo{info.count !== 1 ? 's' : ''} relacionado{info.count !== 1 ? 's' : ''}
                    </p>
                  )}
                </div>
                {isAffected ? (
                  <span className="font-mono text-[0.55rem] rounded px-2 py-0.5 uppercase flex items-center gap-1 shrink-0"
                    style={{ color: '#ff6e84', background: 'rgba(255,110,132,0.1)', border: '1px solid rgba(255,110,132,0.25)' }}>
                    <span className="material-symbols-outlined" style={{ fontSize: 10 }}>warning</span>
                    Afectado
                  </span>
                ) : (
                  <span className="font-mono text-[0.55rem] rounded px-2 py-0.5 uppercase shrink-0"
                    style={{ color: DIM_TEXT, background: 'rgba(255,255,255,0.04)', border: `1px solid ${DIM_BORDER}` }}>
                    OK
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </ModalCard>

      <AISlot title="Análisis de compliance" icon="policy" content={ai.compliance_narrative}
        placeholder="El agente IA generará un análisis de brechas contra OWASP, NIST CSF e ISO 27001, con recomendaciones priorizadas por riesgo regulatorio." />

      {ai.compliance_gaps?.length > 0 && (
        <ModalCard>
          <ModalCardHeader icon="close" label="Brechas identificadas por IA" iconColor="#ff6e84" />
          <div className="space-y-2">
            {ai.compliance_gaps.map((gap, i) => (
              <div key={i} className="flex items-start gap-2">
                <span className="material-symbols-outlined mt-0.5 shrink-0" style={{ fontSize: 14, color: '#ff6e84' }}>cancel</span>
                <p className="text-xs text-white">{typeof gap === 'string' ? gap : JSON.stringify(gap)}</p>
              </div>
            ))}
          </div>
        </ModalCard>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   FULL VIEW
════════════════════════════════════════════════════════════════════════════ */
function FullView({ data, ai }) {
  const sections = [
    { ts: TYPE_STYLE.executive,  icon: 'summarize',     label: 'Ejecutivo',  View: ExecutiveView  },
    { ts: TYPE_STYLE.technical,  icon: 'bug_report',    label: 'Técnico',    View: TechnicalView  },
    { ts: TYPE_STYLE.compliance, icon: 'verified_user', label: 'Compliance', View: ComplianceView },
  ];
  return (
    <div className="space-y-8">
      {sections.map(({ ts, icon, label, View }, idx) => (
        <div key={label}>
          {idx > 0 && <div style={{ borderTop: '1px dashed rgba(255,49,49,0.15)' }} className="pt-2 mb-8" />}
          <div className="flex items-center gap-2 mb-4">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl"
                 style={{ background: ts.bg, border: `1px solid ${ts.border}` }}>
              <span className="material-symbols-outlined" style={{ fontSize: 15, color: ts.color }}>{icon}</span>
              <span className="font-mono text-[0.65rem] font-bold uppercase tracking-widest" style={{ color: ts.color }}>
                {label}
              </span>
            </div>
          </div>
          <View data={data} ai={ai} />
        </div>
      ))}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   SHARED ATOMS
════════════════════════════════════════════════════════════════════════════ */
function SeverityBar({ counts, total }) {
  const order  = ['critical', 'high', 'medium', 'low', 'info'];
  const colors = { critical: '#ff6e84', high: '#ff8f06', medium: '#ff7161', low: PDim(0.8), info: 'rgba(255,255,255,0.2)' };
  return (
    <div className="p-4 rounded-xl" style={{ background: CARD_BG2, border: `1px solid ${DIM_BORDER}` }}>
      <p className="font-mono text-[0.65rem] uppercase tracking-[0.15em] mb-3" style={{ color: DIM_TEXT }}>
        Distribución de severidad
      </p>
      <div className="flex h-2.5 rounded-full overflow-hidden gap-px mb-3">
        {order.map(s => {
          const pct = total > 0 ? ((counts[s] || 0) / total) * 100 : 0;
          return pct > 0
            ? <div key={s} style={{ width: `${pct}%`, background: colors[s], minWidth: 4 }} title={`${s}: ${counts[s]}`} />
            : null;
        })}
      </div>
      <div className="flex flex-wrap gap-4">
        {order.map(s => (
          <div key={s} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full" style={{ background: colors[s] }} />
            <span className="font-mono text-[0.6rem] capitalize" style={{ color: DIM_TEXT }}>{s}</span>
            <span className="font-mono text-[0.6rem] font-bold text-white">{counts[s] || 0}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AISlot({ title, icon, content, placeholder }) {
  return (
    <div className="rounded-xl p-5"
      style={{
        background: content ? PDim(0.05) : CARD_BG,
        border: content ? `1px solid ${PDim(0.2)}` : `1px dashed ${DIM_BORDER}`,
      }}>
      <div className="flex items-center gap-2 mb-3">
        <span className="material-symbols-outlined" style={{ fontSize: 16, color: content ? P : 'rgba(255,255,255,0.25)' }}>
          {icon}
        </span>
        <p className="font-mono text-[0.65rem] uppercase tracking-[0.15em]"
           style={{ color: content ? P : 'rgba(255,255,255,0.25)' }}>{title}</p>
        {content && (
          <span className="ml-auto font-mono text-[0.55rem] rounded px-1.5 py-0.5 flex items-center gap-1 uppercase"
            style={{ color: P, background: PDim(0.1), border: `1px solid ${PDim(0.25)}` }}>
            <span className="material-symbols-outlined" style={{ fontSize: 9 }}>smart_toy</span>
            IA
          </span>
        )}
      </div>
      {content
        ? <p className="text-sm text-white leading-relaxed whitespace-pre-wrap">{content}</p>
        : <p className="text-[0.7rem] italic leading-relaxed" style={{ color: 'rgba(255,255,255,0.2)' }}>{placeholder}</p>
      }
    </div>
  );
}

function ModalCard({ children }) {
  return (
    <div className="rounded-xl p-5" style={{ background: CARD_BG2, border: `1px solid ${DIM_BORDER}` }}>
      {children}
    </div>
  );
}

function ModalCardHeader({ icon, label, iconColor }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <span className="material-symbols-outlined" style={{ fontSize: 16, color: iconColor || P }}>{icon}</span>
      <p className="font-mono text-[0.65rem] uppercase tracking-[0.15em]" style={{ color: DIM_TEXT }}>{label}</p>
    </div>
  );
}

function SevBadge({ sev }) {
  const ss = SEV_STYLE[(sev || 'info').toLowerCase()] || SEV_STYLE.info;
  return (
    <span className="font-mono text-[0.55rem] rounded px-1.5 py-0.5 uppercase shrink-0 font-bold tracking-wider"
          style={{ color: ss.color, background: ss.bg, border: `1px solid ${ss.border}` }}>
      {sev || 'info'}
    </span>
  );
}

function SevRow({ counts }) {
  const c = counts || {};
  return (
    <div className="hidden lg:flex items-center gap-2">
      {c.critical > 0 && <span className="font-mono text-[0.6rem]" style={{ color: '#ff6e84' }}>{c.critical}C</span>}
      {c.high > 0     && <span className="font-mono text-[0.6rem]" style={{ color: '#ff8f06' }}>{c.high}H</span>}
      {c.medium > 0   && <span className="font-mono text-[0.6rem]" style={{ color: '#ff7161' }}>{c.medium}M</span>}
    </div>
  );
}

function Badge({ color, bg, border, children }) {
  return (
    <span className="font-mono text-[0.55rem] rounded px-1.5 py-0.5 uppercase tracking-[0.06em] flex items-center"
          style={{ color, background: bg, border: `1px solid ${border}` }}>
      {children}
    </span>
  );
}

function StatPill({ label, value, color }) {
  return (
    <div className="text-right">
      <p className="font-mono text-[0.6rem]" style={{ color: DIM_TEXT }}>{label}</p>
      <p className="font-mono text-sm font-bold" style={{ color }}>{value}</p>
    </div>
  );
}

function SectionLabel({ icon, label }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <span className="material-symbols-outlined" style={{ fontSize: 18, color: P }}>{icon}</span>
      <p className="font-mono text-[0.65rem] uppercase tracking-[0.18em]" style={{ color: DIM_TEXT }}>{label}</p>
    </div>
  );
}
