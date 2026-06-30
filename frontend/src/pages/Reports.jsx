import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const BASE = 'http://127.0.0.1:8000';

const REPORT_TYPES = [
  {
    id: 'executive',
    label: 'Ejecutivo',
    icon: 'summarize',
    desc: 'Resumen para stakeholders. Riesgo de negocio, score y top hallazgos críticos.',
  },
  {
    id: 'technical',
    label: 'Técnico',
    icon: 'bug_report',
    desc: 'Detalle completo por módulo: evidencias, CVEs y pasos de reproducción.',
  },
  {
    id: 'compliance',
    label: 'Compliance',
    icon: 'verified_user',
    desc: 'Mapeo contra OWASP Top 10, NIST CSF y CIS Controls.',
  },
  {
    id: 'full',
    label: 'Completo',
    icon: 'library_books',
    desc: 'Incluye ejecutivo, técnico y compliance en un único documento PDF.',
    highlight: true,
  },
];

const TYPE_STYLE = {
  executive:  { color: '#9aa8ff', bg: 'rgba(154,168,255,0.1)',  border: 'rgba(154,168,255,0.3)'  },
  technical:  { color: '#ff8f06', bg: 'rgba(255,143,6,0.1)',    border: 'rgba(255,143,6,0.3)'    },
  compliance: { color: '#ff7161', bg: 'rgba(255,113,97,0.1)',   border: 'rgba(255,113,97,0.3)'   },
  full:       { color: '#c8a2f5', bg: 'rgba(200,162,245,0.1)',  border: 'rgba(200,162,245,0.3)'  },
};

const TYPE_ICON  = { executive: 'summarize', technical: 'bug_report', compliance: 'verified_user', full: 'library_books' };
const TYPE_LABEL = { executive: 'Ejecutivo', technical: 'Técnico', compliance: 'Compliance', full: 'Completo' };

const SEV_STYLE = {
  critical: { color: '#ff6e84', bg: 'rgba(255,110,132,0.1)', border: 'rgba(255,110,132,0.3)' },
  high:     { color: '#ff8f06', bg: 'rgba(255,143,6,0.1)',   border: 'rgba(255,143,6,0.3)'   },
  medium:   { color: '#ff7161', bg: 'rgba(255,113,97,0.1)',  border: 'rgba(255,113,97,0.3)'  },
  low:      { color: '#9aa8ff', bg: 'rgba(154,168,255,0.1)', border: 'rgba(154,168,255,0.3)' },
  info:     { color: '#74757f', bg: 'rgba(116,117,127,0.1)', border: 'rgba(116,117,127,0.3)' },
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
export default function Reports() {
  const [targets, setTargets]         = useState([]);
  const [scope, setScope]             = useState('all');
  const [selectedId, setSelectedId]   = useState('');
  const [reportType, setReportType]   = useState('executive');
  const [generating, setGenerating]   = useState(false);
  const [downloading, setDownloading]         = useState(null);
  const [downloadingDocx, setDownloadingDocx] = useState(null);
  const [analyzing, setAnalyzing]     = useState(null); // report id being analyzed
  const [reports, setReports]         = useState([]);
  const [loadingReports, setLoading]  = useState(true);
  const [viewingReport, setViewing]   = useState(null);
  const [error, setError]             = useState('');

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
      // Poll until ai_enhanced = true (max 120s)
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
    <div className="pt-8 pb-32 px-4 md:px-8 max-w-5xl mx-auto space-y-8">

      {/* ── HEADER ──────────────────────────────────────────────────────── */}
      <div>
        <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] mb-1">
          reporting_engine
        </p>
        <h1 className="font-headline text-4xl font-bold text-on-surface tracking-tight">
          Security Reports
        </h1>
        <p className="text-on-surface-variant mt-2 leading-relaxed">
          Genera reportes ejecutivos, técnicos y de compliance. Arquitectura preparada para análisis por agente IA.
        </p>
      </div>

      {/* ── 1. SCOPE ────────────────────────────────────────────────────── */}
      <section
        className="rounded-2xl p-6"
        style={{ background: 'rgba(17,19,28,0.9)', border: '1px solid rgba(116,117,127,0.18)' }}
      >
        <SectionLabel icon="tune" label="Alcance del reporte" />

        <div className="flex flex-col sm:flex-row gap-3">
          {[
            { id: 'all',    label: 'Todos los objetivos', icon: 'hub',      sub: `${targets.length} targets en scope` },
            { id: 'single', label: 'Un objetivo',         icon: 'language', sub: 'Análisis individual' },
          ].map(s => {
            const active = scope === s.id;
            return (
              <button
                key={s.id}
                onClick={() => setScope(s.id)}
                className="flex-1 flex items-center gap-3 p-4 rounded-xl text-left transition-all"
                style={{
                  background: active ? 'rgba(154,168,255,0.08)' : 'rgba(12,14,22,0.5)',
                  border: active ? '1px solid rgba(154,168,255,0.35)' : '1px solid rgba(116,117,127,0.18)',
                }}
              >
                <div
                  className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
                  style={{
                    background: active ? 'rgba(154,168,255,0.18)' : 'rgba(116,117,127,0.1)',
                    border: active ? '1px solid rgba(154,168,255,0.3)' : '1px solid rgba(116,117,127,0.2)',
                  }}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: 18, color: active ? '#9aa8ff' : '#74757f' }}>
                    {s.icon}
                  </span>
                </div>
                <div>
                  <p className="text-sm font-semibold" style={{ color: active ? '#9aa8ff' : '#e4e4f0' }}>{s.label}</p>
                  <p className="font-mono text-[0.6rem] text-on-surface-variant mt-0.5">{s.sub}</p>
                </div>
                {active && (
                  <span className="material-symbols-outlined ml-auto" style={{ fontSize: 16, color: '#9aa8ff' }}>
                    check_circle
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Target chips — only when scope = single */}
        {scope === 'single' && (
          <div className="mt-4">
            {targets.length === 0 ? (
              <div
                className="flex items-center gap-3 p-4 rounded-xl"
                style={{ background: 'rgba(12,14,22,0.5)', border: '1px solid rgba(116,117,127,0.18)' }}
              >
                <span className="material-symbols-outlined text-outline">info</span>
                <p className="font-mono text-xs text-on-surface-variant">
                  No hay objetivos. Añade uno desde <span className="text-primary">Targets</span>.
                </p>
              </div>
            ) : (
              <>
                <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.15em] mb-2">
                  Selecciona el objetivo
                </p>
                <div className="flex flex-wrap gap-2">
                  {targets.map(t => {
                    const active = selectedId === String(t.id);
                    return (
                      <button
                        key={t.id}
                        onClick={() => setSelectedId(String(t.id))}
                        className="flex items-center gap-2 px-3 py-2 rounded-xl text-sm transition-all"
                        style={{
                          background: active ? 'rgba(154,168,255,0.1)' : 'rgba(12,14,22,0.5)',
                          border: active ? '1px solid rgba(154,168,255,0.35)' : '1px solid rgba(116,117,127,0.18)',
                        }}
                      >
                        <span className="material-symbols-outlined shrink-0" style={{ fontSize: 13, color: active ? '#9aa8ff' : '#74757f' }}>
                          language
                        </span>
                        <span className="font-mono text-xs" style={{ color: active ? '#9aa8ff' : '#e4e4f0' }}>{t.name}</span>
                      </button>
                    );
                  })}
                </div>
                {selectedTarget && (
                  <p className="font-mono text-xs text-primary mt-3 flex items-center gap-1.5">
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
      <section
        className="rounded-2xl p-6"
        style={{ background: 'rgba(17,19,28,0.9)', border: '1px solid rgba(116,117,127,0.18)' }}
      >
        <SectionLabel icon="description" label="Tipo de reporte" />
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {REPORT_TYPES.map(rt => {
            const ts     = TYPE_STYLE[rt.id];
            const active = reportType === rt.id;
            const isFull = rt.id === 'full';
            return (
              <button
                key={rt.id}
                onClick={() => setReportType(rt.id)}
                className="text-left p-4 rounded-xl transition-all relative overflow-hidden"
                style={{
                  background: active ? ts.bg : isFull ? 'rgba(200,162,245,0.04)' : 'rgba(12,14,22,0.5)',
                  border: active
                    ? `1px solid ${ts.border}`
                    : isFull
                    ? '1px dashed rgba(200,162,245,0.25)'
                    : '1px solid rgba(116,117,127,0.18)',
                }}
              >
                {isFull && !active && (
                  <span
                    className="absolute top-2 right-2 font-mono text-[0.5rem] uppercase px-1.5 py-0.5 rounded"
                    style={{ color: '#c8a2f5', background: 'rgba(200,162,245,0.1)', border: '1px solid rgba(200,162,245,0.2)' }}
                  >
                    Todo en uno
                  </span>
                )}
                <div
                  className="w-9 h-9 rounded-xl flex items-center justify-center mb-3"
                  style={{
                    background: active ? ts.bg : 'rgba(116,117,127,0.1)',
                    border: active ? `1px solid ${ts.border}` : '1px solid rgba(116,117,127,0.2)',
                  }}
                >
                  <span className="material-symbols-outlined" style={{ fontSize: 18, color: active ? ts.color : '#74757f' }}>
                    {rt.icon}
                  </span>
                </div>
                <p className="text-xs font-bold uppercase tracking-tight mb-1" style={{ color: active ? ts.color : '#e4e4f0' }}>
                  {rt.label}
                </p>
                <p className="text-[0.65rem] text-on-surface-variant leading-snug">{rt.desc}</p>
              </button>
            );
          })}
        </div>
      </section>

      {/* ── 3. GENERATE ─────────────────────────────────────────────────── */}
      <section
        className="rounded-2xl p-6"
        style={{ background: 'rgba(17,19,28,0.9)', borderLeft: '4px solid #9aa8ff', border: '1px solid rgba(116,117,127,0.18)', borderLeftWidth: 4 }}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <span
              className="font-mono text-[0.6rem] rounded px-2 py-0.5 uppercase tracking-[0.1em]"
              style={{ color: '#9aa8ff', background: 'rgba(154,168,255,0.1)', border: '1px solid rgba(154,168,255,0.2)' }}
            >
              {scope === 'all' ? `${targets.length} targets` : (selectedTarget?.name || 'Sin objetivo')}
            </span>
            <h3 className="font-headline text-xl font-bold mt-2">{activeType?.label}</h3>
            <p className="font-mono text-xs text-on-surface-variant mt-1">
              {scope === 'all' ? 'Reporte global · todos los hallazgos' : `Reporte individual · ${selectedTarget?.url || '—'}`}
            </p>
          </div>
          <button
            onClick={handleGenerate}
            disabled={generating || (scope === 'single' && !selectedId) || targets.length === 0}
            className="flex items-center gap-2 px-6 py-3 rounded-xl font-bold text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed shrink-0"
            style={{ background: '#9aa8ff', color: '#0c0e16', boxShadow: '0 6px 20px rgba(154,168,255,0.25)' }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 17 }}>
              {generating ? 'sync' : 'picture_as_pdf'}
            </span>
            {generating ? 'Generando...' : 'Generar Reporte'}
          </button>
        </div>

        {error && (
          <div
            className="mt-4 flex items-center gap-2 p-3 rounded-lg"
            style={{ background: 'rgba(255,110,132,0.08)', border: '1px solid rgba(255,110,132,0.25)' }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 16, color: '#ff6e84' }}>error</span>
            <p className="font-mono text-xs" style={{ color: '#ff6e84' }}>{error}</p>
          </div>
        )}

        <div
          className="mt-5 flex items-start gap-3 p-4 rounded-xl"
          style={{ background: 'rgba(12,14,22,0.6)', border: '1px solid rgba(154,168,255,0.1)' }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: 18, color: '#9aa8ff' }}>smart_toy</span>
          <div>
            <p className="font-mono text-xs text-on-surface font-semibold">Agente IA — próximamente</p>
            <p className="font-mono text-[0.65rem] text-on-surface-variant mt-1 leading-relaxed">
              El reporte se genera con datos reales de hallazgos. Pronto el agente IA enriquecerá
              automáticamente cada sección: resúmenes ejecutivos, recomendaciones técnicas y análisis de compliance.
            </p>
          </div>
        </div>
      </section>

      {/* ── 4. ARCHIVE ──────────────────────────────────────────────────── */}
      <section
        className="rounded-2xl p-6"
        style={{ background: 'rgba(17,19,28,0.9)', border: '1px solid rgba(116,117,127,0.18)' }}
      >
        <SectionLabel icon="history" label={`Archivo de reportes (${reports.length})`} />

        {loadingReports ? (
          <div className="flex items-center justify-center gap-3 py-12">
            <span className="material-symbols-outlined text-primary" style={{ fontSize: 20, animation: 'spin 1s linear infinite' }}>sync</span>
            <p className="font-mono text-xs text-on-surface-variant">Cargando reportes...</p>
          </div>
        ) : reports.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-14 gap-3">
            <span className="material-symbols-outlined text-outline" style={{ fontSize: 44 }}>description</span>
            <p className="font-mono text-xs text-outline">Sin reportes generados todavía.</p>
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

      {/* ── DETAIL MODAL ────────────────────────────────────────────────── */}
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
   REPORT CARD (archive row)
════════════════════════════════════════════════════════════════════════════ */
function ReportCard({ report, onView, onDelete, onDownload, onDownloadDocx, onAnalyze, isDownloading, isDownloadingDocx, isAnalyzing }) {
  const [confirmDel, setConfirmDel] = useState(false);
  const ts = TYPE_STYLE[report.report_type] || TYPE_STYLE.executive;
  const rc = riskColor(report.risk_score || 0);

  return (
    <div
      className="flex items-center gap-3 p-4 rounded-xl transition-colors"
      style={{ background: 'rgba(12,14,22,0.5)', border: '1px solid rgba(116,117,127,0.15)' }}
    >
      {/* Type icon */}
      <div
        className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
        style={{ background: ts.bg, border: `1px solid ${ts.border}` }}
      >
        <span className="material-symbols-outlined" style={{ fontSize: 20, color: ts.color }}>
          {TYPE_ICON[report.report_type] || 'description'}
        </span>
      </div>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-on-surface truncate">{report.title}</p>
        <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
          <Badge color={ts.color} bg={ts.bg} border={ts.border}>
            {TYPE_LABEL[report.report_type] || report.report_type}
          </Badge>
          <Badge color="#74757f" bg="rgba(116,117,127,0.08)" border="rgba(116,117,127,0.2)">
            <span className="material-symbols-outlined" style={{ fontSize: 9, marginRight: 2 }}>
              {report.scope === 'all' ? 'hub' : 'language'}
            </span>
            {report.scope === 'all' ? 'Todos' : `${report.total_targets} target`}
          </Badge>
          {report.ai_enhanced && (
            <Badge color="#9aa8ff" bg="rgba(154,168,255,0.08)" border="rgba(154,168,255,0.2)">
              <span className="material-symbols-outlined" style={{ fontSize: 9, marginRight: 2 }}>smart_toy</span>
              IA Enhanced
            </Badge>
          )}
          <span className="font-mono text-[0.55rem] text-on-surface-variant">{fmtDate(report.generated_at)}</span>
        </div>
      </div>

      {/* Stats */}
      <div className="hidden sm:flex items-center gap-5 shrink-0 mr-2">
        <StatPill label="findings" value={report.total_findings} color="#e4e4f0" />
        <StatPill label="risk" value={report.risk_score || 0} color={rc} />
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 shrink-0">
        <button
          onClick={onView}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all"
          style={{ color: '#9aa8ff', border: '1px solid rgba(154,168,255,0.2)' }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>open_in_full</span>
          Ver
        </button>

        <button
          onClick={onAnalyze}
          disabled={isAnalyzing || report.ai_enhanced}
          title={report.ai_enhanced ? 'Ya analizado con IA' : 'Analizar con IA'}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
          style={{ color: '#c8a2f5', border: '1px solid rgba(200,162,245,0.25)' }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: 14, animation: isAnalyzing ? 'spin 1s linear infinite' : 'none' }}>
            {report.ai_enhanced ? 'check_circle' : 'smart_toy'}
          </span>
          {isAnalyzing ? 'IA...' : 'IA'}
        </button>

        <button
          onClick={onDownload}
          disabled={isDownloading}
          title="Descargar PDF"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
          style={{ color: '#4caf50', border: '1px solid rgba(76,175,80,0.25)' }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>
            {isDownloading ? 'sync' : 'picture_as_pdf'}
          </span>
          PDF
        </button>

        <button
          onClick={onDownloadDocx}
          disabled={isDownloadingDocx}
          title="Descargar DOCX"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
          style={{ color: '#29b6f6', border: '1px solid rgba(41,182,246,0.25)' }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: 14 }}>
            {isDownloadingDocx ? 'sync' : 'description'}
          </span>
          DOCX
        </button>

        {confirmDel ? (
          <div className="flex gap-1">
            <button
              onClick={() => { onDelete(); setConfirmDel(false); }}
              className="px-2 py-1.5 rounded-lg font-mono text-[0.6rem] font-bold transition-colors"
              style={{ color: '#ff6e84', border: '1px solid rgba(255,110,132,0.2)' }}
            >
              Borrar
            </button>
            <button
              onClick={() => setConfirmDel(false)}
              className="px-2 py-1.5 rounded-lg font-mono text-[0.6rem] text-on-surface-variant"
              style={{ border: '1px solid rgba(116,117,127,0.2)' }}
            >
              No
            </button>
          </div>
        ) : (
          <button
            onClick={() => setConfirmDel(true)}
            className="w-8 h-8 rounded-lg flex items-center justify-center transition-colors"
            style={{ color: '#74757f' }}
          >
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
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto py-8 px-4"
      style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(10px)' }}
    >
      <div
        className="relative w-full max-w-4xl rounded-2xl overflow-hidden"
        style={{ background: '#11131c', border: '1px solid rgba(116,117,127,0.2)' }}
      >
        {/* Sticky header */}
        <div
          className="sticky top-0 z-10 flex items-center gap-3 p-5"
          style={{ background: 'rgba(17,19,28,0.97)', borderBottom: '1px solid rgba(116,117,127,0.15)' }}
        >
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
            style={{ background: ts.bg, border: `1px solid ${ts.border}` }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 20, color: ts.color }}>
              {TYPE_ICON[report.report_type]}
            </span>
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-bold text-on-surface truncate">{report.title}</p>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="font-mono text-[0.6rem] uppercase" style={{ color: ts.color }}>
                {TYPE_LABEL[report.report_type]}
              </span>
              <span className="text-outline text-xs">·</span>
              <span className="font-mono text-[0.6rem] text-on-surface-variant">{fmtDate(report.generated_at)}</span>
              {aiContent.ai_generated && (
                <>
                  <span className="text-outline text-xs">·</span>
                  <span className="font-mono text-[0.6rem] text-primary flex items-center gap-1">
                    <span className="material-symbols-outlined" style={{ fontSize: 10 }}>smart_toy</span>
                    IA Enhanced
                  </span>
                </>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 ml-2 shrink-0">
            <button
              onClick={onAnalyze}
              disabled={isAnalyzing || report.ai_enhanced}
              title={report.ai_enhanced ? 'Ya analizado con IA' : 'Analizar con IA'}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
              style={{ color: '#c8a2f5', border: '1px solid rgba(200,162,245,0.25)', background: 'rgba(200,162,245,0.06)' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 15, animation: isAnalyzing ? 'spin 1s linear infinite' : 'none' }}>
                smart_toy
              </span>
              {isAnalyzing ? 'Analizando...' : report.ai_enhanced ? 'IA completada' : 'Analizar con IA'}
            </button>
            <button
              onClick={onDownload}
              disabled={isDownloading}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
              style={{ color: '#4caf50', border: '1px solid rgba(76,175,80,0.25)', background: 'rgba(76,175,80,0.06)' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 15 }}>
                {isDownloading ? 'sync' : 'picture_as_pdf'}
              </span>
              {isDownloading ? 'Generando...' : 'Descargar PDF'}
            </button>
            <button
              onClick={onDownloadDocx}
              disabled={isDownloadingDocx}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl font-mono text-[0.65rem] font-bold uppercase tracking-widest transition-all disabled:opacity-40"
              style={{ color: '#29b6f6', border: '1px solid rgba(41,182,246,0.25)', background: 'rgba(41,182,246,0.06)' }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 15 }}>
                {isDownloadingDocx ? 'sync' : 'description'}
              </span>
              {isDownloadingDocx ? 'Generando...' : 'Descargar DOCX'}
            </button>
            <button
              onClick={onClose}
              className="w-9 h-9 rounded-xl flex items-center justify-center transition-colors"
              style={{ border: '1px solid rgba(116,117,127,0.2)' }}
            >
              <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: 18 }}>close</span>
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 space-y-6">

          {/* KPI row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: 'Targets',  value: data.total_targets || 0, icon: 'radar',   color: '#9aa8ff' },
              { label: 'Findings', value: totalF,                  icon: 'security', color: '#ff8f06' },
              { label: 'Risk',     value: rs,                      icon: 'shield',   color: rc        },
              { label: 'Críticos', value: sevCounts.critical || 0, icon: 'warning',  color: '#ff6e84' },
            ].map(k => (
              <div
                key={k.label}
                className="p-4 rounded-xl"
                style={{ background: 'rgba(12,14,22,0.6)', border: '1px solid rgba(116,117,127,0.13)' }}
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <span className="material-symbols-outlined" style={{ fontSize: 13, color: k.color }}>{k.icon}</span>
                  <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase">{k.label}</p>
                </div>
                <p className="font-mono text-2xl font-bold" style={{ color: k.color }}>{k.value}</p>
              </div>
            ))}
          </div>

          {/* Severity bar */}
          {totalF > 0 && <SeverityBar counts={sevCounts} total={totalF} />}

          {/* Type-specific content */}
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
        if (['critical', 'high'].includes((f.severity || '').toLowerCase())) {
          criticalAndHigh.push({ ...f, target_name: t.name });
        }
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
                <div
                  key={i}
                  className="flex items-start gap-3 p-3 rounded-lg"
                  style={{ background: ss.bg, border: `1px solid ${ss.border}` }}
                >
                  <SevBadge sev={f.severity} />
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-on-surface">{f.title}</p>
                    <p className="font-mono text-[0.6rem] text-on-surface-variant mt-0.5">{f.target_name}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </ModalCard>
      )}

      <AISlot
        title="Resumen ejecutivo"
        icon="summarize"
        content={ai.executive_summary}
        placeholder="El agente IA generará un resumen ejecutivo adaptado para stakeholders no técnicos, destacando el impacto de negocio y la urgencia de remediación."
      />
      <AISlot
        title="Impacto de negocio"
        icon="trending_down"
        content={ai.business_impact}
        placeholder="El agente IA describirá el impacto potencial en operaciones, reputación y cumplimiento regulatorio basado en los hallazgos detectados."
      />
      <AISlot
        title="Narrativa de riesgo"
        icon="shield"
        content={ai.risk_narrative}
        placeholder="Perfil de riesgo actual, superficie de ataque y prioridades de remediación con estimación de esfuerzo."
      />
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
        <div
          key={t.id}
          className="rounded-xl overflow-hidden"
          style={{ border: '1px solid rgba(116,117,127,0.15)', background: 'rgba(12,14,22,0.4)' }}
        >
          <button
            onClick={() => setOpenTarget(openTarget === t.id ? null : t.id)}
            className="w-full flex items-center gap-3 p-4 text-left transition-colors"
          >
            <span className="material-symbols-outlined text-primary" style={{ fontSize: 18 }}>language</span>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-on-surface">{t.name}</p>
              <p className="font-mono text-[0.6rem] text-on-surface-variant">{t.url}</p>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <SevRow counts={t.severity_counts} />
              <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: 16 }}>
                {openTarget === t.id ? 'expand_less' : 'expand_more'}
              </span>
            </div>
          </button>

          {openTarget === t.id && (
            <div
              className="p-4 space-y-2"
              style={{ borderTop: '1px solid rgba(116,117,127,0.1)' }}
            >
              {Object.keys(t.findings_by_module || {}).length === 0 ? (
                <p className="font-mono text-xs text-outline italic px-2">Sin hallazgos registrados.</p>
              ) : Object.entries(t.findings_by_module).map(([mod, mf]) => {
                const modKey = `${t.id}-${mod}`;
                return (
                  <div
                    key={mod}
                    className="rounded-xl overflow-hidden"
                    style={{ border: '1px solid rgba(116,117,127,0.12)', background: 'rgba(12,14,22,0.3)' }}
                  >
                    <button
                      onClick={() => setOpenMod(openMod === modKey ? null : modKey)}
                      className="w-full flex items-center gap-2 p-3 text-left transition-colors"
                    >
                      <span className="material-symbols-outlined text-on-surface-variant" style={{ fontSize: 14 }}>
                        {MODULE_ICONS[mod] || 'circle'}
                      </span>
                      <span className="font-mono text-xs font-bold text-on-surface uppercase">{mod}</span>
                      <span className="font-mono text-[0.6rem] text-on-surface-variant">({mf.length})</span>
                      <span className="material-symbols-outlined text-on-surface-variant ml-auto" style={{ fontSize: 14 }}>
                        {openMod === modKey ? 'expand_less' : 'expand_more'}
                      </span>
                    </button>

                    {openMod === modKey && (
                      <div
                        className="divide-y"
                        style={{ borderTop: '1px solid rgba(116,117,127,0.1)', borderColor: 'rgba(116,117,127,0.1)' }}
                      >
                        {mf.map((f, i) => (
                          <div key={i} className="p-4 space-y-2">
                            <div className="flex items-start gap-3">
                              <SevBadge sev={f.severity} />
                              <p className="text-xs font-semibold text-on-surface">{f.title}</p>
                            </div>
                            {f.description && (
                              <p className="text-[0.7rem] text-on-surface-variant leading-relaxed pl-1">
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

      <AISlot
        title="Recomendaciones técnicas"
        icon="build"
        content={ai.recommendations?.length ? ai.recommendations.map((r, i) =>
          typeof r === 'string' ? r : `${r.finding_title || `#${i+1}`}: ${r.recommendation || ''}`
        ).join('\n\n') : null}
        placeholder="El agente IA generará recomendaciones técnicas por hallazgo: pasos de remediación, referencias CVE, configuraciones recomendadas y prioridad de corrección."
      />
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   COMPLIANCE VIEW
════════════════════════════════════════════════════════════════════════════ */
function ComplianceView({ data, ai }) {
  const owasp = data.owasp_mapping || {};
  const affected = Object.values(owasp).filter(v => v.status === 'affected').length;

  return (
    <div className="space-y-5">
      <ModalCard>
        <div className="flex items-center justify-between mb-4">
          <ModalCardHeader icon="verified_user" label="OWASP Top 10 — 2021" iconColor="#ff7161" />
          <span className="font-mono text-[0.6rem]">
            <span style={{ color: '#ff6e84' }}>{affected}</span>
            <span className="text-on-surface-variant"> / 10 afectados</span>
          </span>
        </div>

        <div
          className="rounded-xl overflow-hidden divide-y"
          style={{ border: '1px solid rgba(116,117,127,0.15)', borderColor: 'rgba(116,117,127,0.15)' }}
        >
          {Object.entries(owasp).map(([code, info]) => {
            const isAffected = info.status === 'affected';
            return (
              <div
                key={code}
                className="flex items-center gap-3 px-4 py-3"
                style={{ background: isAffected ? 'rgba(255,110,132,0.04)' : 'transparent' }}
              >
                <div
                  className="w-14 h-7 rounded flex items-center justify-center shrink-0"
                  style={{
                    background: isAffected ? 'rgba(255,110,132,0.12)' : 'rgba(116,117,127,0.07)',
                    border: isAffected ? '1px solid rgba(255,110,132,0.25)' : '1px solid rgba(116,117,127,0.15)',
                  }}
                >
                  <span
                    className="font-mono text-[0.6rem] font-bold"
                    style={{ color: isAffected ? '#ff6e84' : '#74757f' }}
                  >
                    {code}
                  </span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-xs font-semibold ${isAffected ? 'text-on-surface' : 'text-on-surface-variant'}`}>
                    {info.name}
                  </p>
                  {isAffected && (
                    <p className="font-mono text-[0.55rem] text-on-surface-variant mt-0.5">
                      {info.count} hallazgo{info.count !== 1 ? 's' : ''} relacionado{info.count !== 1 ? 's' : ''}
                    </p>
                  )}
                </div>
                {isAffected ? (
                  <span
                    className="font-mono text-[0.55rem] rounded px-2 py-0.5 uppercase flex items-center gap-1 shrink-0"
                    style={{ color: '#ff6e84', background: 'rgba(255,110,132,0.1)', border: '1px solid rgba(255,110,132,0.25)' }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: 10 }}>warning</span>
                    Afectado
                  </span>
                ) : (
                  <span
                    className="font-mono text-[0.55rem] rounded px-2 py-0.5 uppercase shrink-0"
                    style={{ color: '#74757f', background: 'rgba(116,117,127,0.07)', border: '1px solid rgba(116,117,127,0.15)' }}
                  >
                    OK
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </ModalCard>

      <AISlot
        title="Análisis de compliance"
        icon="policy"
        content={ai.compliance_narrative}
        placeholder="El agente IA generará un análisis de brechas contra OWASP, NIST CSF e ISO 27001, con recomendaciones priorizadas por riesgo regulatorio."
      />

      {ai.compliance_gaps?.length > 0 && (
        <ModalCard>
          <ModalCardHeader icon="close" label="Brechas identificadas por IA" iconColor="#ff6e84" />
          <div className="space-y-2">
            {ai.compliance_gaps.map((gap, i) => (
              <div key={i} className="flex items-start gap-2">
                <span className="material-symbols-outlined mt-0.5 shrink-0" style={{ fontSize: 14, color: '#ff6e84' }}>
                  cancel
                </span>
                <p className="text-xs text-on-surface">{typeof gap === 'string' ? gap : JSON.stringify(gap)}</p>
              </div>
            ))}
          </div>
        </ModalCard>
      )}
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   FULL VIEW (Executive + Technical + Compliance con separadores)
════════════════════════════════════════════════════════════════════════════ */
function FullView({ data, ai }) {
  return (
    <div className="space-y-8">
      {/* Executive */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-xl"
            style={{ background: 'rgba(154,168,255,0.1)', border: '1px solid rgba(154,168,255,0.25)' }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 15, color: '#9aa8ff' }}>summarize</span>
            <span className="font-mono text-[0.65rem] font-bold uppercase tracking-widest" style={{ color: '#9aa8ff' }}>
              Ejecutivo
            </span>
          </div>
        </div>
        <ExecutiveView data={data} ai={ai} />
      </div>

      <div style={{ borderTop: '1px dashed rgba(116,117,127,0.2)' }} className="pt-2" />

      {/* Technical */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-xl"
            style={{ background: 'rgba(255,143,6,0.1)', border: '1px solid rgba(255,143,6,0.25)' }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 15, color: '#ff8f06' }}>bug_report</span>
            <span className="font-mono text-[0.65rem] font-bold uppercase tracking-widest" style={{ color: '#ff8f06' }}>
              Técnico
            </span>
          </div>
        </div>
        <TechnicalView data={data} ai={ai} />
      </div>

      <div style={{ borderTop: '1px dashed rgba(116,117,127,0.2)' }} className="pt-2" />

      {/* Compliance */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-xl"
            style={{ background: 'rgba(255,113,97,0.1)', border: '1px solid rgba(255,113,97,0.25)' }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 15, color: '#ff7161' }}>verified_user</span>
            <span className="font-mono text-[0.65rem] font-bold uppercase tracking-widest" style={{ color: '#ff7161' }}>
              Compliance
            </span>
          </div>
        </div>
        <ComplianceView data={data} ai={ai} />
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   SHARED ATOMS
════════════════════════════════════════════════════════════════════════════ */
function SeverityBar({ counts, total }) {
  const order  = ['critical', 'high', 'medium', 'low', 'info'];
  const colors = { critical: '#ff6e84', high: '#ff8f06', medium: '#ff7161', low: '#9aa8ff', info: '#74757f' };
  return (
    <div
      className="p-4 rounded-xl"
      style={{ background: 'rgba(12,14,22,0.6)', border: '1px solid rgba(116,117,127,0.13)' }}
    >
      <p className="font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em] mb-3">
        Distribución de severidad
      </p>
      <div className="flex h-2.5 rounded-full overflow-hidden gap-px mb-3">
        {order.map(s => {
          const pct = total > 0 ? ((counts[s] || 0) / total) * 100 : 0;
          return pct > 0 ? (
            <div key={s} style={{ width: `${pct}%`, background: colors[s], minWidth: 4 }} title={`${s}: ${counts[s]}`} />
          ) : null;
        })}
      </div>
      <div className="flex flex-wrap gap-4">
        {order.map(s => (
          <div key={s} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full" style={{ background: colors[s] }} />
            <span className="font-mono text-[0.6rem] text-on-surface-variant capitalize">{s}</span>
            <span className="font-mono text-[0.6rem] font-bold text-on-surface">{counts[s] || 0}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AISlot({ title, icon, content, placeholder }) {
  return (
    <div
      className="rounded-xl p-5"
      style={{
        background: content ? 'rgba(154,168,255,0.05)' : 'rgba(12,14,22,0.4)',
        border: content ? '1px solid rgba(154,168,255,0.2)' : '1px dashed rgba(116,117,127,0.2)',
      }}
    >
      <div className="flex items-center gap-2 mb-3">
        <span className="material-symbols-outlined" style={{ fontSize: 16, color: content ? '#9aa8ff' : '#74757f' }}>
          {icon}
        </span>
        <p
          className="font-mono text-[0.65rem] uppercase tracking-[0.15em]"
          style={{ color: content ? '#9aa8ff' : '#74757f' }}
        >
          {title}
        </p>
        {content && (
          <span
            className="ml-auto font-mono text-[0.55rem] rounded px-1.5 py-0.5 flex items-center gap-1 uppercase"
            style={{ color: '#9aa8ff', background: 'rgba(154,168,255,0.1)', border: '1px solid rgba(154,168,255,0.25)' }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 9 }}>smart_toy</span>
            IA
          </span>
        )}
      </div>
      {content
        ? <p className="text-sm text-on-surface leading-relaxed whitespace-pre-wrap">{content}</p>
        : <p className="text-[0.7rem] text-outline italic leading-relaxed">{placeholder}</p>
      }
    </div>
  );
}

function ModalCard({ children }) {
  return (
    <div
      className="rounded-xl p-5"
      style={{ background: 'rgba(12,14,22,0.6)', border: '1px solid rgba(116,117,127,0.13)' }}
    >
      {children}
    </div>
  );
}

function ModalCardHeader({ icon, label, iconColor }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <span className="material-symbols-outlined" style={{ fontSize: 16, color: iconColor || '#9aa8ff' }}>{icon}</span>
      <p className="font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em]">{label}</p>
    </div>
  );
}

function SevBadge({ sev }) {
  const ss = SEV_STYLE[(sev || 'info').toLowerCase()] || SEV_STYLE.info;
  return (
    <span
      className="font-mono text-[0.55rem] rounded px-1.5 py-0.5 uppercase shrink-0 font-bold tracking-wider"
      style={{ color: ss.color, background: ss.bg, border: `1px solid ${ss.border}` }}
    >
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
    <span
      className="font-mono text-[0.55rem] rounded px-1.5 py-0.5 uppercase tracking-[0.06em] flex items-center"
      style={{ color, background: bg, border: `1px solid ${border}` }}
    >
      {children}
    </span>
  );
}

function StatPill({ label, value, color }) {
  return (
    <div className="text-right">
      <p className="font-mono text-[0.6rem] text-on-surface-variant">{label}</p>
      <p className="font-mono text-sm font-bold" style={{ color }}>{value}</p>
    </div>
  );
}

function SectionLabel({ icon, label }) {
  return (
    <div className="flex items-center gap-2 mb-4">
      <span className="material-symbols-outlined text-primary" style={{ fontSize: 18 }}>{icon}</span>
      <p className="font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.18em]">{label}</p>
    </div>
  );
}
