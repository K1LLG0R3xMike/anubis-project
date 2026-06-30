import React from 'react';

function fmt(iso) {
  if (!iso) return '—';
  return iso.replace('T', ' ').substring(0, 19);
}

function EvidenceCard({ result }) {
  const confirmed = result.confirmed_finding;
  return (
    <div style={{
      background: 'rgba(20,5,5,0.7)',
      border: `1px solid ${confirmed ? 'rgba(74,222,128,0.2)' : 'rgba(255,255,255,0.07)'}`,
      borderRadius: 10, padding: '12px 14px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span style={{
          fontSize: 10, fontWeight: 700, color: 'white',
          background: 'rgba(255,49,49,0.15)', padding: '2px 7px', borderRadius: 4,
        }}>
          {result.vector_type}
        </span>
        <span style={{
          fontSize: 10, fontWeight: 700,
          color: confirmed ? '#4ade80' : '#fb923c',
        }}>
          {confirmed ? '✓ CONFIRMADO' : '✗ No confirmado'}
        </span>
      </div>

      <div style={{
        fontSize: 10, color: 'rgba(255,255,255,0.45)',
        wordBreak: 'break-all', marginBottom: 4,
        fontFamily: 'JetBrains Mono, monospace',
      }}
        title={result.evidence_path}
      >
        {result.evidence_path}
      </div>

      <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.25)', display: 'flex', gap: 12 }}>
        <span>Inicio: {fmt(result.started_at)}</span>
        <span>Fin: {fmt(result.completed_at)}</span>
        {result.confidence_delta != null && (
          <span>Δconf: {result.confidence_delta > 0 ? '+' : ''}{result.confidence_delta}</span>
        )}
      </div>
    </div>
  );
}

export default function EvidenceGallery({ results = [] }) {
  const withEvidence = results.filter(r => r.evidence_path);

  if (withEvidence.length === 0) {
    return (
      <div style={{
        background: 'rgba(30,8,8,0.5)', border: '1px solid rgba(255,49,49,0.15)',
        borderRadius: 12, padding: 24, textAlign: 'center',
        color: 'rgba(255,255,255,0.25)', fontSize: 12,
      }}>
        Sin evidencias capturadas aún
      </div>
    );
  }

  return (
    <div style={{
      display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10,
    }}>
      {withEvidence.map(r => (
        <EvidenceCard key={r.id} result={r} />
      ))}
    </div>
  );
}
