import React from 'react';

const STATUS_STYLE = {
  planned:   { color: 'rgba(255,255,255,0.35)', label: 'Planificado' },
  running:   { color: '#facc15',                label: 'Ejecutando'  },
  completed: { color: '#4ade80',                label: 'Completado'  },
  failed:    { color: '#FF3131',                label: 'Fallido'     },
  aborted:   { color: '#fb923c',                label: 'Abortado'    },
  skipped:   { color: 'rgba(255,255,255,0.2)',  label: 'Skipped'     },
};

const INTRUSIVENESS_STYLE = {
  passive:   { bg: 'rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.5)', label: 'PASSIVE'   },
  active:    { bg: 'rgba(251,146,60,0.15)',  color: '#fb923c',               label: 'ACTIVE'    },
  exploitive:{ bg: 'rgba(255,49,49,0.2)',   color: '#FF3131',               label: 'EXPLOITIVE'},
};

function NodeCard({ node, result }) {
  const st = STATUS_STYLE[node.status] || STATUS_STYLE.planned;
  const intr = INTRUSIVENESS_STYLE[node.intrusiveness] || INTRUSIVENESS_STYLE.active;

  const isRunning = node.status === 'running';

  return (
    <div
      style={{
        background: 'rgba(20,5,5,0.6)',
        border: `1px solid ${node.status === 'completed' ? 'rgba(74,222,128,0.2)' : node.status === 'failed' ? 'rgba(255,49,49,0.3)' : 'rgba(255,255,255,0.07)'}`,
        borderRadius: 10,
        padding: '10px 14px',
        marginBottom: 6,
        transition: 'border-color 0.3s',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        {/* Status dot */}
        <span
          style={{
            width: 7, height: 7, borderRadius: '50%',
            backgroundColor: st.color,
            flexShrink: 0,
            animation: isRunning ? 'pulse-red 1.2s infinite' : undefined,
            boxShadow: isRunning ? `0 0 6px ${st.color}` : undefined,
          }}
        />
        {/* vector_type */}
        <span style={{ color: 'white', fontWeight: 700, fontSize: 12, flex: 1 }}>
          {node.vector_type}
        </span>
        {/* intrusiveness badge */}
        <span style={{
          background: intr.bg, color: intr.color,
          fontSize: 9, fontWeight: 700, padding: '2px 6px',
          borderRadius: 4, letterSpacing: '0.05em',
        }}>
          {intr.label}
        </span>
        {/* status badge */}
        <span style={{ color: st.color, fontSize: 9, fontWeight: 700, letterSpacing: '0.05em' }}>
          {st.label.toUpperCase()}
        </span>
      </div>

      <div style={{ display: 'flex', gap: 12, fontSize: 10, color: 'rgba(255,255,255,0.35)', marginBottom: 2 }}>
        <span>priority: {node.priority_score}</span>
        {node.finding_severity && (
          <span>severity: {node.finding_severity}</span>
        )}
        {node.finding_title && (
          <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {node.finding_title}
          </span>
        )}
      </div>

      {node.requires_nodes?.length > 0 && (
        <div style={{ fontSize: 9, color: 'rgba(255,255,255,0.25)', marginTop: 2 }}>
          → espera: {node.requires_nodes.join(', ')}
        </div>
      )}
      {node.provides?.length > 0 && (
        <div style={{ fontSize: 9, color: 'rgba(250,204,21,0.5)', marginTop: 2 }}>
          ⚡ desbloquea: {node.provides.join(', ')}
        </div>
      )}

      {result && (
        <div style={{
          marginTop: 6, padding: '4px 8px', borderRadius: 6,
          background: result.confirmed_finding ? 'rgba(74,222,128,0.08)' : 'rgba(255,255,255,0.04)',
          fontSize: 10,
          color: result.confirmed_finding ? '#4ade80' : 'rgba(255,255,255,0.4)',
        }}>
          {result.confirmed_finding ? '✓ Confirmado' : '✗ No confirmado'}
          {result.confidence_delta != null && (
            <span style={{ marginLeft: 8, color: 'rgba(255,255,255,0.3)' }}>
              Δ{result.confidence_delta > 0 ? '+' : ''}{result.confidence_delta}
            </span>
          )}
          {result.evidence_path && (
            <span style={{ marginLeft: 8, color: 'rgba(255,255,255,0.3)', fontStyle: 'italic' }}>
              evidencia guardada
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export default function AttackPlanViewer({ plan, results = [] }) {
  if (!plan || !plan.nodes || plan.nodes.length === 0) {
    return (
      <div style={{
        background: 'rgba(30,8,8,0.5)', border: '1px solid rgba(255,49,49,0.15)',
        borderRadius: 12, padding: 24, textAlign: 'center',
        color: 'rgba(255,255,255,0.25)', fontSize: 12,
      }}>
        Sin nodos en el plan
      </div>
    );
  }

  const resultsByNodeId = {};
  results.forEach(r => { resultsByNodeId[r.node_id] = r; });

  const sorted = [...plan.nodes].sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));

  return (
    <div style={{
      background: 'rgba(30,8,8,0.5)', border: '1px solid rgba(255,49,49,0.15)',
      borderRadius: 12, padding: 14, maxHeight: 340, overflowY: 'auto',
      scrollbarWidth: 'thin',
    }}>
      <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
        {sorted.length} nodo{sorted.length !== 1 ? 's' : ''} — {plan.target_url}
      </div>
      {sorted.map(node => (
        <NodeCard key={node.id} node={node} result={resultsByNodeId[node.id]} />
      ))}
    </div>
  );
}
