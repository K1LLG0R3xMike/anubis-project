import React, { useEffect, useRef, useState } from 'react';

const WS_BASE = 'ws://127.0.0.1:8000';

function getLineStyle(text) {
  if (text.includes('[DONE]'))  return '#4ade80';
  if (text.includes('[ERROR]')) return '#FF3131';
  if (text.includes('✓'))       return '#4ade80';
  if (text.includes('✗') || text.toLowerCase().includes('error') || text.includes('Fallido'))
    return '#fb923c';
  if (text.includes('[INICIO]') || text.includes('Iniciando'))
    return '#facc15';
  return 'rgba(255,255,255,0.7)';
}

function now() {
  return new Date().toTimeString().slice(0, 8);
}

export default function LiveTerminal({ runId, wsUrl }) {
  const [lines, setLines] = useState([]);
  const [connected, setConnected] = useState(false);
  const bottomRef = useRef(null);
  const wsRef = useRef(null);

  useEffect(() => {
    if (!runId) {
      setLines([]);
      setConnected(false);
      return;
    }

    setLines([{ time: now(), text: `Conectando a run #${runId}…` }]);
    const ws = new WebSocket(wsUrl || `${WS_BASE}/ws/attack/${runId}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      setLines(prev => [...prev, { time: now(), text: `[WS] Conexión establecida` }]);
    };

    ws.onmessage = (evt) => {
      setLines(prev => [...prev, { time: now(), text: evt.data }]);
    };

    ws.onclose = () => {
      setConnected(false);
      setLines(prev => [...prev, { time: now(), text: `[WS] Conexión cerrada` }]);
    };

    ws.onerror = () => {
      setLines(prev => [...prev, { time: now(), text: `[WS] Error de conexión` }]);
    };

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [runId]);

  // Auto-scroll al último mensaje
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  if (!runId) {
    return (
      <div style={{
        background: '#0a0000', borderRadius: 10,
        border: '1px solid rgba(255,49,49,0.15)',
        padding: 24, textAlign: 'center',
        color: 'rgba(255,255,255,0.25)', fontSize: 11,
        fontFamily: 'JetBrains Mono, monospace',
      }}>
        Sin ejecución activa
      </div>
    );
  }

  return (
    <div style={{
      background: '#0a0000', borderRadius: 10,
      border: '1px solid rgba(255,49,49,0.2)',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        padding: '6px 12px',
        background: 'rgba(60,5,5,0.4)',
        borderBottom: '1px solid rgba(255,49,49,0.12)',
        display: 'flex', alignItems: 'center', gap: 8,
      }}>
        <span style={{
          width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
          backgroundColor: connected ? '#4ade80' : 'rgba(255,255,255,0.2)',
          animation: connected ? 'pulse-red 2s infinite' : undefined,
          boxShadow: connected ? '0 0 6px #4ade80' : undefined,
        }} />
        <span style={{ fontSize: 10, fontWeight: 700, color: 'rgba(255,255,255,0.4)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
          Terminal — Run #{runId}
        </span>
        <span style={{ marginLeft: 'auto', fontSize: 9, color: connected ? '#4ade80' : 'rgba(255,255,255,0.2)' }}>
          {connected ? 'CONNECTED' : 'OFFLINE'}
        </span>
      </div>

      {/* Log output */}
      <div style={{
        maxHeight: 260, overflowY: 'auto', padding: '10px 12px',
        fontFamily: 'JetBrains Mono, monospace', fontSize: 11,
        scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,49,49,0.3) transparent',
      }}>
        {lines.map((line, i) => (
          <div key={i} style={{ marginBottom: 2, display: 'flex', gap: 8 }}>
            <span style={{ color: 'rgba(255,255,255,0.2)', flexShrink: 0, userSelect: 'none' }}>
              [{line.time}]
            </span>
            <span style={{ color: getLineStyle(line.text), wordBreak: 'break-all' }}>
              {line.text}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
