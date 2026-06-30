import React, { createContext, useContext, useState, useCallback } from 'react';

const ModeContext = createContext();

export function ModeProvider({ children }) {
  const initial = window.location.pathname.startsWith('/attack') ? 'attack' : 'scan';
  const [mode, setMode] = useState(initial);

  const toggleMode = useCallback(() => {
    setMode(m => (m === 'scan' ? 'attack' : 'scan'));
  }, []);

  return (
    <ModeContext.Provider value={{ mode, isAttack: mode === 'attack', toggleMode }}>
      {children}
    </ModeContext.Provider>
  );
}

export function useMode() {
  return useContext(ModeContext);
}
