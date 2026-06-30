import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import axios from 'axios';
import { ModeProvider } from './context/ModeContext';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import AttackDashboard from './pages/AttackDashboard';
import Targets from './pages/Targets';
import AttackTargets from './pages/AttackTargets';
import Findings from './pages/Findings';
import AttackFindings from './pages/AttackFindings';
import Reports from './pages/Reports';
import AttackReports from './pages/AttackReports';
import Schedule from './pages/Schedule';
import AttackSchedule from './pages/AttackSchedule';
import Historical from './pages/Historical';
import AttackHistorical from './pages/AttackHistorical';
import Layout from './components/Layout';

const ProtectedLayout = () => {
  const [authState, setAuthState] = useState('checking');

  useEffect(() => {
    const token = localStorage.getItem('userToken');
    if (!token) { setAuthState('denied'); return; }
    axios
      .get('http://127.0.0.1:8000/verify-token', {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then(() => setAuthState('ok'))
      .catch(() => {
        localStorage.removeItem('userToken');
        setAuthState('denied');
      });
  }, []);

  if (authState === 'checking') {
    return (
      <div className="fixed inset-0 flex items-center justify-center bg-background">
        <span className="w-6 h-6 rounded-full border-2 border-primary border-t-transparent animate-spin" />
      </div>
    );
  }
  if (authState === 'denied') return <Navigate to="/login" replace />;

  return (
    <Layout>
      <Outlet />
    </Layout>
  );
};

function App() {
  return (
    <ModeProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<ProtectedLayout />}>
            <Route path="/dashboard"          element={<Dashboard />} />
            <Route path="/attack/dashboard" element={<AttackDashboard />} />
            <Route path="/targets"          element={<Targets />} />
            <Route path="/attack/targets"   element={<AttackTargets />} />
            <Route path="/findings"         element={<Findings />} />
            <Route path="/attack/findings"  element={<AttackFindings />} />
            <Route path="/reports"          element={<Reports />} />
            <Route path="/attack/reports"   element={<AttackReports />} />
            <Route path="/schedule"         element={<Schedule />} />
            <Route path="/attack/schedule"  element={<AttackSchedule />} />
            <Route path="/historical"       element={<Historical />} />
            <Route path="/attack/historical" element={<AttackHistorical />} />
            <Route path="/"                 element={<Navigate to="/dashboard" replace />} />
            <Route path="*"                 element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Routes>
      </Router>
    </ModeProvider>
  );
}

export default App;
