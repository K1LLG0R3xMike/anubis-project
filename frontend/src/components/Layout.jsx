import React, { useState, useEffect, useCallback } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { useMode } from '../context/ModeContext';

const SCAN_THEME = {
  headerBg:     'rgba(12,14,22,0.88)',
  sidebarBg:    '#11131c',
  bodyBg:       '#0c0e16',
  primary:      '#9aa8ff',
  primaryAlpha: 'rgba(154,168,255,0.12)',
  primaryBorder:'rgba(154,168,255,0.22)',
  activeBg:     '#1d1f2a',
  logoFilter:   'drop-shadow(0 0 6px rgba(59,130,246,0.5))',
  dotGlow:      '0 0 8px #9aa8ff',
  borderColor:  'rgba(116,117,127,0.12)',
};

const ATTACK_THEME = {
  headerBg:     'rgba(20,5,5,0.92)',
  sidebarBg:    '#0d0303',
  bodyBg:       '#1f0f0f',
  primary:      '#FF3131',
  primaryAlpha: 'rgba(255,49,49,0.12)',
  primaryBorder:'rgba(255,49,49,0.28)',
  activeBg:     'rgba(255,49,49,0.1)',
  logoFilter:   'drop-shadow(0 0 6px rgba(255,49,49,0.7)) sepia(1) saturate(5) hue-rotate(310deg) brightness(0.8)',
  dotGlow:      '0 0 8px #FF3131',
  borderColor:  'rgba(255,49,49,0.12)',
};

export default function Layout({ children }) {
  const location = useLocation();
  const navigate  = useNavigate();
  const { isAttack, toggleMode } = useMode();
  const [targetCount, setTargetCount] = useState(0);
  const [switching, setSwitching]     = useState(false);

  const T = isAttack ? ATTACK_THEME : SCAN_THEME;

  // Change body background when mode switches
  useEffect(() => {
    document.body.style.backgroundColor = T.bodyBg;
    return () => { document.body.style.backgroundColor = ''; };
  }, [T.bodyBg]);

  useEffect(() => {
    axios.get(`http://127.0.0.1:8000/targets/?nocache=${Date.now()}`)
      .then(r => setTargetCount(r.data.length))
      .catch(() => {});
    const iv = setInterval(() => {
      axios.get(`http://127.0.0.1:8000/targets/?nocache=${Date.now()}`)
        .then(r => setTargetCount(r.data.length))
        .catch(() => {});
    }, 10000);
    return () => clearInterval(iv);
  }, []);

  // Route mirroring: scan ↔ attack for every page
  const ROUTE_MAP = {
    '/dashboard':         '/attack/dashboard',
    '/attack/dashboard':  '/dashboard',
    '/targets':           '/attack/targets',
    '/attack/targets':    '/targets',
    '/findings':          '/attack/findings',
    '/attack/findings':   '/findings',
    '/reports':           '/attack/reports',
    '/attack/reports':    '/reports',
    '/schedule':          '/attack/schedule',
    '/attack/schedule':   '/schedule',
    '/historical':        '/attack/historical',
    '/attack/historical': '/historical',
  };

  const handleLogoClick = useCallback(() => {
    if (switching) return;
    setSwitching(true);
    setTimeout(() => {
      toggleMode();
      setSwitching(false);
      const target = ROUTE_MAP[location.pathname];
      if (target) navigate(target);
    }, 320);
  }, [switching, toggleMode, location.pathname, navigate]);

  const scanNav = [
    { name: 'Dashboard', path: '/dashboard',  icon: 'dashboard'      },
    { name: 'Targets',   path: '/targets',    icon: 'radar'          },
    { name: 'Findings',  path: '/findings',   icon: 'security'       },
    { name: 'Historical',path: '/historical', icon: 'history'        },
    { name: 'Reports',   path: '/reports',    icon: 'assessment'     },
    { name: 'Schedule',  path: '/schedule',   icon: 'calendar_month' },
  ];

  const attackNav = [
    { name: 'Dashboard', path: '/attack/dashboard',  icon: 'dashboard'      },
    { name: 'Targets',   path: '/attack/targets',    icon: 'radar'          },
    { name: 'Findings',  path: '/attack/findings',   icon: 'security'       },
    { name: 'Historical',path: '/attack/historical', icon: 'history'        },
    { name: 'Reports',   path: '/attack/reports',    icon: 'assessment'     },
    { name: 'Schedule',  path: '/attack/schedule',   icon: 'calendar_month' },
  ];

  const navItems = isAttack ? attackNav : scanNav;

  const isActive = (path) => location.pathname === path;

  const handleLogout = () => {
    localStorage.clear();
    window.location.href = '/login';
  };

  return (
    <div
      className="min-h-screen text-on-surface font-body transition-colors duration-500"
      style={{ backgroundColor: T.bodyBg }}
    >
      {/* ─── TOP APP BAR ────────────────────────────────────────────── */}
      <header
        className="fixed top-0 w-full z-50 flex items-center justify-between px-5 h-16 border-b transition-all duration-500"
        style={{
          backgroundColor: T.headerBg,
          borderColor: T.borderColor,
          backdropFilter: 'blur(14px)',
        }}
      >
        {/* Logo switch */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleLogoClick}
            title={isAttack ? 'Cambiar a Anubis Scan' : 'Cambiar a Anubis Attack'}
            className="relative focus:outline-none select-none"
            style={{ cursor: 'pointer' }}
          >
            <img
              src="/anubis-logo.png"
              alt="Anubis Logo"
              className="w-9 h-9 object-contain transition-all duration-300"
              style={{
                filter: T.logoFilter,
                animation: switching ? 'logoSwitch 0.32s cubic-bezier(0.34,1.56,0.64,1)' : undefined,
              }}
            />
            {/* Mode indicator ring */}
            <span
              className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 transition-all duration-500"
              style={{
                backgroundColor: T.primary,
                borderColor: T.bodyBg,
                boxShadow: T.dotGlow,
                animation: isAttack ? 'pulse-red 2s infinite' : 'pulse-blue 2s infinite',
              }}
            />
          </button>

          <div className="flex flex-col leading-none">
            <span
              className="font-headline text-base font-black italic tracking-tight transition-all duration-500"
              style={{ color: T.primary, textShadow: `${T.primary}60 0 0 8px` }}
            >
              ANUBIS
            </span>
            <span
              className="font-headline text-[11px] font-bold uppercase tracking-[0.18em] transition-all duration-500"
              style={{ color: isAttack ? 'rgba(255,255,255,0.7)' : 'rgba(228,228,240,0.7)' }}
            >
              {isAttack ? 'ATTACK' : 'SCAN'}
            </span>
          </div>
        </div>

        {/* Desktop nav */}
        <nav className="hidden md:flex items-center gap-6">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className="font-label text-xs uppercase tracking-widest transition-colors pb-0.5"
              style={{
                color: isActive(item.path) ? T.primary : 'rgba(228,228,240,0.5)',
                borderBottom: isActive(item.path) ? `2px solid ${T.primary}` : '2px solid transparent',
              }}
            >
              {item.name}
            </Link>
          ))}
        </nav>

        {/* Status badge */}
        <div
          className="flex items-center gap-2 px-3 py-1 rounded-md transition-all duration-500"
          style={{
            background: T.primaryAlpha,
            border: `1px solid ${T.primaryBorder}`,
          }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full transition-all duration-500"
            style={{
              backgroundColor: T.primary,
              boxShadow: T.dotGlow,
              animation: isAttack ? 'pulse-red 2s infinite' : undefined,
            }}
          />
          <span
            className="font-mono text-[0.65rem] tracking-[0.1em] font-medium transition-all duration-500"
            style={{ color: T.primary }}
          >
            CORE ACTIVE
          </span>
        </div>
      </header>

      <div className="flex pt-16">
        {/* ─── SIDEBAR ─────────────────────────────────────────────── */}
        <aside
          className="hidden md:flex flex-col py-6 px-4 h-[calc(100vh-64px)] w-64 fixed left-0 top-16 border-r overflow-y-auto transition-all duration-500"
          style={{
            backgroundColor: T.sidebarBg,
            borderColor: T.borderColor,
          }}
        >
          {/* Profile card */}
          <div
            className="flex items-center gap-3 mb-8 p-3 rounded-xl transition-all duration-500"
            style={{
              background: isAttack ? 'rgba(255,49,49,0.07)' : 'rgba(23,25,35,0.8)',
              border: `1px solid ${T.primaryBorder}`,
            }}
          >
            <div
              className="w-10 h-10 rounded-full flex items-center justify-center transition-all duration-500"
              style={{
                background: T.primaryAlpha,
                border: `1px solid ${T.primaryBorder}`,
              }}
            >
              <span
                className="material-symbols-outlined"
                style={{ fontSize: 20, color: T.primary }}
              >
                {isAttack ? 'security' : 'hub'}
              </span>
            </div>
            <div>
              <p className="font-headline font-bold text-sm transition-all duration-500"
                 style={{ color: T.primary }}>
                Security Analyst
              </p>
              <p className="font-mono text-[0.65rem] text-on-surface-variant">
                targets: {targetCount}
              </p>
            </div>
          </div>

          <p className="font-mono text-[0.6rem] text-on-surface-variant uppercase tracking-[0.18em] px-2 mb-3">
            navigation
          </p>

          <nav className="space-y-1 flex-grow">
            {navItems.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                className="flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 font-label text-sm"
                style={
                  isActive(item.path)
                    ? { background: T.activeBg, color: T.primary, fontWeight: 600 }
                    : { color: 'rgba(228,228,240,0.6)' }
                }
                onMouseEnter={e => {
                  if (!isActive(item.path)) e.currentTarget.style.background = T.activeBg;
                }}
                onMouseLeave={e => {
                  if (!isActive(item.path)) e.currentTarget.style.background = '';
                }}
              >
                <span className="material-symbols-outlined">{item.icon}</span>
                <span>{item.name}</span>
              </Link>
            ))}
          </nav>

          <div className="mt-4">
            <button
              onClick={handleLogout}
              className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-error text-xs font-medium uppercase tracking-[0.05em] hover:bg-error/10 transition-colors"
            >
              <span className="material-symbols-outlined" style={{ fontSize: 16 }}>logout</span>
              Cerrar Sesión
            </button>
          </div>

          <p className="font-mono text-[0.6rem] text-outline px-2 mt-4">v1.2 · kali_env</p>
        </aside>

        {/* ─── MAIN CONTENT ────────────────────────────────────────── */}
        <main
          className="flex-1 md:ml-64 min-h-[calc(100vh-64px)] overflow-y-auto transition-all duration-500"
          style={{
            animation: switching ? 'modeFlash 0.35s ease-out' : undefined,
          }}
        >
          {children}
        </main>
      </div>

      {/* ─── BOTTOM NAV (Mobile) ─────────────────────────────────── */}
      <nav
        className="md:hidden fixed bottom-0 w-full z-50 flex justify-around items-center px-2 h-16 border-t"
        style={{
          backgroundColor: T.headerBg,
          borderColor: T.borderColor,
          backdropFilter: 'blur(14px)',
        }}
      >
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className="flex flex-col items-center justify-center gap-0.5 transition-all"
            style={{ color: isActive(item.path) ? T.primary : 'rgba(228,228,240,0.4)' }}
          >
            <span className="material-symbols-outlined text-lg">{item.icon}</span>
            <span className="font-mono text-[0.5rem] uppercase tracking-widest">{item.name}</span>
          </Link>
        ))}
      </nav>
    </div>
  );
}
