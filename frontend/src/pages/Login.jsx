import React, { useState } from 'react';
import axios from 'axios';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await axios.post('http://127.0.0.1:8000/login', {
        username,
        password
      });

      if (response.data.token) {
        localStorage.setItem('userToken', response.data.token);
        window.location.href = '/dashboard';
      }
    } catch (error) {
      console.error('Error de login:', error);
      alert('Acceso denegado: Credenciales incorrectas.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-background overflow-hidden"
      style={{
        backgroundImage: `
          radial-gradient(ellipse at 50% 0%, rgba(154, 168, 255, 0.08), transparent 60%),
          radial-gradient(ellipse at 50% 100%, rgba(154, 168, 255, 0.04), transparent 50%)
        `
      }}
    >
      {/* Grid background */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage: `
            linear-gradient(rgba(70,71,81,0.08) 1px, transparent 1px),
            linear-gradient(90deg, rgba(70,71,81,0.08) 1px, transparent 1px)
          `,
          backgroundSize: '32px 32px'
        }}
      />

      <div
        className="relative w-[90%] max-w-md rounded-2xl p-8 sm:p-10"
        style={{
          backgroundColor: '#1d1f2a',
          border: '1px solid rgba(70,71,81,0.3)',
          boxShadow: '0 24px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(154,168,255,0.04), inset 0 1px 0 rgba(255,255,255,0.04)'
        }}
      >
        {/* Header row */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center"
              style={{ backgroundColor: 'rgba(154,168,255,0.1)', border: '1px solid rgba(154,168,255,0.2)' }}>
              <span className="material-symbols-outlined text-primary" style={{ fontSize: 20 }}>hub</span>
            </div>
            <span className="font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.15em]">
              auth_module
            </span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1 rounded-md"
            style={{ backgroundColor: 'rgba(154,168,255,0.08)', border: '1px solid rgba(154,168,255,0.2)' }}>
            <span className="w-1.5 h-1.5 rounded-full bg-primary"
              style={{ boxShadow: '0 0 8px #9aa8ff' }} />
            <span className="font-mono text-[0.65rem] text-primary tracking-[0.1em] font-medium">ONLINE</span>
          </div>
        </div>

        {/* Headline */}
        <h1 className="font-headline text-[2rem] font-bold text-on-surface leading-tight tracking-tight">
          ANUBIS{' '}
          <span className="text-primary">ENGINE</span>
        </h1>
        <p className="mt-2 mb-8 font-body text-xs text-on-surface-variant uppercase tracking-[0.18em]">
          Security Management Systems · v1.2
        </p>

        <form onSubmit={handleLogin} className="space-y-1">
          {/* Username */}
          <label className="block font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.2em] mb-1.5 mt-2">
            › usuario
          </label>
          <input
            type="text"
            placeholder="operator_name"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            className="w-full rounded-lg px-4 py-3 text-sm font-body text-on-surface bg-surface-container-lowest
              outline-none transition-colors
              border border-outline-variant/30 hover:border-outline-variant/60
              focus:border-primary"
          />

          {/* Password */}
          <label className="block font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.2em] mb-1.5 mt-4">
            › contraseña
          </label>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full rounded-lg px-4 py-3 pr-12 text-sm font-body text-on-surface bg-surface-container-lowest
                outline-none transition-colors
                border border-outline-variant/30 hover:border-outline-variant/60
                focus:border-primary"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-primary transition-colors"
              tabIndex={-1}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 20 }}>
                {showPassword ? 'visibility_off' : 'visibility'}
              </span>
            </button>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-8 py-4 rounded-xl font-body font-bold text-sm uppercase tracking-[0.05em]
              bg-primary text-on-primary transition-all duration-200
              hover:bg-primary-dim hover:-translate-y-px active:translate-y-0
              disabled:opacity-50 disabled:cursor-not-allowed disabled:translate-y-0"
            style={{ boxShadow: '0 8px 24px rgba(154,168,255,0.2)' }}
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <span className="w-4 h-4 rounded-full border-2 border-on-primary border-t-transparent animate-spin" />
                Autenticando...
              </span>
            ) : (
              '› Iniciar Sesión'
            )}
          </button>
        </form>

        {/* Footer */}
        <div className="mt-8 pt-6 flex justify-between items-center"
          style={{ borderTop: '1px solid rgba(70,71,81,0.15)' }}>
          <span className="font-mono text-[0.65rem] text-on-surface-variant uppercase tracking-[0.12em]">
            kali_env · secure_access
          </span>
          <span className="font-mono text-[0.65rem] text-outline tracking-[0.1em]">v1.2</span>
        </div>
      </div>
    </div>
  );
};

export default Login;
