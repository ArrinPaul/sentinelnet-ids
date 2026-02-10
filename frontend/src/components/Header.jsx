import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Shield, ShieldAlert, ShieldOff, Menu, Wifi, WifiOff } from 'lucide-react';
import { getSystemStats } from '../services/api';

const modeConfig = {
  SAFE: {
    icon: Shield,
    color: 'var(--color-accent)',
    bg: 'var(--color-accent-dim)',
    border: 'rgba(0,229,160,0.2)',
    label: 'SECURE',
  },
  WARNING: {
    icon: ShieldAlert,
    color: 'var(--color-warning)',
    bg: 'var(--color-warning-dim)',
    border: 'rgba(255,176,32,0.2)',
    label: 'WARNING',
  },
  CRITICAL: {
    icon: ShieldOff,
    color: 'var(--color-danger)',
    bg: 'var(--color-danger-dim)',
    border: 'rgba(255,59,92,0.2)',
    label: 'CRITICAL',
  },
};

export default function Header({ sidebarOpen, setSidebarOpen }) {
  const [mode, setMode] = useState('SAFE');
  const [connected, setConnected] = useState(false);
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const fetchMode = async () => {
      try {
        const { data } = await getSystemStats();
        setMode(data.security_mode || 'SAFE');
        setConnected(true);
      } catch {
        setConnected(false);
      }
    };
    fetchMode();
    const interval = setInterval(fetchMode, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const tick = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(tick);
  }, []);

  const config = modeConfig[mode] || modeConfig.SAFE;
  const Icon = config.icon;

  return (
    <header
      className="h-14 flex items-center justify-between px-5 relative z-10"
      style={{
        background: 'rgba(10,22,40,0.8)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid var(--color-panel-border)',
      }}
    >
      <div className="flex items-center gap-4">
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="md:hidden cursor-pointer"
          style={{ color: 'var(--color-text-secondary)' }}
        >
          <Menu className="w-5 h-5" />
        </button>
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold tracking-wide" style={{ color: 'var(--color-text-secondary)' }}>
            Intelligent Traffic Control & Intrusion Prevention
          </h2>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Clock */}
        <span className="text-xs font-mono hidden sm:block" style={{ color: 'var(--color-text-muted)' }}>
          {time.toLocaleTimeString('en-US', { hour12: false })}
        </span>

        {/* Connection status */}
        <div className="flex items-center gap-1.5">
          {connected ? (
            <Wifi className="w-3.5 h-3.5" style={{ color: 'var(--color-accent)' }} />
          ) : (
            <WifiOff className="w-3.5 h-3.5" style={{ color: 'var(--color-danger)' }} />
          )}
          <span className="text-[10px] font-bold uppercase tracking-wider"
            style={{ color: connected ? 'var(--color-accent)' : 'var(--color-danger)' }}
          >
            {connected ? 'LIVE' : 'OFFLINE'}
          </span>
        </div>

        {/* Security mode badge */}
        <AnimatePresence mode="wait">
          <motion.div
            key={mode}
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.8, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold tracking-wider"
            style={{
              background: config.bg,
              color: config.color,
              border: `1px solid ${config.border}`,
              boxShadow: mode === 'CRITICAL' ? `0 0 15px ${config.bg}` : 'none',
            }}
          >
            <Icon className="w-3.5 h-3.5" />
            {config.label}
          </motion.div>
        </AnimatePresence>
      </div>
    </header>
  );
}
