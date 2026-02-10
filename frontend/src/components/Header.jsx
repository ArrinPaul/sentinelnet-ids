import { useEffect, useState } from 'react';
import { Shield, ShieldAlert, ShieldOff, Menu } from 'lucide-react';
import { getSystemStats } from '../services/api';

const modeConfig = {
  SAFE: {
    icon: Shield,
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10 border-emerald-500/30',
    label: 'SECURE',
  },
  WARNING: {
    icon: ShieldAlert,
    color: 'text-amber-400',
    bg: 'bg-amber-500/10 border-amber-500/30',
    label: 'WARNING',
  },
  CRITICAL: {
    icon: ShieldOff,
    color: 'text-red-400',
    bg: 'bg-red-500/10 border-red-500/30 animate-pulse',
    label: 'CRITICAL',
  },
};

export default function Header({ sidebarOpen, setSidebarOpen }) {
  const [mode, setMode] = useState('SAFE');

  useEffect(() => {
    const fetchMode = async () => {
      try {
        const { data } = await getSystemStats();
        setMode(data.security_mode || 'SAFE');
      } catch {
        // Backend not reachable
      }
    };
    fetchMode();
    const interval = setInterval(fetchMode, 3000);
    return () => clearInterval(interval);
  }, []);

  const config = modeConfig[mode] || modeConfig.SAFE;
  const Icon = config.icon;

  return (
    <header className="h-14 bg-gray-900/80 backdrop-blur-sm border-b border-gray-800 flex items-center justify-between px-5">
      <div className="flex items-center gap-3">
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="md:hidden text-gray-400 hover:text-white"
        >
          <Menu className="w-5 h-5" />
        </button>
        <h2 className="text-sm font-semibold text-gray-300 tracking-wide">
          Intelligent Traffic Control & Intrusion Prevention
        </h2>
      </div>

      <div
        className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-bold tracking-wider ${config.bg} ${config.color}`}
      >
        <Icon className="w-3.5 h-3.5" />
        {config.label}
      </div>
    </header>
  );
}
