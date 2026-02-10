import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ShieldAlert, Filter, Trash2 } from 'lucide-react';
import AlertTable from '../components/AlertTable';
import Panel, { PanelHeader } from '../components/Panel';
import { getAlerts, clearSystem } from '../services/api';

const SEVERITY_FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const severityTheme = {
  CRITICAL: { color: '#ff3b5c', bg: 'rgba(255,59,92,0.12)', border: 'rgba(255,59,92,0.25)' },
  HIGH:     { color: '#ff6b35', bg: 'rgba(255,107,53,0.12)', border: 'rgba(255,107,53,0.25)' },
  MEDIUM:   { color: '#ffb020', bg: 'rgba(255,176,32,0.12)', border: 'rgba(255,176,32,0.25)' },
  LOW:      { color: '#38a0ff', bg: 'rgba(56,160,255,0.12)', border: 'rgba(56,160,255,0.25)' },
};

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');

  const fetchData = async () => {
    try {
      const { data } = await getAlerts(100);
      setAlerts(data.alerts || []);
    } catch (err) {
      console.error('Alerts fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleClear = async () => {
    try {
      await clearSystem();
      setAlerts([]);
    } catch (err) {
      console.error('Clear error:', err);
    }
  };

  const filtered = filter === 'ALL' ? alerts : alerts.filter((a) => a.severity === filter);

  const severityCounts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] || 0) + 1;
    return acc;
  }, {});

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Loading alerts...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col sm:flex-row sm:items-center justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--color-text-primary)' }}>
            Security Alerts
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
            <span className="font-mono">{alerts.length}</span> total alerts —{' '}
            <span className="font-mono">{filtered.length}</span> shown
          </p>
        </div>
        <button
          onClick={handleClear}
          className="flex items-center gap-2 px-3 py-2 text-[11px] font-semibold rounded-lg transition-all cursor-pointer"
          style={{
            background: 'rgba(255,59,92,0.08)',
            color: 'var(--color-danger)',
            border: '1px solid rgba(255,59,92,0.15)',
          }}
        >
          <Trash2 className="w-3.5 h-3.5" />
          Clear All
        </button>
      </motion.div>

      {/* Severity Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {Object.entries(severityTheme).map(([sev, theme], i) => {
          const count = severityCounts[sev] || 0;
          return (
            <motion.button
              key={sev}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.05 * i }}
              onClick={() => setFilter(filter === sev ? 'ALL' : sev)}
              className="rounded-xl p-4 text-left transition-all cursor-pointer"
              style={{
                background: filter === sev ? theme.bg : 'var(--color-panel)',
                border: `1px solid ${filter === sev ? theme.border : 'var(--color-panel-border)'}`,
              }}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] uppercase tracking-[0.1em] font-bold" style={{ color: theme.color }}>
                  {sev}
                </span>
                {filter === sev && (
                  <motion.div layoutId="sev-active" className="w-1.5 h-1.5 rounded-full" style={{ background: theme.color }} />
                )}
              </div>
              <p className="text-xl font-bold font-mono" style={{ color: count > 0 ? theme.color : 'var(--color-text-muted)' }}>
                {count}
              </p>
            </motion.button>
          );
        })}
      </div>

      {/* Filter Bar */}
      <Panel delay={0.15}>
        <div className="flex items-center gap-3 flex-wrap">
          <Filter className="w-4 h-4" style={{ color: 'var(--color-text-muted)' }} />
          {SEVERITY_FILTERS.map((sev) => {
            const isActive = filter === sev;
            const theme = severityTheme[sev];
            return (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className="px-3 py-1.5 rounded-md text-[10px] uppercase tracking-[0.1em] font-bold transition-all cursor-pointer"
                style={{
                  background: isActive ? (theme ? theme.bg : 'var(--color-accent-dim)') : 'transparent',
                  color: isActive ? (theme ? theme.color : 'var(--color-accent)') : 'var(--color-text-muted)',
                  border: `1px solid ${isActive ? (theme ? theme.border : 'rgba(0,229,160,0.2)') : 'transparent'}`,
                }}
              >
                {sev}
              </button>
            );
          })}
          <span className="ml-auto text-[10px] font-mono" style={{ color: 'var(--color-text-muted)' }}>
            {filtered.length} result{filtered.length !== 1 ? 's' : ''}
          </span>
        </div>
      </Panel>

      {/* Alert Table */}
      <Panel delay={0.2} noPad>
        <div className="p-5 pb-0">
          <PanelHeader icon={ShieldAlert} title="Alert Log" />
        </div>
        <AlertTable alerts={filtered} />
      </Panel>
    </div>
  );
}
