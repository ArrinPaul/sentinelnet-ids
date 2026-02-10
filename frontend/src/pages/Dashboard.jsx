import { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import {
  Activity,
  ShieldAlert,
  FileCode,
  TrendingUp,
  Radio,
  Zap,
  Send,
} from 'lucide-react';
import KPICard from '../components/KPICard';
import AlertTable from '../components/AlertTable';
import Panel, { PanelHeader } from '../components/Panel';
import { getSystemStats, getCurrentAlerts, simulateTraffic } from '../services/api';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(null);

  const fetchData = async () => {
    try {
      const [statsRes, alertsRes] = await Promise.all([
        getSystemStats(),
        getCurrentAlerts(),
      ]);
      setStats(statsRes.data);
      setAlerts(alertsRes.data.alerts || []);
    } catch (err) {
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulate = async (mode) => {
    setSimulating(mode);
    try {
      await simulateTraffic(mode, 3);
      await fetchData();
    } catch (err) {
      console.error('Simulate error:', err);
    } finally {
      setSimulating(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="text-center">
          <div className="w-12 h-12 rounded-full mx-auto mb-4 flex items-center justify-center"
            style={{ border: '2px solid var(--color-accent)', borderTopColor: 'transparent' }}
          >
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
              className="w-full h-full rounded-full"
              style={{ border: '2px solid var(--color-accent)', borderTopColor: 'transparent' }}
            />
          </div>
          <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
            Initializing control plane...
          </p>
        </div>
      </div>
    );
  }

  const modeColor = stats?.security_mode === 'CRITICAL'
    ? 'var(--color-danger)'
    : stats?.security_mode === 'WARNING'
    ? 'var(--color-warning)'
    : 'var(--color-accent)';

  return (
    <div className="space-y-6">
      {/* Page header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex flex-col sm:flex-row sm:items-center justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--color-text-primary)' }}>
            Dashboard
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
            Real-time network security overview
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {[
            { mode: 'normal', label: 'Normal', color: 'var(--color-accent)' },
            { mode: 'random', label: 'Random Mix', color: 'var(--color-info)' },
            { mode: 'mixed_attack', label: 'Attack', color: 'var(--color-danger)' },
          ].map(({ mode, label, color }) => (
            <button
              key={mode}
              onClick={() => handleSimulate(mode)}
              disabled={simulating !== null}
              className="flex items-center gap-1.5 px-3 py-2 text-[11px] font-semibold rounded-lg transition-all cursor-pointer disabled:opacity-50"
              style={{
                background: `${color}15`,
                color: color,
                border: `1px solid ${color}30`,
              }}
            >
              {simulating === mode ? (
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 0.6, repeat: Infinity, ease: 'linear' }}
                >
                  <Send className="w-3 h-3" />
                </motion.div>
              ) : (
                <Zap className="w-3 h-3" />
              )}
              {label}
            </button>
          ))}
        </div>
      </motion.div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard
          title="Total Traffic"
          value={stats?.total_traffic?.toLocaleString() || '0'}
          subtitle="packets analyzed"
          icon={Activity}
          color="accent"
          index={0}
        />
        <KPICard
          title="Avg Packet Rate"
          value={`${stats?.avg_packet_rate || 0}`}
          subtitle="packets per second"
          icon={TrendingUp}
          color="info"
          index={1}
        />
        <KPICard
          title="Active Alerts"
          value={stats?.total_alerts || 0}
          subtitle={
            stats?.severity_breakdown
              ? `${stats.severity_breakdown.CRITICAL || 0} critical · ${stats.severity_breakdown.HIGH || 0} high`
              : ''
          }
          icon={ShieldAlert}
          color={stats?.total_alerts > 0 ? 'danger' : 'accent'}
          index={2}
        />
        <KPICard
          title="Policies"
          value={stats?.total_policies || 0}
          subtitle="ACL + routing rules"
          icon={FileCode}
          color="purple"
          index={3}
        />
      </div>

      {/* Middle row: Security mode + Severity + Protocol */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Security Mode */}
        <Panel delay={0.2}>
          <PanelHeader icon={Radio} title="Security Mode" />
          <div className="flex items-center gap-5">
            <div className="relative">
              <motion.div
                className="w-16 h-16 rounded-full flex items-center justify-center"
                style={{
                  background: `${modeColor}15`,
                  border: `2px solid ${modeColor}40`,
                }}
                animate={stats?.security_mode === 'CRITICAL' ? { scale: [1, 1.05, 1] } : {}}
                transition={{ duration: 1.5, repeat: Infinity }}
              >
                <Radio className="w-7 h-7" style={{ color: modeColor }} />
              </motion.div>
              {stats?.security_mode === 'CRITICAL' && (
                <motion.div
                  className="absolute inset-0 rounded-full"
                  style={{ border: `2px solid ${modeColor}` }}
                  animate={{ scale: [1, 1.8], opacity: [0.6, 0] }}
                  transition={{ duration: 1.5, repeat: Infinity }}
                />
              )}
            </div>
            <div>
              <p className="text-2xl font-bold" style={{ color: modeColor }}>
                {stats?.security_mode || 'SAFE'}
              </p>
              <p className="text-[11px] mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
                Network threat level
              </p>
            </div>
          </div>
        </Panel>

        {/* Severity Breakdown */}
        <Panel delay={0.25}>
          <PanelHeader title="Severity Breakdown" />
          <div className="space-y-3">
            {[
              { key: 'CRITICAL', color: 'var(--color-danger)' },
              { key: 'HIGH', color: 'var(--color-warning)' },
              { key: 'MEDIUM', color: '#e5c040' },
              { key: 'LOW', color: 'var(--color-info)' },
            ].map(({ key, color }) => {
              const count = stats?.severity_breakdown?.[key] || 0;
              const total = stats?.total_alerts || 1;
              const pct = total > 0 ? (count / total) * 100 : 0;
              return (
                <div key={key} className="flex items-center gap-3">
                  <span className="text-[10px] font-bold uppercase tracking-wider w-16" style={{ color: 'var(--color-text-muted)' }}>
                    {key}
                  </span>
                  <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--color-panel-border)' }}>
                    <motion.div
                      className="h-full rounded-full"
                      style={{ background: color }}
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 0.6, ease: 'easeOut' }}
                    />
                  </div>
                  <span className="text-[11px] font-mono w-8 text-right" style={{ color: 'var(--color-text-secondary)' }}>
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
        </Panel>

        {/* Protocol Distribution */}
        <Panel delay={0.3}>
          <PanelHeader title="Protocol Distribution" />
          <div className="space-y-3">
            {Object.entries(stats?.protocol_distribution || {}).map(([proto, count]) => {
              const total = stats?.total_traffic || 1;
              const pct = (count / total) * 100;
              const colors = { TCP: '#00e5a0', UDP: '#38a0ff', ICMP: '#ffb020' };
              return (
                <div key={proto} className="flex items-center gap-3">
                  <span className="text-[11px] font-mono w-12" style={{ color: 'var(--color-text-muted)' }}>{proto}</span>
                  <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'var(--color-panel-border)' }}>
                    <motion.div
                      className="h-full rounded-full"
                      style={{ background: colors[proto] || 'var(--color-purple)' }}
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 0.6, ease: 'easeOut' }}
                    />
                  </div>
                  <span className="text-[11px] font-mono w-16 text-right" style={{ color: 'var(--color-text-secondary)' }}>
                    {count} <span style={{ color: 'var(--color-text-muted)' }}>({pct.toFixed(0)}%)</span>
                  </span>
                </div>
              );
            })}
            {Object.keys(stats?.protocol_distribution || {}).length === 0 && (
              <p className="text-[11px] text-center py-4" style={{ color: 'var(--color-text-muted)' }}>
                No traffic data yet
              </p>
            )}
          </div>
        </Panel>
      </div>

      {/* Attack types + Top IPs */}
      {(stats?.total_alerts > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Attack Type Breakdown */}
          <Panel delay={0.35}>
            <PanelHeader icon={ShieldAlert} title="Attack Types Detected" />
            <div className="space-y-2">
              {Object.entries(stats?.attack_type_breakdown || {}).map(([type, count]) => (
                <div key={type} className="flex items-center justify-between py-1.5"
                  style={{ borderBottom: '1px solid var(--color-panel-border)' }}
                >
                  <span className="text-[12px] font-medium" style={{ color: 'var(--color-text-primary)' }}>
                    {type}
                  </span>
                  <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded"
                    style={{ background: 'var(--color-danger-dim)', color: 'var(--color-danger)' }}
                  >
                    {count}
                  </span>
                </div>
              ))}
            </div>
          </Panel>

          {/* Top offending IPs */}
          <Panel delay={0.4}>
            <PanelHeader title="Top Offending IPs" />
            <div className="space-y-2">
              {(stats?.top_offending_ips || []).map(({ ip, count }, i) => (
                <div key={ip} className="flex items-center gap-3 py-1.5"
                  style={{ borderBottom: '1px solid var(--color-panel-border)' }}
                >
                  <span className="text-[10px] font-bold w-5 text-center"
                    style={{ color: i === 0 ? 'var(--color-danger)' : 'var(--color-text-muted)' }}
                  >
                    {i + 1}
                  </span>
                  <span className="text-[12px] font-mono flex-1" style={{ color: 'var(--color-text-primary)' }}>
                    {ip}
                  </span>
                  <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded"
                    style={{ background: 'var(--color-warning-dim)', color: 'var(--color-warning)' }}
                  >
                    {count} alerts
                  </span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      )}

      {/* Recent Alerts */}
      <Panel delay={0.45} noPad>
        <div className="p-5 pb-0">
          <PanelHeader icon={ShieldAlert} title="Recent Alerts" />
        </div>
        <AlertTable alerts={alerts.slice(0, 10)} />
      </Panel>
    </div>
  );
}
