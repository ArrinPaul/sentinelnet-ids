import { useEffect, useState } from 'react';
import {
  Activity,
  ShieldAlert,
  FileCode,
  Zap,
  TrendingUp,
  Radio,
} from 'lucide-react';
import KPICard from '../components/KPICard';
import AlertTable from '../components/AlertTable';
import { getSystemStats, getCurrentAlerts, simulateTraffic } from '../services/api';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

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
    try {
      await simulateTraffic(mode, 3);
      fetchData();
    } catch (err) {
      console.error('Simulate error:', err);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">
            Real-time network security overview
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleSimulate('normal')}
            className="px-3 py-2 text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg hover:bg-emerald-500/20 transition-colors"
          >
            + Normal Traffic
          </button>
          <button
            onClick={() => handleSimulate('random')}
            className="px-3 py-2 text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-lg hover:bg-cyan-500/20 transition-colors"
          >
            + Random Mix
          </button>
          <button
            onClick={() => handleSimulate('flood')}
            className="px-3 py-2 text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors"
          >
            + Attack
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard
          title="Total Traffic"
          value={stats?.total_traffic || 0}
          subtitle="packets analyzed"
          icon={Activity}
          color="cyan"
        />
        <KPICard
          title="Avg Packet Rate"
          value={`${stats?.avg_packet_rate || 0} pps`}
          subtitle="packets per second"
          icon={TrendingUp}
          color="emerald"
        />
        <KPICard
          title="Active Alerts"
          value={stats?.total_alerts || 0}
          subtitle={
            stats?.severity_breakdown
              ? `${stats.severity_breakdown.CRITICAL || 0} critical, ${stats.severity_breakdown.HIGH || 0} high`
              : ''
          }
          icon={ShieldAlert}
          color={stats?.total_alerts > 0 ? 'red' : 'emerald'}
        />
        <KPICard
          title="Policies Generated"
          value={stats?.total_policies || 0}
          subtitle="ACL + routing rules"
          icon={FileCode}
          color="purple"
        />
      </div>

      {/* Security Mode + Protocol Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Security Mode */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h3 className="text-xs uppercase tracking-widest text-gray-400 font-semibold mb-4">
            Security Mode
          </h3>
          <div className="flex items-center gap-4">
            <div
              className={`w-16 h-16 rounded-full flex items-center justify-center ${
                stats?.security_mode === 'CRITICAL'
                  ? 'bg-red-500/20 animate-pulse'
                  : stats?.security_mode === 'WARNING'
                  ? 'bg-amber-500/20'
                  : 'bg-emerald-500/20'
              }`}
            >
              <Radio
                className={`w-8 h-8 ${
                  stats?.security_mode === 'CRITICAL'
                    ? 'text-red-400'
                    : stats?.security_mode === 'WARNING'
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              />
            </div>
            <div>
              <p
                className={`text-2xl font-bold ${
                  stats?.security_mode === 'CRITICAL'
                    ? 'text-red-400'
                    : stats?.security_mode === 'WARNING'
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {stats?.security_mode || 'SAFE'}
              </p>
              <p className="text-xs text-gray-500">Network threat level</p>
            </div>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h3 className="text-xs uppercase tracking-widest text-gray-400 font-semibold mb-4">
            Severity Breakdown
          </h3>
          <div className="space-y-3">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
              const count = stats?.severity_breakdown?.[sev] || 0;
              const total = stats?.total_alerts || 1;
              const pct = total > 0 ? (count / total) * 100 : 0;
              const colors = {
                CRITICAL: 'bg-red-500',
                HIGH: 'bg-orange-500',
                MEDIUM: 'bg-amber-500',
                LOW: 'bg-blue-500',
              };
              return (
                <div key={sev} className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 w-16">{sev}</span>
                  <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${colors[sev]} rounded-full transition-all duration-500`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-400 w-8 text-right">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h3 className="text-xs uppercase tracking-widest text-gray-400 font-semibold mb-4">
            Protocol Distribution
          </h3>
          <div className="space-y-3">
            {Object.entries(stats?.protocol_distribution || {}).map(([proto, count]) => {
              const total = stats?.total_traffic || 1;
              const pct = (count / total) * 100;
              const colors = {
                TCP: 'bg-emerald-500',
                UDP: 'bg-blue-500',
                ICMP: 'bg-amber-500',
              };
              return (
                <div key={proto} className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 w-12 font-mono">{proto}</span>
                  <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${colors[proto] || 'bg-purple-500'} rounded-full transition-all duration-500`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-400 w-16 text-right">
                    {count} ({pct.toFixed(0)}%)
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h3 className="text-xs uppercase tracking-widest text-gray-400 font-semibold mb-4">
          Recent Alerts
        </h3>
        <AlertTable alerts={alerts.slice(0, 10)} />
      </div>
    </div>
  );
}
