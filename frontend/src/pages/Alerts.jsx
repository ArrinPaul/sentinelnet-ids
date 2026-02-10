import { useEffect, useState } from 'react';
import { ShieldAlert, Filter } from 'lucide-react';
import AlertTable from '../components/AlertTable';
import { getAlertHistory } from '../services/api';

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');

  const fetchData = async () => {
    try {
      const { data } = await getAlertHistory(100);
      setAlerts(data.alerts || []);
    } catch (err) {
      console.error('Alert fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const filteredAlerts =
    filter === 'ALL' ? alerts : alerts.filter((a) => a.severity === filter);

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
          <h1 className="text-2xl font-bold tracking-tight">Intrusion Alerts</h1>
          <p className="text-sm text-gray-500 mt-1">
            {alerts.length} total alerts detected
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-500" />
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((level) => (
            <button
              key={level}
              onClick={() => setFilter(level)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
                filter === level
                  ? level === 'CRITICAL'
                    ? 'bg-red-500/20 text-red-400 border-red-500/30'
                    : level === 'HIGH'
                    ? 'bg-orange-500/20 text-orange-400 border-orange-500/30'
                    : level === 'MEDIUM'
                    ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                    : level === 'LOW'
                    ? 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                    : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                  : 'bg-gray-800/50 text-gray-400 border-gray-700 hover:border-gray-600'
              }`}
            >
              {level}
            </button>
          ))}
        </div>
      </div>

      {/* Alert Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
          const count = alerts.filter((a) => a.severity === sev).length;
          const colors = {
            CRITICAL: 'border-red-500/20 bg-red-500/5 text-red-400',
            HIGH: 'border-orange-500/20 bg-orange-500/5 text-orange-400',
            MEDIUM: 'border-amber-500/20 bg-amber-500/5 text-amber-400',
            LOW: 'border-blue-500/20 bg-blue-500/5 text-blue-400',
          };
          return (
            <div
              key={sev}
              className={`p-4 rounded-xl border ${colors[sev]} cursor-pointer hover:scale-[1.02] transition-transform`}
              onClick={() => setFilter(sev)}
            >
              <p className="text-3xl font-bold">{count}</p>
              <p className="text-xs uppercase tracking-wider opacity-70 mt-1">{sev}</p>
            </div>
          );
        })}
      </div>

      {/* Alert Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xs uppercase tracking-widest text-gray-400 font-semibold">
            <ShieldAlert className="w-4 h-4 inline mr-2" />
            Alert Log ({filteredAlerts.length} shown)
          </h3>
        </div>
        <AlertTable alerts={filteredAlerts} />
      </div>
    </div>
  );
}
