import { useEffect, useState } from 'react';
import { FileCode, RefreshCw } from 'lucide-react';
import PolicyBlock from '../components/PolicyBlock';
import { getGeneratedPolicies } from '../services/api';

export default function Policies() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const { data } = await getGeneratedPolicies(50);
      setPolicies(data.policies || []);
    } catch (err) {
      console.error('Policy fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

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
          <h1 className="text-2xl font-bold tracking-tight">Generated Policies</h1>
          <p className="text-sm text-gray-500 mt-1">
            Cisco IOS-compatible ACL rules and OSPF routing recommendations
          </p>
        </div>
        <button
          onClick={fetchData}
          className="flex items-center gap-2 px-3 py-2 text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700 rounded-lg hover:bg-gray-700 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Policy Count */}
      <div className="flex gap-4">
        <div className="px-4 py-3 bg-purple-500/10 border border-purple-500/20 rounded-xl">
          <p className="text-2xl font-bold text-purple-400">{policies.length}</p>
          <p className="text-xs text-gray-500 uppercase tracking-wider">Total Policies</p>
        </div>
        <div className="px-4 py-3 bg-red-500/10 border border-red-500/20 rounded-xl">
          <p className="text-2xl font-bold text-red-400">
            {policies.filter((p) => p.trigger_alert === 'CRITICAL').length}
          </p>
          <p className="text-xs text-gray-500 uppercase tracking-wider">Critical Blocks</p>
        </div>
        <div className="px-4 py-3 bg-cyan-500/10 border border-cyan-500/20 rounded-xl">
          <p className="text-2xl font-bold text-cyan-400">
            {policies.filter((p) => p.routing_policy?.reroute_required).length}
          </p>
          <p className="text-xs text-gray-500 uppercase tracking-wider">Reroutes</p>
        </div>
      </div>

      {/* Policies List */}
      {policies.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
          <FileCode className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <p className="text-gray-500">No policies generated yet</p>
          <p className="text-xs text-gray-600 mt-1">
            Policies are created automatically when intrusions are detected
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {policies.map((policy, i) => (
            <PolicyBlock key={policy.id || i} policy={policy} />
          ))}
        </div>
      )}
    </div>
  );
}
