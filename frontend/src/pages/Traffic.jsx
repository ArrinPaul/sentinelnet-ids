import { useEffect, useState } from 'react';
import { Activity, Zap, Send } from 'lucide-react';
import { PacketRateChart, ProtocolChart } from '../components/TrafficChart';
import { getRecentTraffic, simulateTraffic } from '../services/api';

export default function Traffic() {
  const [traffic, setTraffic] = useState([]);
  const [loading, setLoading] = useState(true);
  const [simMode, setSimMode] = useState('random');

  const fetchData = async () => {
    try {
      const { data } = await getRecentTraffic(50);
      setTraffic(data.records || []);
    } catch (err) {
      console.error('Traffic fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulate = async () => {
    try {
      await simulateTraffic(simMode, 5);
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
          <h1 className="text-2xl font-bold tracking-tight">Traffic Monitor</h1>
          <p className="text-sm text-gray-500 mt-1">
            Real-time network traffic analysis — {traffic.length} records
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={simMode}
            onChange={(e) => setSimMode(e.target.value)}
            className="bg-gray-800 border border-gray-700 text-gray-300 text-xs rounded-lg px-3 py-2 focus:border-emerald-500 focus:outline-none"
          >
            <option value="random">Random Mix</option>
            <option value="normal">Normal Only</option>
            <option value="port_scan">Port Scan</option>
            <option value="flood">Flood Attack</option>
            <option value="anomaly">Protocol Anomaly</option>
          </select>
          <button
            onClick={handleSimulate}
            className="flex items-center gap-2 px-4 py-2 text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-lg hover:bg-emerald-500/20 transition-colors"
          >
            <Send className="w-3.5 h-3.5" />
            Simulate Traffic
          </button>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h3 className="text-xs uppercase tracking-widest text-gray-400 font-semibold mb-4">
            <Activity className="w-4 h-4 inline mr-2" />
            Packet Rate Over Time
          </h3>
          <PacketRateChart data={traffic.slice().reverse()} />
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h3 className="text-xs uppercase tracking-widest text-gray-400 font-semibold mb-4">
            <Zap className="w-4 h-4 inline mr-2" />
            Protocol Distribution
          </h3>
          <ProtocolChart data={traffic} />
        </div>
      </div>

      {/* Traffic Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h3 className="text-xs uppercase tracking-widest text-gray-400 font-semibold mb-4">
          Recent Traffic Records
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 uppercase text-xs tracking-wider">
                <th className="text-left py-3 px-4">Time</th>
                <th className="text-left py-3 px-4">Source</th>
                <th className="text-left py-3 px-4">Destination</th>
                <th className="text-left py-3 px-4">Protocol</th>
                <th className="text-right py-3 px-4">Packet Rate</th>
                <th className="text-right py-3 px-4">Ports</th>
                <th className="text-right py-3 px-4">Avg Size</th>
                <th className="text-right py-3 px-4">Duration</th>
              </tr>
            </thead>
            <tbody>
              {traffic.map((record, i) => {
                const isHighRate = record.packet_rate > 1000;
                const isHighPorts = record.unique_ports > 15;
                return (
                  <tr
                    key={record.id || i}
                    className={`border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${
                      isHighRate || isHighPorts ? 'bg-red-500/5' : ''
                    }`}
                  >
                    <td className="py-2.5 px-4 text-gray-400 font-mono text-xs">
                      {new Date(record.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-xs">{record.src_ip}</td>
                    <td className="py-2.5 px-4 font-mono text-xs text-gray-400">{record.dst_ip}</td>
                    <td className="py-2.5 px-4">
                      <span
                        className={`text-xs font-medium px-2 py-0.5 rounded ${
                          record.protocol === 'TCP'
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : record.protocol === 'UDP'
                            ? 'bg-blue-500/10 text-blue-400'
                            : record.protocol === 'ICMP'
                            ? 'bg-amber-500/10 text-amber-400'
                            : 'bg-purple-500/10 text-purple-400'
                        }`}
                      >
                        {record.protocol}
                      </span>
                    </td>
                    <td
                      className={`py-2.5 px-4 text-right font-mono text-xs ${
                        isHighRate ? 'text-red-400 font-bold' : 'text-gray-300'
                      }`}
                    >
                      {record.packet_rate}
                    </td>
                    <td
                      className={`py-2.5 px-4 text-right font-mono text-xs ${
                        isHighPorts ? 'text-red-400 font-bold' : 'text-gray-300'
                      }`}
                    >
                      {record.unique_ports}
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono text-xs text-gray-300">
                      {record.avg_packet_size}B
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono text-xs text-gray-300">
                      {record.duration}s
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
