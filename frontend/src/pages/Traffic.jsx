import { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { Activity, Zap, Send } from 'lucide-react';
import { PacketRateChart, ProtocolChart } from '../components/TrafficChart';
import Panel, { PanelHeader } from '../components/Panel';
import { getRecentTraffic, simulateTraffic } from '../services/api';

export default function Traffic() {
  const [traffic, setTraffic] = useState([]);
  const [loading, setLoading] = useState(true);
  const [simMode, setSimMode] = useState('random');
  const [simulating, setSimulating] = useState(false);

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
    setSimulating(true);
    try {
      await simulateTraffic(simMode, 5);
      await fetchData();
    } catch (err) {
      console.error('Simulate error:', err);
    } finally {
      setSimulating(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Loading traffic data...</p>
      </div>
    );
  }

  const protocolBadgeColors = {
    TCP: { bg: 'rgba(0,229,160,0.12)', color: '#00e5a0', border: 'rgba(0,229,160,0.2)' },
    UDP: { bg: 'rgba(56,160,255,0.12)', color: '#38a0ff', border: 'rgba(56,160,255,0.2)' },
    ICMP: { bg: 'rgba(255,176,32,0.12)', color: '#ffb020', border: 'rgba(255,176,32,0.2)' },
  };
  const defaultBadge = { bg: 'rgba(168,85,247,0.12)', color: '#a855f7', border: 'rgba(168,85,247,0.2)' };

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
            Traffic Monitor
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
            Real-time network traffic analysis — <span className="font-mono">{traffic.length}</span> records
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={simMode}
            onChange={(e) => setSimMode(e.target.value)}
            className="text-[11px] rounded-lg px-3 py-2 cursor-pointer font-medium outline-none"
            style={{
              background: 'var(--color-panel)',
              border: '1px solid var(--color-panel-border)',
              color: 'var(--color-text-secondary)',
            }}
          >
            <option value="random">Random Mix</option>
            <option value="normal">Normal Only</option>
            <option value="port_scan">Port Scan</option>
            <option value="flood">Flood Attack</option>
            <option value="syn_flood">SYN Flood</option>
            <option value="slowloris">Slowloris</option>
            <option value="dns_amplification">DNS Amplification</option>
            <option value="anomaly">Protocol Anomaly</option>
            <option value="mixed_attack">Mixed Attack</option>
          </select>
          <button
            onClick={handleSimulate}
            disabled={simulating}
            className="flex items-center gap-2 px-4 py-2 text-[11px] font-semibold rounded-lg transition-all cursor-pointer disabled:opacity-50"
            style={{
              background: 'var(--color-accent-dim)',
              color: 'var(--color-accent)',
              border: '1px solid rgba(0,229,160,0.2)',
            }}
          >
            {simulating ? (
              <motion.div animate={{ rotate: 360 }} transition={{ duration: 0.6, repeat: Infinity, ease: 'linear' }}>
                <Send className="w-3.5 h-3.5" />
              </motion.div>
            ) : (
              <Send className="w-3.5 h-3.5" />
            )}
            Simulate
          </button>
        </div>
      </motion.div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel delay={0.1}>
          <PanelHeader icon={Activity} title="Packet Rate Over Time" />
          <PacketRateChart data={traffic.slice().reverse()} />
        </Panel>
        <Panel delay={0.15}>
          <PanelHeader icon={Zap} title="Protocol Distribution" />
          <ProtocolChart data={traffic} />
        </Panel>
      </div>

      {/* Traffic Table */}
      <Panel delay={0.2} noPad>
        <div className="p-5 pb-0">
          <PanelHeader title="Recent Traffic Records" />
        </div>
        <div className="overflow-x-auto">
          {/* Header */}
          <div
            className="grid items-center gap-4 px-4 py-2.5 text-[10px] uppercase tracking-[0.12em] font-bold"
            style={{
              gridTemplateColumns: '90px 1fr 1fr 80px 100px 70px 90px 70px',
              color: 'var(--color-text-muted)',
              borderBottom: '1px solid var(--color-panel-border)',
            }}
          >
            <span>Time</span>
            <span>Source</span>
            <span>Destination</span>
            <span>Protocol</span>
            <span className="text-right">Packet Rate</span>
            <span className="text-right">Ports</span>
            <span className="text-right">Avg Size</span>
            <span className="text-right">Duration</span>
          </div>

          {/* Rows */}
          {traffic.map((record, i) => {
            const isHighRate = record.packet_rate > 1000;
            const isHighPorts = record.unique_ports > 15;
            const isSuspicious = isHighRate || isHighPorts;
            const badge = protocolBadgeColors[record.protocol] || defaultBadge;

            return (
              <motion.div
                key={record.id || i}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.015 }}
                className="grid items-center gap-4 px-4 py-2.5 transition-colors"
                style={{
                  gridTemplateColumns: '90px 1fr 1fr 80px 100px 70px 90px 70px',
                  background: isSuspicious ? 'rgba(255,59,92,0.04)' : 'transparent',
                  borderBottom: '1px solid var(--color-panel-border)',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--color-panel-hover)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = isSuspicious ? 'rgba(255,59,92,0.04)' : 'transparent')}
              >
                <span className="font-mono text-[10px]" style={{ color: 'var(--color-text-muted)' }}>
                  {new Date(record.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                </span>
                <span className="font-mono text-[11px]" style={{ color: 'var(--color-text-primary)' }}>
                  {record.src_ip}
                </span>
                <span className="font-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                  {record.dst_ip}
                </span>
                <span
                  className="inline-flex items-center justify-center px-2 py-0.5 rounded text-[10px] font-bold w-fit"
                  style={{ background: badge.bg, color: badge.color, border: `1px solid ${badge.border}` }}
                >
                  {record.protocol}
                </span>
                <span
                  className="text-right font-mono text-[11px]"
                  style={{ color: isHighRate ? 'var(--color-danger)' : 'var(--color-text-primary)', fontWeight: isHighRate ? 700 : 400 }}
                >
                  {record.packet_rate}
                </span>
                <span
                  className="text-right font-mono text-[11px]"
                  style={{ color: isHighPorts ? 'var(--color-danger)' : 'var(--color-text-primary)', fontWeight: isHighPorts ? 700 : 400 }}
                >
                  {record.unique_ports}
                </span>
                <span className="text-right font-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                  {record.avg_packet_size}B
                </span>
                <span className="text-right font-mono text-[11px]" style={{ color: 'var(--color-text-secondary)' }}>
                  {record.duration}s
                </span>
              </motion.div>
            );
          })}

          {traffic.length === 0 && (
            <div className="text-center py-12" style={{ color: 'var(--color-text-muted)' }}>
              <p className="text-sm">No traffic records yet. Simulate some traffic to get started.</p>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
