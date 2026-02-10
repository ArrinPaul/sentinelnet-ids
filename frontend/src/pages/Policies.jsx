import { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { Shield, FileText } from 'lucide-react';
import PolicyBlock from '../components/PolicyBlock';
import Panel, { PanelHeader } from '../components/Panel';
import { getPolicies } from '../services/api';

export default function Policies() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      const { data } = await getPolicies(50);
      setPolicies(data.policies || []);
    } catch (err) {
      console.error('Policy fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Loading policies...</p>
      </div>
    );
  }

  const severityCounts = policies.reduce((acc, p) => {
    const sev = p.severity || 'UNKNOWN';
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const summaryCards = [
    { label: 'Total Policies', value: policies.length, color: 'var(--color-accent)' },
    { label: 'Critical', value: severityCounts['CRITICAL'] || 0, color: 'var(--color-danger)' },
    { label: 'High', value: severityCounts['HIGH'] || 0, color: '#ff6b35' },
    { label: 'Medium / Low', value: (severityCounts['MEDIUM'] || 0) + (severityCounts['LOW'] || 0), color: '#ffb020' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--color-text-primary)' }}>
          Security Policies
        </h1>
        <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
          Auto-generated ACL and routing rules from threat analysis
        </p>
      </motion.div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {summaryCards.map((card, i) => (
          <motion.div
            key={card.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.05 * i }}
            className="rounded-xl p-4"
            style={{
              background: 'var(--color-panel)',
              border: '1px solid var(--color-panel-border)',
            }}
          >
            <p className="text-[10px] uppercase tracking-[0.1em] font-bold mb-2" style={{ color: 'var(--color-text-muted)' }}>
              {card.label}
            </p>
            <p className="text-2xl font-bold font-mono" style={{ color: card.value > 0 ? card.color : 'var(--color-text-muted)' }}>
              {card.value}
            </p>
          </motion.div>
        ))}
      </div>

      {/* Policy List */}
      {policies.length > 0 ? (
        <Panel delay={0.15} noPad>
          <div className="p-5 pb-0">
            <PanelHeader icon={Shield} title="Active Policies" />
          </div>
          <div className="p-4 space-y-3">
            {policies.map((policy, i) => (
              <motion.div
                key={policy.alert_id || i}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.03 * i }}
              >
                <PolicyBlock policy={policy} />
              </motion.div>
            ))}
          </div>
        </Panel>
      ) : (
        <Panel delay={0.15}>
          <div className="flex flex-col items-center justify-center py-16 gap-4">
            <div className="p-4 rounded-xl" style={{ background: 'var(--color-accent-dim)' }}>
              <FileText className="w-8 h-8" style={{ color: 'var(--color-accent)' }} />
            </div>
            <div className="text-center">
              <p className="text-sm font-medium" style={{ color: 'var(--color-text-primary)' }}>
                No policies generated yet
              </p>
              <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
                Policies are auto-generated when threats are detected. Simulate traffic to trigger detection.
              </p>
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}
