import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ChevronDown, ChevronUp } from 'lucide-react';

const severityStyles = {
  CRITICAL: {
    badge: { background: 'rgba(255,59,92,0.15)', color: 'var(--color-danger)', border: '1px solid rgba(255,59,92,0.25)' },
    row: 'rgba(255,59,92,0.03)',
  },
  HIGH: {
    badge: { background: 'rgba(255,176,32,0.15)', color: 'var(--color-warning)', border: '1px solid rgba(255,176,32,0.25)' },
    row: 'rgba(255,176,32,0.03)',
  },
  MEDIUM: {
    badge: { background: 'rgba(229,192,64,0.15)', color: '#e5c040', border: '1px solid rgba(229,192,64,0.25)' },
    row: 'rgba(229,192,64,0.02)',
  },
  LOW: {
    badge: { background: 'rgba(56,160,255,0.15)', color: 'var(--color-info)', border: '1px solid rgba(56,160,255,0.25)' },
    row: 'transparent',
  },
};

function AlertRow({ alert, index }) {
  const [expanded, setExpanded] = useState(false);
  const style = severityStyles[alert.severity] || severityStyles.LOW;

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.25, delay: index * 0.03 }}
    >
      <div
        className="grid items-center gap-4 px-4 py-3 cursor-pointer transition-colors"
        style={{
          gridTemplateColumns: '100px 1fr 1fr 1fr 90px 100px 40px',
          background: expanded ? 'var(--color-panel-hover)' : style.row,
          borderBottom: '1px solid var(--color-panel-border)',
        }}
        onClick={() => setExpanded(!expanded)}
        onMouseEnter={(e) => { if (!expanded) e.currentTarget.style.background = 'var(--color-panel-hover)'; }}
        onMouseLeave={(e) => { if (!expanded) e.currentTarget.style.background = style.row; }}
      >
        <span className="font-mono text-[11px]" style={{ color: 'var(--color-text-muted)' }}>
          {new Date(alert.timestamp).toLocaleTimeString('en-US', { hour12: false })}
        </span>
        <span className="font-mono text-[12px]" style={{ color: 'var(--color-text-primary)' }}>
          {alert.src_ip}
        </span>
        <span className="font-mono text-[12px]" style={{ color: 'var(--color-text-secondary)' }}>
          {alert.dst_ip || '—'}
        </span>
        <span className="text-[12px] font-medium" style={{ color: 'var(--color-text-primary)' }}>
          {alert.attack_type}
        </span>
        <span
          className="inline-flex items-center justify-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
          style={style.badge}
        >
          {alert.severity}
        </span>
        <div className="flex items-center gap-2">
          <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--color-panel-border)' }}>
            <motion.div
              className="h-full rounded-full"
              style={{ background: 'var(--color-accent)' }}
              initial={{ width: 0 }}
              animate={{ width: `${(alert.confidence || 0) * 100}%` }}
              transition={{ duration: 0.5, delay: index * 0.03 }}
            />
          </div>
          <span className="text-[10px] font-mono" style={{ color: 'var(--color-text-muted)' }}>
            {((alert.confidence || 0) * 100).toFixed(0)}%
          </span>
        </div>
        <div className="flex justify-center">
          {expanded
            ? <ChevronUp className="w-3.5 h-3.5" style={{ color: 'var(--color-text-muted)' }} />
            : <ChevronDown className="w-3.5 h-3.5" style={{ color: 'var(--color-text-muted)' }} />}
        </div>
      </div>

      {/* Expandable detail */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
            style={{ background: 'var(--color-panel-light)', borderBottom: '1px solid var(--color-panel-border)' }}
          >
            <div className="px-6 py-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-[12px]">
              <div>
                <span className="text-[10px] uppercase tracking-wider block mb-1" style={{ color: 'var(--color-text-muted)' }}>
                  Action
                </span>
                <span style={{ color: 'var(--color-text-primary)' }}>{alert.recommended_action}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase tracking-wider block mb-1" style={{ color: 'var(--color-text-muted)' }}>
                  Rule IDS
                </span>
                <span style={{ color: alert.rule_triggered ? 'var(--color-warning)' : 'var(--color-text-secondary)' }}>
                  {alert.rule_triggered ? `Triggered (${alert.rules_matched || 1} rules)` : 'Not triggered'}
                </span>
              </div>
              <div>
                <span className="text-[10px] uppercase tracking-wider block mb-1" style={{ color: 'var(--color-text-muted)' }}>
                  ML IDS
                </span>
                <span style={{ color: alert.ml_triggered ? 'var(--color-info)' : 'var(--color-text-secondary)' }}>
                  {alert.ml_triggered ? `Anomaly (score: ${alert.ml_detail?.score || 'N/A'})` : 'Normal'}
                </span>
              </div>
              <div>
                <span className="text-[10px] uppercase tracking-wider block mb-1" style={{ color: 'var(--color-text-muted)' }}>
                  Traffic ID
                </span>
                <span className="font-mono" style={{ color: 'var(--color-text-secondary)' }}>
                  {alert.traffic_id || 'N/A'}
                </span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function AlertTable({ alerts }) {
  return (
    <div className="overflow-x-auto">
      {/* Table header */}
      <div
        className="grid items-center gap-4 px-4 py-2.5 text-[10px] uppercase tracking-[0.12em] font-semibold"
        style={{
          gridTemplateColumns: '100px 1fr 1fr 1fr 90px 100px 40px',
          color: 'var(--color-text-muted)',
          borderBottom: '1px solid var(--color-panel-border)',
        }}
      >
        <span>Time</span>
        <span>Source IP</span>
        <span>Dest IP</span>
        <span>Attack Type</span>
        <span>Severity</span>
        <span>Confidence</span>
        <span></span>
      </div>

      {/* Table body */}
      {alerts.length === 0 ? (
        <div className="text-center py-12" style={{ color: 'var(--color-text-muted)' }}>
          <div className="w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3"
            style={{ background: 'var(--color-accent-dim)' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
              <path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"
                stroke="currentColor" strokeWidth="1.5"/>
              <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <p className="text-sm font-medium">No alerts detected</p>
          <p className="text-xs mt-1">Network perimeter is secure</p>
        </div>
      ) : (
        alerts.map((alert, i) => (
          <AlertRow key={alert.traffic_id || i} alert={alert} index={i} />
        ))
      )}
    </div>
  );
}
