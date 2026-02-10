import { useState } from 'react';
import { motion } from 'motion/react';
import { Copy, Check, Terminal, Route } from 'lucide-react';

export default function PolicyBlock({ policy, index = 0 }) {
  const [copied, setCopied] = useState(false);

  const aclText = policy.acl_rules?.commands?.join('\n') || 'No ACL rules';
  const interfaceText = policy.acl_rules?.interface_commands?.join('\n') || '';
  const fullText = aclText + '\n' + interfaceText;

  const copyToClipboard = () => {
    navigator.clipboard.writeText(fullText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const severityColors = {
    CRITICAL: { border: 'rgba(255,59,92,0.2)', glow: 'rgba(255,59,92,0.08)', badge: 'var(--color-danger)' },
    HIGH: { border: 'rgba(255,176,32,0.2)', glow: 'rgba(255,176,32,0.08)', badge: 'var(--color-warning)' },
    MEDIUM: { border: 'rgba(229,192,64,0.2)', glow: 'rgba(229,192,64,0.05)', badge: '#e5c040' },
    LOW: { border: 'rgba(56,160,255,0.2)', glow: 'rgba(56,160,255,0.05)', badge: 'var(--color-info)' },
  };

  const sc = severityColors[policy.trigger_alert] || severityColors.MEDIUM;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: index * 0.06 }}
      className="rounded-xl overflow-hidden"
      style={{
        border: `1px solid ${sc.border}`,
        background: `linear-gradient(135deg, ${sc.glow} 0%, transparent 60%)`,
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-5 py-3"
        style={{ borderBottom: `1px solid ${sc.border}` }}
      >
        <div className="flex items-center gap-3">
          <span className="font-mono text-[11px] font-bold" style={{ color: 'var(--color-text-muted)' }}>
            #{policy.id}
          </span>
          <span
            className="text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider"
            style={{ background: `${sc.badge}20`, color: sc.badge, border: `1px solid ${sc.badge}30` }}
          >
            {policy.trigger_alert}
          </span>
          <span className="text-[11px] font-mono" style={{ color: 'var(--color-text-muted)' }}>
            {policy.src_ip}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[11px]" style={{ color: 'var(--color-text-muted)' }}>
            {new Date(policy.timestamp).toLocaleString('en-US', { hour12: false })}
          </span>
          <button
            onClick={copyToClipboard}
            className="p-1.5 rounded-md transition-colors cursor-pointer"
            style={{
              color: copied ? 'var(--color-accent)' : 'var(--color-text-muted)',
              background: copied ? 'var(--color-accent-dim)' : 'transparent',
            }}
            title="Copy ACL commands"
          >
            {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      <div className="p-5 grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* ACL Rules */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Terminal className="w-3.5 h-3.5" style={{ color: 'var(--color-accent)' }} />
            <h4 className="text-[10px] font-bold uppercase tracking-[0.12em]" style={{ color: 'var(--color-text-muted)' }}>
              ACL Configuration
            </h4>
          </div>
          <pre
            className="rounded-lg p-3 text-[11px] font-mono leading-relaxed overflow-x-auto"
            style={{
              background: 'var(--color-midnight)',
              border: '1px solid var(--color-panel-border)',
              color: 'var(--color-accent)',
            }}
          >
            {fullText}
          </pre>
        </div>

        {/* Routing Policy */}
        {policy.routing_policy && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Route className="w-3.5 h-3.5" style={{ color: 'var(--color-info)' }} />
              <h4 className="text-[10px] font-bold uppercase tracking-[0.12em]" style={{ color: 'var(--color-text-muted)' }}>
                Routing Recommendation
              </h4>
            </div>
            <div
              className="rounded-lg p-3 text-[12px] leading-relaxed"
              style={{
                background: 'var(--color-midnight)',
                border: '1px solid var(--color-panel-border)',
                color: 'var(--color-text-secondary)',
              }}
            >
              {policy.routing_policy.recommendation}
            </div>
            {policy.routing_policy.ospf_cost_change > 0 && (
              <div className="mt-3 flex flex-wrap gap-2">
                <span
                  className="text-[10px] font-mono font-bold px-2.5 py-1 rounded"
                  style={{
                    background: 'var(--color-info-dim)',
                    color: 'var(--color-info)',
                    border: '1px solid rgba(56,160,255,0.15)',
                  }}
                >
                  OSPF Cost → {policy.routing_policy.ospf_cost_change}
                </span>
                {policy.routing_policy.reroute_required && (
                  <span
                    className="text-[10px] font-bold px-2.5 py-1 rounded"
                    style={{
                      background: 'var(--color-danger-dim)',
                      color: 'var(--color-danger)',
                      border: '1px solid rgba(255,59,92,0.15)',
                    }}
                  >
                    REROUTE REQUIRED
                  </span>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </motion.div>
  );
}
