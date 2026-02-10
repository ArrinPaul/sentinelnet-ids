import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export default function PolicyBlock({ policy }) {
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
    CRITICAL: 'border-red-500/30 bg-red-500/5',
    HIGH: 'border-orange-500/30 bg-orange-500/5',
    MEDIUM: 'border-amber-500/30 bg-amber-500/5',
    LOW: 'border-blue-500/30 bg-blue-500/5',
  };

  return (
    <div
      className={`border rounded-xl overflow-hidden ${
        severityColors[policy.trigger_alert] || 'border-gray-800 bg-gray-900'
      }`}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800/50">
        <div className="flex items-center gap-3">
          <span className="text-xs font-bold uppercase tracking-wider text-gray-400">
            Policy #{policy.id}
          </span>
          <span
            className={`text-xs font-bold px-2 py-0.5 rounded-full ${
              policy.trigger_alert === 'CRITICAL'
                ? 'bg-red-500/20 text-red-400'
                : policy.trigger_alert === 'HIGH'
                ? 'bg-orange-500/20 text-orange-400'
                : 'bg-amber-500/20 text-amber-400'
            }`}
          >
            {policy.trigger_alert}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">
            {new Date(policy.timestamp).toLocaleString()}
          </span>
          <button
            onClick={copyToClipboard}
            className="p-1.5 rounded-md hover:bg-gray-700/50 text-gray-400 hover:text-white transition-colors"
            title="Copy ACL commands"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* ACL Rules */}
      <div className="p-4">
        <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
          ACL Rules — Target: {policy.src_ip}
        </h4>
        <pre className="bg-gray-950 rounded-lg p-3 text-xs font-mono text-emerald-300 overflow-x-auto border border-gray-800">
          {fullText}
        </pre>
      </div>

      {/* Routing Policy */}
      {policy.routing_policy && (
        <div className="px-4 pb-4">
          <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Routing Recommendation
          </h4>
          <p className="text-sm text-gray-300 bg-gray-950 rounded-lg p-3 border border-gray-800">
            {policy.routing_policy.recommendation}
          </p>
          {policy.routing_policy.ospf_cost_change > 0 && (
            <div className="mt-2 flex gap-2">
              <span className="text-xs px-2 py-1 bg-cyan-500/10 text-cyan-400 rounded-md border border-cyan-500/20">
                OSPF Cost → {policy.routing_policy.ospf_cost_change}
              </span>
              {policy.routing_policy.reroute_required && (
                <span className="text-xs px-2 py-1 bg-red-500/10 text-red-400 rounded-md border border-red-500/20">
                  Reroute Required
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
