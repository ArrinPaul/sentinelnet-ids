const severityColors = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/30',
  HIGH: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  LOW: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

export default function AlertTable({ alerts, showFilter = true }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 text-gray-500 uppercase text-xs tracking-wider">
            <th className="text-left py-3 px-4">Time</th>
            <th className="text-left py-3 px-4">Source IP</th>
            <th className="text-left py-3 px-4">Dest IP</th>
            <th className="text-left py-3 px-4">Attack Type</th>
            <th className="text-left py-3 px-4">Severity</th>
            <th className="text-left py-3 px-4">Confidence</th>
          </tr>
        </thead>
        <tbody>
          {alerts.length === 0 ? (
            <tr>
              <td colSpan={6} className="text-center py-8 text-gray-600">
                No alerts detected — system is secure
              </td>
            </tr>
          ) : (
            alerts.map((alert, i) => (
              <tr
                key={i}
                className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
              >
                <td className="py-3 px-4 text-gray-400 font-mono text-xs">
                  {new Date(alert.timestamp).toLocaleTimeString()}
                </td>
                <td className="py-3 px-4 font-mono">{alert.src_ip}</td>
                <td className="py-3 px-4 font-mono text-gray-400">{alert.dst_ip || '—'}</td>
                <td className="py-3 px-4">{alert.attack_type}</td>
                <td className="py-3 px-4">
                  <span
                    className={`inline-block px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                      severityColors[alert.severity] || 'bg-gray-700 text-gray-300'
                    }`}
                  >
                    {alert.severity}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-emerald-500 rounded-full"
                        style={{ width: `${(alert.confidence || 0) * 100}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-500">
                      {((alert.confidence || 0) * 100).toFixed(0)}%
                    </span>
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
