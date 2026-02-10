export default function KPICard({ title, value, subtitle, icon: Icon, color = 'emerald' }) {
  const colorMap = {
    emerald: 'from-emerald-500/20 to-emerald-500/5 border-emerald-500/20 text-emerald-400',
    red: 'from-red-500/20 to-red-500/5 border-red-500/20 text-red-400',
    amber: 'from-amber-500/20 to-amber-500/5 border-amber-500/20 text-amber-400',
    cyan: 'from-cyan-500/20 to-cyan-500/5 border-cyan-500/20 text-cyan-400',
    purple: 'from-purple-500/20 to-purple-500/5 border-purple-500/20 text-purple-400',
  };

  const cls = colorMap[color] || colorMap.emerald;

  return (
    <div
      className={`bg-gradient-to-br ${cls} border rounded-xl p-5 transition-transform hover:scale-[1.02]`}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs uppercase tracking-widest text-gray-400 font-semibold">
          {title}
        </span>
        {Icon && <Icon className="w-5 h-5 opacity-60" />}
      </div>
      <div className="text-3xl font-bold tracking-tight">{value}</div>
      {subtitle && (
        <p className="text-xs text-gray-500 mt-1">{subtitle}</p>
      )}
    </div>
  );
}
