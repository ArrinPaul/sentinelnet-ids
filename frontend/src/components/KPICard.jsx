import { motion } from 'motion/react';

export default function KPICard({ title, value, subtitle, icon: Icon, color = 'accent', index = 0 }) {
  const colorMap = {
    accent: {
      gradient: 'linear-gradient(135deg, rgba(0,229,160,0.12) 0%, rgba(0,229,160,0.03) 100%)',
      border: 'rgba(0,229,160,0.15)',
      iconColor: 'var(--color-accent)',
      valueColor: 'var(--color-accent)',
    },
    danger: {
      gradient: 'linear-gradient(135deg, rgba(255,59,92,0.12) 0%, rgba(255,59,92,0.03) 100%)',
      border: 'rgba(255,59,92,0.15)',
      iconColor: 'var(--color-danger)',
      valueColor: 'var(--color-danger)',
    },
    warning: {
      gradient: 'linear-gradient(135deg, rgba(255,176,32,0.12) 0%, rgba(255,176,32,0.03) 100%)',
      border: 'rgba(255,176,32,0.15)',
      iconColor: 'var(--color-warning)',
      valueColor: 'var(--color-warning)',
    },
    info: {
      gradient: 'linear-gradient(135deg, rgba(56,160,255,0.12) 0%, rgba(56,160,255,0.03) 100%)',
      border: 'rgba(56,160,255,0.15)',
      iconColor: 'var(--color-info)',
      valueColor: 'var(--color-info)',
    },
    purple: {
      gradient: 'linear-gradient(135deg, rgba(168,85,247,0.12) 0%, rgba(168,85,247,0.03) 100%)',
      border: 'rgba(168,85,247,0.15)',
      iconColor: 'var(--color-purple)',
      valueColor: 'var(--color-purple)',
    },
  };

  const c = colorMap[color] || colorMap.accent;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.08 }}
      className="rounded-xl p-5 relative overflow-hidden group"
      style={{
        background: c.gradient,
        border: `1px solid ${c.border}`,
      }}
    >
      {/* Subtle corner accent */}
      <div className="absolute top-0 right-0 w-20 h-20 opacity-[0.04]"
        style={{
          background: `radial-gradient(circle at top right, ${c.iconColor}, transparent 70%)`,
        }}
      />

      <div className="flex items-start justify-between mb-3 relative z-10">
        <span className="text-[11px] uppercase tracking-[0.12em] font-semibold"
          style={{ color: 'var(--color-text-muted)' }}
        >
          {title}
        </span>
        {Icon && (
          <div className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: `${c.iconColor}15` }}
          >
            <Icon className="w-4 h-4" style={{ color: c.iconColor }} />
          </div>
        )}
      </div>

      <div className="relative z-10">
        <div className="text-[28px] font-bold tracking-tight leading-none"
          style={{ color: c.valueColor }}
        >
          {value}
        </div>
        {subtitle && (
          <p className="text-[11px] mt-2" style={{ color: 'var(--color-text-muted)' }}>
            {subtitle}
          </p>
        )}
      </div>
    </motion.div>
  );
}
