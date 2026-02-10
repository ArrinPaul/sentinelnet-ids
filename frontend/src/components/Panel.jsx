import { motion } from 'motion/react';

/**
 * Consistent panel wrapper for all dashboard cards.
 */
export default function Panel({ children, className = '', delay = 0, noPad = false }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      className={`rounded-xl ${noPad ? '' : 'p-5'} ${className}`}
      style={{
        background: 'var(--color-panel)',
        border: '1px solid var(--color-panel-border)',
      }}
    >
      {children}
    </motion.div>
  );
}

export function PanelHeader({ icon: Icon, title, right }) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-2">
        {Icon && <Icon className="w-4 h-4" style={{ color: 'var(--color-accent)' }} />}
        <h3 className="text-[11px] uppercase tracking-[0.12em] font-bold"
          style={{ color: 'var(--color-text-muted)' }}
        >
          {title}
        </h3>
      </div>
      {right}
    </div>
  );
}
