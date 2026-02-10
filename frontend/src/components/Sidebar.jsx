import { NavLink } from 'react-router-dom';
import { motion } from 'motion/react';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  FileCode,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/traffic', icon: Activity, label: 'Traffic' },
  { to: '/alerts', icon: ShieldAlert, label: 'Alerts' },
  { to: '/policies', icon: FileCode, label: 'Policies' },
];

export default function Sidebar({ open, setOpen }) {
  return (
    <aside
      className={`${
        open ? 'w-60' : 'w-[72px]'
      } flex flex-col transition-all duration-300 ease-in-out relative z-20`}
      style={{
        background: 'var(--color-panel)',
        borderRight: '1px solid var(--color-panel-border)',
      }}
    >
      {/* Logo */}
      <div
        className="flex items-center gap-3 px-4 py-5"
        style={{ borderBottom: '1px solid var(--color-panel-border)' }}
      >
        <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 relative"
          style={{
            background: 'linear-gradient(135deg, #00e5a0 0%, #00b8d4 100%)',
            boxShadow: '0 0 20px rgba(0,229,160,0.3)',
          }}
        >
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L22 8V16L12 22L2 16V8L12 2Z" stroke="#060b18" strokeWidth="2" fill="none"/>
            <circle cx="12" cy="12" r="3.5" fill="#060b18"/>
            <path d="M12 8.5V5M12 19V15.5M8.5 12H5M19 12H15.5" stroke="#060b18" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
        </div>
        {open && (
          <motion.div
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <h1 className="text-[15px] font-bold tracking-tight leading-tight"
              style={{ color: 'var(--color-text-primary)' }}
            >
              NetShield
            </h1>
            <p className="text-[10px] uppercase tracking-[0.2em] font-medium"
              style={{ color: 'var(--color-accent)' }}
            >
              IDS Control
            </p>
          </motion.div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1">
        {navItems.map(({ to, icon: Icon, label }, i) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group relative ${
                isActive ? 'active-nav' : ''
              }`
            }
            style={({ isActive }) =>
              isActive
                ? {
                    background: 'var(--color-accent-dim)',
                    color: 'var(--color-accent)',
                    border: '1px solid rgba(0,229,160,0.15)',
                  }
                : {
                    color: 'var(--color-text-secondary)',
                    border: '1px solid transparent',
                  }
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <motion.div
                    layoutId="nav-indicator"
                    className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full"
                    style={{ background: 'var(--color-accent)' }}
                    transition={{ type: 'spring', stiffness: 350, damping: 30 }}
                  />
                )}
                <Icon className="w-[18px] h-[18px] flex-shrink-0" />
                {open && (
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.05 }}
                  >
                    {label}
                  </motion.span>
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* System info at bottom */}
      {open && (
        <div className="px-4 pb-3">
          <div className="rounded-lg p-3" style={{ background: 'var(--color-panel-light)', border: '1px solid var(--color-panel-border)' }}>
            <div className="flex items-center gap-2 mb-1">
              <div className="w-2 h-2 rounded-full" style={{ background: 'var(--color-accent)' }} />
              <span className="text-[10px] uppercase tracking-[0.15em] font-semibold" style={{ color: 'var(--color-text-muted)' }}>
                System Active
              </span>
            </div>
            <p className="text-[10px] font-mono" style={{ color: 'var(--color-text-secondary)' }}>
              v1.0.0 — Control Plane
            </p>
          </div>
        </div>
      )}

      {/* Collapse toggle */}
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center justify-center py-3 transition-colors cursor-pointer"
        style={{
          borderTop: '1px solid var(--color-panel-border)',
          color: 'var(--color-text-muted)',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--color-text-primary)')}
        onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--color-text-muted)')}
      >
        {open ? <ChevronLeft className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
      </button>
    </aside>
  );
}
