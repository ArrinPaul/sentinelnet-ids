import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  FileCode,
  ChevronLeft,
  ChevronRight,
  Shield,
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
        open ? 'w-64' : 'w-20'
      } bg-gray-900 border-r border-gray-800 flex flex-col transition-all duration-300 ease-in-out`}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-gray-800">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500 flex items-center justify-center flex-shrink-0">
          <Shield className="w-5 h-5 text-white" />
        </div>
        {open && (
          <div className="overflow-hidden">
            <h1 className="text-sm font-bold text-white tracking-tight leading-tight">
              NetShield IDS
            </h1>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest">
              Control Plane
            </p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800/50 border border-transparent'
              }`
            }
          >
            <Icon className="w-5 h-5 flex-shrink-0" />
            {open && <span>{label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center justify-center py-3 border-t border-gray-800 text-gray-500 hover:text-white transition-colors"
      >
        {open ? <ChevronLeft className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
      </button>
    </aside>
  );
}
