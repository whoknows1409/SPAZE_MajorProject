import { NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard, CreditCard, Users, Monitor,
  Shield, ScrollText, LogOut,
} from 'lucide-react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/badges', icon: CreditCard, label: 'Badges' },
  { to: '/users', icon: Users, label: 'Users' },
  { to: '/devices', icon: Monitor, label: 'Devices' },
  { to: '/policies', icon: Shield, label: 'Policies' },
  { to: '/audit', icon: ScrollText, label: 'Audit Logs' },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const location = useLocation();

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <h2>SPAZE</h2>
        <span>Admin Dashboard</span>
      </div>

      <nav className="sidebar-nav">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <Icon />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="avatar">
          {user?.name?.charAt(0).toUpperCase() || 'A'}
        </div>
        <div className="user-info">
          <div className="user-name">{user?.name || 'Admin'}</div>
          <div className="user-role">{user?.role || 'admin'}</div>
        </div>
        <button className="logout-btn" onClick={logout} title="Logout">
          <LogOut size={16} />
        </button>
      </div>
    </aside>
  );
}
