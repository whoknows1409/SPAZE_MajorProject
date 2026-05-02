import { useState, useEffect } from 'react';
import client from '../api/client';
import StatCard from '../components/StatCard';
import { CreditCard, Users, Monitor, ScrollText } from 'lucide-react';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, logsRes] = await Promise.all([
          client.get('/api/audit/stats'),
          client.get('/api/audit/logs?limit=10'),
        ]);
        setStats(statsRes.data);
        setRecentLogs(logsRes.data);
      } catch (err) {
        console.error('Dashboard fetch error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const getActionColor = (action) => {
    if (action.includes('unlock')) return 'var(--success)';
    if (action.includes('lock')) return 'var(--warning)';
    if (action.includes('denied')) return 'var(--danger)';
    if (action.includes('delivered')) return 'var(--info)';
    return 'var(--text-tertiary)';
  };

  const formatTime = (ts) => {
    const d = new Date(ts);
    return d.toLocaleString('en-IN', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
  };

  if (loading) {
    return <div className="loading-spinner"><div className="spinner" /> Loading...</div>;
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1>Overview</h1>
          <p>System metrics and recent activity</p>
        </div>
      </div>

      <div className="stats-grid">
        <StatCard icon={CreditCard} value={stats?.total_badges || 0} label="Badges" color="primary" />
        <StatCard icon={Users} value={stats?.total_users || 0} label="Users" color="success" />
        <StatCard icon={Monitor} value={stats?.total_devices || 0} label="Devices" color="warning" />
        <StatCard icon={ScrollText} value={stats?.total_audit_logs || 0} label="Events" color="info" />
      </div>

      <div className="grid-2">
        <div className="card">
          <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '14px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Recent Activity
          </div>
          <div className="activity-list">
            {recentLogs.length === 0 && (
              <p style={{ color: 'var(--text-tertiary)', fontSize: '0.82rem' }}>No recent activity</p>
            )}
            {recentLogs.map((log) => (
              <div key={log.id} className="activity-item">
                <span className="activity-dot" style={{ background: getActionColor(log.action) }} />
                <span className="activity-text">
                  <strong>{log.action.replace(/_/g, ' ')}</strong>
                  {log.details && <span> — {log.details}</span>}
                </span>
                <span className="activity-time">{formatTime(log.timestamp)}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '14px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            System Status
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {['Server', 'Database', 'Redis Cache', 'RBAC Engine'].map((name) => (
              <div key={name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>{name}</span>
                <span className="pill active"><span className="pill-dot"/>operational</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
