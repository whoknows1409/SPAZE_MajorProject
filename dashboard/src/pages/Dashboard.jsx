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
    return 'var(--primary)';
  };

  const formatTime = (ts) => {
    const d = new Date(ts);
    return d.toLocaleString('en-IN', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
  };

  if (loading) {
    return <div className="loading-spinner"><div className="spinner" /> Loading dashboard...</div>;
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1>Dashboard</h1>
          <p>SPAZE system overview</p>
        </div>
      </div>

      <div className="stats-grid">
        <StatCard icon={CreditCard} value={stats?.total_badges || 0} label="Total Badges" color="primary" />
        <StatCard icon={Users} value={stats?.total_users || 0} label="Total Users" color="success" />
        <StatCard icon={Monitor} value={stats?.total_devices || 0} label="Total Devices" color="warning" />
        <StatCard icon={ScrollText} value={stats?.total_audit_logs || 0} label="Audit Events" color="info" />
      </div>

      <div className="grid-2">
        <div className="card">
          <h3 style={{ marginBottom: '16px', fontSize: '1rem', fontWeight: 600 }}>Recent Activity</h3>
          <div className="activity-list">
            {recentLogs.length === 0 && (
              <p className="text-muted text-sm">No recent activity</p>
            )}
            {recentLogs.map((log) => (
              <div key={log.id} className="activity-item">
                <span className="activity-dot" style={{ background: getActionColor(log.action) }} />
                <span className="activity-text">
                  <strong className={`action-${log.action}`}>{log.action.replace(/_/g, ' ')}</strong>
                  {log.details && <span className="text-muted"> — {log.details}</span>}
                </span>
                <span className="activity-time">{formatTime(log.timestamp)}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h3 style={{ marginBottom: '16px', fontSize: '1rem', fontWeight: 600 }}>System Status</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="text-muted text-sm">Server</span>
              <span className="pill active"><span className="pill-dot"/>online</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="text-muted text-sm">Database</span>
              <span className="pill active"><span className="pill-dot"/>connected</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="text-muted text-sm">Redis Cache</span>
              <span className="pill active"><span className="pill-dot"/>active</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span className="text-muted text-sm">RBAC Engine</span>
              <span className="pill active"><span className="pill-dot"/>enforcing</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
