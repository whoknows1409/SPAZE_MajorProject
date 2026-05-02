import { useState, useEffect } from 'react';
import client from '../api/client';
import StatCard from '../components/StatCard';
import { CreditCard, Users, Monitor, ScrollText } from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { useTheme } from '../context/ThemeContext';

const CHART_COLORS = ['#0070f3', '#00a86b', '#f5a623', '#e5484d', '#52a8ff', '#a855f7'];

function ChartCard({ title, children }) {
  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{
        padding: '14px 20px',
        borderBottom: '1px solid var(--border)',
        fontSize: '0.82rem',
        fontWeight: 600,
        color: 'var(--text-secondary)',
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
      }}>
        {title}
      </div>
      <div style={{ padding: '16px 12px 8px' }}>
        {children}
      </div>
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'var(--bg-elevated)',
      border: '1px solid var(--border-strong)',
      borderRadius: 'var(--radius-sm)',
      padding: '8px 12px',
      fontSize: '0.78rem',
      boxShadow: 'var(--shadow-md)',
    }}>
      <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: 4 }}>{label}</div>
      {payload.map((entry, i) => (
        <div key={i} style={{ color: entry.color, display: 'flex', gap: 8, justifyContent: 'space-between' }}>
          <span>{entry.name}</span>
          <span style={{ fontWeight: 600 }}>{entry.value}</span>
        </div>
      ))}
    </div>
  );
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [analytics, setAnalytics] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const { theme } = useTheme();

  const gridColor = theme === 'dark' ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.06)';
  const axisColor = theme === 'dark' ? '#555' : '#999';

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, analyticsRes, logsRes] = await Promise.all([
          client.get('/api/audit/stats'),
          client.get('/api/audit/analytics?days=7'),
          client.get('/api/audit/logs?limit=8'),
        ]);
        setStats(statsRes.data);
        setAnalytics(analyticsRes.data);
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
    const d = new Date(ts.endsWith('Z') ? ts : ts + 'Z');
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
          <p>System metrics and security analytics</p>
        </div>
      </div>

      {/* ── Stat Cards ── */}
      <div className="stats-grid">
        <StatCard icon={CreditCard} value={stats?.total_badges || 0} label="Badges" color="primary" />
        <StatCard icon={Users} value={stats?.total_users || 0} label="Users" color="success" />
        <StatCard icon={Monitor} value={stats?.total_devices || 0} label="Devices" color="warning" />
        <StatCard icon={ScrollText} value={stats?.total_audit_logs || 0} label="Events" color="info" />
      </div>

      {/* ── Charts Row 1: Activity Timeline + Action Breakdown ── */}
      <div className="grid-2" style={{ marginBottom: 16 }}>
        <ChartCard title="Vault Activity — Last 7 Days">
          {analytics?.activity_timeline?.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={analytics.activity_timeline}>
                <defs>
                  <linearGradient id="gradUnlocks" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00a86b" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#00a86b" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradLocks" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f5a623" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#f5a623" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke={gridColor} strokeDasharray="3 3" />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: axisColor }} tickFormatter={(v) => v.slice(5)} />
                <YAxis tick={{ fontSize: 11, fill: axisColor }} allowDecimals={false} />
                <Tooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize: '0.75rem' }} />
                <Area type="monotone" dataKey="unlocks" name="Unlocks" stroke="#00a86b" fill="url(#gradUnlocks)" strokeWidth={2} />
                <Area type="monotone" dataKey="locks" name="Locks" stroke="#f5a623" fill="url(#gradLocks)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: '0.82rem' }}>
              No vault activity in the last 7 days
            </div>
          )}
        </ChartCard>

        <ChartCard title="Event Distribution">
          {analytics?.action_breakdown?.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={analytics.action_breakdown}
                  dataKey="count"
                  nameKey="action"
                  cx="50%" cy="50%"
                  outerRadius={80}
                  innerRadius={45}
                  paddingAngle={3}
                  stroke="none"
                >
                  {analytics.action_breakdown.map((_, i) => (
                    <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize: '0.72rem' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: '0.82rem' }}>
              No events recorded yet
            </div>
          )}
        </ChartCard>
      </div>

      {/* ── Charts Row 2: Hourly Pattern + RSSI Distribution ── */}
      <div className="grid-2" style={{ marginBottom: 16 }}>
        <ChartCard title="Activity by Hour of Day">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={analytics?.hourly_activity || []}>
              <CartesianGrid stroke={gridColor} strokeDasharray="3 3" />
              <XAxis dataKey="hour" tick={{ fontSize: 10, fill: axisColor }} interval={2} />
              <YAxis tick={{ fontSize: 11, fill: axisColor }} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="events" name="Events" fill="#0070f3" radius={[3, 3, 0, 0]} maxBarSize={24} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="RSSI Signal Distribution">
          {analytics?.rssi_distribution?.some(d => d.count > 0) ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={analytics.rssi_distribution} layout="vertical">
                <CartesianGrid stroke={gridColor} strokeDasharray="3 3" />
                <XAxis type="number" tick={{ fontSize: 11, fill: axisColor }} allowDecimals={false} />
                <YAxis type="category" dataKey="range" tick={{ fontSize: 10, fill: axisColor }} width={110} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="Readings" radius={[0, 3, 3, 0]} maxBarSize={20}>
                  {analytics.rssi_distribution.map((_, i) => (
                    <Cell key={i} fill={['#00a86b', '#0070f3', '#f5a623', '#e5484d'][i]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)', fontSize: '0.82rem' }}>
              No RSSI data available
            </div>
          )}
        </ChartCard>
      </div>

      {/* ── Bottom Row: Recent Activity + System Status ── */}
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
                <span className="pill active"><span className="pill-dot" />operational</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
