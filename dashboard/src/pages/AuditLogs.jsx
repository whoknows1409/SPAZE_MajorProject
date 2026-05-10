import { useState, useEffect, useRef } from 'react';
import client from '../api/client';
import { Search, RefreshCw } from 'lucide-react';

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState('');
  const [limit, setLimit] = useState(50);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const intervalRef = useRef(null);

  const fetchLogs = async () => {
    try {
      let url = `/api/audit/logs?limit=${limit}`;
      if (actionFilter) url += `&action=${actionFilter}`;
      const res = await client.get(url);
      setLogs(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLogs(); }, [actionFilter, limit]);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(fetchLogs, 5000);
    } else {
      clearInterval(intervalRef.current);
    }
    return () => clearInterval(intervalRef.current);
  }, [autoRefresh, actionFilter, limit]);

  const getActionColor = (action) => {
    if (action.includes('exfiltration')) return 'var(--danger)';
    if (action.includes('clipboard')) return 'var(--warning)';
    if (action.includes('screenshot')) return 'var(--danger)';
    if (action.includes('upload')) return 'var(--danger)';
    if (action.includes('usb')) return 'var(--danger)';
    if (action.includes('print')) return 'var(--warning)';
    if (action.includes('unlock')) return 'var(--success)';
    if (action.includes('lock') && !action.includes('unlock')) return 'var(--warning)';
    if (action.includes('denied')) return 'var(--danger)';
    if (action.includes('delivered')) return 'var(--info)';
    return 'var(--text-secondary)';
  };

  const formatTime = (ts) => {
    const d = new Date(ts.endsWith('Z') ? ts : ts + 'Z');
    return d.toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  };

  const actionTypes = ['vault_unlock', 'vault_lock', 'keys_delivered', 'key_stored', 'key_request_denied', 'exfiltration_blocked', 'exfiltration_detected', 'clipboard_cleared', 'screenshot_blocked', 'upload_blocked', 'usb_blocked', 'print_blocked'];

  if (loading) return <div className="loading-spinner"><div className="spinner" /> Loading...</div>;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1>Audit Logs</h1>
          <p>Security event timeline</p>
        </div>
        <div className="btn-group">
          <button
            className={`btn btn-sm ${autoRefresh ? 'btn-primary' : 'btn-outline'}`}
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            <RefreshCw size={14} style={autoRefresh ? { animation: 'spin 2s linear infinite' } : {}} />
            {autoRefresh ? 'Live' : 'Auto-refresh'}
          </button>
          <button className="btn btn-outline btn-sm" onClick={fetchLogs}>Refresh</button>
        </div>
      </div>

      <div className="table-wrapper">
        <div className="table-toolbar">
          <div className="btn-group" style={{ flexWrap: 'wrap' }}>
            <button className={`btn btn-sm ${!actionFilter ? 'btn-primary' : 'btn-outline'}`} onClick={() => setActionFilter('')}>All</button>
            {actionTypes.map((a) => (
              <button key={a} className={`btn btn-sm ${actionFilter === a ? 'btn-primary' : 'btn-outline'}`} onClick={() => setActionFilter(a)}>
                {a.replace(/_/g, ' ')}
              </button>
            ))}
          </div>
          <select className="form-select" style={{ width: 'auto', padding: '6px 32px 6px 10px', fontSize: '0.8rem' }} value={limit} onChange={(e) => setLimit(parseInt(e.target.value))}>
            <option value={25}>25 rows</option>
            <option value={50}>50 rows</option>
            <option value={100}>100 rows</option>
            <option value={200}>200 rows</option>
          </select>
        </div>
        <table>
          <thead>
            <tr><th>ID</th><th>Action</th><th>Badge</th><th>Details</th><th>RSSI</th><th>Timestamp</th></tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id}>
                <td className="text-muted">{log.id}</td>
                <td>
                  <span style={{ color: getActionColor(log.action), fontWeight: 600, fontSize: '0.84rem' }}>
                    {log.action.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="mono">{log.badge_mac || <span className="text-muted">—</span>}</td>
                <td className="text-sm" style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {log.details || <span className="text-muted">—</span>}
                </td>
                <td className="mono">{log.rssi_value != null ? `${log.rssi_value} dBm` : <span className="text-muted">—</span>}</td>
                <td className="text-muted text-sm" style={{ whiteSpace: 'nowrap' }}>{formatTime(log.timestamp)}</td>
              </tr>
            ))}
            {logs.length === 0 && (
              <tr><td colSpan={6} className="table-empty">No audit logs found</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
