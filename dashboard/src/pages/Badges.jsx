import { useState, useEffect } from 'react';
import client from '../api/client';
import Modal from '../components/Modal';
import StatusPill from '../components/StatusPill';
import { Plus, Search } from 'lucide-react';

export default function Badges() {
  const [badges, setBadges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState({ mac_address: '', badge_name: '' });
  const [saving, setSaving] = useState(false);

  const fetchBadges = async () => {
    try {
      const res = await client.get('/api/admin/badges/');
      setBadges(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchBadges(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await client.post('/api/admin/badges/', form);
      setShowModal(false);
      setForm({ mac_address: '', badge_name: '' });
      fetchBadges();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to create badge');
    } finally {
      setSaving(false);
    }
  };

  const updateStatus = async (id, status) => {
    try {
      await client.patch(`/api/admin/badges/${id}`, { status });
      fetchBadges();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to update');
    }
  };

  const filtered = badges.filter((b) =>
    b.badge_name?.toLowerCase().includes(search.toLowerCase()) ||
    b.mac_address.toLowerCase().includes(search.toLowerCase())
  );

  if (loading) return <div className="loading-spinner"><div className="spinner" /> Loading...</div>;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1>Badges</h1>
          <p>Manage BLE proximity badges</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={16} /> Register Badge
        </button>
      </div>

      <div className="table-wrapper">
        <div className="table-toolbar">
          <div className="search-wrap">
            <Search />
            <input className="search-input" placeholder="Search badges..." value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <span className="text-muted text-sm">{filtered.length} badge(s)</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>ID</th><th>Name</th><th>MAC Address</th><th>Status</th><th>Assigned User</th><th>Registered</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((b) => (
              <tr key={b.id}>
                <td>{b.id}</td>
                <td style={{ fontWeight: 600 }}>{b.badge_name || '—'}</td>
                <td className="mono">{b.mac_address}</td>
                <td><StatusPill status={b.status} /></td>
                <td>{b.assigned_user || <span className="text-muted">Unassigned</span>}</td>
                <td className="text-muted text-sm">{new Date(b.registered_at).toLocaleDateString()}</td>
                <td>
                  <div className="btn-group">
                    {b.status === 'active' && (
                      <button className="btn btn-ghost btn-sm" onClick={() => updateStatus(b.id, 'revoked')}>Revoke</button>
                    )}
                    {b.status !== 'active' && (
                      <button className="btn btn-ghost btn-sm" onClick={() => updateStatus(b.id, 'active')}>Activate</button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={7} className="table-empty">No badges found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal
        title="Register New Badge"
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        footer={
          <>
            <button className="btn btn-outline" onClick={() => setShowModal(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={handleCreate} disabled={saving}>
              {saving ? 'Creating...' : 'Register'}
            </button>
          </>
        }
      >
        <form onSubmit={handleCreate}>
          <div className="form-group">
            <label className="form-label">Badge Name</label>
            <input className="form-input" placeholder="SZ-BADGE-001" value={form.badge_name} onChange={(e) => setForm({ ...form, badge_name: e.target.value })} required />
          </div>
          <div className="form-group">
            <label className="form-label">MAC Address</label>
            <input className="form-input mono" placeholder="AA:BB:CC:DD:EE:FF" value={form.mac_address} onChange={(e) => setForm({ ...form, mac_address: e.target.value })} required />
          </div>
        </form>
      </Modal>
    </div>
  );
}
