import { useState, useEffect } from 'react';
import client from '../api/client';
import Modal from '../components/Modal';
import StatusPill from '../components/StatusPill';
import { Plus, Trash2, Search } from 'lucide-react';

export default function Policies() {
  const [policies, setPolicies] = useState([]);
  const [badges, setBadges] = useState([]);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState({ badge_id: '', device_id: '' });
  const [saving, setSaving] = useState(false);
  const [filter, setFilter] = useState('all');

  const fetchData = async () => {
    try {
      const [pRes, bRes, dRes] = await Promise.all([
        client.get('/api/admin/policies/'),
        client.get('/api/admin/badges/'),
        client.get('/api/admin/devices/'),
      ]);
      setPolicies(pRes.data);
      setBadges(bRes.data);
      setDevices(dRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await client.post('/api/admin/policies/', {
        badge_id: parseInt(form.badge_id),
        device_id: parseInt(form.device_id),
      });
      setShowModal(false);
      setForm({ badge_id: '', device_id: '' });
      fetchData();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to create policy');
    } finally {
      setSaving(false);
    }
  };

  const revokePolicy = async (id) => {
    try {
      await client.delete(`/api/admin/policies/${id}`);
      fetchData();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to revoke');
    }
  };

  const filtered = policies.filter((p) => {
    if (filter === 'active') return p.is_active;
    if (filter === 'revoked') return !p.is_active;
    return true;
  });

  if (loading) return <div className="loading-spinner"><div className="spinner" /> Loading...</div>;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1>Policies</h1>
          <p>Manage badge-to-device access policies</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={16} /> Create Policy
        </button>
      </div>

      <div className="table-wrapper">
        <div className="table-toolbar">
          <div className="btn-group">
            {['all', 'active', 'revoked'].map((f) => (
              <button key={f} className={`btn btn-sm ${filter === f ? 'btn-primary' : 'btn-outline'}`} onClick={() => setFilter(f)}>
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
          <span className="text-muted text-sm">{filtered.length} polic{filtered.length === 1 ? 'y' : 'ies'}</span>
        </div>
        <table>
          <thead>
            <tr><th>ID</th><th>Badge</th><th>Device</th><th>Status</th><th>Granted By</th><th>Created</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {filtered.map((p) => (
              <tr key={p.id}>
                <td>{p.id}</td>
                <td>
                  <div style={{ fontWeight: 600 }}>{p.badge_mac}</div>
                </td>
                <td style={{ fontWeight: 500 }}>{p.device_hostname}</td>
                <td><StatusPill status={p.is_active ? 'active' : 'revoked'} /></td>
                <td className="text-muted">Admin #{p.granted_by}</td>
                <td className="text-muted text-sm">{new Date(p.created_at).toLocaleDateString()}</td>
                <td>
                  {p.is_active && (
                    <button className="btn btn-danger btn-sm" onClick={() => revokePolicy(p.id)}>
                      <Trash2 size={14} /> Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={7} className="table-empty">No policies found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal
        title="Create Access Policy"
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        footer={
          <>
            <button className="btn btn-outline" onClick={() => setShowModal(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={handleCreate} disabled={saving || !form.badge_id || !form.device_id}>
              {saving ? 'Creating...' : 'Grant Access'}
            </button>
          </>
        }
      >
        <form onSubmit={handleCreate}>
          <div className="form-group">
            <label className="form-label">Badge</label>
            <select className="form-select" value={form.badge_id} onChange={(e) => setForm({ ...form, badge_id: e.target.value })} required>
              <option value="">— Select Badge —</option>
              {badges.filter(b => b.status === 'active').map((b) => (
                <option key={b.id} value={b.id}>{b.badge_name} ({b.mac_address})</option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Device</label>
            <select className="form-select" value={form.device_id} onChange={(e) => setForm({ ...form, device_id: e.target.value })} required>
              <option value="">— Select Device —</option>
              {devices.filter(d => d.is_active).map((d) => (
                <option key={d.id} value={d.id}>{d.hostname} ({d.mac_address})</option>
              ))}
            </select>
          </div>
        </form>
      </Modal>
    </div>
  );
}
