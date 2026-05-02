import { useState, useEffect } from 'react';
import client from '../api/client';
import Modal from '../components/Modal';
import StatusPill from '../components/StatusPill';
import { Plus, Search } from 'lucide-react';

export default function UsersPage() {
  const [users, setUsers] = useState([]);
  const [badges, setBadges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState({ name: '', email: '', password: '', role: 'employee', badge_id: '' });
  const [saving, setSaving] = useState(false);

  const fetchData = async () => {
    try {
      const [usersRes, badgesRes] = await Promise.all([
        client.get('/api/admin/users/'),
        client.get('/api/admin/badges/'),
      ]);
      setUsers(usersRes.data);
      setBadges(badgesRes.data);
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
      const payload = { ...form };
      if (payload.badge_id) payload.badge_id = parseInt(payload.badge_id);
      else delete payload.badge_id;
      await client.post('/api/admin/users/', payload);
      setShowModal(false);
      setForm({ name: '', email: '', password: '', role: 'employee', badge_id: '' });
      fetchData();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to create user');
    } finally {
      setSaving(false);
    }
  };

  const filtered = users.filter((u) =>
    u.name.toLowerCase().includes(search.toLowerCase()) ||
    u.email.toLowerCase().includes(search.toLowerCase())
  );

  if (loading) return <div className="loading-spinner"><div className="spinner" /> Loading...</div>;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1>Users</h1>
          <p>Manage system users and role assignments</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={16} /> Add User
        </button>
      </div>

      <div className="table-wrapper">
        <div className="table-toolbar">
          <div className="search-wrap">
            <Search />
            <input className="search-input" placeholder="Search users..." value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <span className="text-muted text-sm">{filtered.length} user(s)</span>
        </div>
        <table>
          <thead>
            <tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>Badge</th><th>Created</th></tr>
          </thead>
          <tbody>
            {filtered.map((u) => (
              <tr key={u.id}>
                <td>{u.id}</td>
                <td style={{ fontWeight: 600 }}>{u.name}</td>
                <td className="mono">{u.email}</td>
                <td><StatusPill status={u.role} /></td>
                <td>{u.badge_name || <span className="text-muted">None</span>}</td>
                <td className="text-muted text-sm">{new Date(u.created_at).toLocaleDateString()}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={6} className="table-empty">No users found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal
        title="Add New User"
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        footer={
          <>
            <button className="btn btn-outline" onClick={() => setShowModal(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={handleCreate} disabled={saving}>
              {saving ? 'Creating...' : 'Create User'}
            </button>
          </>
        }
      >
        <form onSubmit={handleCreate}>
          <div className="form-group">
            <label className="form-label">Full Name</label>
            <input className="form-input" placeholder="John Doe" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </div>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input className="form-input" type="email" placeholder="john@spaze.io" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input className="form-input" type="password" placeholder="••••••••" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
          </div>
          <div className="form-group">
            <label className="form-label">Role</label>
            <select className="form-select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              <option value="employee">Employee</option>
              <option value="manager">Manager</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div className="form-group">
            <label className="form-label">Assign Badge (optional)</label>
            <select className="form-select" value={form.badge_id} onChange={(e) => setForm({ ...form, badge_id: e.target.value })}>
              <option value="">— No badge —</option>
              {badges.filter(b => !b.assigned_user).map((b) => (
                <option key={b.id} value={b.id}>{b.badge_name} ({b.mac_address})</option>
              ))}
            </select>
          </div>
        </form>
      </Modal>
    </div>
  );
}
