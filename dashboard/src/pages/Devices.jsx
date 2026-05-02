import { useState, useEffect } from 'react';
import client from '../api/client';
import Modal from '../components/Modal';
import StatusPill from '../components/StatusPill';
import { Plus, Search } from 'lucide-react';

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState({ hostname: '', mac_address: '', location: '' });
  const [saving, setSaving] = useState(false);

  const fetchDevices = async () => {
    try {
      const res = await client.get('/api/admin/devices/');
      setDevices(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchDevices(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await client.post('/api/admin/devices/', form);
      setShowModal(false);
      setForm({ hostname: '', mac_address: '', location: '' });
      fetchDevices();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to register device');
    } finally {
      setSaving(false);
    }
  };

  const filtered = devices.filter((d) =>
    d.hostname.toLowerCase().includes(search.toLowerCase()) ||
    d.mac_address.toLowerCase().includes(search.toLowerCase())
  );

  if (loading) return <div className="loading-spinner"><div className="spinner" /> Loading...</div>;

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <h1>Devices</h1>
          <p>Manage registered workstations</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={16} /> Register Device
        </button>
      </div>

      <div className="table-wrapper">
        <div className="table-toolbar">
          <div className="search-wrap">
            <Search />
            <input className="search-input" placeholder="Search devices..." value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          <span className="text-muted text-sm">{filtered.length} device(s)</span>
        </div>
        <table>
          <thead>
            <tr><th>ID</th><th>Hostname</th><th>MAC Address</th><th>Location</th><th>Status</th><th>Registered</th></tr>
          </thead>
          <tbody>
            {filtered.map((d) => (
              <tr key={d.id}>
                <td>{d.id}</td>
                <td style={{ fontWeight: 600 }}>{d.hostname}</td>
                <td className="mono">{d.mac_address}</td>
                <td>{d.location || <span className="text-muted">—</span>}</td>
                <td><StatusPill status={d.is_active ? 'active' : 'inactive'} /></td>
                <td className="text-muted text-sm">{new Date(d.registered_at).toLocaleDateString()}</td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={6} className="table-empty">No devices found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <Modal
        title="Register New Device"
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        footer={
          <>
            <button className="btn btn-outline" onClick={() => setShowModal(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={handleCreate} disabled={saving}>
              {saving ? 'Registering...' : 'Register'}
            </button>
          </>
        }
      >
        <form onSubmit={handleCreate}>
          <div className="form-group">
            <label className="form-label">Hostname</label>
            <input className="form-input" placeholder="WORKSTATION-01" value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} required />
          </div>
          <div className="form-group">
            <label className="form-label">MAC Address</label>
            <input className="form-input mono" placeholder="AA:BB:CC:DD:EE:FF" value={form.mac_address} onChange={(e) => setForm({ ...form, mac_address: e.target.value })} required />
          </div>
          <div className="form-group">
            <label className="form-label">Location (optional)</label>
            <input className="form-input" placeholder="Lab A, Room 204" value={form.location} onChange={(e) => setForm({ ...form, location: e.target.value })} />
          </div>
        </form>
      </Modal>
    </div>
  );
}
