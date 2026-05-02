export default function StatCard({ icon: Icon, value, label, color = 'primary' }) {
  return (
    <div className="stat-card fade-in" style={{ '--accent': `var(--${color})` }}>
      <div className={`stat-icon ${color}`}>
        <Icon />
      </div>
      <div className="stat-content">
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}
