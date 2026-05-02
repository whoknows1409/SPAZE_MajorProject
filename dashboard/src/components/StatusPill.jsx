export default function StatusPill({ status }) {
  const normalized = String(status).toLowerCase();
  return (
    <span className={`pill ${normalized}`}>
      <span className="pill-dot" />
      {normalized}
    </span>
  );
}
