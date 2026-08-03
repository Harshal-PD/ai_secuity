export default function StatBox({ label, value, color, highlight }) {
  return (
    <div className={`stat-tile${highlight ? " stat-tile-highlight" : ""}`}>
      <div className="stat-value" style={{ color }}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}
