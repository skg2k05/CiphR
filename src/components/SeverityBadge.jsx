export default function SeverityBadge({ level }) {
  const key = String(level || "Low").toLowerCase();
  return <span className={`severity-badge severity-${key}`}>{level}</span>;
}
