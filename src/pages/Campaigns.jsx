import { Link } from "react-router-dom";
import SeverityBadge from "../components/SeverityBadge";
import { campaigns } from "../data/mockData";

export default function Campaigns() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Campaign Intelligence</h1>
          <p>Coordinated fraud campaigns correlated across APK samples</p>
        </div>
      </div>

      <div style={{ display: "grid", gap: 14 }}>
        {campaigns.map((c) => (
          <Link
            key={c.id}
            to={`/app/campaigns/${c.id}`}
            className="card"
            style={{ display: "block", transition: "border-color 0.15s" }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
              <div>
                <h3 style={{ fontFamily: "var(--font-display)", fontSize: 18, marginBottom: 6 }}>{c.name}</h3>
                <p style={{ color: "var(--text-muted)", fontSize: 14, maxWidth: 640 }}>{c.summary}</p>
              </div>
              <SeverityBadge level={c.risk} />
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(5, 1fr)",
                gap: 12,
                marginTop: 16,
                fontSize: 13,
              }}
            >
              <Metric label="APKs" value={c.apkCount} />
              <Metric label="Certificates" value={c.certificates} />
              <Metric label="Domains" value={c.domains} />
              <Metric label="Packages" value={c.packages} />
              <Metric label="Last seen" value={c.lastSeen} />
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function Metric({ label, value }) {
  return (
    <div style={{ padding: 10, background: "var(--bg)", borderRadius: 8, border: "1px solid var(--border)" }}>
      <div style={{ color: "var(--text-dim)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {label}
      </div>
      <div style={{ fontWeight: 600, marginTop: 4 }}>{value}</div>
    </div>
  );
}
