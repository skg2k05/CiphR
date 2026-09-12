import { Link } from "react-router-dom";
import { Bell } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import { alerts } from "../data/mockData";

export default function Alerts() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Alerts & Notifications</h1>
          <p>Critical events requiring analyst attention</p>
        </div>
      </div>

      <div style={{ display: "grid", gap: 10 }}>
        {alerts.map((a) => (
          <Link
            key={a.id}
            to={a.link}
            className="card"
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: 14,
              textDecoration: "none",
            }}
          >
            <div
              style={{
                width: 40,
                height: 40,
                borderRadius: 10,
                background: "var(--warning-dim)",
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
              }}
            >
              <Bell size={18} color="var(--warning)" />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                <strong style={{ fontSize: 15 }}>{a.title}</strong>
                <SeverityBadge level={a.severity} />
              </div>
              <div style={{ color: "var(--text-dim)", fontSize: 13, marginTop: 6 }}>{a.time}</div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
