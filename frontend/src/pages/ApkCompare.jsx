import { useState } from "react";
import SeverityBadge from "../components/SeverityBadge";
import { recentApks } from "../data/mockData";

export default function ApkCompare() {
  const [left, setLeft] = useState(recentApks[0].id);
  const [right, setRight] = useState(recentApks[1].id);
  const a = recentApks.find((x) => x.id === left);
  const b = recentApks.find((x) => x.id === right);
  const sameCampaign = a.campaign === b.campaign;
  const tlsh = sameCampaign ? 92 : 41;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>APK Comparison</h1>
          <p>Side-by-side similarity for related-origin analysis</p>
        </div>
      </div>

      <div className="grid-2">
        <Picker label="APK A" value={left} onChange={setLeft} exclude={right} />
        <Picker label="APK B" value={right} onChange={setRight} exclude={left} />
      </div>

      <div className="grid-2" style={{ marginTop: 16 }}>
        <CompareCard apk={a} />
        <CompareCard apk={b} />
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Relationship conclusion</div>
        <div className="stat-grid" style={{ marginBottom: 12 }}>
          <div className="stat-card">
            <div className="stat-label">TLSH similarity</div>
            <div className="stat-value">{tlsh}%</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Signing certificate</div>
            <div style={{ marginTop: 8, fontWeight: 600 }}>
              {sameCampaign ? "Shared / similar" : "Different"}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Common permissions</div>
            <div className="stat-value">5</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Common domains</div>
            <div className="stat-value">{sameCampaign ? 2 : 0}</div>
          </div>
        </div>
        <p style={{ color: "var(--text-muted)", fontSize: 14, lineHeight: 1.6 }}>
          {tlsh >= 80
            ? "High likelihood of common origin — samples share campaign membership, elevated TLSH similarity, and overlapping indicators."
            : "Moderate/low relatedness — packages differ in campaign association; investigate certificate and domain overlap before concluding common origin."}
        </p>
      </div>
    </div>
  );
}

function Picker({ label, value, onChange, exclude }) {
  return (
    <div className="card">
      <div className="card-title">{label}</div>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          width: "100%",
          padding: 10,
          background: "var(--bg)",
          border: "1px solid var(--border)",
          borderRadius: 8,
        }}
      >
        {recentApks
          .filter((a) => a.id !== exclude)
          .map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
      </select>
    </div>
  );
}

function CompareCard({ apk }) {
  return (
    <div className="card">
      <h3 style={{ fontFamily: "var(--font-display)", marginBottom: 12 }}>{apk.name}</h3>
      <div style={{ display: "grid", gap: 8, fontSize: 13.5 }}>
        <Row label="Package" value={apk.package} />
        <Row label="Risk" value={<SeverityBadge level={apk.risk} />} />
        <Row label="Score" value={apk.score} />
        <Row label="Campaign" value={apk.campaign} />
        <Row label="SHA-256" value={apk.sha256} />
      </div>
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "100px 1fr" }}>
      <span style={{ color: "var(--text-dim)" }}>{label}</span>
      <span>{value}</span>
    </div>
  );
}
