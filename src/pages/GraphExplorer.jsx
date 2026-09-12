import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import RelationshipGraph from "../components/RelationshipGraph";

const FILTERS = [
  { id: "all", label: "All nodes" },
  { id: "apk", label: "APKs" },
  { id: "campaign", label: "Campaigns" },
  { id: "certificate", label: "Certificates" },
  { id: "domain", label: "Domains" },
  { id: "package", label: "Packages" },
];

export default function GraphExplorer() {
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState(null);

  const onNodeSelect = useCallback((node) => setSelected(node), []);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Graph Explorer</h1>
          <p>3D relationship graph — hover to rotate, drag to orbit, scroll to zoom</p>
        </div>
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 14 }}>
        {FILTERS.map((f) => (
          <button
            key={f.id}
            type="button"
            onClick={() => setFilter(f.id)}
            className={filter === f.id ? "btn-primary" : "btn-ghost"}
            style={{ padding: "8px 12px" }}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div
        style={{
          display: "flex",
          gap: 16,
          flexWrap: "wrap",
          marginBottom: 12,
          fontSize: 12,
          color: "var(--text-muted)",
        }}
      >
        <Legend color="#00d4aa" label="APK" />
        <Legend color="#ff4d6a" label="Campaign" />
        <Legend color="#ffb020" label="Certificate" />
        <Legend color="#3b9eff" label="Domain" />
        <Legend color="#a78bfa" label="Package" />
      </div>

      <RelationshipGraph filter={filter} onNodeSelect={onNodeSelect} height="560px" />

      {selected && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title">Selected node</div>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
            <div>
              <div style={{ fontFamily: "var(--font-display)", fontSize: 18 }}>{selected.label}</div>
              <div style={{ color: "var(--text-muted)", fontSize: 13, marginTop: 4 }}>
                Type: {selected.group} · Connected links highlighted in the 3D view
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              {selected.group === "apk" && (
                <Link to="/app/apk/apk-001" className="btn-primary">
                  Open APK report
                </Link>
              )}
              {selected.group === "campaign" && (
                <Link to="/app/campaigns/camp-001" className="btn-primary">
                  Open campaign
                </Link>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Legend({ color, label }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <span
        style={{
          width: 12,
          height: 12,
          borderRadius: "50%",
          background: `radial-gradient(circle at 30% 30%, #fff 0%, ${color} 45%, ${color} 100%)`,
          boxShadow: `0 0 8px ${color}66`,
        }}
      />
      {label}
    </span>
  );
}
