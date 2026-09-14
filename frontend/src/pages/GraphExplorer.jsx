import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import RelationshipGraph from "../components/RelationshipGraph";
import api from "../api/client";

const FILTERS = [
  { id: "all", label: "All nodes" },
  { id: "apk", label: "APKs" },
  { id: "campaign", label: "Campaigns" },
  { id: "certificate", label: "Certificates" },
];

export default function GraphExplorer() {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlCampaignId = searchParams.get("campaign");
  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState(urlCampaignId || "");
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    api.listCampaigns()
      .then((res) => {
        const items = res?.items || [];
        setCampaigns(items);
        if (!selectedCampaignId && items.length > 0) {
          setSelectedCampaignId(items[0].id);
        }
      })
      .catch((err) => console.error("Failed to load campaigns for graph:", err));
  }, [selectedCampaignId]);

  const handleCampaignChange = (cid) => {
    setSelectedCampaignId(cid);
    setSearchParams(cid ? { campaign: cid } : {});
    setSelected(null);
  };

  const onNodeSelect = useCallback((node) => setSelected(node), []);

  const targetId = selected?.rawId || selected?.id?.replace(/^(sample_|camp_|cert_)/, "") || "";

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Graph Explorer</h1>
          <p>3D relationship graph — hover to rotate, drag to orbit, scroll to zoom</p>
        </div>
        {campaigns.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 13, color: "var(--text-muted)" }}>Active Campaign:</span>
            <select
              value={selectedCampaignId}
              onChange={(e) => handleCampaignChange(e.target.value)}
              style={{
                background: "var(--bg-card)",
                border: "1px solid var(--border)",
                color: "var(--text)",
                padding: "6px 12px",
                borderRadius: 8,
                fontSize: 13,
              }}
            >
              {campaigns.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>
        )}
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
      </div>

      <RelationshipGraph
        campaignId={selectedCampaignId}
        filter={filter}
        onNodeSelect={onNodeSelect}
        height="560px"
      />

      {selected && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-title">Selected node</div>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              gap: 16,
              flexWrap: "wrap",
              alignItems: "center",
            }}
          >
            <div>
              <div style={{ fontFamily: "var(--font-display)", fontSize: 18 }}>
                {selected.label}
              </div>
              <div style={{ color: "var(--text-muted)", fontSize: 13, marginTop: 4 }}>
                Type: {selected.group} · ID: {targetId} · Connected links highlighted in 3D view
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              {selected.group === "apk" && targetId && (
                <Link to={`/app/apk/${targetId}`} className="btn-primary">
                  Open APK report
                </Link>
              )}
              {selected.group === "campaign" && targetId && (
                <Link to={`/app/campaigns/${targetId}`} className="btn-primary">
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
