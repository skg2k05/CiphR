import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Loader2 } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import api from "../api/client";

export default function CampaignDetail() {
  const { id } = useParams();
  const [loading, setLoading] = useState(true);
  const [campaign, setCampaign] = useState(null);
  const [samples, setSamples] = useState([]);
  const [timeline, setTimeline] = useState(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);

    Promise.allSettled([
      api.getCampaign(id),
      api.getCampaignSamples(id),
      api.getCampaignTimeline(id),
    ]).then(([cRes, sRes, tRes]) => {
      if (!mounted) return;
      if (cRes.status === "fulfilled") setCampaign(cRes.value);
      if (sRes.status === "fulfilled") setSamples(Array.isArray(sRes.value) ? sRes.value : []);
      if (tRes.status === "fulfilled") setTimeline(tRes.value);
      setLoading(false);
    }).catch(() => {
      if (mounted) setLoading(false);
    });

    return () => {
      mounted = false;
    };
  }, [id]);

  if (loading) {
    return (
      <div style={{ padding: 48, textAlign: "center", color: "var(--text-muted)" }}>
        <Loader2 size={32} className="spin" style={{ margin: "0 auto 16px", color: "var(--accent)" }} />
        <p>Loading campaign details from backend...</p>
        <style>{`
          .spin { animation: spin 1s linear infinite; }
          @keyframes spin { to { transform: rotate(360deg); } }
        `}</style>
      </div>
    );
  }

  if (!campaign) {
    return (
      <div className="card" style={{ textAlign: "center", padding: 48 }}>
        <h2>Campaign not found</h2>
        <p style={{ color: "var(--text-muted)", marginTop: 8 }}>The requested campaign UUID does not exist.</p>
        <Link to="/app/campaigns" className="btn-primary" style={{ marginTop: 16, display: "inline-block" }}>
          Back to Campaigns
        </Link>
      </div>
    );
  }

  const certCount = campaign.intelligence_summary?.certificates?.length || (samples.length ? 1 : 0);
  const domainCount = campaign.intelligence_summary?.domains?.length || 0;
  const pkgCount = campaign.intelligence_summary?.packages?.length || (samples.length ? 1 : 0);
  const firstSeen = campaign.first_seen ? new Date(campaign.first_seen).toLocaleDateString() : "N/A";
  const lastSeen = campaign.last_seen ? new Date(campaign.last_seen).toLocaleDateString() : "N/A";

  // Build timeline chart data from events
  const events = timeline?.events || [];
  const chartData = events.length > 0
    ? events.map((ev, i) => ({
        point: new Date(ev.timestamp).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
        samples: i + 1,
        title: ev.title,
      }))
    : [
        { point: "First seen", samples: 1 },
        { point: "Now", samples: samples.length || 1 },
      ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>{campaign.name}</h1>
          <p>
            First seen {firstSeen} · Last seen {lastSeen}
          </p>
        </div>
        <SeverityBadge level={campaign.severity || "High"} />
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Related APKs</div>
          <div className="stat-value">{samples.length || campaign.sample_count || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Certificates</div>
          <div className="stat-value">{certCount}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Domains</div>
          <div className="stat-value">{domainCount}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Package families</div>
          <div className="stat-value">{pkgCount}</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">Campaign risk summary</div>
          <p style={{ color: "var(--text-muted)", fontSize: 14, lineHeight: 1.6 }}>
            {campaign.description || "Correlated campaign infrastructure exhibiting shared signing and behavior."}
          </p>
          <div style={{ marginTop: 16 }}>
            <Link to={`/app/graph?campaign=${campaign.id}`} className="btn-outline">
              Open relationship graph
            </Link>
          </div>
        </div>
        <div className="card">
          <div className="card-title">Growth / activity timeline ({events.length} events)</div>
          <div style={{ height: 200 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <XAxis dataKey="point" stroke="#5c6d86" fontSize={12} />
                <YAxis stroke="#5c6d86" fontSize={12} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "#0f1828",
                    border: "1px solid #1c2b3f",
                    borderRadius: 8,
                  }}
                />
                <Area type="monotone" dataKey="samples" stroke="#ffb020" fill="rgba(255,176,32,0.2)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Associated APK Samples ({samples.length})</div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>SHA-256</th>
              <th>Status</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {samples.length > 0 ? (
              samples.map((apk) => (
                <tr key={apk.id}>
                  <td>
                    <strong>{apk.filename}</strong>
                  </td>
                  <td style={{ color: "var(--text-muted)", fontFamily: "monospace", fontSize: 12 }}>
                    {apk.sha256?.slice(0, 16)}...
                  </td>
                  <td>
                    <span
                      style={{
                        padding: "3px 8px",
                        borderRadius: 6,
                        background: apk.status === "COMPLETED" ? "var(--accent-dim)" : "var(--bg)",
                        color: apk.status === "COMPLETED" ? "var(--accent)" : "var(--text-dim)",
                        fontSize: 12,
                        fontWeight: 600,
                      }}
                    >
                      {apk.status}
                    </span>
                  </td>
                  <td style={{ fontSize: 13, color: "var(--text-muted)" }}>
                    {apk.created_at ? new Date(apk.created_at).toLocaleDateString() : "-"}
                  </td>
                  <td>
                    <Link to={`/app/apk/${apk.id}`} style={{ color: "var(--accent)", fontWeight: 600 }}>
                      Report
                    </Link>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} style={{ textAlign: "center", color: "var(--text-dim)", padding: 24 }}>
                  No samples associated with this campaign yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
