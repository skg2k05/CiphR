import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Loader2 } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import api from "../api/client";

export default function Campaigns() {
  const [campaignList, setCampaignList] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    api.listCampaigns()
      .then((res) => {
        if (!mounted) return;
        setCampaignList(res?.items || []);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load campaigns:", err);
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, []);

  if (loading) {
    return (
      <div style={{ padding: 48, textAlign: "center", color: "var(--text-muted)" }}>
        <Loader2 size={32} className="spin" style={{ margin: "0 auto 16px", color: "var(--accent)" }} />
        <p>Loading campaigns from backend...</p>
        <style>{`
          .spin { animation: spin 1s linear infinite; }
          @keyframes spin { to { transform: rotate(360deg); } }
        `}</style>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Campaign Intelligence</h1>
          <p>Coordinated fraud campaigns correlated across APK samples</p>
        </div>
      </div>

      <div style={{ display: "grid", gap: 14 }}>
        {campaignList.length > 0 ? (
          campaignList.map((c) => {
            const certCount = c.intelligence_summary?.certificates?.length || (c.sample_count ? 1 : 0);
            const domainCount = c.intelligence_summary?.domains?.length || 0;
            const pkgCount = c.intelligence_summary?.packages?.length || (c.sample_count ? 1 : 0);
            const lastSeen = c.last_seen ? new Date(c.last_seen).toISOString().split("T")[0] : "N/A";

            return (
              <Link
                key={c.id}
                to={`/app/campaigns/${c.id}`}
                className="card"
                style={{ display: "block", transition: "border-color 0.15s" }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 12,
                    alignItems: "flex-start",
                  }}
                >
                  <div>
                    <h3 style={{ fontFamily: "var(--font-display)", fontSize: 18, marginBottom: 6 }}>
                      {c.name}
                    </h3>
                    <p style={{ color: "var(--text-muted)", fontSize: 14, maxWidth: 640 }}>
                      {c.description || "Correlated campaign cluster identifying shared certificate and code indicators."}
                    </p>
                  </div>
                  <SeverityBadge level={c.severity || "High"} />
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
                  <Metric label="APKs" value={c.sample_count ?? 0} />
                  <Metric label="Certificates" value={certCount} />
                  <Metric label="Domains" value={domainCount} />
                  <Metric label="Packages" value={pkgCount} />
                  <Metric label="Last seen" value={lastSeen} />
                </div>
              </Link>
            );
          })
        ) : (
          <div className="card" style={{ textAlign: "center", padding: 32, color: "var(--text-muted)" }}>
            No campaigns detected yet. Upload correlated APKs to trigger campaign grouping.
          </div>
        )}
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
