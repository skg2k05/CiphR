import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Download, ChevronDown, ChevronUp, Sparkles } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import { apkDetail, mitreTechniques, recentApks } from "../data/mockData";
import { useAuth } from "../context/AuthContext";
import { exportThreatReportPdf } from "../utils/exportPdf";

export default function ThreatReport() {
  const { id } = useParams();
  const { showToast } = useAuth();
  const [simple, setSimple] = useState(false);
  const [openMitre, setOpenMitre] = useState(null);
  const [showEvidence, setShowEvidence] = useState(true);

  const apk = { ...apkDetail, id: id || apkDetail.id };
  const related = recentApks.filter((a) => a.id !== apk.id).slice(0, 3);

  const exportReport = () => {
    exportThreatReportPdf({ apk, mitreTechniques });
    showToast("Threat report exported as PDF");
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Threat Report</h1>
          <p>{apk.name} · {apk.package}</p>
        </div>
        <button type="button" className="btn-primary" onClick={exportReport}>
          <Download size={16} /> Export Report
        </button>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Threat level</div>
          <div style={{ marginTop: 8 }}>
            <SeverityBadge level={apk.risk} />
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Risk score</div>
          <div className="stat-value" style={{ color: "var(--danger)" }}>
            {apk.score}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Campaign</div>
          <Link to={`/app/campaigns/${apk.campaignId}`} style={{ color: "var(--accent)", fontWeight: 600 }}>
            {apk.campaign}
          </Link>
        </div>
        <div className="stat-card">
          <div className="stat-label">Related APKs</div>
          <div className="stat-value">{apk.relatedCount}</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">Metadata & indicators</div>
          <div style={{ fontSize: 13.5, display: "grid", gap: 8 }}>
            <Row label="SHA-256" value={apk.sha256} mono />
            <Row label="First seen" value={apk.firstSeen} />
            <Row label="Last seen" value={apk.lastSeen} />
            <Row label="Certificate" value={apk.certificate.subject} />
            <Row label="Cert shared with" value={`${apk.certificate.sharedWith} samples`} />
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="card-title">Suspicious permissions</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {apk.permissions.map((p) => (
                <span
                  key={p}
                  style={{
                    padding: "4px 8px",
                    background: "var(--danger-dim)",
                    color: "var(--danger)",
                    borderRadius: 6,
                    fontSize: 12,
                    fontFamily: "monospace",
                  }}
                >
                  {p}
                </span>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="card-title">Suspicious domains</div>
            <ul style={{ paddingLeft: 18, color: "var(--text-muted)", fontSize: 13.5 }}>
              {apk.domains.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>
          </div>
          <div style={{ marginTop: 16 }}>
            <div className="card-title">Threat indicators</div>
            <ul style={{ paddingLeft: 18, color: "var(--text-muted)", fontSize: 13.5 }}>
              {apk.indicators.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>
          </div>
        </div>

        <div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div className="card-title" style={{ marginBottom: 0, display: "flex", alignItems: "center", gap: 8 }}>
                <Sparkles size={14} color="var(--accent)" /> Why was this APK flagged?
              </div>
              <button type="button" className="btn-ghost" style={{ padding: "6px 10px" }} onClick={() => setSimple((s) => !s)}>
                {simple ? "Technical view" : "Explain in simple terms"}
              </button>
            </div>
            <p style={{ marginTop: 14, fontSize: 14, color: "var(--text-muted)", lineHeight: 1.6 }}>
              {simple ? apk.aiSimple : apk.aiExplanation}
            </p>
            <button
              type="button"
              onClick={() => setShowEvidence((v) => !v)}
              style={{
                marginTop: 12,
                display: "flex",
                alignItems: "center",
                gap: 6,
                color: "var(--accent)",
                fontSize: 13,
                fontWeight: 600,
              }}
            >
              {showEvidence ? <ChevronUp size={14} /> : <ChevronDown size={14} />} Evidence vs AI interpretation
            </button>
            {showEvidence && (
              <div
                style={{
                  marginTop: 10,
                  padding: 12,
                  background: "var(--bg)",
                  borderRadius: 8,
                  border: "1px solid var(--border)",
                  fontSize: 13,
                }}
              >
                <div style={{ color: "var(--text-dim)", marginBottom: 6 }}>Detected evidence</div>
                <div>Certificate reuse · TLSH similarity · High-risk permissions · Domain contacts</div>
                <div style={{ color: "var(--text-dim)", margin: "10px 0 6px" }}>AI-generated interpretation</div>
                <div style={{ color: "var(--text-muted)" }}>
                  Narrative above synthesizes evidence into analyst-ready language; it is not a substitute for raw indicators.
                </div>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title">MITRE ATT&CK mapping</div>
            <div style={{ display: "grid", gap: 8 }}>
              {mitreTechniques.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setOpenMitre(openMitre === t.id ? null : t.id)}
                  style={{
                    textAlign: "left",
                    padding: 12,
                    background: "var(--bg)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <strong style={{ color: "var(--blue)" }}>{t.id}</strong>
                    {openMitre === t.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  </div>
                  <div style={{ fontSize: 14, marginTop: 4 }}>{t.name}</div>
                  {openMitre === t.id && (
                    <p style={{ marginTop: 8, fontSize: 13, color: "var(--text-muted)" }}>{t.evidence}</p>
                  )}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Related samples · navigate to campaign / graph</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 12 }}>
          <Link to={`/app/campaigns/${apk.campaignId}`} className="btn-outline">
            Open campaign
          </Link>
          <Link to="/app/graph" className="btn-ghost">
            Open graph investigation
          </Link>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>APK</th>
              <th>Risk</th>
              <th>Score</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {related.map((r) => (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td>
                  <SeverityBadge level={r.risk} />
                </td>
                <td>{r.score}</td>
                <td>
                  <Link to={`/app/apk/${r.id}`} style={{ color: "var(--accent)" }}>
                    View
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Row({ label, value, mono }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: 8 }}>
      <span style={{ color: "var(--text-dim)" }}>{label}</span>
      <span style={{ fontFamily: mono ? "monospace" : undefined, wordBreak: "break-all" }}>{value}</span>
    </div>
  );
}
