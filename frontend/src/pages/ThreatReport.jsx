import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ChevronDown, ChevronUp, Sparkles, Download, Loader2 } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import ThreatNarrativeView from "../components/ThreatNarrativeView";
import { exportPdf } from "../utils/exportPdf";
import api from "../api/client";

export default function ThreatReport() {
  const { id } = useParams();
  const [loading, setLoading] = useState(true);
  const [sample, setSample] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [findings, setFindings] = useState([]);
  const [related, setRelated] = useState([]);
  const [openMitre, setOpenMitre] = useState(null);
  const [simple, setSimple] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);

  useEffect(() => {
    let isMounted = true;
    setLoading(true);

    Promise.allSettled([
      api.getSample(id),
      api.getSampleAnalysis(id),
      api.getSampleFindings(id),
      api.getRelatedSamples(id),
    ]).then(([sRes, aRes, fRes, rRes]) => {
      if (!isMounted) return;
      if (sRes.status === "fulfilled") setSample(sRes.value);
      if (aRes.status === "fulfilled") setAnalysis(aRes.value);
      if (fRes.status === "fulfilled") setFindings(Array.isArray(fRes.value) ? fRes.value : []);
      if (rRes.status === "fulfilled") setRelated(rRes.value?.items || []);
      setLoading(false);
    }).catch(() => {
      if (isMounted) setLoading(false);
    });

    return () => {
      isMounted = false;
    };
  }, [id]);

  if (loading) {
    return (
      <div style={{ padding: 48, textAlign: "center", color: "var(--text-muted)" }}>
        <Loader2 size={32} className="spin" style={{ margin: "0 auto 16px", color: "var(--accent)" }} />
        <p>Loading threat report from backend...</p>
        <style>{`
          .spin { animation: spin 1s linear infinite; }
          @keyframes spin { to { transform: rotate(360deg); } }
        `}</style>
      </div>
    );
  }

  // Derive campaign information
  const campaign = sample?.campaigns?.[0] || (related.find((r) => r.campaign_id) ? {
    id: related.find((r) => r.campaign_id).campaign_id,
    name: related.find((r) => r.campaign_id).campaign_name || "Correlated Campaign",
  } : null);

  const appTitle = analysis?.app_name || sample?.filename || "Unknown APK";
  const packageName = analysis?.package_name || "N/A";
  const version = analysis?.version_name ? `v${analysis.version_name}` : (analysis?.version_code ? `build ${analysis.version_code}` : "");
  const riskScore = analysis?.risk_score ?? (sample?.status === "COMPLETED" ? 0 : 0);
  const riskLevel = analysis?.risk_level || (riskScore >= 80 ? "Critical" : riskScore >= 50 ? "High" : riskScore >= 20 ? "Medium" : "Low");

  const factorStrings = (analysis?.risk_factors || []).map((f) => {
    if (typeof f === "object" && f !== null) {
      return f.indicator || f.mitre_technique_name || f.title || f.evidence || JSON.stringify(f);
    }
    return String(f);
  });

  const mitreTechniques = findings
    .filter((f) => f.mitre_technique_id)
    .map((f) => ({
      id: f.mitre_technique_id,
      name: f.title,
      evidence: f.evidence || f.description || "Observed during static manifest/DEX inspection.",
    }));

  return (
    <div id="threat-report">
      <div className="page-header">
        <div>
          <h1>{appTitle}</h1>
          <p>
            {packageName} {version && `· ${version}`} · SHA-256: {sample?.sha256?.slice(0, 16)}...
          </p>
        </div>
        <button
          type="button"
          className="btn-outline"
          onClick={() => exportPdf({ apk: { name: appTitle, package: packageName, risk: riskLevel, score: riskScore }, mitreTechniques })}
        >
          <Download size={16} /> Export PDF
        </button>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Threat level</div>
          <div style={{ marginTop: 8 }}>
            <SeverityBadge level={riskLevel} />
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Risk score</div>
          <div
            className="stat-value"
            style={{
              color: riskScore >= 70 ? "var(--danger)" : riskScore >= 40 ? "var(--warning)" : "var(--accent)",
            }}
          >
            {riskScore}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Campaign</div>
          {campaign ? (
            <Link
              to={`/app/campaigns/${campaign.id}`}
              style={{ color: "var(--accent)", fontWeight: 600, display: "inline-block", marginTop: 8 }}
            >
              {campaign.name}
            </Link>
          ) : (
            <div className="stat-value" style={{ fontSize: 16, color: "var(--text-muted)", marginTop: 8 }}>
              Standalone / None
            </div>
          )}
        </div>
        <div className="stat-card">
          <div className="stat-label">Related APKs</div>
          <div className="stat-value">{related.length}</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">Metadata & indicators</div>
          <div style={{ fontSize: 13.5, display: "grid", gap: 8 }}>
            <Row label="SHA-256" value={sample?.sha256 || "N/A"} mono />
            <Row
              label="First seen"
              value={sample?.created_at ? new Date(sample.created_at).toLocaleString() : "N/A"}
            />
            <Row
              label="Last updated"
              value={sample?.updated_at ? new Date(sample.updated_at).toLocaleString() : "N/A"}
            />
            <Row
              label="Certificate"
              value={
                analysis?.certificate_details?.subject ||
                analysis?.certificate_fingerprint ||
                "N/A"
              }
            />
            <Row
              label="Cert shared with"
              value={`${
                analysis?.certificate_details?.shared_with ??
                related.filter((r) => r.relationship === "SHARED_CERTIFICATE").length
              } samples`}
            />
            {(analysis?.min_sdk || analysis?.target_sdk) && (
              <Row
                label="SDK (Min / Target)"
                value={`${analysis.min_sdk || "?"} / ${analysis.target_sdk || "?"}`}
              />
            )}
            {analysis?.tlsh && <Row label="TLSH" value={analysis.tlsh} mono />}
          </div>

          <div style={{ marginTop: 16 }}>
            <div className="card-title">Declared permissions ({analysis?.permissions?.length || 0})</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {analysis?.permissions && analysis.permissions.length > 0 ? (
                analysis.permissions.map((p) => (
                  <span
                    key={p}
                    style={{
                      padding: "4px 8px",
                      background: "var(--danger-dim, rgba(255, 77, 106, 0.1))",
                      color: "var(--danger)",
                      borderRadius: 6,
                      fontSize: 12,
                      fontFamily: "monospace",
                    }}
                  >
                    {p}
                  </span>
                ))
              ) : (
                <span style={{ color: "var(--text-dim)", fontSize: 13 }}>No permissions declared</span>
              )}
            </div>
          </div>

          {analysis?.risk_factors && analysis.risk_factors.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="card-title">Threat indicators & risk factors ({analysis.risk_factors.length})</div>
              <ul style={{ paddingLeft: 18, color: "var(--text-muted)", fontSize: 13.5 }}>
                {analysis.risk_factors.map((factor, idx) => {
                  if (typeof factor === "object" && factor !== null) {
                    return (
                      <li key={idx} style={{ marginBottom: 6 }}>
                        <strong style={{ color: factor.severity === "CRITICAL" ? "var(--danger)" : "var(--text)" }}>
                          {factor.indicator || factor.title || "Suspicious Indicator"}
                        </strong>
                        {factor.evidence && (
                          <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 2 }}>
                            {factor.evidence}
                          </div>
                        )}
                      </li>
                    );
                  }
                  return <li key={idx} style={{ marginBottom: 4 }}>{String(factor)}</li>;
                })}
              </ul>
            </div>
          )}

          {analysis?.dex_data && (
            <div style={{ marginTop: 16 }}>
              <div className="card-title">DEX Intelligence</div>
              <div style={{ fontSize: 13, display: "grid", gap: 6, color: "var(--text-muted)" }}>
                {analysis.dex_data.class_count !== undefined && (
                  <div>Classes detected: {analysis.dex_data.class_count}</div>
                )}
                {analysis.dex_data.method_count !== undefined && (
                  <div>Methods detected: {analysis.dex_data.method_count}</div>
                )}
                {analysis.dex_data.suspicious_strings?.length > 0 && (
                  <div>
                    Suspicious strings: {analysis.dex_data.suspicious_strings.slice(0, 5).join(", ")}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        <div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div className="card-title" style={{ marginBottom: 0, display: "flex", alignItems: "center", gap: 8 }}>
                <Sparkles size={14} color="var(--accent)" /> Why was this APK flagged?
              </div>
              <button
                type="button"
                className="btn-ghost"
                style={{ padding: "6px 10px" }}
                onClick={() => setSimple((s) => !s)}
              >
                {simple ? "Technical view" : "Explain in simple terms"}
              </button>
            </div>
            <ThreatNarrativeView
              narrative={analysis?.threat_narrative}
              simple={simple}
              riskScore={riskScore}
              appName={appTitle}
              factorStrings={factorStrings}
              findings={findings}
            />
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
                background: "none",
                border: "none",
                cursor: "pointer",
                padding: 0,
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
                <div style={{ color: "var(--text-dim)", marginBottom: 6 }}>Detected evidence (Deterministic)</div>
                <div>
                  {factorStrings.length > 0
                    ? factorStrings.join(" · ")
                    : "Certificate validation · SHA-256 integrity · Permission analysis"}
                </div>
                <div style={{ color: "var(--text-dim)", margin: "10px 0 6px" }}>AI-generated interpretation</div>
                <div style={{ color: "var(--text-muted)" }}>
                  {analysis?.threat_narrative || "Synthesizes evidence into analyst-ready language; not a substitute for raw indicators."}
                </div>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-title">MITRE ATT&CK mapping ({mitreTechniques.length})</div>
            <div style={{ display: "grid", gap: 8 }}>
              {mitreTechniques.length > 0 ? (
                mitreTechniques.map((t, idx) => (
                  <button
                    key={`${t.id}-${idx}`}
                    type="button"
                    onClick={() => setOpenMitre(openMitre === t.id ? null : t.id)}
                    style={{
                      textAlign: "left",
                      padding: 12,
                      background: "var(--bg)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      cursor: "pointer",
                      width: "100%",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <strong style={{ color: "var(--blue)" }}>{t.id}</strong>
                      {openMitre === t.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </div>
                    <div style={{ fontSize: 14, marginTop: 4, color: "var(--text)" }}>{t.name}</div>
                    {openMitre === t.id && (
                      <p style={{ marginTop: 8, fontSize: 13, color: "var(--text-muted)" }}>{t.evidence}</p>
                    )}
                  </button>
                ))
              ) : (
                <div style={{ color: "var(--text-dim)", fontSize: 13, padding: 8 }}>
                  No MITRE ATT&CK techniques mapped for this sample.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Related samples · navigate to campaign / graph</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginBottom: 12 }}>
          {campaign && (
            <Link to={`/app/campaigns/${campaign.id}`} className="btn-outline">
              Open campaign
            </Link>
          )}
          <Link to="/app/graph" className="btn-ghost">
            Open graph investigation
          </Link>
        </div>
        <table className="data-table">
          <thead>
            <tr>
              <th>APK</th>
              <th>Relationship</th>
              <th>Confidence</th>
              <th>Reason</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {related.length > 0 ? (
              related.map((r, idx) => (
                <tr key={r.sample_id || idx}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{r.filename || "Related Sample"}</div>
                    <div style={{ fontSize: 12, color: "var(--text-dim)" }}>{r.sha256?.slice(0, 16)}...</div>
                  </td>
                  <td>
                    <span
                      style={{
                        padding: "3px 8px",
                        borderRadius: 6,
                        background: "var(--accent-dim)",
                        color: "var(--accent)",
                        fontSize: 12,
                        fontWeight: 600,
                      }}
                    >
                      {r.relationship}
                    </span>
                  </td>
                  <td>{Math.round((r.confidence || 0) * 100)}%</td>
                  <td style={{ color: "var(--text-muted)", fontSize: 13 }}>{r.reason || "-"}</td>
                  <td>
                    <Link to={`/app/apk/${r.sample_id}`} style={{ color: "var(--accent)", fontWeight: 600 }}>
                      View
                    </Link>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} style={{ textAlign: "center", color: "var(--text-dim)", padding: 24 }}>
                  No correlated samples found for this APK.
                </td>
              </tr>
            )}
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
