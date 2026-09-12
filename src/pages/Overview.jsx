import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Upload,
  Search,
  Megaphone,
  Download,
  AlertTriangle,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import SeverityBadge from "../components/SeverityBadge";
import { useAuth } from "../context/AuthContext";
import {
  stats,
  threatOverTime,
  severityDistribution,
  recentApks,
  campaigns,
  alerts,
} from "../data/mockData";
import { exportIntelligencePdf } from "../utils/exportPdf";

export default function Overview() {
  const navigate = useNavigate();
  const { showToast } = useAuth();
  const fileRef = useRef(null);
  const [dragOver, setDragOver] = useState(false);

  const handleFile = (file) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".apk")) {
      showToast("Please upload a valid .apk file", "error");
      return;
    }
    showToast(`Uploaded ${file.name} — starting analysis`);
    navigate("/app/apk-analysis", { state: { fileName: file.name, analyzing: true } });
  };

  const exportReport = () => {
    exportIntelligencePdf({ stats, recentApks, campaigns });
    showToast("Intelligence report exported as PDF");
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Intelligence Overview</h1>
          <p>Threat environment snapshot and quick investigation actions</p>
        </div>
        <button type="button" className="btn-primary" onClick={exportReport}>
          <Download size={16} /> Export Report
        </button>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">APKs Analyzed</div>
          <div className="stat-value">{stats.apksAnalyzed.toLocaleString()}</div>
          <div className="stat-hint">+128 this week</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Malicious APKs</div>
          <div className="stat-value" style={{ color: "var(--danger)" }}>
            {stats.maliciousApks}
          </div>
          <div className="stat-hint">16.9% of total</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Active Campaigns</div>
          <div className="stat-value" style={{ color: "var(--warning)" }}>
            {stats.activeCampaigns}
          </div>
          <div className="stat-hint">3 surged in 24h</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">High-Risk Samples</div>
          <div className="stat-value" style={{ color: "#ff7a59" }}>
            {stats.highRiskSamples}
          </div>
          <div className="stat-hint">Needs review</div>
        </div>
      </div>

      <div
        className="card"
        style={{
          marginBottom: 16,
          borderStyle: "dashed",
          borderColor: dragOver ? "var(--accent)" : "var(--border-strong)",
          background: dragOver ? "var(--accent-dim)" : undefined,
          textAlign: "center",
          padding: 28,
          cursor: "pointer",
        }}
        onClick={() => fileRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          handleFile(e.dataTransfer.files?.[0]);
        }}
      >
        <Upload size={28} color="var(--accent)" style={{ margin: "0 auto 10px" }} />
        <h3 style={{ fontFamily: "var(--font-display)", marginBottom: 6 }}>
          Upload an APK for analysis
        </h3>
        <p style={{ color: "var(--text-muted)", fontSize: 14 }}>
          Drag & drop a suspicious .apk here, or click to browse
        </p>
        <input
          ref={fileRef}
          type="file"
          accept=".apk"
          hidden
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
      </div>

      <div className="grid-3" style={{ marginBottom: 16 }}>
        <button type="button" className="card" style={{ textAlign: "left", cursor: "pointer" }} onClick={() => navigate("/app/apk-analysis")}>
          <Upload size={18} color="var(--accent)" />
          <div style={{ marginTop: 10, fontWeight: 600 }}>Upload APK</div>
          <div style={{ fontSize: 13, color: "var(--text-muted)" }}>Start analysis pipeline</div>
        </button>
        <button type="button" className="card" style={{ textAlign: "left", cursor: "pointer" }} onClick={() => navigate("/app/search")}>
          <Search size={18} color="var(--blue)" />
          <div style={{ marginTop: 10, fontWeight: 600 }}>Search Intelligence</div>
          <div style={{ fontSize: 13, color: "var(--text-muted)" }}>Hash, cert, package, campaign</div>
        </button>
        <button type="button" className="card" style={{ textAlign: "left", cursor: "pointer" }} onClick={() => navigate("/app/campaigns")}>
          <Megaphone size={18} color="var(--warning)" />
          <div style={{ marginTop: 10, fontWeight: 600 }}>Open Campaigns</div>
          <div style={{ fontSize: 13, color: "var(--text-muted)" }}>Explore fraud rings</div>
        </button>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">Threat activity (7 days)</div>
          <div style={{ height: 220 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={threatOverTime}>
                <defs>
                  <linearGradient id="det" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00d4aa" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#00d4aa" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" stroke="#5c6d86" fontSize={12} />
                <YAxis stroke="#5c6d86" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    background: "#0f1828",
                    border: "1px solid #1c2b3f",
                    borderRadius: 8,
                  }}
                />
                <Area type="monotone" dataKey="detections" stroke="#00d4aa" fill="url(#det)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card">
          <div className="card-title">Threat severity distribution</div>
          <div style={{ height: 220 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityDistribution}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={3}
                >
                  {severityDistribution.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#0f1828",
                    border: "1px solid #1c2b3f",
                    borderRadius: 8,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "center" }}>
            {severityDistribution.map((s) => (
              <span key={s.name} style={{ fontSize: 12, color: "var(--text-muted)" }}>
                <span style={{ color: s.color }}>●</span> {s.name} ({s.value})
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">Recent suspicious APKs</div>
          <table className="data-table">
            <thead>
              <tr>
                <th>APK</th>
                <th>Risk</th>
                <th>Score</th>
                <th>Campaign</th>
              </tr>
            </thead>
            <tbody>
              {recentApks.map((apk) => (
                <tr key={apk.id} style={{ cursor: "pointer" }} onClick={() => navigate(`/app/apk/${apk.id}`)}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{apk.name}</div>
                    <div style={{ fontSize: 12, color: "var(--text-dim)" }}>{apk.package}</div>
                  </td>
                  <td>
                    <SeverityBadge level={apk.risk} />
                  </td>
                  <td>{apk.score}</td>
                  <td style={{ color: "var(--text-muted)" }}>{apk.campaign}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <div className="card-title">Active campaigns & alerts</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
            {campaigns.slice(0, 3).map((c) => (
              <Link
                key={c.id}
                to={`/app/campaigns/${c.id}`}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "10px 12px",
                  background: "var(--bg)",
                  borderRadius: 8,
                  border: "1px solid var(--border)",
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14 }}>{c.name}</div>
                  <div style={{ fontSize: 12, color: "var(--text-dim)" }}>{c.apkCount} samples</div>
                </div>
                <SeverityBadge level={c.risk} />
              </Link>
            ))}
          </div>
          <div className="card-title">Recent alerts</div>
          {alerts.slice(0, 3).map((a) => (
            <Link
              key={a.id}
              to={a.link}
              style={{
                display: "flex",
                gap: 10,
                padding: "10px 0",
                borderBottom: "1px solid var(--border)",
                fontSize: 13,
              }}
            >
              <AlertTriangle size={16} color="var(--warning)" style={{ flexShrink: 0, marginTop: 2 }} />
              <div>
                <div>{a.title}</div>
                <div style={{ color: "var(--text-dim)", fontSize: 12 }}>{a.time}</div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
