import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { analytics, severityDistribution, campaigns } from "../data/mockData";

const COLORS = ["#00d4aa", "#3b9eff", "#ffb020", "#ff4d6a", "#a78bfa"];

export default function Analytics() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Threat Analytics</h1>
          <p>Trends, distributions and recurring attack patterns</p>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">Campaign growth over time</div>
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={analytics.campaignGrowth}>
                <XAxis dataKey="month" stroke="#5c6d86" fontSize={12} />
                <YAxis stroke="#5c6d86" fontSize={12} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line type="monotone" dataKey="samples" stroke="#00d4aa" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card">
          <div className="card-title">Threat category distribution</div>
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={analytics.categories} dataKey="value" nameKey="name" outerRadius={90}>
                  {analytics.categories.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid-2" style={{ marginTop: 16 }}>
        <div className="card">
          <div className="card-title">Risk-score / severity distribution</div>
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityDistribution}>
                <XAxis dataKey="name" stroke="#5c6d86" fontSize={12} />
                <YAxis stroke="#5c6d86" fontSize={12} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {severityDistribution.map((e) => (
                    <Cell key={e.name} fill={e.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="card">
          <div className="card-title">MITRE ATT&CK technique frequency</div>
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analytics.mitreFreq} layout="vertical" margin={{ left: 20 }}>
                <XAxis type="number" stroke="#5c6d86" fontSize={12} />
                <YAxis type="category" dataKey="id" stroke="#5c6d86" fontSize={12} width={55} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="count" fill="#3b9eff" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid-2" style={{ marginTop: 16 }}>
        <div className="card">
          <div className="card-title">Most frequently observed certificates</div>
          {analytics.topCerts.map((c) => (
            <div
              key={c.name}
              style={{
                display: "flex",
                justifyContent: "space-between",
                padding: "12px 0",
                borderBottom: "1px solid var(--border)",
                fontSize: 14,
              }}
            >
              <span style={{ fontFamily: "monospace", fontSize: 13 }}>{c.name}</span>
              <strong>{c.count}</strong>
            </div>
          ))}
        </div>
        <div className="card">
          <div className="card-title">Most active campaigns</div>
          {[...campaigns]
            .sort((a, b) => b.apkCount - a.apkCount)
            .map((c) => (
              <div
                key={c.id}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "12px 0",
                  borderBottom: "1px solid var(--border)",
                  fontSize: 14,
                }}
              >
                <span>{c.name}</span>
                <strong>{c.apkCount} APKs</strong>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}

const tooltipStyle = {
  background: "#0f1828",
  border: "1px solid #1c2b3f",
  borderRadius: 8,
};
