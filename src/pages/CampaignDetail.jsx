import { Link, useParams } from "react-router-dom";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import SeverityBadge from "../components/SeverityBadge";
import { campaigns, recentApks, analytics } from "../data/mockData";

export default function CampaignDetail() {
  const { id } = useParams();
  const campaign = campaigns.find((c) => c.id === id) || campaigns[0];
  const related = recentApks.filter((a) => a.campaign === campaign.name);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>{campaign.name}</h1>
          <p>
            First seen {campaign.firstSeen} · Last seen {campaign.lastSeen}
          </p>
        </div>
        <SeverityBadge level={campaign.risk} />
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Related APKs</div>
          <div className="stat-value">{campaign.apkCount}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Certificates</div>
          <div className="stat-value">{campaign.certificates}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Domains</div>
          <div className="stat-value">{campaign.domains}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Package families</div>
          <div className="stat-value">{campaign.packages}</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">Campaign risk summary</div>
          <p style={{ color: "var(--text-muted)", fontSize: 14, lineHeight: 1.6 }}>{campaign.summary}</p>
          <Link to="/app/graph" className="btn-outline" style={{ marginTop: 16 }}>
            Open relationship graph
          </Link>
        </div>
        <div className="card">
          <div className="card-title">Growth / activity timeline</div>
          <div style={{ height: 200 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={analytics.campaignGrowth}>
                <XAxis dataKey="month" stroke="#5c6d86" fontSize={12} />
                <YAxis stroke="#5c6d86" fontSize={12} />
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
        <div className="card-title">Related APKs</div>
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Package</th>
              <th>Risk</th>
              <th>Score</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(related.length ? related : recentApks.slice(0, 3)).map((apk) => (
              <tr key={apk.id}>
                <td>{apk.name}</td>
                <td style={{ color: "var(--text-muted)" }}>{apk.package}</td>
                <td>
                  <SeverityBadge level={apk.risk} />
                </td>
                <td>{apk.score}</td>
                <td>
                  <Link to={`/app/apk/${apk.id}`} style={{ color: "var(--accent)" }}>
                    Report
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
