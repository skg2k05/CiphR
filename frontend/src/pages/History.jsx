import { Link } from "react-router-dom";
import SeverityBadge from "../components/SeverityBadge";
import { historyItems } from "../data/mockData";

export default function History() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Investigation History</h1>
          <p>Previously analyzed samples and analyst activity</p>
        </div>
      </div>

      <div className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>APK</th>
              <th>Analyzed</th>
              <th>Risk</th>
              <th>Campaign</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {historyItems.map((h) => (
              <tr key={h.id}>
                <td style={{ fontWeight: 600 }}>{h.name}</td>
                <td>{h.date}</td>
                <td>
                  <SeverityBadge level={h.risk} />
                </td>
                <td>{h.campaign}</td>
                <td>
                  <div style={{ display: "flex", gap: 12, fontSize: 13 }}>
                    <Link to={`/app/apk/${h.apkId}`} style={{ color: "var(--accent)" }}>
                      Report
                    </Link>
                    <Link to="/app/campaigns/camp-001" style={{ color: "var(--blue)" }}>
                      Campaign
                    </Link>
                    <Link to="/app/graph" style={{ color: "var(--warning)" }}>
                      Graph
                    </Link>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
