import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Search as SearchIcon } from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import { recentApks, campaigns } from "../data/mockData";

export default function SearchPage() {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") || "";

  const results = useMemo(() => {
    const term = q.trim().toLowerCase();
    if (!term) {
      return { apks: recentApks, campaigns, certificates: [], domains: [] };
    }
    const apks = recentApks.filter(
      (a) =>
        a.name.toLowerCase().includes(term) ||
        a.package.toLowerCase().includes(term) ||
        a.sha256.toLowerCase().includes(term) ||
        a.campaign.toLowerCase().includes(term)
    );
    const camps = campaigns.filter(
      (c) => c.name.toLowerCase().includes(term) || c.id.toLowerCase().includes(term)
    );
    const certificates = term.includes("cert") || term.includes("quick") || term.includes("sha")
      ? [{ name: "CN=QuickSoft Labs", shared: 8 }]
      : [];
    const domains = ["verify-kyc-loan.in", "cdn-quickupdate.xyz", "upi-secure-auth.in"].filter((d) =>
      d.includes(term)
    );
    return { apks, campaigns: camps, certificates, domains };
  }, [q]);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Search & Investigate</h1>
          <p>Search by APK name, SHA-256, certificate, campaign, or package</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <SearchIcon size={18} color="var(--text-dim)" />
          <input
            value={q}
            onChange={(e) => setParams(e.target.value ? { q: e.target.value } : {})}
            placeholder="e.g. QuickKYC, Fake Loan, a3f2c8e1, com.quickkyc..."
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              outline: "none",
              fontSize: 15,
            }}
          />
        </div>
      </div>

      <div className="grid-2">
        <ResultGroup title="APKs">
          {results.apks.map((a) => (
            <Link key={a.id} to={`/app/apk/${a.id}`} className="result-row">
              <div>
                <strong>{a.name}</strong>
                <div className="muted">{a.package}</div>
              </div>
              <SeverityBadge level={a.risk} />
            </Link>
          ))}
          {!results.apks.length && <Empty />}
        </ResultGroup>

        <ResultGroup title="Campaigns">
          {results.campaigns.map((c) => (
            <Link key={c.id} to={`/app/campaigns/${c.id}`} className="result-row">
              <div>
                <strong>{c.name}</strong>
                <div className="muted">{c.apkCount} samples</div>
              </div>
              <SeverityBadge level={c.risk} />
            </Link>
          ))}
          {!results.campaigns.length && <Empty />}
        </ResultGroup>

        <ResultGroup title="Certificates">
          {results.certificates.map((c) => (
            <div key={c.name} className="result-row static">
              <div>
                <strong>{c.name}</strong>
                <div className="muted">Shared with {c.shared} samples</div>
              </div>
            </div>
          ))}
          {!results.certificates.length && <Empty />}
        </ResultGroup>

        <ResultGroup title="Domains">
          {results.domains.map((d) => (
            <div key={d} className="result-row static">
              <strong>{d}</strong>
            </div>
          ))}
          {!results.domains.length && <Empty />}
        </ResultGroup>
      </div>

      <style>{`
        .result-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
          padding: 12px;
          border-bottom: 1px solid var(--border);
        }
        .result-row:hover { background: var(--bg-hover); }
        .result-row.static { cursor: default; }
        .muted { font-size: 12px; color: var(--text-dim); margin-top: 2px; }
      `}</style>
    </div>
  );
}

function ResultGroup({ title, children }) {
  return (
    <div className="card">
      <div className="card-title">{title}</div>
      {children}
    </div>
  );
}

function Empty() {
  return <div style={{ padding: 12, color: "var(--text-dim)", fontSize: 13 }}>No matches</div>;
}
