import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Upload, CheckCircle2, Loader2, FileArchive } from "lucide-react";
import { pipelineStages, recentApks } from "../data/mockData";
import SeverityBadge from "../components/SeverityBadge";
import { useAuth } from "../context/AuthContext";

export default function ApkAnalysis() {
  const location = useLocation();
  const navigate = useNavigate();
  const { showToast } = useAuth();
  const fileRef = useRef(null);
  const [fileName, setFileName] = useState(location.state?.fileName || "");
  const [stage, setStage] = useState(-1);
  const [done, setDone] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  useEffect(() => {
    if (location.state?.analyzing && location.state?.fileName) {
      startAnalysis(location.state.fileName);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startAnalysis = (name) => {
    setFileName(name);
    setDone(false);
    setStage(0);
    let i = 0;
    const timer = setInterval(() => {
      i += 1;
      if (i >= pipelineStages.length) {
        clearInterval(timer);
        setStage(pipelineStages.length);
        setDone(true);
        showToast("Analysis complete");
      } else {
        setStage(i);
      }
    }, 700);
  };

  const handleFile = (file) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".apk")) {
      showToast("Please upload a valid .apk file", "error");
      return;
    }
    startAnalysis(file.name);
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>APK Analysis</h1>
          <p>Upload, monitor the pipeline, and open threat reports</p>
        </div>
        <button type="button" className="btn-ghost" onClick={() => navigate("/app/compare")}>
          Compare APKs
        </button>
      </div>

      <div
        className="card"
        style={{
          marginBottom: 16,
          borderStyle: "dashed",
          borderColor: dragOver ? "var(--accent)" : "var(--border-strong)",
          textAlign: "center",
          padding: 32,
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
        <h3 style={{ fontFamily: "var(--font-display)" }}>Drop APK here or browse</h3>
        <p style={{ color: "var(--text-muted)", fontSize: 14, marginTop: 6 }}>
          Validates .apk extension · Max demo size unlimited (mock)
        </p>
        <input
          ref={fileRef}
          type="file"
          accept=".apk"
          hidden
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
      </div>

      {(stage >= 0 || fileName) && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-title">Analysis progress</div>
          {fileName && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
              <FileArchive size={18} color="var(--accent)" />
              <strong>{fileName}</strong>
            </div>
          )}
          <div style={{ display: "grid", gap: 8 }}>
            {pipelineStages.map((s, i) => {
              const complete = stage > i || (done && stage >= pipelineStages.length);
              const active = stage === i && !done;
              return (
                <div
                  key={s}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "10px 12px",
                    borderRadius: 8,
                    background: active ? "var(--accent-dim)" : "var(--bg)",
                    border: `1px solid ${active ? "var(--accent)" : "var(--border)"}`,
                    color: complete || active ? "var(--text)" : "var(--text-dim)",
                  }}
                >
                  {complete ? (
                    <CheckCircle2 size={16} color="var(--accent)" />
                  ) : active ? (
                    <Loader2 size={16} color="var(--accent)" className="spin" />
                  ) : (
                    <span style={{ width: 16, height: 16, borderRadius: "50%", border: "1px solid var(--border-strong)" }} />
                  )}
                  {s}
                </div>
              );
            })}
          </div>
          {done && (
            <button
              type="button"
              className="btn-primary"
              style={{ marginTop: 16 }}
              onClick={() => navigate("/app/apk/apk-001")}
            >
              Open threat report
            </button>
          )}
        </div>
      )}

      <div className="card">
        <div className="card-title">Recent analyses</div>
        <table className="data-table">
          <thead>
            <tr>
              <th>APK</th>
              <th>Risk</th>
              <th>Score</th>
              <th>First seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {recentApks.map((apk) => (
              <tr key={apk.id}>
                <td>
                  <div style={{ fontWeight: 600 }}>{apk.name}</div>
                  <div style={{ fontSize: 12, color: "var(--text-dim)" }}>{apk.sha256}</div>
                </td>
                <td>
                  <SeverityBadge level={apk.risk} />
                </td>
                <td>{apk.score}</td>
                <td>{apk.firstSeen}</td>
                <td>
                  <Link to={`/app/apk/${apk.id}`} style={{ color: "var(--accent)", fontWeight: 600 }}>
                    Report
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <style>{`
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
