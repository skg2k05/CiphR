import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Upload, CheckCircle2, Loader2, FileArchive, AlertCircle } from "lucide-react";
import { pipelineStages, recentApks } from "../data/mockData";
import SeverityBadge from "../components/SeverityBadge";
import { useAuth } from "../context/AuthContext";
import api from "../api/client";

export default function ApkAnalysis() {
  const location = useLocation();
  const navigate = useNavigate();
  const { showToast } = useAuth();
  const fileRef = useRef(null);
  const [fileName, setFileName] = useState(location.state?.fileName || "");
  const [sampleId, setSampleId] = useState(null);
  const [stage, setStage] = useState(-1);
  const [done, setDone] = useState(false);
  const [failed, setFailed] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [recentList, setRecentList] = useState([]);
  const pollTimerRef = useRef(null);
  const stageTimerRef = useRef(null);

  const fetchRecent = () => {
    api.listSamples({ size: 10 })
      .then((res) => {
        if (res?.items?.length) {
          setRecentList(res.items);
        }
      })
      .catch((err) => console.error("Failed to load recent samples", err));
  };

  useEffect(() => {
    fetchRecent();
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      if (stageTimerRef.current) clearInterval(stageTimerRef.current);
    };
  }, []);

  const handleUpload = async (file) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".apk")) {
      showToast("Please upload a valid .apk file", "error");
      return;
    }

    setFileName(file.name);
    setDone(false);
    setFailed(false);
    setErrorMessage("");
    setStage(0); // Stage 0: APK Upload

    try {
      // 1. POST /samples/upload
      const sample = await api.uploadSample(file);
      const sid = sample.id;
      setSampleId(sid);
      setStage(1); // Upload succeeded, advance to Parsing

      // Incremental stage progression while waiting for pipeline
      let currentVisualStage = 1;
      stageTimerRef.current = setInterval(() => {
        if (currentVisualStage < pipelineStages.length - 1) {
          currentVisualStage += 1;
          setStage(currentVisualStage);
        }
      }, 700);

      // 2. Poll /samples/{sample_id}/status
      pollTimerRef.current = setInterval(async () => {
        try {
          const statusRes = await api.getSampleStatus(sid);
          const status = statusRes.status?.toUpperCase();

          if (status === "COMPLETED") {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            if (stageTimerRef.current) clearInterval(stageTimerRef.current);
            setStage(pipelineStages.length);
            setDone(true);
            showToast("Analysis complete");
            fetchRecent();
          } else if (status === "FAILED") {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            if (stageTimerRef.current) clearInterval(stageTimerRef.current);
            setFailed(true);
            const err = statusRes.stages?.error || "Pipeline analysis failed";
            setErrorMessage(err);
            showToast(err, "error");
          }
        } catch (pollErr) {
          console.error("Polling error:", pollErr);
        }
      }, 1000);
    } catch (uploadErr) {
      console.error("Upload failed:", uploadErr);
      setFailed(true);
      const msg = uploadErr.message || "Failed to upload APK";
      setErrorMessage(msg);
      showToast(msg, "error");
      setStage(-1);
    }
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
          handleUpload(e.dataTransfer.files?.[0]);
        }}
      >
        <Upload size={28} color="var(--accent)" style={{ margin: "0 auto 10px" }} />
        <h3 style={{ fontFamily: "var(--font-display)" }}>Drop APK here or browse</h3>
        <p style={{ color: "var(--text-muted)", fontSize: 14, marginTop: 6 }}>
          Uploads to CiphR backend · Max file size: 50MB
        </p>
        <input
          ref={fileRef}
          type="file"
          accept=".apk"
          hidden
          onChange={(e) => handleUpload(e.target.files?.[0])}
        />
      </div>

      {(stage >= 0 || fileName) && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-title">Analysis progress</div>
          {fileName && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
              <FileArchive size={18} color="var(--accent)" />
              <strong>{fileName}</strong>
              {sampleId && (
                <span style={{ fontSize: 12, color: "var(--text-dim)", fontFamily: "monospace" }}>
                  ({sampleId})
                </span>
              )}
            </div>
          )}

          {failed && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "10px 14px",
                borderRadius: 8,
                background: "var(--danger-dim, rgba(255, 77, 106, 0.1))",
                border: "1px solid var(--danger)",
                color: "var(--danger)",
                marginBottom: 16,
                fontSize: 14,
              }}
            >
              <AlertCircle size={18} />
              <span>{errorMessage || "Analysis failed. Please check the backend logs."}</span>
            </div>
          )}

          <div style={{ display: "grid", gap: 8 }}>
            {pipelineStages.map((s, i) => {
              const complete = stage > i || (done && stage >= pipelineStages.length);
              const active = stage === i && !done && !failed;
              const isFailedStage = failed && stage === i;
              return (
                <div
                  key={s}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "10px 12px",
                    borderRadius: 8,
                    background: active
                      ? "var(--accent-dim)"
                      : isFailedStage
                      ? "var(--danger-dim, rgba(255, 77, 106, 0.1))"
                      : "var(--bg)",
                    border: `1px solid ${
                      active ? "var(--accent)" : isFailedStage ? "var(--danger)" : "var(--border)"
                    }`,
                    color: complete || active ? "var(--text)" : "var(--text-dim)",
                  }}
                >
                  {complete ? (
                    <CheckCircle2 size={16} color="var(--accent)" />
                  ) : active ? (
                    <Loader2 size={16} color="var(--accent)" className="spin" />
                  ) : isFailedStage ? (
                    <AlertCircle size={16} color="var(--danger)" />
                  ) : (
                    <span
                      style={{
                        width: 16,
                        height: 16,
                        borderRadius: "50%",
                        border: "1px solid var(--border-strong)",
                      }}
                    />
                  )}
                  {s}
                </div>
              );
            })}
          </div>

          {done && sampleId && (
            <button
              type="button"
              className="btn-primary"
              style={{ marginTop: 16 }}
              onClick={() => navigate(`/app/apk/${sampleId}`)}
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
            {(recentList.length > 0 ? recentList : recentApks).map((apk) => {
              const id = apk.id;
              const name = apk.filename || apk.name;
              const sha = apk.sha256;
              const risk = apk.analysis?.risk_level || apk.risk || (apk.status === "COMPLETED" ? "Low" : apk.status || "Pending");
              const score = apk.analysis?.risk_score ?? apk.score ?? "-";
              const firstSeen = apk.created_at
                ? new Date(apk.created_at).toISOString().split("T")[0]
                : apk.firstSeen || "-";

              return (
                <tr key={id}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{name}</div>
                    <div style={{ fontSize: 12, color: "var(--text-dim)" }}>{sha}</div>
                  </td>
                  <td>
                    <SeverityBadge level={risk} />
                  </td>
                  <td>{score}</td>
                  <td>{firstSeen}</td>
                  <td>
                    <Link
                      to={`/app/apk/${id}`}
                      style={{ color: "var(--accent)", fontWeight: 600 }}
                    >
                      Report
                    </Link>
                  </td>
                </tr>
              );
            })}
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
