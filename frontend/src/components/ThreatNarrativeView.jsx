import React from "react";
import { AlertTriangle, ShieldAlert, Cpu, Share2, Layers, Info, CheckCircle2 } from "lucide-react";
import SeverityBadge from "./SeverityBadge";

// Helper to translate common technical factors into simple, plain-English explanations
function getSimpleExplanation(factor) {
  const f = String(factor).toLowerCase();
  if (f.includes("accessibility")) {
    return {
      title: "Screen & Gesture Control (Accessibility Service)",
      desc: "This app requests permission to observe your screen and simulate touches. Financial trojans abuse this to capture typed passwords, bypass 2FA, and interact with bank apps without consent.",
      severity: "CRITICAL",
    };
  }
  if (f.includes("alert_window") || f.includes("overlay")) {
    return {
      title: "Screen Overlay (Fake Login Screens)",
      desc: "Allows the app to draw floating windows on top of other running applications. Attackers use this to display fake banking login forms directly over genuine banking apps.",
      severity: "HIGH",
    };
  }
  if (f.includes("boot_completed") || f.includes("persistence")) {
    return {
      title: "Automatic Background Startup",
      desc: "Starts automatically every time the phone powers on, ensuring the malware remains active even if you close it or reboot.",
      severity: "LOW",
    };
  }
  if (f.includes("read_sms") || f.includes("receive_sms")) {
    return {
      title: "SMS Message Interception",
      desc: "Can read incoming text messages, often used to steal one-time bank OTPs and authentication codes.",
      severity: "CRITICAL",
    };
  }
  if (f.includes("call_log") || f.includes("call_phone")) {
    return {
      title: "Call Log Access & Dialing",
      desc: "Can access private phone call logs or place phone calls in the background without user interaction.",
      severity: "LOW",
    };
  }
  if (f.includes("camera") || f.includes("record_audio")) {
    return {
      title: "Surveillance Hardware Access",
      desc: "Requests access to the device camera and microphone, enabling background surveillance without user notice.",
      severity: "MEDIUM",
    };
  }
  if (f.includes("contacts")) {
    return {
      title: "Contact List Harvesting",
      desc: "Can copy your entire phone contact list to remote command servers for phishing campaigns.",
      severity: "LOW",
    };
  }
  return {
    title: factor,
    desc: "Identified as an anomalous or high-risk capability during automated code inspection.",
    severity: "MEDIUM",
  };
}

export default function ThreatNarrativeView({
  narrative = "",
  simple = false,
  riskScore = 0,
  appName = "This application",
  factorStrings = [],
  findings = [],
}) {
  if (!narrative && factorStrings.length === 0) {
    return (
      <div style={{ padding: "14px 0", color: "var(--text-muted)", fontSize: 13.5 }}>
        No specific threat flags detected for this APK.
      </div>
    );
  }

  // Handle Simple / Plain Language View
  if (simple) {
    const rawFactors = factorStrings.length > 0 ? factorStrings : findings.map((f) => f.title || f.indicator);
    const explanations = rawFactors.slice(0, 4).map((f) => getSimpleExplanation(f));

    return (
      <div style={{ marginTop: 14, display: "grid", gap: 12 }}>
        <div
          style={{
            padding: 12,
            background: "rgba(0, 212, 170, 0.08)",
            border: "1px solid rgba(0, 212, 170, 0.25)",
            borderRadius: 8,
            fontSize: 13.5,
            color: "var(--text)",
            lineHeight: 1.5,
          }}
        >
          <strong>Plain-Language Summary:</strong> {appName} received a risk score of{" "}
          <strong style={{ color: riskScore >= 70 ? "var(--danger)" : "var(--warning)" }}>{riskScore}/100</strong>.
          It requests critical device privileges that allow it to intercept user input, persist on restart, and potentially perform unauthorized actions.
        </div>

        <div style={{ display: "grid", gap: 10 }}>
          {explanations.map((item, idx) => (
            <div
              key={idx}
              style={{
                padding: 12,
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: 8,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                <strong style={{ fontSize: 13.5, color: "var(--text)" }}>{item.title}</strong>
                <SeverityBadge level={item.severity} />
              </div>
              <p style={{ margin: 0, fontSize: 13, color: "var(--text-muted)", lineHeight: 1.5 }}>
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // Handle Technical View with Structured Markdown Parsing
  let text = narrative || "";
  const isMock = text.includes("[MOCK NARRATIVE]");
  text = text.replace(/^\[MOCK NARRATIVE\]\s*/, "");

  // Extract footer note if present (e.g. *This narrative was generated...*)
  let footerNote = null;
  const footerMatch = text.match(/\n\s*\*([^*]+)\*\s*$/);
  if (footerMatch) {
    footerNote = footerMatch[1];
    text = text.slice(0, footerMatch.index).trim();
  }

  // Split narrative by ### headers
  const parts = text.split(/(?=###\s+)/g);
  let leadParagraph = "";
  const sections = [];

  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.startsWith("###")) {
      const headerEnd = trimmed.indexOf("\n");
      const title = headerEnd !== -1 ? trimmed.slice(3, headerEnd).trim().replace(/:$/, "") : trimmed.slice(3).trim();
      const content = headerEnd !== -1 ? trimmed.slice(headerEnd).trim() : "";
      sections.push({ title, content });
    } else {
      leadParagraph = trimmed;
    }
  }

  // If no sections were parsed, fallback to paragraphs
  if (sections.length === 0 && text) {
    return (
      <div style={{ marginTop: 14, fontSize: 14, color: "var(--text-muted)", lineHeight: 1.6 }}>
        {text.split("\n\n").map((p, i) => (
          <p key={i} style={{ marginBottom: 10 }}>
            {p}
          </p>
        ))}
      </div>
    );
  }

  return (
    <div style={{ marginTop: 14, display: "grid", gap: 14 }}>
      {/* Lead Summary */}
      {leadParagraph && (
        <div
          style={{
            padding: "10px 14px",
            background: "var(--bg)",
            borderLeft: "3px solid var(--accent)",
            borderRadius: "0 8px 8px 0",
            fontSize: 13.5,
            color: "var(--text)",
            lineHeight: 1.55,
          }}
        >
          {leadParagraph}
        </div>
      )}

      {/* Sections */}
      {sections.map((section, sIdx) => {
        const titleLower = section.title.toLowerCase();

        // 1. KEY RISK FACTORS
        if (titleLower.includes("key risk factors")) {
          const lines = section.content.split("\n").filter((l) => l.trim().startsWith("-"));
          return (
            <div key={sIdx} style={{ display: "grid", gap: 6 }}>
              <div
                style={{
                  fontSize: 12,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  fontWeight: 700,
                  color: "var(--danger)",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <AlertTriangle size={13} /> {section.title}
              </div>
              <div style={{ display: "grid", gap: 6 }}>
                {lines.map((line, lIdx) => {
                  const cleanedLine = line.replace(/^-\s*/, "");
                  const ptsMatch = cleanedLine.match(/\(\+(\d+)\s*pts\)/i);
                  const pts = ptsMatch ? ptsMatch[1] : null;
                  const factorName = ptsMatch
                    ? cleanedLine.replace(/\s*\(\+\d+\s*pts\)/i, "").trim()
                    : cleanedLine;

                  return (
                    <div
                      key={lIdx}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "8px 12px",
                        background: "var(--bg)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        fontSize: 13,
                        fontFamily: factorName.includes("android.permission") || factorName.includes("pattern.") ? "monospace" : "inherit",
                      }}
                    >
                      <span style={{ color: "var(--text)", wordBreak: "break-all" }}>{factorName}</span>
                      {pts && (
                        <span
                          style={{
                            padding: "2px 8px",
                            background: parseInt(pts, 10) >= 20 ? "var(--danger-dim)" : "var(--warning-dim)",
                            color: parseInt(pts, 10) >= 20 ? "var(--danger)" : "var(--warning)",
                            borderRadius: 4,
                            fontWeight: 700,
                            fontSize: 11.5,
                            marginLeft: 8,
                            whiteSpace: "nowrap",
                          }}
                        >
                          +{pts} pts
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        }

        // 2. STATIC EVIDENCE & COMPONENTS
        if (titleLower.includes("static evidence") || titleLower.includes("components")) {
          const lines = section.content.split("\n").filter((l) => l.trim().startsWith("-"));
          return (
            <div key={sIdx} style={{ display: "grid", gap: 6 }}>
              <div
                style={{
                  fontSize: 12,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  fontWeight: 700,
                  color: "var(--text-dim)",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <Cpu size={13} /> {section.title}
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {lines.map((line, lIdx) => {
                  const cleaned = line.replace(/^-\s*/, "");
                  const [key, val] = cleaned.split(":");
                  return (
                    <div
                      key={lIdx}
                      style={{
                        padding: "6px 12px",
                        background: "var(--bg)",
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        fontSize: 12.5,
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 6,
                      }}
                    >
                      <span style={{ color: "var(--text-muted)" }}>{key?.trim()}:</span>
                      <strong style={{ color: "var(--accent)" }}>{val?.trim() || "-"}</strong>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        }

        // 3. CAMPAIGN & CORRELATION
        if (titleLower.includes("campaign") || titleLower.includes("correlation")) {
          const lines = section.content.split("\n").filter((l) => l.trim().startsWith("-"));
          return (
            <div key={sIdx} style={{ display: "grid", gap: 6 }}>
              <div
                style={{
                  fontSize: 12,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  fontWeight: 700,
                  color: "var(--accent)",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <Share2 size={13} /> {section.title}
              </div>
              <div
                style={{
                  padding: 10,
                  background: "var(--bg)",
                  border: "1px solid var(--border)",
                  borderRadius: 6,
                  display: "grid",
                  gap: 4,
                  fontSize: 13,
                }}
              >
                {lines.map((line, lIdx) => {
                  const cleaned = line.replace(/^-\s*/, "");
                  return (
                    <div key={lIdx} style={{ color: "var(--text-muted)" }}>
                      • {cleaned}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        }

        // 4. SUSPICIOUS INDICATORS & MITRE ATT&CK
        if (titleLower.includes("suspicious") || titleLower.includes("mitre")) {
          const lines = section.content.split("\n").filter((l) => l.trim().startsWith("-"));
          return (
            <div key={sIdx} style={{ display: "grid", gap: 6 }}>
              <div
                style={{
                  fontSize: 12,
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  fontWeight: 700,
                  color: "var(--blue)",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <ShieldAlert size={13} /> {section.title}
              </div>
              <div style={{ display: "grid", gap: 8 }}>
                {lines.map((line, lIdx) => {
                  const cleaned = line.replace(/^-\s*/, "");
                  // Format: Title: Description [T1453] (Severity: HIGH)
                  const mitreMatch = cleaned.match(/\[(T\d+(?:\.\d+)?)\]/);
                  const sevMatch = cleaned.match(/\(Severity:\s*([^)]+)\)/i);

                  let descClean = cleaned;
                  if (mitreMatch) descClean = descClean.replace(mitreMatch[0], "");
                  if (sevMatch) descClean = descClean.replace(sevMatch[0], "");

                  const colonIdx = descClean.indexOf(":");
                  const itemTitle = colonIdx !== -1 ? descClean.slice(0, colonIdx).trim() : "";
                  const itemBody = colonIdx !== -1 ? descClean.slice(colonIdx + 1).trim() : descClean.trim();

                  return (
                    <div
                      key={lIdx}
                      style={{
                        padding: 12,
                        background: "var(--bg)",
                        border: "1px solid var(--border)",
                        borderRadius: 8,
                        display: "grid",
                        gap: 6,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8, flexWrap: "wrap" }}>
                        <strong style={{ fontSize: 13.5, color: "var(--text)" }}>
                          {itemTitle || itemBody}
                        </strong>
                        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                          {mitreMatch && (
                            <span
                              style={{
                                padding: "2px 8px",
                                background: "var(--blue-dim)",
                                color: "var(--blue)",
                                borderRadius: 4,
                                fontSize: 11.5,
                                fontWeight: 600,
                                fontFamily: "monospace",
                              }}
                            >
                              {mitreMatch[1]}
                            </span>
                          )}
                          {sevMatch && <SeverityBadge level={sevMatch[1]} />}
                        </div>
                      </div>
                      {itemTitle && (
                        <p style={{ margin: 0, fontSize: 13, color: "var(--text-muted)", lineHeight: 1.5 }}>
                          {itemBody}
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        }

        // Generic fallback for any other markdown section
        return (
          <div key={sIdx} style={{ display: "grid", gap: 6 }}>
            <div
              style={{
                fontSize: 12,
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                fontWeight: 700,
                color: "var(--text-dim)",
                display: "flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              <Layers size={13} /> {section.title}
            </div>
            <div
              style={{
                padding: 10,
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: 6,
                fontSize: 13,
                color: "var(--text-muted)",
                lineHeight: 1.5,
              }}
            >
              {section.content}
            </div>
          </div>
        );
      })}

      {/* Footer / Mock disclaimer */}
      {(isMock || footerNote) && (
        <div
          style={{
            marginTop: 4,
            padding: "8px 12px",
            background: "var(--bg-card)",
            border: "1px dashed var(--border)",
            borderRadius: 6,
            display: "flex",
            alignItems: "center",
            gap: 8,
            fontSize: 12,
            color: "var(--text-dim)",
          }}
        >
          <Info size={14} style={{ flexShrink: 0 }} />
          <span>
            {footerNote || "Simulated AI Analysis: Generated by deterministic heuristics (no external LLM key active)."}
          </span>
        </div>
      )}
    </div>
  );
}
