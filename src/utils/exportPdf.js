import { jsPDF } from "jspdf";

function addWrappedText(doc, text, x, y, maxWidth, lineHeight = 6) {
  const lines = doc.splitTextToSize(String(text ?? ""), maxWidth);
  doc.text(lines, x, y);
  return y + lines.length * lineHeight;
}

function ensureSpace(doc, y, needed = 20) {
  if (y > 280 - needed) {
    doc.addPage();
    return 20;
  }
  return y;
}

export function exportIntelligencePdf({ stats, recentApks, campaigns }) {
  const doc = new jsPDF();
  let y = 20;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("CiphR Intelligence Report", 14, y);
  y += 10;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(80);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, y);
  y += 12;

  doc.setTextColor(0);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("Summary", 14, y);
  y += 8;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  const summaryLines = [
    `APKs analyzed: ${stats.apksAnalyzed}`,
    `Malicious APKs: ${stats.maliciousApks}`,
    `Active campaigns: ${stats.activeCampaigns}`,
    `High-risk samples: ${stats.highRiskSamples}`,
  ];
  summaryLines.forEach((line) => {
    doc.text(line, 14, y);
    y += 6;
  });
  y += 6;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("Active Campaigns", 14, y);
  y += 8;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);

  campaigns.slice(0, 5).forEach((c) => {
    y = ensureSpace(doc, y, 18);
    doc.setFont("helvetica", "bold");
    doc.text(`${c.name} [${c.risk}]`, 14, y);
    y += 5;
    doc.setFont("helvetica", "normal");
    y = addWrappedText(
      doc,
      `${c.apkCount} APKs · First seen ${c.firstSeen} · Last seen ${c.lastSeen}. ${c.summary}`,
      14,
      y,
      180,
      5
    );
    y += 4;
  });

  y = ensureSpace(doc, y, 24);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.text("Recent Suspicious APKs", 14, y);
  y += 8;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);

  recentApks.forEach((apk) => {
    y = ensureSpace(doc, y, 16);
    doc.setFont("helvetica", "bold");
    doc.text(apk.name, 14, y);
    y += 5;
    doc.setFont("helvetica", "normal");
    doc.text(
      `Risk: ${apk.risk} (${apk.score}) · Campaign: ${apk.campaign} · ${apk.package}`,
      14,
      y
    );
    y += 5;
    doc.setTextColor(90);
    doc.text(`SHA-256: ${apk.sha256}`, 14, y);
    doc.setTextColor(0);
    y += 8;
  });

  doc.save("ciphr-intelligence-report.pdf");
}

export function exportThreatReportPdf({ apk, mitreTechniques }) {
  const doc = new jsPDF();
  let y = 20;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("CiphR Threat Report", 14, y);
  y += 10;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(80);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, y);
  y += 12;
  doc.setTextColor(0);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.text(apk.name, 14, y);
  y += 7;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.text(`Package: ${apk.package}`, 14, y);
  y += 6;
  doc.text(`Threat level: ${apk.risk} · Risk score: ${apk.score}`, 14, y);
  y += 6;
  doc.text(`Campaign: ${apk.campaign}`, 14, y);
  y += 6;
  doc.text(`First seen: ${apk.firstSeen}`, 14, y);
  y += 6;
  doc.text(`Last seen: ${apk.lastSeen}`, 14, y);
  y += 6;
  y = addWrappedText(doc, `SHA-256: ${apk.sha256}`, 14, y, 180, 5);
  y += 8;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("Threat Indicators", 14, y);
  y += 7;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  (apk.indicators || []).forEach((ind) => {
    y = ensureSpace(doc, y, 10);
    y = addWrappedText(doc, `• ${ind}`, 14, y, 180, 5);
    y += 2;
  });
  y += 4;

  y = ensureSpace(doc, y, 20);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("Suspicious Permissions", 14, y);
  y += 7;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  y = addWrappedText(doc, (apk.permissions || []).join(", "), 14, y, 180, 5);
  y += 6;

  y = ensureSpace(doc, y, 20);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("Certificate", 14, y);
  y += 7;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  y = addWrappedText(doc, apk.certificate?.subject || "N/A", 14, y, 180, 5);
  y += 4;
  doc.text(`Shared with ${apk.certificate?.sharedWith ?? 0} samples`, 14, y);
  y += 8;

  y = ensureSpace(doc, y, 20);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("Domains", 14, y);
  y += 7;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  (apk.domains || []).forEach((d) => {
    y = ensureSpace(doc, y, 8);
    doc.text(`• ${d}`, 14, y);
    y += 5;
  });
  y += 4;

  y = ensureSpace(doc, y, 24);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("AI Explanation", 14, y);
  y += 7;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  y = addWrappedText(doc, apk.aiExplanation || "", 14, y, 180, 5);
  y += 8;

  y = ensureSpace(doc, y, 24);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("MITRE ATT&CK Techniques", 14, y);
  y += 7;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  (mitreTechniques || []).forEach((t) => {
    y = ensureSpace(doc, y, 16);
    doc.setFont("helvetica", "bold");
    doc.text(`${t.id} — ${t.name}`, 14, y);
    y += 5;
    doc.setFont("helvetica", "normal");
    y = addWrappedText(doc, t.evidence, 14, y, 180, 5);
    y += 4;
  });

  const safeName = String(apk.name || "threat-report").replace(/\.apk$/i, "");
  doc.save(`${safeName}-threat-report.pdf`);
}
