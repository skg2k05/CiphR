export const stats = {
  apksAnalyzed: 1847,
  maliciousApks: 312,
  activeCampaigns: 18,
  highRiskSamples: 47,
};

export const threatOverTime = [
  { day: "Mon", detections: 22 },
  { day: "Tue", detections: 31 },
  { day: "Wed", detections: 18 },
  { day: "Thu", detections: 42 },
  { day: "Fri", detections: 37 },
  { day: "Sat", detections: 28 },
  { day: "Sun", detections: 35 },
];

export const severityDistribution = [
  { name: "Critical", value: 28, color: "#ff4d6a" },
  { name: "High", value: 64, color: "#ff7a59" },
  { name: "Medium", value: 112, color: "#ffb020" },
  { name: "Low", value: 89, color: "#3b9eff" },
  { name: "Safe", value: 1554, color: "#2dd4a8" },
];

export const recentApks = [
  {
    id: "apk-001",
    name: "QuickKYC_Verify.apk",
    package: "com.quickkyc.verify",
    risk: "Critical",
    score: 94,
    campaign: "Fake Loan Ring-7",
    firstSeen: "2026-09-11",
    sha256: "a3f2c8e1b9d0476f...",
  },
  {
    id: "apk-002",
    name: "BHIM_SecurePay.apk",
    package: "in.bhim.securepay",
    risk: "High",
    score: 81,
    campaign: "UPI Phish Cluster",
    firstSeen: "2026-09-10",
    sha256: "c91e44a0d2b8f317...",
  },
  {
    id: "apk-003",
    name: "AadhaarUpdate.apk",
    package: "gov.aadhaar.updatex",
    risk: "High",
    score: 78,
    campaign: "Fake Loan Ring-7",
    firstSeen: "2026-09-10",
    sha256: "7b1d90ee5cfa2241...",
  },
  {
    id: "apk-004",
    name: "TelegramWallet.apk",
    package: "org.tg.walletpro",
    risk: "Medium",
    score: 56,
    campaign: "TG Dropper Mesh",
    firstSeen: "2026-09-09",
    sha256: "e4aa12c09f78bd33...",
  },
  {
    id: "apk-005",
    name: "InstantCash_v3.apk",
    package: "com.instant.cashloan",
    risk: "Critical",
    score: 91,
    campaign: "Fake Loan Ring-7",
    firstSeen: "2026-09-08",
    sha256: "1190fdce88ab4472...",
  },
];

export const campaigns = [
  {
    id: "camp-001",
    name: "Fake Loan Ring-7",
    risk: "Critical",
    apkCount: 42,
    certificates: 3,
    domains: 11,
    packages: 8,
    firstSeen: "2026-06-14",
    lastSeen: "2026-09-11",
    summary:
      "Coordinated fake KYC/loan APKs distributed via WhatsApp and SMS. Shared signing certificates and TLSH-similar payloads.",
  },
  {
    id: "camp-002",
    name: "UPI Phish Cluster",
    risk: "High",
    apkCount: 19,
    certificates: 2,
    domains: 7,
    packages: 5,
    firstSeen: "2026-07-02",
    lastSeen: "2026-09-10",
    summary:
      "Spoofed UPI payment apps harvesting credentials. Certificate reuse across BHIM-looking packages.",
  },
  {
    id: "camp-003",
    name: "TG Dropper Mesh",
    risk: "Medium",
    apkCount: 14,
    certificates: 4,
    domains: 9,
    packages: 6,
    firstSeen: "2026-08-01",
    lastSeen: "2026-09-09",
    summary:
      "Telegram-distributed droppers staging secondary payloads. Domain infrastructure overlaps with prior SMS campaigns.",
  },
  {
    id: "camp-004",
    name: "SMS Banker Wave",
    risk: "High",
    apkCount: 27,
    certificates: 2,
    domains: 15,
    packages: 10,
    firstSeen: "2026-05-20",
    lastSeen: "2026-09-07",
    summary:
      "Banking trojans requesting SMS permissions and overlay attacks against major Indian banks.",
  },
];

export const alerts = [
  {
    id: "al-1",
    severity: "Critical",
    title: "New critical APK linked to Fake Loan Ring-7",
    time: "12 min ago",
    link: "/app/apk/apk-001",
  },
  {
    id: "al-2",
    severity: "High",
    title: "Shared signing certificate with known malicious samples",
    time: "1 hr ago",
    link: "/app/campaigns/camp-002",
  },
  {
    id: "al-3",
    severity: "High",
    title: "Rapid campaign activity increase — UPI Phish Cluster",
    time: "3 hr ago",
    link: "/app/campaigns/camp-002",
  },
  {
    id: "al-4",
    severity: "Medium",
    title: "New domain indicator observed in TG Dropper Mesh",
    time: "5 hr ago",
    link: "/app/campaigns/camp-003",
  },
];

export const mitreTechniques = [
  {
    id: "T1406",
    name: "Obfuscated Files or Information",
    evidence: "Heavily obfuscated DEX with encrypted string tables.",
  },
  {
    id: "T1417",
    name: "Input Capture",
    evidence: "Accessibility service used to capture OTP and form input.",
  },
  {
    id: "T1516",
    name: "Input Injection",
    evidence: "Overlay windows targeting banking login screens.",
  },
  {
    id: "T1437",
    name: "Application Layer Protocol",
    evidence: "C2 over HTTPS to suspicious loan-verification domains.",
  },
];

export const apkDetail = {
  id: "apk-001",
  name: "QuickKYC_Verify.apk",
  package: "com.quickkyc.verify",
  risk: "Critical",
  score: 94,
  campaign: "Fake Loan Ring-7",
  campaignId: "camp-001",
  firstSeen: "2026-09-11 08:42 IST",
  lastSeen: "2026-09-12 11:05 IST",
  sha256: "a3f2c8e1b9d0476f8a12c90ee44bd217aa91f0c3e8d55b7a1c2e9f0844d3a6b1",
  relatedCount: 11,
  permissions: [
    "READ_SMS",
    "RECEIVE_SMS",
    "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES",
    "READ_CONTACTS",
    "CAMERA",
  ],
  certificate: {
    subject: "CN=QuickSoft Labs, O=QuickSoft, C=IN",
    sha1: "B1:4F:9A:22:...",
    sharedWith: 8,
  },
  domains: ["verify-kyc-loan.in", "cdn-quickupdate.xyz", "otp-secure-check.com"],
  indicators: [
    "SMS interception for OTP theft",
    "Fake KYC camera flow",
    "TLSH similarity 92% with InstantCash_v3.apk",
    "Shared signing cert with Fake Loan Ring-7",
  ],
  aiExplanation:
    "This APK was flagged because it combines high-risk permissions (SMS + overlay + install packages) with a signing certificate already linked to Fake Loan Ring-7. Behavior closely matches known fake KYC/loan apps that phish users via WhatsApp. The risk score reflects certificate reuse, TLSH similarity to known malware, and suspicious domain contacts.",
  aiSimple:
    "This app pretends to do KYC for loans, but it can read your SMS (including OTPs), put fake screens over real bank apps, and install more apps. It was signed with the same key as other known scam apps, so it is almost certainly part of the same fraud campaign.",
};

export const pipelineStages = [
  "APK Upload",
  "Parsing",
  "Manifest Extraction",
  "Permission Analysis",
  "Certificate Extraction",
  "TLSH Generation",
  "Threat Correlation",
  "AI Analysis",
];

export const historyItems = [
  {
    id: "h1",
    name: "QuickKYC_Verify.apk",
    date: "2026-09-12 11:08",
    risk: "Critical",
    campaign: "Fake Loan Ring-7",
    apkId: "apk-001",
  },
  {
    id: "h2",
    name: "BHIM_SecurePay.apk",
    date: "2026-09-11 16:22",
    risk: "High",
    campaign: "UPI Phish Cluster",
    apkId: "apk-002",
  },
  {
    id: "h3",
    name: "AadhaarUpdate.apk",
    date: "2026-09-10 09:15",
    risk: "High",
    campaign: "Fake Loan Ring-7",
    apkId: "apk-003",
  },
];

export const graphData = {
  nodes: [
    { id: "c1", label: "Fake Loan Ring-7", group: "campaign", title: "Campaign" },
    { id: "c2", label: "UPI Phish Cluster", group: "campaign", title: "Campaign" },
    { id: "a1", label: "QuickKYC_Verify", group: "apk", title: "APK" },
    { id: "a2", label: "InstantCash_v3", group: "apk", title: "APK" },
    { id: "a3", label: "AadhaarUpdate", group: "apk", title: "APK" },
    { id: "a4", label: "BHIM_SecurePay", group: "apk", title: "APK" },
    { id: "cert1", label: "Cert: QuickSoft", group: "certificate", title: "Certificate" },
    { id: "cert2", label: "Cert: PaySecure", group: "certificate", title: "Certificate" },
    { id: "d1", label: "verify-kyc-loan.in", group: "domain", title: "Domain" },
    { id: "d2", label: "cdn-quickupdate.xyz", group: "domain", title: "Domain" },
    { id: "d3", label: "upi-secure-auth.in", group: "domain", title: "Domain" },
    { id: "p1", label: "com.quickkyc.verify", group: "package", title: "Package" },
    { id: "p2", label: "in.bhim.securepay", group: "package", title: "Package" },
  ],
  edges: [
    { from: "a1", to: "c1", label: "member" },
    { from: "a2", to: "c1", label: "member" },
    { from: "a3", to: "c1", label: "member" },
    { from: "a4", to: "c2", label: "member" },
    { from: "a1", to: "cert1", label: "signed by" },
    { from: "a2", to: "cert1", label: "signed by" },
    { from: "a3", to: "cert1", label: "signed by" },
    { from: "a4", to: "cert2", label: "signed by" },
    { from: "a1", to: "a2", label: "TLSH 92%" },
    { from: "a1", to: "d1", label: "contacts" },
    { from: "a2", to: "d2", label: "contacts" },
    { from: "a4", to: "d3", label: "contacts" },
    { from: "a1", to: "p1", label: "package" },
    { from: "a4", to: "p2", label: "package" },
    { from: "d1", to: "c1", label: "infra" },
    { from: "d3", to: "c2", label: "infra" },
  ],
};

export const analytics = {
  campaignGrowth: [
    { month: "Apr", samples: 12 },
    { month: "May", samples: 28 },
    { month: "Jun", samples: 45 },
    { month: "Jul", samples: 67 },
    { month: "Aug", samples: 89 },
    { month: "Sep", samples: 112 },
  ],
  categories: [
    { name: "Fake KYC/Loan", value: 38 },
    { name: "UPI Phishing", value: 24 },
    { name: "Banking Trojan", value: 19 },
    { name: "Dropper", value: 12 },
    { name: "Other", value: 7 },
  ],
  topCerts: [
    { name: "CN=QuickSoft Labs", count: 18 },
    { name: "CN=PaySecure IN", count: 11 },
    { name: "CN=TG Wallet Dev", count: 9 },
  ],
  mitreFreq: [
    { id: "T1417", name: "Input Capture", count: 44 },
    { id: "T1406", name: "Obfuscation", count: 39 },
    { id: "T1516", name: "Input Injection", count: 31 },
    { id: "T1437", name: "App Layer Protocol", count: 27 },
  ],
};
