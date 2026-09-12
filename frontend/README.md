# CiphR

Fraud-intelligence frontend for analyzing suspicious Android APKs and correlating them into coordinated fraud campaigns.

**Stack:** React (Vite) + React Router + vis-network + Recharts

## Run

```bash
npm install
npm run dev
```

Open the local URL shown in the terminal (usually `http://localhost:5173`).

## Demo flow

1. Home → Sign up / Log in (top right)
2. Success toast → Overview (upload APK, intelligence cards, export report)
3. APK Analysis → pipeline → Threat Report (AI + MITRE)
4. Campaigns → Graph Explorer (vis-network)
5. Search, Analytics, Alerts, History, Settings
