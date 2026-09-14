import { Link } from "react-router-dom";
import { Shield, Network, Brain, FileSearch, ArrowRight, Lock } from "lucide-react";
import Logo from "../components/Logo";
import ThemeToggle from "../components/ThemeToggle";
import "./Home.css";

export default function Home() {
  return (
    <div className="home">
      <nav className="home-nav">
        <Logo size={40} textSize={26} />
        <div className="home-nav-actions">
          <ThemeToggle />
          <Link to="/login" className="btn-ghost">
            Log in
          </Link>
          <Link to="/signup" className="btn-primary">
            Sign up
          </Link>
        </div>
      </nav>

      <section className="home-hero">
        <div className="hero-copy">
          <p className="hero-eyebrow">INFERENTIA · Security You Can Trust</p>
          <h1>
            <span className="brand-hero">
              Ciph<span>R</span>
            </span>
          </h1>
          <p className="hero-lead">
            Fraud-intelligence layer for suspicious Android APKs — correlate samples into
            coordinated campaigns, not just one-off verdicts.
          </p>
          <div className="hero-cta">
            <Link to="/signup" className="btn-primary">
              Get started <ArrowRight size={16} />
            </Link>
            <Link to="/login" className="btn-outline">
              Analyst login
            </Link>
          </div>
        </div>
        <div className="hero-visual" aria-hidden>
          <div className="hero-grid-glow" />
          <div className="hero-panel">
            <div className="hero-panel-row">
              <span className="pulse-dot" /> Live campaign correlation
            </div>
            <div className="hero-metric-row">
              <div>
                <strong>1,847</strong>
                <span>APKs analyzed</span>
              </div>
              <div>
                <strong>18</strong>
                <span>Active campaigns</span>
              </div>
              <div>
                <strong>94</strong>
                <span>Peak risk score</span>
              </div>
            </div>
            <div className="hero-graph-mock">
              <span className="node camp" />
              <span className="node apk" />
              <span className="node cert" />
              <span className="node domain" />
              <svg viewBox="0 0 280 120" className="mock-edges">
                <line x1="40" y1="60" x2="100" y2="30" stroke="#2a3f5a" />
                <line x1="40" y1="60" x2="100" y2="90" stroke="#2a3f5a" />
                <line x1="100" y1="30" x2="180" y2="50" stroke="#2a3f5a" />
                <line x1="100" y1="90" x2="180" y2="70" stroke="#2a3f5a" />
                <line x1="180" y1="50" x2="240" y2="60" stroke="#00d4aa" strokeWidth="1.5" />
              </svg>
            </div>
          </div>
        </div>
      </section>

      <section className="home-about" id="about">
        <h2>What CiphR does</h2>
        <p className="section-lead">
          Malicious Android APKs spread through WhatsApp, SMS phishing, fake KYC/loan apps and
          Telegram. CiphR moves past clean/malicious labels to institutional threat intelligence.
        </p>
        <div className="feature-grid">
          <article>
            <Shield size={22} color="var(--accent)" />
            <h3>APK threat analysis</h3>
            <p>
              Upload suspicious APKs, track the full analysis pipeline, and get risk scores with
              permissions, certificates and indicators.
            </p>
          </article>
          <article>
            <Network size={22} color="var(--blue)" />
            <h3>Campaign correlation</h3>
            <p>
              Link samples via TLSH similarity and shared signing certificates into coordinated
              fraud campaigns.
            </p>
          </article>
          <article>
            <Brain size={22} color="var(--warning)" />
            <h3>AI explanations</h3>
            <p>
              Plain-English narratives explain why an APK was flagged and how it connects to a
              campaign — plus MITRE ATT&CK mapping.
            </p>
          </article>
          <article>
            <FileSearch size={22} color="#a78bfa" />
            <h3>Investigation graph</h3>
            <p>
              Interactive vis-network graphs reveal relationships between APKs, certificates,
              domains and campaigns.
            </p>
          </article>
        </div>
      </section>

      <section className="home-flow">
        <h2>Built for analysts</h2>
        <p className="section-lead">
          Evidence → explanation → related samples → campaign → relationship graph → timeline.
        </p>
        <ol className="flow-steps">
          <li>
            <Lock size={16} /> Authenticate as Security Analyst or Bank Admin
          </li>
          <li>Upload an APK and watch the analysis pipeline</li>
          <li>Review risk score, AI narrative and MITRE techniques</li>
          <li>Explore campaign intelligence and export reports</li>
        </ol>
        <Link to="/signup" className="btn-primary" style={{ marginTop: 24 }}>
          Create analyst account
        </Link>
      </section>

      <footer className="home-footer">
        <Logo size={28} textSize={18} />
        <span>Team Rangobati · Hackathon INFERENTIA</span>
      </footer>
    </div>
  );
}
