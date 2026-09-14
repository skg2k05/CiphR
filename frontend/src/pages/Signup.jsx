import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Logo from "../components/Logo";
import ThemeToggle from "../components/ThemeToggle";
import { useAuth } from "../context/AuthContext";
import "./Auth.css";

export default function Signup() {
  const { signup } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("Security Analyst");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!name || !email || !password) return;
    signup(name, email, password, role);
    navigate("/app/overview");
  };

  return (
    <div className="auth-page">
      <Link to="/" className="auth-back">
        ← Back to home
      </Link>
      <div className="auth-theme">
        <ThemeToggle />
      </div>
      <div className="auth-card">
        <Logo size={42} textSize={28} />
        <h1>Sign up</h1>
        <p className="auth-sub">Create your analyst account</p>
        <form onSubmit={handleSubmit}>
          <label>
            Full name
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Priya Sharma"
              required
            />
          </label>
          <label>
            Email
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@bank.in"
              required
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              minLength={6}
            />
          </label>
          <label>
            Role
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option>Security Analyst</option>
              <option>Bank Admin</option>
            </select>
          </label>
          <button type="submit" className="btn-primary auth-submit">
            Create account
          </button>
        </form>
        <p className="auth-switch">
          Already have an account? <Link to="/login">Log in</Link>
        </p>
      </div>
    </div>
  );
}
