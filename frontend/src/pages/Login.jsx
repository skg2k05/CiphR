import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Logo from "../components/Logo";
import ThemeToggle from "../components/ThemeToggle";
import { useAuth } from "../context/AuthContext";
import "./Auth.css";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("Security Analyst");

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!email || !password) return;
    login(email, password, role);
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
        <h1>Log in</h1>
        <p className="auth-sub">Access the CiphR intelligence console</p>
        <form onSubmit={handleSubmit}>
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
            Log in
          </button>
        </form>
        <p className="auth-switch">
          No account? <Link to="/signup">Sign up</Link>
        </p>
        <p className="auth-forgot">Forgot password? Contact your administrator.</p>
      </div>
    </div>
  );
}
