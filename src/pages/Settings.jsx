import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import ThemeToggle from "../components/ThemeToggle";

export default function Settings() {
  const { user, showToast } = useAuth();
  const { theme } = useTheme();

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Settings / Profile</h1>
          <p>Account preferences and role information</p>
        </div>
      </div>

      <div className="card" style={{ maxWidth: 520, marginBottom: 16 }}>
        <div className="card-title">Appearance</div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <div>
            <div style={{ fontWeight: 600 }}>Theme</div>
            <div style={{ fontSize: 13, color: "var(--text-muted)" }}>
              Currently using {theme} mode
            </div>
          </div>
          <ThemeToggle />
        </div>
      </div>

      <div className="card" style={{ maxWidth: 520 }}>
        <div className="card-title">User profile</div>
        <div style={{ display: "grid", gap: 14 }}>
          <Field label="Name" value={user?.name} />
          <Field label="Email" value={user?.email} />
          <Field label="Role" value={user?.role} />
        </div>
        <button
          type="button"
          className="btn-primary"
          style={{ marginTop: 20 }}
          onClick={() => showToast("Preferences saved")}
        >
          Save preferences
        </button>
      </div>
    </div>
  );
}

function Field({ label, value }) {
  return (
    <label style={{ display: "grid", gap: 6, fontSize: 13, color: "var(--text-muted)" }}>
      {label}
      <input
        readOnly
        value={value || ""}
        style={{
          padding: "10px 12px",
          background: "var(--bg)",
          border: "1px solid var(--border)",
          borderRadius: 8,
          color: "var(--text)",
        }}
      />
    </label>
  );
}
