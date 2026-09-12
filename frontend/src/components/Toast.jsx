import { useAuth } from "../context/AuthContext";
import { CheckCircle2, AlertCircle } from "lucide-react";

export default function Toast() {
  const { toast } = useAuth();
  if (!toast) return null;

  return (
    <div className={`app-toast ${toast.type === "error" ? "error" : ""}`} role="status">
      {toast.type === "error" ? (
        <AlertCircle size={18} color="var(--danger)" />
      ) : (
        <CheckCircle2 size={18} color="var(--accent)" />
      )}
      <span>{toast.message}</span>
    </div>
  );
}
