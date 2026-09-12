import { createContext, useContext, useMemo, useState, useCallback } from "react";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const raw = localStorage.getItem("ciphr_user");
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  });
  const [toast, setToast] = useState(null);

  const showToast = useCallback((message, type = "success") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 2800);
  }, []);

  const login = useCallback(
    (email, _password, role = "Security Analyst") => {
      const next = { email, role, name: email.split("@")[0] };
      localStorage.setItem("ciphr_user", JSON.stringify(next));
      setUser(next);
      showToast("Login successful");
      return true;
    },
    [showToast]
  );

  const signup = useCallback(
    (name, email, _password, role = "Security Analyst") => {
      const next = { email, role, name };
      localStorage.setItem("ciphr_user", JSON.stringify(next));
      setUser(next);
      showToast("Sign up successful");
      return true;
    },
    [showToast]
  );

  const logout = useCallback(() => {
    localStorage.removeItem("ciphr_user");
    setUser(null);
    showToast("Logged out");
  }, [showToast]);

  const value = useMemo(
    () => ({ user, login, signup, logout, toast, showToast }),
    [user, login, signup, logout, toast, showToast]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
