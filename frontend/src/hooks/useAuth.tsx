import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, clearToken, getToken } from "../services/api";

interface AuthContextValue {
  isAuthenticated: boolean;
  username: string | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = getToken();
    if (!token) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then((data) => setUsername(data.username))
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  async function login(user: string, password: string) {
    await api.login(user, password);
    const data = await api.me();
    setUsername(data.username);
  }

  function logout() {
    clearToken();
    setUsername(null);
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated: !!username, username, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
