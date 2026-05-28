// src/context/AuthContext.jsx
import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authLogin, checkHealth, getMe } from '../api/socApi';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem('soc_token'));
  const [user, setUser]   = useState(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [loading, setLoading]     = useState(true);

  // Poll API health every 10 s
  const pollHealth = useCallback(async () => {
    try {
      await checkHealth();
      setApiOnline(true);
    } catch {
      setApiOnline(false);
    }
  }, []);

  useEffect(() => {
    pollHealth();
    const iv = setInterval(pollHealth, 10000);
    return () => clearInterval(iv);
  }, [pollHealth]);

  // Resolve user on mount if token exists
  useEffect(() => {
    if (!token) { setLoading(false); return; }
    getMe()
      .then(setUser)
      .catch(() => {
        localStorage.removeItem('soc_token');
        setToken(null);
      })
      .finally(() => setLoading(false));
  }, [token]);

  const login = async (username, password) => {
    const data = await authLogin(username, password);
    localStorage.setItem('soc_token', data.access_token);
    setToken(data.access_token);
    const me = await getMe();
    setUser(me);
    return me;
  };

  const logout = () => {
    localStorage.removeItem('soc_token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ token, user, apiOnline, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
