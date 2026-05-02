import { createContext, useContext, useState, useEffect } from 'react';
import client from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('spaze_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState(() => localStorage.getItem('spaze_token'));

  const isAuthenticated = !!token;

  const login = async (email, password) => {
    const res = await client.post('/api/auth/login', { email, password });
    const { access_token, user: userData } = res.data;
    localStorage.setItem('spaze_token', access_token);
    localStorage.setItem('spaze_user', JSON.stringify(userData));
    setToken(access_token);
    setUser(userData);
    return userData;
  };

  const logout = () => {
    localStorage.removeItem('spaze_token');
    localStorage.removeItem('spaze_user');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
