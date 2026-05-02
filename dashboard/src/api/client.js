import axios from 'axios';

const API_BASE = 'http://localhost:8000';

const client = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
});

// JWT interceptor — attach token to every request
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('spaze_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor — redirect to login on 401
client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401 && window.location.pathname !== '/login') {
      localStorage.removeItem('spaze_token');
      localStorage.removeItem('spaze_user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export default client;
