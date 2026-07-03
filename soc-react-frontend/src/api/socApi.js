// src/api/socApi.js
import axios from 'axios';
import { API_BASE } from '../constants/scenarios';

const client = axios.create({ baseURL: API_BASE, timeout: 600000 });

// Attach JWT automatically
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('soc_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export const authLogin = async (username, password) => {
  const res = await client.post('/auth/token', { username, password });
  return res.data; // { access_token, token_type, expires_in }
};

export const checkHealth = async () => {
  const res = await client.get('/health');
  return res.data;
};

export const getDashboardStats = async () => {
  const res = await client.get('/dashboard/stats');
  return res.data;
};

export const investigate = async (logs) => {
  const res = await client.post('/investigate', { logs });
  return res.data;
};

export const investigateAgent = async (logs, entityId = null) => {
  const payload = { logs };
  if (entityId) payload.entity_id = entityId;
  const res = await client.post('/investigate/agent', payload);
  return res.data;
};

export const ragTest = async (query, k = 3) => {
  const res = await client.post('/rag-test', { query, k });
  return res.data;
};

export const parseLogs = async (logs, k = 3) => {
  const res = await client.post('/parse', { logs, k });
  return res.data;
};

export const evaluate = async () => {
  const res = await client.get('/evaluate');
  return res.data;
};

export const getMe = async () => {
  const res = await client.get('/auth/me');
  return res.data;
};
