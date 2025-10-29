import axios from "axios";

const API_URL = "https://localhost:3001";

export const register = (username, password) =>
  axios.post(`${API_URL}/register`, { username, password });

export const login = (username, password) =>
  axios.post(`${API_URL}/login`, { username, password });

export const sendMessage = (token, content) =>
  axios.post(`${API_URL}/send`, { token, content });

export const getMessages = (token, opts = {}) => {
  const headers = { Authorization: `Bearer ${token}` };
  const params = {};
  if (opts.limit) params.limit = opts.limit;
  if (opts.before) params.before = opts.before;
  return axios.get(`${API_URL}/messages`, { headers, params });
};
