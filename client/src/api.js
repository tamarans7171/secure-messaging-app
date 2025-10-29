import axios from "axios";

const API_URL = "https://localhost:3001";

export const register = (username, password) =>
  axios.post(`${API_URL}/register`, { username, password });

export const login = (username, password, extra = {}) =>
  axios.post(`${API_URL}/login`, { username, password, ...extra });

export const sendMessage = (token, content) =>
  axios.post(`${API_URL}/send`, { token, content });

export const getMessages = (token) =>
  axios.get(`${API_URL}/messages`, { headers: { Authorization: `Bearer ${token}` } });
