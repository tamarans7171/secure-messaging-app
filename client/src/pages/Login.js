import React, { useState } from "react";
import { login } from "../api";

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");
  const [msgType, setMsgType] = useState("info");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMsg("");
    try {
      const res = await login(username, password);
      setMsgType('success');
      setMsg('Login successful');
      onLogin({ token: res.data.token, groupKey: res.data.groupKey });
    } catch (err) {
      const resp = err && err.response && err.response.data;
      const message = (resp && (resp.details || resp.error)) || err.message || "Login failed.";
      setMsgType('error');
      setMsg(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <h2>Login</h2>
      <form className="auth-form" onSubmit={handleSubmit}>
        <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
        <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
        <button type="submit" disabled={loading}>{loading ? 'Signing in...' : 'Login'}</button>
      </form>
      {msg && <div className={`msg ${msgType}`}>{msg}</div>}
    </div>
  );
}
