import React, { useState } from "react";
import { register } from "../api";

export default function Register() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");
  const [msgType, setMsgType] = useState('info');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMsg("");
    try {
      await register(username, password);
      setMsgType('success');
      setMsg("Registration successful! You can log in now.");
    } catch (err) {
      const resp = err && err.response && err.response.data;
      const message = (resp && (resp.details || resp.error)) || err.message || "Registration failed.";
      setMsgType('error');
      setMsg(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <h2>Register</h2>
      <form className="auth-form" onSubmit={handleSubmit}>
        <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
        <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
        <button type="submit" disabled={loading}>{loading ? 'Registering...' : 'Register'}</button>
      </form>
      {msg && <div className={`msg ${msgType}`}>{msg}</div>}
    </div>
  );
}
