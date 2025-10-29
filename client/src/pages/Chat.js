import React, { useEffect, useState } from "react";
import { sendMessage } from "../api";
import JSEncrypt from "jsencrypt";

export default function Chat({ token, groupKey }) {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [publicKey, setPublicKey] = useState(null);

  useEffect(() => {
    const b64ToBytes = (b64) => {
      const bin = atob(b64);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr;
    };
    // קבלת public key מהשרת (HTTPS)
    fetch("https://localhost:3001/public-key")
      .then(r => r.text())
      .then(k => setPublicKey(k))
      .catch(err => console.error("Failed to fetch public key", err));

    const evtSource = new EventSource(`https://localhost:3001/events?token=${encodeURIComponent(token)}`);
    evtSource.onmessage = (e) => {
      const payload = JSON.parse(e.data);
      let content = "";
      if (payload.content && payload.content.mode === "aes-gcm" && groupKey) {
        try {
          const keyBytes = b64ToBytes(groupKey);
          const iv = b64ToBytes(payload.content.iv);
          const ct = b64ToBytes(payload.content.ciphertext);
          const tag = b64ToBytes(payload.content.authTag);
          // Web Crypto API for AES-GCM
          window.crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']).then(k => {
            const combined = new Uint8Array(ct.length + tag.length);
            combined.set(ct, 0);
            combined.set(tag, ct.length);
            return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, k, combined);
          }).then(ab => {
            const dec = new TextDecoder();
            const txt = dec.decode(new Uint8Array(ab));
            setMessages(prev => [...prev, { sender: payload.sender, content: txt, timestamp: payload.timestamp }]);
          }).catch(() => {
            setMessages(prev => [...prev, { sender: payload.sender, content: '<decrypt failed>', timestamp: payload.timestamp }]);
          });
          return;
        } catch (_) {}
      }
      // plaintext fallback (e.g., when no group key configured)
      setMessages(prev => [...prev, { sender: payload.sender, content: payload.content.mode ? '<unsupported>' : payload.content, timestamp: payload.timestamp }]);
    };
    return () => evtSource.close();
  }, []);

  const handleSend = async () => {
    if (!publicKey) return alert("Public key not loaded yet");
    const encrypt = new JSEncrypt();
    encrypt.setPublicKey(publicKey);
    const encrypted = encrypt.encrypt(text); // returns base64 string
    if (!encrypted) return alert("Encryption failed");
    console.log({ token, encrypt });

    await sendMessage(token, encrypted); // sendMessage uses axios to POST to /send
    setText("");
  };

  return (
    <div>
      <h2>Chat</h2>
      <div style={{ maxHeight: "300px", overflowY: "auto" }}>
        {messages.map((m, i) => (
          <div key={i}><b>{m.sender}</b>: {m.content}</div>
        ))}
      </div>
      <input value={text} onChange={e => setText(e.target.value)} />
      <button onClick={handleSend}>Send</button>
    </div>
  );
}
