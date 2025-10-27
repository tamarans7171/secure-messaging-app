import React, { useEffect, useState } from "react";
import { sendMessage } from "../api";
import JSEncrypt from "jsencrypt";

export default function Chat({ token }) {
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [publicKey, setPublicKey] = useState(null);

  useEffect(() => {
    // קבלת public key מהשרת (HTTPS)
    fetch("https://localhost:3001/public-key")
      .then(r => r.text())
      .then(k => setPublicKey(k))
      .catch(err => console.error("Failed to fetch public key", err));

    const evtSource = new EventSource("https://localhost:3001/events");
    evtSource.onmessage = (e) => {
      const data = JSON.parse(e.data);
      setMessages(prev => [...prev, data]);
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
