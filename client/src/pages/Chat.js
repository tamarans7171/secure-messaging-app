import React, { useEffect, useState } from "react";
import { sendMessage } from "../api";

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

    // Fetch server public key (SPKI PEM)
    fetch("https://localhost:3001/public-key")
      .then(r => r.text())
      .then(k => setPublicKey(k))
      .catch(err => console.error("Failed to fetch public key", err));

    const evtSource = new EventSource(`https://localhost:3001/events?token=${encodeURIComponent(token)}`);

    evtSource.onmessage = async (e) => {
      const payload = JSON.parse(e.data);

      // Case 1: Encrypted message with key available
      if (payload.content.mode === "aes-gcm" && groupKey) {
        try {
          const keyBytes = b64ToBytes(groupKey);
          const iv = b64ToBytes(payload.content.iv);
          const ct = b64ToBytes(payload.content.ciphertext);
          const tag = b64ToBytes(payload.content.authTag);

          const cryptoKey = await window.crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
          );

          const combined = new Uint8Array(ct.length + tag.length);
          combined.set(ct, 0);
          combined.set(tag, ct.length);

          const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            cryptoKey,
            combined
          );

          const txt = new TextDecoder().decode(new Uint8Array(decrypted));
          setMessages(prev => [...prev, {
            sender: payload.sender,
            content: txt,
            timestamp: payload.timestamp
          }]);
        } catch (err) {
          console.error("Decryption failed:", err);
          setMessages(prev => [...prev, {
            sender: payload.sender,
            content: '<decrypt failed>',
            timestamp: payload.timestamp
          }]);
        }
        return;
      }

      // Case 2: Encrypted but no key (user not logged in or key not shared)
      if (payload.content.mode === "aes-gcm") {
        setMessages(prev => [...prev, {
          sender: payload.sender,
          content: '<encrypted - no key>',
          timestamp: payload.timestamp
        }]);
        return;
      }

      // Case 3: Plaintext mode
      if (payload.content.mode === "plaintext") {
        setMessages(prev => [...prev, {
          sender: payload.sender,
          content: payload.content.content,  // ← Note: .content.content
          timestamp: payload.timestamp
        }]);
        return;
      }

      // Fallback: Unknown format
      console.warn("Unknown message format:", payload);
      setMessages(prev => [...prev, {
        sender: payload.sender,
        content: '<unknown format>',
        timestamp: payload.timestamp
      }]);
    };

    evtSource.onerror = (err) => {
      console.error("SSE error:", err);
    };

    return () => evtSource.close();
  }, [token, groupKey]); // Added groupKey to dependencies

  const handleSend = async () => {
    if (!text.trim()) return;
    if (!publicKey) return alert("Public key not loaded yet");

    try {
      // Import server public key (PEM -> ArrayBuffer -> CryptoKey)
      const pem = publicKey.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, '');
      const binaryDer = Uint8Array.from(atob(pem), c => c.charCodeAt(0)).buffer;
      const serverPubKey = await window.crypto.subtle.importKey(
        'spki',
        binaryDer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
      );

      // Generate ephemeral AES-GCM key
      const aesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(text);
      const ctBuffer = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);

      // Export raw AES key and encrypt it with server public key
      const rawKey = await window.crypto.subtle.exportKey('raw', aesKey);
      const wrappedKey = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, serverPubKey, rawKey);

      const toSend = {
        mode: 'hybrid',
        key: btoa(String.fromCharCode(...new Uint8Array(wrappedKey))),
        iv: btoa(String.fromCharCode(...iv)),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ctBuffer)))
      };

      await sendMessage(token, toSend);
      setText("");
    } catch (err) {
      console.error("Send failed:", err);
      alert("Failed to send message");
    }
  };

  return (
    <div>
      <h2>Chat</h2>
      <div style={{ maxHeight: "300px", overflowY: "auto", border: "1px solid #ccc", padding: "10px", marginBottom: "10px" }}>
        {messages.length === 0 ? (
          <p style={{ color: "#999" }}>No messages yet...</p>
        ) : (
          messages.map((m, i) => (
            <div key={i} style={{ marginBottom: "8px" }}>
              <b>{m.sender}</b>: {m.content}
            </div>
          ))
        )}
      </div>
      <div style={{ display: "flex", gap: "8px" }}>
        <input
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSend()}
          placeholder="Type a message..."
          style={{ flex: 1, padding: "8px" }}
        />
        <button onClick={handleSend}>Send</button>
      </div>
    </div>
  );
}