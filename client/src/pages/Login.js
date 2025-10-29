import React, { useState } from "react";
import { login as apiLogin } from "../api";

// Helper: convert ArrayBuffer to PEM base64
function arrayBufferToPem(buffer, label) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = btoa(binary);
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

async function generateOrLoadKeyPair() {
  const storedPriv = localStorage.getItem('privJwk');
  const storedPub = localStorage.getItem('pubPem');
  if (storedPriv && storedPub) {
    const jwk = JSON.parse(storedPriv);
    return { privateJwk: jwk, publicPem: storedPub };
  }

  const kp = await window.crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  const pubSpki = await window.crypto.subtle.exportKey('spki', kp.publicKey);
  const privJwk = await window.crypto.subtle.exportKey('jwk', kp.privateKey);
  localStorage.setItem('privJwk', JSON.stringify(privJwk));
  const publicPem = arrayBufferToPem(pubSpki, 'PUBLIC KEY');
  localStorage.setItem('pubPem', publicPem);
  return { privateJwk: privJwk, publicPem };
}

async function importPrivateKey(jwk) {
  return window.crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
}

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const kp = await generateOrLoadKeyPair();
      const clientPublicKey = kp.publicPem;
      let publicPem = clientPublicKey;
      if (!publicPem && kp.privateJwk) {
        const regen = await generateOrLoadKeyPair();
        publicPem = regen.publicPem;
      }

      const res = await apiLogin(username, password, publicPem ? { clientPublicKey: publicPem } : undefined);

      const token = res.data.token;
      let groupKey = null;
      if (res.data.wrappedGroupKey) {
        const wrapped = res.data.wrappedGroupKey;
        const stored = localStorage.getItem('privJwk');
        if (stored) {
          const jwk = JSON.parse(stored);
          const privKey = await importPrivateKey(jwk);
          const wrappedBuf = Uint8Array.from(atob(wrapped), c => c.charCodeAt(0)).buffer;
          try {
            const decrypted = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, wrappedBuf);
              const bytes = new Uint8Array(decrypted);
              let bin = '';
              for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
              groupKey = btoa(bin);
          } catch (err) {
            console.error('Failed to unwrap group key', err);
          }
        }
      }

      onLogin({ token, groupKey });
    } catch (err) {
      console.error(err);
      setMsg("Login failed.");
    }
  };

  return (
    <div>
      <h2>Login</h2>
      <form onSubmit={handleSubmit}>
        <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
        <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
        <button type="submit">Login</button>
      </form>
      <div>{msg}</div>
    </div>
  );
}
