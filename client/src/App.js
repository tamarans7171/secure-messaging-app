import React, { useState } from "react";
import Register from "./pages/Register";
import Login from "./pages/Login";
import Chat from "./pages/Chat";

function App() {
  const [token, setToken] = useState(null);
  const [groupKey, setGroupKey] = useState(null);

  if (!token) {
    return (
      <div>
        <Register />
        <Login onLogin={({ token, groupKey }) => { setToken(token); setGroupKey(groupKey || null); }} />
      </div>
    );
  }

  return <Chat token={token} groupKey={groupKey} />;
}

export default App;
