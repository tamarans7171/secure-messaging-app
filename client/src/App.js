import React, { useState } from "react";
import Register from "./pages/Register";
import Login from "./pages/Login";
import Chat from "./pages/Chat";

function App() {
  const [token, setToken] = useState(null);

  if (!token) {
    return (
      <div>
        <Register />
        <Login onLogin={setToken} />
      </div>
    );
  }

  return <Chat token={token} />;
}

export default App;
