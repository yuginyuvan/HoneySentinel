import { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Login.css";
const DEMO_USER = "admin";
const DEMO_PASS = "admin123";
export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();
  const handleLogin = () => {
    if (username === DEMO_USER && password === DEMO_PASS) {
      setError("");
      navigate("/dashboard");
    } else {
      setError("Invalid credentials. Use admin / admin123");
    }
  };
  const handleKeyDown = (e) => {
    if (e.key === "Enter") handleLogin();
  };
  return (
    <div className="login-page">
      <div className="login-page__glow" />
      <div className="login-card">
        <div className="login-card__brand">
          <span className="login-card__mark"></span>
          <span className="login-card__brandText mono"><h1>AI HONEYPOT</h1></span>
        </div>
        <h2 className="login-card__title"> Dashboard Login</h2>
        <div className="login-card__field">
          <label className="login-card__label">Username</label>
          <input
            className="login-card__input mono"
            type="text"
            placeholder="Enter username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={handleKeyDown}
            autoFocus
          />
        </div>
        <div className="login-card__field">
          <label className="login-card__label">Password</label>
          <input
            className="login-card__input mono"
            type="password"
            placeholder="Enter password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={handleKeyDown}
          />
        </div>
        {error && <p className="login-card__error"> {error}</p>}
        <button className="login-card__submit" onClick={handleLogin}>
          Access Dashboard
        </button>
        <p className="login-card__hint">
          Demo credentials: <span className="mono">admin / admin123</span>
        </p>
      </div>
    </div>
  );
}
