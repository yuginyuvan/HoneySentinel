import { NavLink, useNavigate } from "react-router-dom";
import "./Layout.css";


const NAV_ITEMS = [
  { label: "Dashboard", path: "/dashboard", icon: "◈" },
  { label: "Attack Logs", path: "/attacks", icon: "🛡" },
  { label: "Credentials", path: "/credentials", icon: "🔑" },
  { label: "Commands", path: "/commands", icon: "⌨" },
  { label: "AI Analysis", path: "/ai-analysis", icon: "✦" },
  { label: "Settings", path: "/settings", icon: "⚙" },
];
export default function Layout({ children, title, subtitle }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    navigate("/");
  };

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar__logo">
          <div className="sidebar__logoText">
            <span className="sidebar__logoTitle">
              AI HONEYPOT<span className="sidebar__cursor"></span>
            </span>
          </div>
        </div>

        <nav className="sidebar__nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                "sidebar__link" + (isActive ? " sidebar__link--active" : "")
              }
            >
              <span className="sidebar__linkIcon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <div className="main">
        <header className="topbar">
          <div>
            <h1 className="topbar__title">{title}</h1>
            {subtitle && <p className="topbar__subtitle">{subtitle}</p>}
          </div>
          <button className="topbar__logout" onClick={handleLogout}>
            Logout
          </button>
        </header>

        <div className="page-content">{children}</div>
      </div>
    </div>
  );
}
