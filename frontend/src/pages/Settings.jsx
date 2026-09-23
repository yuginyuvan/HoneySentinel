import { useState, useEffect } from "react";
import Layout from "../components/Layout";
import {
  getApiBaseUrl,
  setApiBaseUrl,
  checkSystemHealth,
} from "../api/api";
import "./Settings.css";

export default function Settings() {
  const [backendUrl, setBackendUrlState] = useState(getApiBaseUrl());
  const [saved, setSaved] = useState(false);

  const [systemStatus, setSystemStatus] = useState([
    {
      service: "Cowrie Honeypot",
      status: "Checking",
      tone: "amber",
    },
    {
      service: "Spring Boot Gateway",
      status: "Checking",
      tone: "amber",
    },
    {
      service: "MySQL Database",
      status: "Checking",
      tone: "amber",
    },
    {
      service: "AI Engine",
      status: "Checking",
      tone: "amber",
    },
  ]);

  // ============================================================
  // LIVE SYSTEM HEALTH CHECK
  // ============================================================

  useEffect(() => {
    let mounted = true;

    async function checkHealth() {
      try {
        const statuses = await checkSystemHealth();

        if (mounted) {
          setSystemStatus(statuses);
        }
      } catch (error) {
        console.error(
          "[SETTINGS] Health check failed:",
          error
        );
      }
    }

    // Initial check
    checkHealth();

    // Refresh every 6 seconds
    const timer = setInterval(checkHealth, 6000);

    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  // ============================================================
  // SAVE GATEWAY URL
  // ============================================================

  const handleSave = () => {
    setApiBaseUrl(backendUrl);

    setSaved(true);

    setTimeout(() => {
      setSaved(false);
    }, 2000);
  };

  return (
    <Layout
      title="Settings"
      subtitle="System configuration & live microservice health"
    >
      <div className="settings__grid">

        {/* ======================================================
            DASHBOARD SETTINGS
        ====================================================== */}

        <div className="panel settings__card">
          <h3 className="settings__cardTitle">
            Dashboard Settings
          </h3>

          <div className="settings__row">
            <span className="settings__key">
              Theme
            </span>

            <span className="settings__val">
              Dark Mode (SOC)
            </span>
          </div>

          <div className="settings__row">
            <span className="settings__key">
              Refresh Interval
            </span>

            <span className="settings__val">
              5 sec
            </span>
          </div>

          <div className="settings__row">
            <span className="settings__key">
              Microservice Gateway
            </span>

            <span className="settings__val settings__val--green">
              Active
            </span>
          </div>
        </div>


        {/* ======================================================
            SYSTEM STATUS
        ====================================================== */}

        <div className="panel settings__card">
          <h3 className="settings__cardTitle">
            System Status
          </h3>

          {systemStatus.map((s) => (
            <div
              key={s.service}
              className="settings__row"
            >
              <span className="settings__key">
                {s.service}
              </span>

              <span
                className={`settings__val settings__val--${s.tone}`}
              >
                <span
                  className={`status-dot settings__dot--${s.tone}`}
                />

                {s.status}
              </span>
            </div>
          ))}
        </div>


        {/* ======================================================
            SECURITY SETTINGS
        ====================================================== */}

        <div className="panel settings__card">
          <h3 className="settings__cardTitle">
            Security Settings
          </h3>

          <div className="settings__row">
            <span className="settings__key">
              Auto-Block Attacker IPs
            </span>

            <span className="settings__val settings__val--white">
              ON
            </span>
          </div>

          <div className="settings__row">
            <span className="settings__key">
              Log Retention
            </span>

            <span className="settings__val">
              30 days
            </span>
          </div>

          <div className="settings__row">
            <span className="settings__key">
              Alert Threshold
            </span>

            <span className="settings__val settings__val--white">
              High
            </span>
          </div>
        </div>


        {/* ======================================================
            API GATEWAY CONFIGURATION
        ====================================================== */}

        <div className="panel settings__card">
          <h3 className="settings__cardTitle">
            API Gateway Configuration
          </h3>

          <div className="settings__fieldGroup">
            <label className="settings__fieldLabel">
              Gateway URL
            </label>

            <input
              className="settings__input mono"
              value={backendUrl}
              onChange={(e) =>
                setBackendUrlState(e.target.value)
              }
              placeholder="http://localhost:8080"
            />
          </div>

          <button
            className="settings__saveBtn"
            onClick={handleSave}
          >
            {saved ? "Saved" : "Save Settings"}
          </button>
        </div>

      </div>
    </Layout>
  );
}