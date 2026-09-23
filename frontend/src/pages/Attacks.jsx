import { useState, useEffect } from "react";
import Layout from "../components/Layout";
import { getAttackLogs } from "../api/api";
import "./Attacks.css";

export default function Attacks() {
  const [attacks, setAttacks] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAttacks = async () => {
    try {
      const data = await getAttackLogs();
      if (Array.isArray(data)) {
        setAttacks(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAttacks();
    const interval = setInterval(fetchAttacks, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <Layout title="Attack Logs" subtitle="Live Honeypot Cowrie event stream">
      <div className="panel attacks__card">
        <div className="attacks__cardHeader">
          <h3 className="attacks__cardTitle">All Attacks</h3>
          <span className="attacks__count mono">{attacks.length} Events</span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>IP Address</th>
                <th>Username</th>
                <th>Password</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {attacks.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                    {loading ? "Loading attack logs..." : "No attack logs captured yet."}
                  </td>
                </tr>
              ) : (
                attacks.map((row, i) => (
                  <tr key={i}>
                    <td className="mono">{row.time}</td>
                    <td className="mono">{row.ip}</td>
                    <td className="mono">{row.user}</td>
                    <td className="mono">{row.pass}</td>
                    <td>
                      <span
                        className={
                          "status-pill " +
                          (row.status === "SUCCESS" ? "status-pill--green" : "status-pill--amber")
                        }
                      >
                        {row.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
