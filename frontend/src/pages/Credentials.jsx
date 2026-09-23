import { useState, useEffect } from "react";
import Layout from "../components/Layout";
import { getCapturedCredentials } from "../api/api";
import "./Credentials.css";

export default function Credentials() {
  const [data, setData] = useState({
    credentials: [],
    topUser: "-",
    topPass: "-"
  });

  const fetchCreds = async () => {
    try {
      const res = await getCapturedCredentials();
      if (res && Array.isArray(res.credentials)) {
        setData(res);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchCreds();
    const interval = setInterval(fetchCreds, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <Layout title="Captured Credentials" subtitle="Dictionary & brute force password attempts">
      <div className="panel credentials__card">
        <h3 className="credentials__cardTitle">Stolen Credential Attempts</h3>
        <div style={{ overflowX: "auto" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Password</th>
                <th>Attempts</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {data.credentials.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                    No stolen credentials captured yet.
                  </td>
                </tr>
              ) : (
                data.credentials.map((row, i) => (
                  <tr key={i}>
                    <td className="mono">{row.user}</td>
                    <td className="mono">{row.pass}</td>
                    <td className="mono">{row.attempts}</td>
                    <td>
                      <span className="status-pill status-pill--amber">{row.status}</span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      <div className="credentials__bottomRow">
        <div className="panel credentials__infoCard">
          <p className="credentials__infoLabel">Top Username</p>
          <p className="credentials__infoValue mono">{data.topUser || "-"}</p>
        </div>
        <div className="panel credentials__infoCard">
          <p className="credentials__infoLabel">Top Password</p>
          <p className="credentials__infoValue mono">{data.topPass || "-"}</p>
        </div>
      </div>
    </Layout>
  );
}
