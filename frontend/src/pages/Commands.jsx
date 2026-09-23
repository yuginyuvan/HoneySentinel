import { useState, useEffect } from "react";
import Layout from "../components/Layout";
import { getExecutedCommands, classifyCommand } from "../api/api";
import "./Commands.css";

const riskPillClass = (risk) => {
  const r = String(risk).toUpperCase();
  if (r === "CRITICAL" || r === "HIGH") return "status-pill--red";
  if (r === "MEDIUM") return "status-pill--amber";
  if (r === "LOW") return "status-pill--green";
  return "status-pill--amber";
};

export default function Commands() {
  const [commands, setCommands] = useState([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);

  const fetchCmds = async () => {
    try {
      const data = await getExecutedCommands();
      if (Array.isArray(data)) {
        setCommands(data);
        if (data.length > 0 && !selectedAnalysis) {
          handleSelectCommand(data[0]);
        }
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchCmds();
    const interval = setInterval(fetchCmds, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSelectCommand = async (row) => {
    const aiResult = await classifyCommand(row.cmd);
    if (aiResult) {
      setSelectedAnalysis({
        command: row.cmd,
        risk: aiResult.risk || row.risk,
        category: aiResult.category || "Malware Download",
        recommendation: aiResult.recommendation || "Block IP immediately",
        mitre_tactic: aiResult.mitre_tactic || "T1059 - Command Execution"
      });
    }
  };

  return (
    <Layout title="Attacker Commands" subtitle="Shell commands executed in sandbox honeypot">
      <div className="commands__row">
        <div className="panel commands__card">
          <h3 className="commands__cardTitle">Executed Commands (Click to inspect)</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>IP Address</th>
                <th>Command</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {commands.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                    No executed commands captured yet.
                  </td>
                </tr>
              ) : (
                commands.map((row, i) => (
                  <tr
                    key={i}
                    onClick={() => handleSelectCommand(row)}
                    style={{ cursor: "pointer" }}
                    title="Click to run AI threat analysis"
                  >
                    <td className="mono">{row.time}</td>
                    <td className="mono">{row.ip}</td>
                    <td className="mono commands__cmd">{row.cmd}</td>
                    <td>
                      <span className={"status-pill " + riskPillClass(row.risk)}>
                        {row.risk}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="panel commands__analysisCard">
          <h3 className="commands__cardTitle">AI Command Analysis</h3>
          {selectedAnalysis ? (
            <>
              <p className="commands__alert">
                {selectedAnalysis.risk === "CRITICAL" || selectedAnalysis.risk === "HIGH"
                  ? "High risk command detected"
                  : "Command analyzed"}
              </p>
              <div className="commands__divider" />
              <p className="commands__label">Command</p>
              <p className="commands__value mono">{selectedAnalysis.command}</p>
              <div className="commands__divider" />
              <p className="commands__label">Attack Type</p>
              <p className="commands__value commands__value--danger">{selectedAnalysis.category}</p>
              <div className="commands__divider" />
              <p className="commands__label">MITRE ATT&CK</p>
              <p className="commands__value mono" style={{ fontSize: "12px", color: "#9ca3af" }}>{selectedAnalysis.mitre_tactic}</p>
              <div className="commands__divider" />
              <p className="commands__label">Recommendation</p>
              <p className="commands__value">{selectedAnalysis.recommendation}</p>
            </>
          ) : (
            <p style={{ color: "var(--text-muted)", fontSize: "13px", padding: "20px 0" }}>
              Select a command to inspect AI analysis.
            </p>
          )}
        </div>
      </div>
    </Layout>
  );
}
