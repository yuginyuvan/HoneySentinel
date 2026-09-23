import { useState, useEffect } from "react";
import Layout from "../components/Layout";
import {
  getAIAnalysisSummary,
  getExecutedCommands,
  classifyCommand,
} from "../api/api";
import "./AIAnalysis.css";

export default function AIAnalysis() {
  const [data, setData] = useState({
    threatLevel: "UNKNOWN",
    attackType: "No analysis available",
    confidence: "0%",
    classification: [
      { label: "Total Logs Analyzed", val: "0" },
      { label: "Failed Attempts", val: "0" },
      { label: "Suspicious IPs", val: "0" },
      { label: "Risk Score", val: "0 / 10" },
    ],
    recommendations: ["Waiting for AI analysis"],
  });

  const [commands, setCommands] = useState([]);
  const [selectedCommand, setSelectedCommand] = useState(null);
  const [commandAnalysis, setCommandAnalysis] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);

  // ============================================================
  // FETCH AI SUMMARY
  // ============================================================

  const fetchAI = async () => {
    try {
      const res = await getAIAnalysisSummary();

      if (res) {
        setData(res);
      }
    } catch (error) {
      console.error("AI summary error:", error);
    }
  };

  // ============================================================
  // FETCH REAL COWRIE COMMANDS
  // ============================================================

  const fetchCommands = async () => {
    try {
      const res = await getExecutedCommands();

      if (Array.isArray(res)) {
        setCommands(res);

        // Automatically analyze the first command
        if (res.length > 0 && !selectedCommand) {
          handleCommandAnalysis(res[0]);
        }
      }
    } catch (error) {
      console.error("Command fetch error:", error);
    }
  };

  // ============================================================
  // ANALYZE SELECTED COMMAND USING PYTHON AI SERVICE
  // ============================================================

  const handleCommandAnalysis = async (command) => {
    if (!command || !command.cmd) {
      return;
    }

    setSelectedCommand(command);
    setAnalyzing(true);

    try {
      const result = await classifyCommand(command.cmd);

      if (result) {
        setCommandAnalysis(result);
      }
    } catch (error) {
      console.error("Command AI analysis error:", error);
    } finally {
      setAnalyzing(false);
    }
  };

  // ============================================================
  // INITIAL LOAD + AUTO REFRESH
  // ============================================================

  useEffect(() => {
    fetchAI();
    fetchCommands();

    const interval = setInterval(() => {
      fetchAI();
      fetchCommands();
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  // ============================================================
  // CONFIDENCE VALUE
  // ============================================================

  const confidenceValue =
    data.confidence ||
    (data.confidenceVal !== undefined
      ? `${data.confidenceVal}%`
      : "0%");

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <Layout
      title="AI Threat Analysis"
      subtitle="Machine learning threat scoring & mitigation heuristics"
    >
      {/* ======================================================
          TOP SECTION
      ====================================================== */}

      <div className="ai-analysis__topRow">

        {/* ====================================================
            THREAT PREDICTION
        ==================================================== */}

        <div className="panel ai-analysis__card">

          <h3 className="ai-analysis__cardTitle">
            Threat Prediction
          </h3>

          <span className="ai-analysis__label">
            Threat Level
          </span>

          <p className="ai-analysis__highLevel">
            {data.threatLevel || "UNKNOWN"}
          </p>

          <div className="ai-analysis__divider" />

          <span className="ai-analysis__label">
            Attack Type
          </span>

          <p className="ai-analysis__value">
            {data.attackType || "Unknown Attack"}
          </p>

          <div className="ai-analysis__divider" />

          <span className="ai-analysis__label">
            Model Confidence
          </span>

          <p className="ai-analysis__confidence mono">
            {confidenceValue}
          </p>

          <div className="ai-analysis__progressBar">
            <div
              className="ai-analysis__progressFill"
              style={{
                width: confidenceValue,
              }}
            />
          </div>

        </div>


        {/* ====================================================
            AI CLASSIFICATION
        ==================================================== */}

        <div className="panel ai-analysis__card">

          <h3 className="ai-analysis__cardTitle">
            AI Classification
          </h3>

          {Array.isArray(data.classification) &&
            data.classification.map((item) => (

              <div
                key={item.label}
                className="ai-analysis__classRow"
              >

                <span className="ai-analysis__label">
                  {item.label}
                </span>

                <span className="ai-analysis__classVal mono">
                  {item.val}
                </span>

              </div>

            ))}

        </div>

      </div>


      {/* ======================================================
          LIVE COMMAND ANALYSIS
      ====================================================== */}

      <div className="panel ai-analysis__commandCard">

        <h3 className="ai-analysis__cardTitle">
          Live Command Analysis
        </h3>

        <p className="ai-analysis__sectionDescription">
          Commands captured from the Cowrie honeypot and analyzed
          by the Python AI threat engine.
        </p>


        {/* COMMAND LIST */}

        <div className="ai-analysis__commandList">

          {commands.length === 0 ? (

            <p className="ai-analysis__empty">
              No attacker commands captured yet.
            </p>

          ) : (

            commands.map((command, index) => (

              <div
                key={`${command.time}-${command.cmd}-${index}`}
                className={`ai-analysis__commandRow ${
                  selectedCommand?.cmd === command.cmd
                    ? "ai-analysis__commandRow--selected"
                    : ""
                }`}
                onClick={() => handleCommandAnalysis(command)}
              >

                <span className="mono">
                  {command.time}
                </span>

                <span className="mono">
                  {command.ip}
                </span>

                <span className="mono ai-analysis__commandText">
                  {command.cmd}
                </span>

                <span className="status-pill">
                  {command.risk}
                </span>

              </div>

            ))

          )}

        </div>

      </div>


      {/* ======================================================
          SELECTED COMMAND RESULT
      ====================================================== */}

      {selectedCommand && (

        <div className="panel ai-analysis__detailCard">

          <h3 className="ai-analysis__cardTitle">
            Command Threat Analysis
          </h3>

          <div className="ai-analysis__detailGrid">

            {/* COMMAND */}

            <div className="ai-analysis__detailItem">

              <span className="ai-analysis__label">
                Command
              </span>

              <span className="ai-analysis__detailValue mono">
                {selectedCommand.cmd}
              </span>

            </div>


            {/* SOURCE IP */}

            <div className="ai-analysis__detailItem">

              <span className="ai-analysis__label">
                Source IP
              </span>

              <span className="ai-analysis__detailValue mono">
                {selectedCommand.ip}
              </span>

            </div>


            {/* RISK */}

            <div className="ai-analysis__detailItem">

              <span className="ai-analysis__label">
                Risk
              </span>

              <span className="ai-analysis__detailValue">
                {analyzing
                  ? "Analyzing..."
                  : commandAnalysis?.risk ||
                    selectedCommand.risk ||
                    "UNKNOWN"}
              </span>

            </div>


            {/* SCORE */}

            <div className="ai-analysis__detailItem">

              <span className="ai-analysis__label">
                Risk Score
              </span>

              <span className="ai-analysis__detailValue mono">
                {analyzing
                  ? "..."
                  : commandAnalysis?.score !== undefined
                  ? `${commandAnalysis.score} / 100`
                  : "N/A"}
              </span>

            </div>


            {/* ATTACK TYPE */}

            <div className="ai-analysis__detailItem">

              <span className="ai-analysis__label">
                Attack Type
              </span>

              <span className="ai-analysis__detailValue ai-analysis__value--danger">
                {analyzing
                  ? "Analyzing..."
                  : commandAnalysis?.category ||
                    "Not analyzed"}
              </span>

            </div>


            {/* MITRE */}

            <div className="ai-analysis__detailItem">

              <span className="ai-analysis__label">
                MITRE ATT&CK
              </span>

              <span className="ai-analysis__detailValue mono">
                {analyzing
                  ? "Analyzing..."
                  : commandAnalysis?.mitre_tactic ||
                    "Not mapped"}
              </span>

            </div>

          </div>


          {/* RECOMMENDATION */}

          <div className="ai-analysis__recommendation">

            <span className="ai-analysis__label">
              AI Recommendation
            </span>

            <p className="ai-analysis__recommendationText">
              {analyzing
                ? "Analyzing command..."
                : commandAnalysis?.recommendation ||
                  "No recommendation available"}
            </p>

          </div>

        </div>

      )}


      {/* ======================================================
          RECOMMENDATIONS
      ====================================================== */}

      <div className="panel ai-analysis__recommendCard">

        <h3 className="ai-analysis__cardTitle">
          Recommendation
        </h3>

        {Array.isArray(data.recommendations) &&
          data.recommendations.map((rec, index) => (

            <div
              key={index}
              className="ai-analysis__recItem"
            >

              <span className="ai-analysis__bullet">
                ▸
              </span>

              <span className="ai-analysis__recText">
                {rec}
              </span>

            </div>

          ))}

      </div>

    </Layout>
  );
}