import { useState, useEffect } from "react";
import Layout from "../components/Layout";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

import {
  getDashboardStats,
  generateThreatReport,
} from "../api/api";

import "./Dashboard.css";


// ============================================================
// CUSTOM CHART TOOLTIP
// ============================================================

function ChartTooltip({ active, payload, label }) {

  if (!active || !payload || !payload.length) {
    return null;
  }

  return (
    <div className="dashboard__tooltip">

      <p className="dashboard__tooltipTime mono">
        {label}
      </p>

      <p className="dashboard__tooltipValue">

        <span
          className="status-dot"
          style={{ background: "#ce8620" }}
        />

        {payload[0].value} attacks

      </p>

    </div>
  );
}


// ============================================================
// SEVERITY CLASS
// ============================================================

const getSeverityClass = (severity) => {

  switch (String(severity).toUpperCase()) {

    case "CRITICAL":
      return "status-pill--amber";

    case "HIGH":
      return "status-pill--amber";

    case "MEDIUM":
      return "status-pill--amber";

    case "LOW":
      return "status-pill--green";

    default:
      return "status-pill--green";
  }
};


// ============================================================
// DASHBOARD
// ============================================================

export default function Dashboard() {

  const [data, setData] = useState({

    totalAttacks: 0,

    failedLogins: 0,

    successfulLogins: 0,

    uniqueAttackerIps: 0,

    threatLevel: "UNKNOWN",

    primaryAttackType: "No data",

    riskScore: 0,

    recommendation:
      "Waiting for attack data",

    timeline: [],

    recentLogs: [],
  });


  const [loading, setLoading] =
    useState(true);


  // ==========================================================
  // REPORT STATE
  // ==========================================================

  const [reportLoading, setReportLoading] =
    useState(false);


  // ==========================================================
  // FETCH DASHBOARD DATA
  // ==========================================================

  const fetchStats = async () => {

    try {

      const response =
        await getDashboardStats();

      if (response) {
        setData(response);
      }

    } catch (error) {

      console.error(
        "[Dashboard] Error:",
        error
      );

    } finally {

      setLoading(false);
    }
  };


  // ==========================================================
  // GENERATE REPORT
  // ==========================================================

  const handleGenerateReport = async () => {

    try {

      setReportLoading(true);

      await generateThreatReport();

    } catch (error) {

      console.error(
        "[Dashboard] Report generation error:",
        error
      );

      alert(
        "Failed to generate threat intelligence report."
      );

    } finally {

      setReportLoading(false);
    }
  };


  // ==========================================================
  // LIVE REFRESH
  // ==========================================================

  useEffect(() => {

    fetchStats();

    const timer =
      setInterval(
        fetchStats,
        5000
      );

    return () => {
      clearInterval(timer);
    };

  }, []);


  // ==========================================================
  // KPI CARDS
  // ==========================================================

  const statCards = [

    {
      label: "Total Attacks",

      value:
        data.totalAttacks ?? 0,
    },

    {
      label: "Failed Logins",

      value:
        data.failedLogins ?? 0,
    },

    {
      label: "Successful Logins",

      value:
        data.successfulLogins ?? 0,
    },

    {
      label: "Unique Attacker IPs",

      value:
        data.uniqueAttackerIps ?? 0,
    },

  ];


  // ==========================================================
  // TIMELINE
  // ==========================================================

  const timelineData =
    Array.isArray(data.timeline)
      ? data.timeline
      : [];


  // ==========================================================
  // RECENT ATTACKS
  // ==========================================================

  const recentAttacks =
    Array.isArray(data.recentLogs)
      ? data.recentLogs
      : [];


  // ==========================================================
  // RENDER
  // ==========================================================

  return (

    <Layout
      title="AI Honeypot Dashboard"
      subtitle="Real-time cyber attack monitoring & AI Threat Scoring"
    >

      {/* ====================================================
          REPORT ACTION
      ==================================================== */}

      <div className="dashboard__actions">

        <button
          type="button"
          className="dashboard__reportButton"
          onClick={handleGenerateReport}
          disabled={reportLoading}
        >

          {reportLoading
            ? "Generating Report..."
            : "📄 Generate Report"}

        </button>

      </div>


      {/* ====================================================
          KPI CARDS
      ==================================================== */}

      <div className="dashboard__stats">

        {statCards.map((stat) => (

          <div
            key={stat.label}
            className="panel dashboard__statCard"
          >

            <p className="dashboard__statLabel">
              {stat.label}
            </p>

            <p className="dashboard__statValue mono">

              {loading
                ? "..."
                : stat.value}

            </p>

          </div>

        ))}

      </div>


      {/* ====================================================
          TIMELINE + AI THREAT
      ==================================================== */}

      <div className="dashboard__midRow">


        {/* ==================================================
            ATTACK TIMELINE
        ================================================== */}

        <div className="panel dashboard__chartCard">

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "12px",
            }}
          >

            <h3
              className="dashboard__cardTitle"
              style={{ margin: 0 }}
            >
              Attack Timeline
            </h3>

            <span
              style={{
                fontSize: "11px",
                color: "#6b7280",
              }}
            >
              Live • 5s refresh
            </span>

          </div>


          {timelineData.length > 0 ? (

            <ResponsiveContainer
              width="100%"
              height={210}
            >

              <LineChart
                data={timelineData}
                margin={{
                  left: -18,
                  right: 8,
                }}
              >

                <CartesianGrid
                  stroke="#263445"
                  vertical={false}
                />

                <XAxis
                  dataKey="t"
                  tick={{
                    fill: "#9ca3af",
                    fontSize: 11,
                  }}
                  axisLine={{
                    stroke: "#374151",
                  }}
                  tickLine={false}
                />

                <YAxis
                  tick={{
                    fill: "#9ca3af",
                    fontSize: 11,
                  }}
                  axisLine={false}
                  tickLine={false}
                />

                <Tooltip
                  content={<ChartTooltip />}
                  cursor={{
                    stroke: "#374151",
                  }}
                />

                <Line
                  type="monotone"
                  dataKey="attacks"
                  stroke="#38bdf8"
                  strokeWidth={2}
                  dot={false}
                  activeDot={{
                    r: 4,
                    fill: "#ffffff",
                  }}
                />

              </LineChart>

            </ResponsiveContainer>

          ) : (

            <div
              style={{
                height: "210px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#6b7280",
                fontSize: "13px",
              }}
            >
              Waiting for attack timeline data...
            </div>

          )}

        </div>


        {/* ==================================================
            AI THREAT ANALYSIS
        ================================================== */}

        <div className="panel dashboard__threatCard">

          <h3 className="dashboard__cardTitle">
            AI Threat Analysis
          </h3>


          <span className="dashboard__threatLabel">
            Threat Level
          </span>


          <p className="dashboard__threatHigh">
            {data.threatLevel || "UNKNOWN"}
          </p>


          <p className="dashboard__threatItem">
            {data.primaryAttackType ||
              "No attack classification"}
          </p>


          <div className="dashboard__divider" />


          <span className="dashboard__threatLabel">
            AI Risk Score
          </span>


          <p className="dashboard__threatItem">
            {data.riskScore ?? 0} / 10
          </p>


          <div className="dashboard__divider" />


          <span className="dashboard__threatLabel">
            Recommendation
          </span>


          <p className="dashboard__threatItem">
            {data.recommendation ||
              "No recommendation"}
          </p>

        </div>

      </div>


      {/* ====================================================
          RECENT ATTACKS
      ==================================================== */}

      <div className="panel dashboard__logsCard">

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "12px",
          }}
        >

          <h3 className="dashboard__cardTitle">
            Recent Attacks & AI Risk Scores
          </h3>

          <span
            style={{
              fontSize: "11px",
              color: "#6b7280",
            }}
          >
            Live from Cowrie
          </span>

        </div>


        {recentAttacks.length > 0 ? (

          <div
            style={{
              overflowX: "auto",
            }}
          >

            <table className="data-table">

              <thead>

                <tr>

                  <th>
                    Time
                  </th>

                  <th>
                    IP Address
                  </th>

                  <th>
                    Executed Command / Event
                  </th>

                  <th>
                    Severity
                  </th>

                  <th>
                    Attack Type
                  </th>

                  <th>
                    MITRE ATT&CK
                  </th>

                  <th>
                    AI Risk Score
                  </th>

                </tr>

              </thead>


              <tbody>

                {recentAttacks.map(
                  (row, index) => (

                    <tr key={index}>

                      {/* TIME */}

                      <td className="mono">
                        {row.time || "--:--"}
                      </td>


                      {/* IP */}

                      <td className="mono">
                        {row.ip || "Unknown"}
                      </td>


                      {/* COMMAND */}

                      <td
                        className="mono"
                        style={{
                          color: "#38bdf8",
                          maxWidth: "300px",
                          overflow: "hidden",
                          textOverflow:
                            "ellipsis",
                          whiteSpace:
                            "nowrap",
                        }}
                      >
                        {row.command ||
                          "SSH Connection"}
                      </td>


                      {/* SEVERITY */}

                      <td>

                        <span
                          className={
                            "status-pill " +
                            getSeverityClass(
                              row.severity
                            )
                          }
                        >
                          {row.severity ||
                            "LOW"}
                        </span>

                      </td>


                      {/* ATTACK TYPE */}

                      <td
                        style={{
                          color: "#f87171",
                          fontSize: "12px",
                        }}
                      >
                        {row.attackType ||
                          "Unknown"}
                      </td>


                      {/* MITRE */}

                      <td
                        className="mono"
                        style={{
                          fontSize: "11px",
                          color: "#9ca3af",
                          maxWidth: "250px",
                        }}
                      >
                        {row.mitre ||
                          "Not mapped"}
                      </td>


                      {/* RISK */}

                      <td
                        className="mono"
                        style={{
                          fontWeight: "bold",
                          color: "#facc15",
                        }}
                      >
                        {row.riskScore ||
                          "0.0 / 10"}
                      </td>

                    </tr>

                  )
                )}

              </tbody>

            </table>

          </div>

        ) : (

          <div
            style={{
              padding: "40px",
              textAlign: "center",
              color: "#6b7280",
              fontSize: "13px",
            }}
          >
            No attack commands available yet.
          </div>

        )}

      </div>


    </Layout> 

  );
}