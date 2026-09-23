// ============================================================
// HoneySentinel API Service Layer
// ============================================================
// React Frontend
//        ↓
// Spring Boot API Gateway :8080
//        ↓
// ┌──────────────┬──────────────┬────────────────┐
// │ Backend :8081│ ML :8000     │ Analytics :8083│
// └──────────────┴──────────────┴────────────────┘
//                       ↓
//                     MySQL
// ============================================================


// ============================================================
// BASE URL
// ============================================================

let BASE_URL =
  localStorage.getItem("honeypot_api_url") ||
  "http://localhost:8080";


export const setApiBaseUrl = (url) => {

  if (
    url &&
    !url.startsWith("http://") &&
    !url.startsWith("https://")
  ) {
    url = "http://" + url;
  }

  BASE_URL = url;

  localStorage.setItem(
    "honeypot_api_url",
    url
  );
};


export const getApiBaseUrl = () => {
  return BASE_URL;
};


// ============================================================
// GENERIC API REQUEST
// ============================================================

async function apiRequest(
  endpoint,
  options = {},
  fallbackData = null
) {

  const url = `${BASE_URL}${endpoint}`;

  let timeoutId;

  try {

    const controller =
      new AbortController();

    timeoutId = setTimeout(() => {
      controller.abort();
    }, 4000);


    const response =
      await fetch(url, {

        ...options,

        signal: controller.signal,

        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",

          ...(options.headers || {}),
        },
      });


    clearTimeout(timeoutId);


    if (!response.ok) {

      console.warn(
        `[API] HTTP ${response.status} from ${endpoint}`
      );

      return fallbackData;
    }


    const data =
      await response.json();

    return data;

  } catch (error) {

    clearTimeout(timeoutId);

    console.info(
      `[API] Endpoint ${endpoint} offline, using fallback:`,
      error.message
    );

    return fallbackData;
  }
}


// ============================================================
// 1. DASHBOARD APIs
// ============================================================

export async function getDashboardStats() {

  const fallback = {

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
  };


  return await apiRequest(
    "/api/dashboard/stats",

    {
      method: "GET",
    },

    fallback
  );
}


// ============================================================
// 2. ATTACK LOGS APIs
// ============================================================

export async function getAttackLogs() {

  const fallback = [];


  const data =
    await apiRequest(
      "/api/attacks/sessions",

      {
        method: "GET",
      },

      null
    );


  if (
    data &&
    Array.isArray(data)
  ) {

    return data.map((s) => ({

      time:
        s.loginTime
          ? s.loginTime.substring(11, 16)
          : "--:--",

      ip:
        s.sourceIp ||
        "Unknown",

      user:
        s.username ||
        "Unknown",

      pass:
        s.password ||
        "******",

      status:
        s.loginStatus ||
        "UNKNOWN",

      country:
        s.country ||
        "Unknown",
    }));
  }


  return fallback;
}


// ============================================================
// 3. CAPTURED CREDENTIALS APIs
// ============================================================

export async function getCapturedCredentials() {

  const fallback = {

    credentials: [],

    topUser: "-",

    topPass: "-",
  };


  const data =
    await apiRequest(
      "/api/attacks/credentials/top",

      {
        method: "GET",
      },

      null
    );


  if (
    data &&
    Array.isArray(data) &&
    data.length > 0
  ) {

    const list =
      data.map((c) => ({

        user:
          c.username ||
          "Unknown",

        pass:
          c.password ||
          "******",

        attempts:
          c.attempts ||
          1,

        status:
          c.status ||
          "Weak",
      }));


    return {

      credentials: list,

      topUser:
        list[0]?.user ||
        "-",

      topPass:
        list[0]?.pass ||
        "-",
    };
  }


  return fallback;
}


// ============================================================
// 4. EXECUTED COMMANDS APIs
// ============================================================

export async function getExecutedCommands() {

  const fallback = [];


  const data =
    await apiRequest(
      "/api/attacks/commands",

      {
        method: "GET",
      },

      null
    );


  if (
    data &&
    Array.isArray(data)
  ) {

    return data.map((c) => ({

      time:
        c.commandTime
          ? c.commandTime.substring(
              11,
              16
            )
          : "--:--",

      ip:
        c.session?.sourceIp ||
        "Unknown",

      cmd:
        c.command ||
        "Unknown",

      risk:
        c.riskLevel ||
        "LOW",
    }));
  }


  return fallback;
}


// ============================================================
// 5. AI COMMAND CLASSIFIER
// ============================================================

export async function classifyCommand(
  command
) {

  const fallback = {

    command: command,

    risk: "UNKNOWN",

    score: 0,

    category:
      "Not analyzed",

    mitre_tactic:
      "Not mapped",

    recommendation:
      "No recommendation available",
  };


  return await apiRequest(
    "/api/ai/classify-command",

    {
      method: "POST",

      body: JSON.stringify({
        command,
      }),
    },

    fallback
  );
}


// ============================================================
// 6. AI THREAT ANALYSIS SUMMARY
// ============================================================

export async function getAIAnalysisSummary() {

  const fallback = {

    threatLevel:
      "UNKNOWN",

    attackType:
      "No analysis available",

    confidence:
      "0%",

    classification: [

      {
        label:
          "Total Logs Analyzed",

        val:
          "0",
      },

      {
        label:
          "Failed Attempts",

        val:
          "0",
      },

      {
        label:
          "Suspicious IPs",

        val:
          "0",
      },

      {
        label:
          "Risk Score",

        val:
          "0 / 10",
      },
    ],

    recommendations: [
      "Waiting for AI analysis",
    ],
  };


  const data =
    await apiRequest(
      "/api/ai/analysis/summary",

      {
        method: "GET",
      },

      null
    );


  if (!data) {
    return fallback;
  }


  return {

    threatLevel:
      data.threatLevel ??
      "UNKNOWN",

    attackType:
      data.attackType ??
      "Unknown Attack",

    confidence:
      data.modelConfidence ??
      (
        data.confidenceVal !==
        undefined
          ? `${data.confidenceVal}%`
          : "0%"
      ),

    classification:
      Array.isArray(
        data.classification
      )
        ? data.classification
        : fallback.classification,

    recommendations:
      Array.isArray(
        data.recommendations
      ) &&
      data.recommendations.length > 0
        ? data.recommendations
        : fallback.recommendations,
  };
}


// ============================================================
// 7. SYSTEM HEALTH
// ============================================================

export async function checkSystemHealth() {

  const status = [

    {
      service:
        "Cowrie Honeypot",

      status:
        "Checking",

      tone:
        "amber",
    },

    {
      service:
        "Spring Boot Gateway",

      status:
        "Checking",

      tone:
        "amber",
    },

    {
      service:
        "MySQL Database",

      status:
        "Checking",

      tone:
        "amber",
    },

    {
      service:
        "AI Engine",

      status:
        "Checking",

      tone:
        "amber",
    },
  ];


  // ==========================================================
  // 1. SPRING BOOT GATEWAY :8080
  // ==========================================================

  try {

    const gatewayResponse =
      await fetch(
        `${BASE_URL}/health`,
        {
          method: "GET",

          headers: {
            Accept:
              "application/json",
          },
        }
      );


    if (
      gatewayResponse.ok
    ) {

      status[1].status =
        "Connected (Port 8080)";

      status[1].tone =
        "green";

    } else {

      status[1].status =
        "Offline";

      status[1].tone =
        "amber";
    }

  } catch (error) {

    status[1].status =
      "Offline";

    status[1].tone =
      "amber";

    console.warn(
      "[HEALTH] Gateway unavailable:",
      error.message
    );
  }


  // ==========================================================
  // 2. AI / ML SERVICE :8000
  //
  // Gateway:
  // /api/ai/** → http://localhost:8000
  // ==========================================================

  try {

    const aiResponse =
      await fetch(
        `${BASE_URL}/api/ai/health`,
        {
          method: "GET",

          headers: {
            Accept:
              "application/json",
          },
        }
      );


    if (
      aiResponse.ok
    ) {

      const aiData =
        await aiResponse.json();


      if (
        aiData.status === "UP"
      ) {

        status[3].status =
          "Running (Port 8000)";

        status[3].tone =
          "cyan";

      } else {

        status[3].status =
          "Unavailable";

        status[3].tone =
          "amber";
      }

    } else {

      status[3].status =
        "Offline";

      status[3].tone =
        "amber";
    }

  } catch (error) {

    status[3].status =
      "Offline";

    status[3].tone =
      "amber";

    console.warn(
      "[HEALTH] AI service unavailable:",
      error.message
    );
  }


  // ==========================================================
  // 3. ANALYTICS SERVICE :8083 + MYSQL
  //
  // Gateway:
  // /api/dashboard/** → Analytics :8083
  //
  // If this endpoint returns successfully,
  // Analytics is running and its database query succeeded.
  // ==========================================================

  try {

    const analyticsResponse =
      await fetch(
        `${BASE_URL}/api/dashboard/stats`,
        {
          method: "GET",

          headers: {
            Accept:
              "application/json",
          },
        }
      );


    if (
      analyticsResponse.ok
    ) {

      status[2].status =
        "Connected (MySQL via Analytics)";

      status[2].tone =
        "green";

    } else {

      status[2].status =
        "Unavailable";

      status[2].tone =
        "amber";
    }

  } catch (error) {

    status[2].status =
      "Unavailable";

    status[2].tone =
      "amber";

    console.warn(
      "[HEALTH] Analytics/MySQL unavailable:",
      error.message
    );
  }


  // ==========================================================
  // 4. COWRIE HONEYPOT / LOG PIPELINE
  //
  // Gateway:
  // /api/attacks/** → Backend :8081
  //
  // The browser cannot directly check the Cowrie process.
  // We verify that the attack-session pipeline is responding.
  // ==========================================================

  try {

    const logsResponse =
      await fetch(
        `${BASE_URL}/api/attacks/sessions`,
        {
          method: "GET",

          headers: {
            Accept:
              "application/json",
          },
        }
      );


    if (
      logsResponse.ok
    ) {

      status[0].status =
        "Active (Log Pipeline Connected)";

      status[0].tone =
        "green";

    } else {

      status[0].status =
        "No Log Data";

      status[0].tone =
        "amber";
    }

  } catch (error) {

    status[0].status =
      "Offline";

    status[0].tone =
      "amber";

    console.warn(
      "[HEALTH] Cowrie log pipeline unavailable:",
      error.message
    );
  }


  return status;
}


// ============================================================
// 8. GENERATE THREAT INTELLIGENCE REPORT
// ============================================================
//
// React
//   ↓
// API Gateway :8080
//   ↓
// /api/reports/generate
//   ↓
// Backend :8081
//   ↓
// ReportService
//   ↓
// PDF
// ============================================================

export async function generateThreatReport() {

  const url =
    `${BASE_URL}/api/reports/generate`;

  try {

    console.log(
      "[REPORT] Generating threat intelligence report..."
    );


    const response =
      await fetch(
        url,
        {
          method: "GET",

          headers: {
            Accept:
              "application/pdf",
          },
        }
      );


    if (!response.ok) {

      throw new Error(
        `Report generation failed: HTTP ${response.status}`
      );
    }


    const blob =
      await response.blob();


    if (
      !blob ||
      blob.size === 0
    ) {

      throw new Error(
        "Generated report is empty."
      );
    }


    const downloadUrl =
      window.URL.createObjectURL(
        blob
      );


    const link =
      document.createElement("a");


    link.href =
      downloadUrl;


    link.download =
      "AI-Honeypot-Threat-Report.pdf";


    document.body.appendChild(
      link
    );


    link.click();


    link.remove();


    window.URL.revokeObjectURL(
      downloadUrl
    );


    console.log(
      "[REPORT] Threat intelligence report downloaded successfully."
    );


    return true;

  } catch (error) {

    console.error(
      "[REPORT] Failed to generate report:",
      error
    );

    throw error;
  }
}