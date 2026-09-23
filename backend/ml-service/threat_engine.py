import os
import json
import re
import joblib
from typing import Dict, Any, Optional, Tuple


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "command_classifier.pkl"
)

CONFIDENCE_THRESHOLD = 0.55


# ============================================================
# MITRE ATT&CK MAPPINGS
# ============================================================

MITRE_MAP = {

    "Account Discovery": {
        "id": "T1033",
        "name": "System Owner/User Discovery"
    },

    "Directory Recon": {
        "id": "T1083",
        "name": "File and Directory Discovery"
    },

    "System Discovery": {
        "id": "T1082",
        "name": "System Information Discovery"
    },

    "System Network Discovery": {
        "id": "T1016",
        "name": "System Network Configuration Discovery"
    },

    "Malware Download": {
        "id": "T1105",
        "name": "Ingress Tool Transfer"
    },

    "Permission Modification": {
        "id": "T1222.001",
        "name": "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification"
    },

    "Reverse Shell": {
        "id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell"
    },

    "Data Destruction": {
        "id": "T1485",
        "name": "Data Destruction"
    },

    "Defense Tampering": {
        "id": "T1562.004",
        "name": "Disable or Modify System Firewall"
    },

    "Generic Execution": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter"
    }
}


# ============================================================
# SEVERITY DEFAULTS
# ============================================================

SEVERITY_MAP = {

    "Account Discovery": "Medium",
    "Directory Recon": "Low",
    "System Discovery": "Medium",
    "System Network Discovery": "Medium",
    "Generic Execution": "Low",
    "Malware Download": "High",
    "Permission Modification": "High",
    "Reverse Shell": "Critical",
    "Data Destruction": "Critical",
    "Defense Tampering": "Critical",
    "Unknown": "Low",
    "Benign": "Low"
}


# ============================================================
# BASE RISK SCORES
# ============================================================

RISK_MAP = {

    "Account Discovery": 45,
    "Directory Recon": 30,
    "System Discovery": 50,
    "System Network Discovery": 50,
    "Generic Execution": 20,
    "Malware Download": 75,
    "Permission Modification": 70,
    "Reverse Shell": 95,
    "Data Destruction": 90,
    "Defense Tampering": 82,
    "Unknown": 10,
    "Benign": 0
}


# ============================================================
# BENIGN COMMANDS
# ============================================================

BENIGN_EXACT = {

    "clear",
    "true",
    "false",
    "echo",
    "echo hello",
    "pwd"
}


# ============================================================
# LOAD MODEL
# ============================================================

model = None

try:

    if os.path.exists(MODEL_PATH):

        model = joblib.load(MODEL_PATH)

        print("[ML] Model loaded successfully.")

        if hasattr(model, "named_steps"):

            classifier = model.named_steps.get("classifier")

            if classifier is not None:
                print(
                    f"[ML] Model: {classifier.__class__.__name__}"
                )
            else:
                print(
                    f"[ML] Model: {model.__class__.__name__}"
                )

        else:
            print(
                f"[ML] Model: {model.__class__.__name__}"
            )

    else:

        print("[ML] Model file not found.")
        print(f"[ML] Expected path: {MODEL_PATH}")

except Exception as e:

    print("[ML] Failed to load model.")
    print(f"[ML] Error: {e}")
    model = None


# ============================================================
# NORMALIZE COMMAND
# ============================================================

def normalize_command(command: str) -> str:

    if not command:
        return ""

    command = command.strip()

    # Collapse multiple spaces
    command = re.sub(r"\s+", " ", command)

    return command.lower()


# ============================================================
# BENIGN DETECTION
# ============================================================

def is_benign(command: str) -> bool:

    normalized = normalize_command(command)

    if not normalized:
        return True

    if normalized in BENIGN_EXACT:
        return True

    # echo followed by harmless text
    if re.match(r"^echo\s+[^;&|]+$", normalized):
        return True

    return False


# ============================================================
# RULE ENGINE
# ============================================================

def rule_engine(command: str) -> Optional[Dict[str, Any]]:

    cmd = normalize_command(command)

    if not cmd:
        return None


    # --------------------------------------------------------
    # ACCOUNT DISCOVERY
    # --------------------------------------------------------

    if re.fullmatch(r"whoami", cmd):

        return {
            "category": "Account Discovery",
            "reason": "Command identifies the current system user."
        }


    # --------------------------------------------------------
    # DIRECTORY RECON
    # --------------------------------------------------------

    if (
        re.fullmatch(r"ls", cmd)
        or re.match(r"^ls\s+", cmd)
        or re.fullmatch(r"tree", cmd)
        or re.fullmatch(r"find\s+.*", cmd)
        or re.fullmatch(r"du\s+.*", cmd)
    ):

        return {
            "category": "Directory Recon",
            "reason": "Command performs file or directory discovery."
        }


    # --------------------------------------------------------
    # DIRECTORY NAVIGATION
    # --------------------------------------------------------

    if (
        re.fullmatch(r"cd\s+.*", cmd)
        or re.fullmatch(r"pushd\s+.*", cmd)
        or re.fullmatch(r"popd", cmd)
    ):

        return {
            "category": "Directory Recon",
            "reason": "Command interacts with filesystem directories."
        }


    # --------------------------------------------------------
    # SYSTEM DISCOVERY
    # --------------------------------------------------------

    if (
        re.fullmatch(r"uname(\s+-.*)?", cmd)
        or re.fullmatch(r"hostname", cmd)
        or re.fullmatch(r"arch", cmd)
        or re.fullmatch(r"cat\s+/etc/os-release", cmd)
        or re.fullmatch(r"cat\s+/etc/issue", cmd)
        or re.fullmatch(r"lsb_release\s+.*", cmd)
        or re.fullmatch(r"nproc", cmd)
        or re.fullmatch(r"lscpu", cmd)
        or re.fullmatch(r"free\s+.*", cmd)
    ):

        return {
            "category": "System Discovery",
            "reason": "Command gathers information about the operating system or hardware."
        }


    # --------------------------------------------------------
    # NETWORK DISCOVERY
    # --------------------------------------------------------

    if (
        re.fullmatch(r"ifconfig", cmd)
        or re.fullmatch(r"ifconfig\s+.*", cmd)
        or re.fullmatch(r"ip\s+addr.*", cmd)
        or re.fullmatch(r"ip\s+a.*", cmd)
        or re.fullmatch(r"ip\s+route.*", cmd)
        or re.fullmatch(r"route\s+-n", cmd)
        or re.fullmatch(r"arp\s+-a", cmd)
        or re.fullmatch(r"hostname\s+-i", cmd)
        or re.fullmatch(r"hostname\s+-I", cmd)
        or re.fullmatch(r"netstat\s+.*", cmd)
        or re.fullmatch(r"ss\s+.*", cmd)
    ):

        return {
            "category": "System Network Discovery",
            "reason": "Command gathers network configuration or connectivity information."
        }


    # --------------------------------------------------------
    # MALWARE DOWNLOAD / INGRESS TOOL TRANSFER
    # --------------------------------------------------------

    if (
        re.search(r"\bwget\b", cmd)
        or re.search(r"\bcurl\b.*\|\s*(bash|sh)", cmd)
        or re.search(r"\bcurl\b.*-o\s+", cmd)
        or re.search(r"\bcurl\b.*-O\b", cmd)
        or re.search(r"\bscp\b", cmd)
        or re.search(r"\bsftp\b", cmd)
    ):

        return {
            "category": "Malware Download",
            "reason": "Command transfers files from a remote source."
        }


    # --------------------------------------------------------
    # PERMISSION MODIFICATION
    # --------------------------------------------------------

    if (
        re.match(r"^chmod\s+", cmd)
        or re.match(r"^chown\s+", cmd)
        or re.match(r"^chgrp\s+", cmd)
    ):

        return {
            "category": "Permission Modification",
            "reason": "Command modifies file permissions or ownership."
        }


    # --------------------------------------------------------
    # REVERSE SHELL
    # --------------------------------------------------------

    if (
        re.search(r"\bbash\s+-i\b", cmd)
        or re.search(r"\bsh\s+-i\b", cmd)
        or re.search(r"\bnc\b.*\s-e\s+", cmd)
        or re.search(r"\bncat\b.*\s-e\s+", cmd)
        or re.search(r"/dev/tcp/", cmd)
        or re.search(r"mkfifo.*nc", cmd)
    ):

        return {
            "category": "Reverse Shell",
            "reason": "Command contains a shell or network pattern associated with interactive remote command execution."
        }


    # --------------------------------------------------------
    # DATA DESTRUCTION
    # --------------------------------------------------------

    if (
        re.match(r"^rm\s+", cmd)
        or re.match(r"^shred\s+", cmd)
        or re.match(r"^wipe\s+", cmd)
        or re.search(r">\s*/.*history", cmd)
        or re.search(r">\s*.*\.log", cmd)
    ):

        return {
            "category": "Data Destruction",
            "reason": "Command can delete, overwrite, or destroy files."
        }


    # --------------------------------------------------------
    # DEFENSE TAMPERING
    # --------------------------------------------------------

    if (
        re.match(r"^iptables\s+-f\b", cmd)
        or re.match(r"^iptables\s+--flush\b", cmd)
        or re.match(r"^iptables\s+-d\b", cmd)
        or re.match(r"^ufw\s+disable\b", cmd)
        or re.match(r"^systemctl\s+(stop|disable)\s+.*", cmd)
        or re.match(r"^service\s+.*\s+stop\b", cmd)
    ):

        return {
            "category": "Defense Tampering",
            "reason": "Command modifies or disables host security controls."
        }


    return None


# ============================================================
# ML PREDICTION
# ============================================================

def ml_predict(command: str) -> Tuple[Optional[str], float]:

    if model is None:

        return None, 0.0

    try:

        prediction = model.predict([command])[0]

        confidence = 0.0

        if hasattr(model, "predict_proba"):

            probabilities = model.predict_proba([command])[0]

            confidence = float(max(probabilities))

        return str(prediction), confidence

    except Exception as e:

        print(f"[ML] Prediction error: {e}")

        return None, 0.0


# ============================================================
# MITRE INFORMATION
# ============================================================

def get_mitre(category: str) -> Optional[str]:

    info = MITRE_MAP.get(category)

    if not info:
        return None

    return f"{info['id']} - {info['name']}"


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score: int) -> str:

    if score >= 85:
        return "Critical"

    if score >= 70:
        return "High"

    if score >= 40:
        return "Medium"

    return "Low"


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk(
    category: str,
    confidence: float,
    source: str
) -> int:

    base_score = RISK_MAP.get(category, 10)

    if source == "Rule":
        return base_score

    if source == "ML":

        # Confidence adjustment
        if confidence >= 0.90:
            return min(100, base_score + 5)

        if confidence >= 0.75:
            return base_score

        if confidence >= CONFIDENCE_THRESHOLD:
            return max(0, base_score - 5)

        return max(0, base_score - 15)

    return base_score


# ============================================================
# MAIN THREAT ANALYSIS
# ============================================================

def analyze_command(command: str) -> Dict[str, Any]:

    normalized = normalize_command(command)

    # --------------------------------------------------------
    # Empty command
    # --------------------------------------------------------

    if not normalized:

        return {
            "command": command,
            "mlPrediction": None,
            "mlConfidence": 0.0,
            "detectionSource": "Benign",
            "category": "Benign",
            "mitre": None,
            "severity": "Low",
            "riskScore": 0,
            "riskLevel": "Low",
            "ruleMatched": False,
            "benign": True,
            "summary": "Empty command ignored."
        }


    # --------------------------------------------------------
    # ML PREDICTION
    # --------------------------------------------------------

    ml_prediction, ml_confidence = ml_predict(normalized)


    # --------------------------------------------------------
    # BENIGN CHECK FIRST
    # --------------------------------------------------------

    if is_benign(normalized):

        return {
            "command": command,
            "mlPrediction": ml_prediction,
            "mlConfidence": round(ml_confidence, 4),
            "detectionSource": "Benign",
            "category": "Benign",
            "mitre": None,
            "severity": "Low",
            "riskScore": 0,
            "riskLevel": "Low",
            "ruleMatched": False,
            "benign": True,
            "summary": "Command identified as benign and excluded from threat scoring."
        }


    # --------------------------------------------------------
    # RULE ENGINE
    # --------------------------------------------------------

    rule_result = rule_engine(normalized)

    if rule_result:

        category = rule_result["category"]

        mitre = get_mitre(category)

        severity = SEVERITY_MAP.get(
            category,
            "Medium"
        )

        risk_score = calculate_risk(
            category,
            ml_confidence,
            "Rule"
        )

        summary = (
            f"Deterministic security rule classified the command "
            f"as {category}. "
        )

        if mitre:

            summary += f"MITRE ATT&CK: {mitre}."

        else:

            summary += rule_result["reason"]

        return {
            "command": command,
            "mlPrediction": ml_prediction,
            "mlConfidence": round(ml_confidence, 4),
            "detectionSource": "Rule",
            "category": category,
            "mitre": mitre,
            "severity": severity,
            "riskScore": risk_score,
            "riskLevel": get_risk_level(risk_score),
            "ruleMatched": True,
            "benign": False,
            "summary": summary
        }


    # --------------------------------------------------------
    # ML DECISION
    # --------------------------------------------------------

    if (
        ml_prediction is not None
        and ml_confidence >= CONFIDENCE_THRESHOLD
    ):

        category = ml_prediction

        # Don't allow benign-ish ML categories to create threats
        if category == "Generic Execution":

            return {
                "command": command,
                "mlPrediction": ml_prediction,
                "mlConfidence": round(ml_confidence, 4),
                "detectionSource": "ML",
                "category": "Generic Execution",
                "mitre": get_mitre("Generic Execution"),
                "severity": "Low",
                "riskScore": calculate_risk(
                    "Generic Execution",
                    ml_confidence,
                    "ML"
                ),
                "riskLevel": get_risk_level(
                    calculate_risk(
                        "Generic Execution",
                        ml_confidence,
                        "ML"
                    )
                ),
                "ruleMatched": False,
                "benign": False,
                "summary": (
                    f"Machine learning classified the command as "
                    f"Generic Execution with "
                    f"{ml_confidence * 100:.2f}% confidence."
                )
            }

        mitre = get_mitre(category)

        severity = SEVERITY_MAP.get(
            category,
            "Medium"
        )

        risk_score = calculate_risk(
            category,
            ml_confidence,
            "ML"
        )

        summary = (
            f"Machine learning classified the command as "
            f"{category} with "
            f"{ml_confidence * 100:.2f}% confidence."
        )

        return {
            "command": command,
            "mlPrediction": ml_prediction,
            "mlConfidence": round(ml_confidence, 4),
            "detectionSource": "ML",
            "category": category,
            "mitre": mitre,
            "severity": severity,
            "riskScore": risk_score,
            "riskLevel": get_risk_level(risk_score),
            "ruleMatched": False,
            "benign": False,
            "summary": summary
        }


    # --------------------------------------------------------
    # UNKNOWN / LOW CONFIDENCE
    # --------------------------------------------------------

    return {
        "command": command,
        "mlPrediction": ml_prediction,
        "mlConfidence": round(ml_confidence, 4),
        "detectionSource": "Unknown",
        "category": "Unknown",
        "mitre": None,
        "severity": "Low",
        "riskScore": 10,
        "riskLevel": "Low",
        "ruleMatched": False,
        "benign": False,
        "summary": (
            "Command did not match a deterministic security rule "
            "and the ML model confidence was below the "
            f"{CONFIDENCE_THRESHOLD * 100:.0f}% threshold."
        )
    }


# ============================================================
# ML STATUS
# ============================================================

def get_ml_status() -> Dict[str, Any]:

    model_name = None

    if model is not None:

        if hasattr(model, "named_steps"):

            classifier = model.named_steps.get("classifier")

            if classifier is not None:

                model_name = classifier.__class__.__name__

        if model_name is None:

            model_name = model.__class__.__name__


    return {
        "available": model is not None,
        "modelExists": os.path.exists(MODEL_PATH),
        "model": model_name,
        "modelPath": MODEL_PATH,
        "confidenceThreshold": CONFIDENCE_THRESHOLD
    }


# ============================================================
# PRINT RESULT
# ============================================================

def print_analysis(index: int, command: str) -> None:

    result = analyze_command(command)

    print()
    print(
        f"[{index}] COMMAND: {command}"
    )

    print("-" * 70)

    confidence = result["mlConfidence"] * 100

    print(
        f"ML Prediction : {result['mlPrediction']}"
    )

    print(
        f"ML Confidence : {confidence:.2f}%"
    )

    print(
        f"Detection Src : {result['detectionSource']}"
    )

    print(
        f"Category      : {result['category']}"
    )

    print(
        f"MITRE         : {result['mitre']}"
    )

    print(
        f"Severity      : {result['severity']}"
    )

    print(
        f"Risk Score    : {result['riskScore']}"
    )

    print(
        f"Risk Level    : {result['riskLevel']}"
    )

    print(
        f"Rule Matched  : {result['ruleMatched']}"
    )

    print(
        f"Benign        : {result['benign']}"
    )

    print(
        f"Summary       : {result['summary']}"
    )


# ============================================================
# TEST COMMANDS
# ============================================================

TEST_COMMANDS = [

    "whoami",

    "ls -la",

    "uname -a",

    "ifconfig",

    "hostname -I",

    "wget http://example.com/file.sh",

    "chmod 777 test.sh",

    "bash -i",

    "rm -rf /tmp/test",

    "iptables -F",

    "echo hello",

    "clear",

    "cat /etc/os-release",

    "arch",

    "true",

    "false",

    "some_unknown_command_123",

    "randomtool --scan 192.168.1.1"
]


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("HoneySentinel Threat Engine Test")
    print("=" * 70)

    print()
    print("ML STATUS")
    print("-" * 70)

    print(
        json.dumps(
            get_ml_status(),
            indent=2
        )
    )

    print()
    print("=" * 70)
    print("COMMAND ANALYSIS")
    print("=" * 70)

    for index, command in enumerate(
        TEST_COMMANDS,
        start=1
    ):

        print_analysis(
            index,
            command
        )

    print()
    print("=" * 70)
    print("THREAT ENGINE TEST COMPLETED")
    print("=" * 70)