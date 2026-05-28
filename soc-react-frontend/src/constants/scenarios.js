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
};

export const API_BASE = 'http://localhost:8000';

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
  { id: 0, label: 'Log Normalization', desc: 'Regex + JSON parser' },
  { id: 1, label: 'Event Extraction', desc: 'Rule-based (10 types)' },
  { id: 2, label: 'LSTM Anomaly Detection', desc: 'Sequence autoencoder' },
  { id: 3, label: 'Threat Intel Lookup', desc: 'IP/hash/command DB' },
  { id: 4, label: 'MITRE ATT&CK RAG', desc: 'ChromaDB semantic search' },
  { id: 5, label: 'LLM Investigation', desc: 'OpenAI via OpenRouter' },
  { id: 6, label: 'Attack Graph Build', desc: 'NetworkX kill-chain' },
  { id: 7, label: 'Agent Correlation', desc: 'ReAct cross-session' },
];
