# Security Advisor Script

A Python tool to analyze outputs from popular security scanning tools — **Nmap, Nikto, SQLMap, WhatWeb, dig, and nslookup** — and provide actionable advice on next steps.

---

## Features

- Parses scan outputs from multiple tools
- Identifies common vulnerabilities and findings
- Suggests practical steps for exploitation or further investigation
- Supports major pentesting tools and DNS enumeration
- Simple text-based CLI with built-in help

---

## Supported Tools

- **Nmap**: Port scanning and service detection
- **Nikto**: Web server vulnerability scanning
- **SQLMap**: Automated SQL injection detection
- **WhatWeb**: Web technology fingerprinting
- **dig/nslookup**: DNS enumeration and analysis

---

## Usage

```bash
python3 security_advisor.py --tool <tool_name> --file <path_to_output_file>

example :
python3 security_advisor.py --tool nmap --file nmap_output.txt
python3 security_advisor.py --tool nikto --file nikto_output.txt
python3 security_advisor.py --tool sqlmap --file sqlmap_output.txt
python3 security_advisor.py --tool whatweb --file whatweb_output.txt
python3 security_advisor.py --tool dig --file dig_output.txt
python3 security_advisor.py --tool nslookup --file nslookup_output.txt
 
```
---
## To see Help
```bash
python3 security_advisor.py -h
```
---
### Installation
```bash
python3 requirements.py
```
---
```bash
or manually :  
pip install colorama rich
```
---
