import sys
import argparse
import re

# --- Nmap Port Advice ---
port_advice = {
    "21": "FTP – Check for anonymous login or brute-force with Hydra.",
    "22": "SSH – Brute-force with Hydra, check for weak keys.",
    "23": "Telnet – Insecure; try default creds.",
    "25": "SMTP – Check for open relay or user enum.",
    "53": "DNS – Try zone transfer: dig axfr @<ip>.",
    "69": "TFTP – Download config files.",
    "80": "HTTP – Run Nikto, WhatWeb, Gobuster.",
    "88": "Kerberos – Try AS-REP or Kerberoasting (AD).",
    "110": "POP3 – Test for plaintext auth.",
    "111": "RPC – Look for NFS.",
    "135": "MSRPC – Windows, check DCOM/DCERPC vulns.",
    "137": "NetBIOS – Use enum4linux or nbtstat.",
    "139": "SMB – Check for EternalBlue or file shares.",
    "143": "IMAP – Brute-force or SSL test.",
    "161": "SNMP – Try snmpwalk with 'public'.",
    "389": "LDAP – Enumerate users/groups.",
    "445": "SMB – Try smbclient, crackmapexec, enum4linux.",
    "512": "exec – Check for RCE.",
    "513": "login – Test R-services.",
    "514": "shell – Insecure remote shell.",
    "873": "rsync – Anonymous file access?",
    "1433": "MSSQL – Try default creds, metasploit.",
    "2049": "NFS – showmount -e <ip>",
    "2082": "cPanel – Brute-force admin panel.",
    "2083": "cPanel SSL – Same.",
    "3268": "GC LDAP – Multi-domain AD.",
    "3269": "GC LDAPS – Same over SSL.",
    "3389": "RDP – Ncrack, check BlueKeep.",
    "4455": "NTLM – Relay attacks possible.",
    "5432": "PostgreSQL – Test creds.",
    "5900": "VNC – No password?",
    "5985": "WinRM – Use evil-winrm if creds.",
    "6379": "Redis – May allow RCE.",
    "8000": "Alt HTTP – Gobuster, Nikto.",
    "8080": "Alt HTTP – Same.",
    "8443": "HTTPS – Test SSL/TLS ciphers.",
    "9200": "Elasticsearch – Test unauth access.",
    "11211": "Memcached – Test for abuse.",
}

# --- Nikto Pattern Advice ---
nikto_patterns = {
    "x-powered-by": "Header leaks technology – check for outdated software.",
    "directory indexing": "Directory listing enabled – may expose sensitive files.",
    "cgi-bin": "CGI found – test for RCE.",
    "OSVDB": "Known vuln – check CVE details.",
    "admin": "Admin page – test default creds.",
    "robots.txt": "Check disallowed entries in robots.txt.",
    "phpmyadmin": "phpMyAdmin exposed – check version and default creds.",
    "backup": "Backup file/folder found – may leak source code or creds.",
    "passwd": "passwd file exposed – security misconfig.",
    "config": "Configuration file found – may contain secrets.",
    "login": "Login page – test with brute-force or default passwords.",
    "shell": "Web shell detected – possible RCE.",
    "ssl": "SSL issue – test with SSLScan or testssl.sh.",
    "vulnerable": "Known vulnerability – check Exploit-DB or CVE.",
    "test": "Test or dev file found – often insecure.",
    "install": "Installation script found – may allow re-install or leaks.",
}

# --- SQLMap Patterns & Advice ---
sqlmap_patterns = {
    "Parameter:": "SQL injection confirmed – start with data dump: `--dump`.",
    "Type: boolean-based": "Boolean-based blind SQLi – try time-based or union too.",
    "Type: time-based": "Time-based blind – slower, use threading.",
    "Type: UNION query": "Union-based SQLi – check number of columns.",
    "back-end DBMS: MySQL": "Target DB is MySQL – test for file write with `--os-shell`.",
    "back-end DBMS: PostgreSQL": "PostgreSQL – try `--os-shell` or `--file-write`.",
    "back-end DBMS: Microsoft SQL Server": "MSSQL – check xp_cmdshell with `--os-shell`.",
    "back-end DBMS: Oracle": "Oracle – advanced SQLi, use `--priv-esc` and `--passwords`.",
    "banner:": "Banner grabbing done – check version for exploits.",
    "current user:": "DB user found – check if DBA/root.",
    "current database:": "Use this DB name in targeted queries.",
    "hostname:": "Internal hostname leaked – note for pivoting.",
}

# --- WhatWeb Patterns & Advice ---
whatweb_patterns = {
    "apache": "Apache web server detected – check version and known CVEs.",
    "nginx": "Nginx web server detected – check for misconfigurations.",
    "wordpress": "WordPress CMS found – scan with WPScan.",
    "joomla": "Joomla CMS found – check for outdated extensions.",
    "drupal": "Drupal CMS detected – look for recent security advisories.",
    "php": "PHP technology detected – check for info leaks.",
    "iis": "Microsoft IIS detected – look for known exploits.",
}

# --- dig/nslookup Patterns & Advice ---
dns_patterns = {
    "version": "DNS server version leak – potential for targeted attacks.",
    "axfr": "Zone transfer allowed – download DNS zone data.",
    "nameserver": "Nameserver info found – useful for reconnaissance.",
    "mail exchanger": "MX records found – check mail server for vulnerabilities.",
    "canonical name": "CNAME record found – note for aliasing and pivoting.",
}

# --- Parsers ---

def parse_nmap(file):
    with open(file, "r") as f:
        for line in f:
            if "Ports:" in line:
                ip = re.search(r"Host: ([\d\.]+)", line)
                ports = re.findall(r"(\d+)/open", line)
                if ip:
                    print(f"\n🔍 Target: {ip.group(1)}")
                    for port in ports:
                        advice = port_advice.get(port, f"Port {port} open – No specific advice.")
                        print(f"  - {advice}")

def parse_nikto(file):
    print("\n🧪 Analyzing Nikto output...")
    with open(file, "r") as f:
        for line in f:
            for pattern, advice in nikto_patterns.items():
                if pattern.lower() in line.lower():
                    print(f"  - Found: {pattern} → {advice}")

def parse_sqlmap(file):
    print("\n🎯 Analyzing SQLMap output...")
    with open(file, "r") as f:
        for line in f:
            for pattern, advice in sqlmap_patterns.items():
                if pattern.lower() in line.lower():
                    print(f"  - {advice}")

def parse_whatweb(file):
    print("\n🌐 Analyzing WhatWeb output...")
    with open(file, "r") as f:
        content = f.read().lower()
        for pattern, advice in whatweb_patterns.items():
            if pattern in content:
                print(f"  - Detected: {pattern} → {advice}")

def parse_dns(file):
    print("\n🧩 Analyzing dig/nslookup output...")
    with open(file, "r") as f:
        content = f.read().lower()
        for pattern, advice in dns_patterns.items():
            if pattern in content:
                print(f"  - Found: {pattern} → {advice}")

# --- Main ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan output advisor")
    parser.add_argument("--tool", required=True, help="Tool used (nmap, nikto, sqlmap, whatweb, dig, nslookup)")
    parser.add_argument("--file", required=True, help="Path to output file")

    args = parser.parse_args()
    tool = args.tool.lower()

    if tool == "nmap":
        parse_nmap(args.file)
    elif tool == "nikto":
        parse_nikto(args.file)
    elif tool == "sqlmap":
        parse_sqlmap(args.file)
    elif tool == "whatweb":
        parse_whatweb(args.file)
    elif tool == "dig" or tool == "nslookup":
        parse_dns(args.file)
    else:
        print("❌ Tool not supported. Use: nmap, nikto, sqlmap, whatweb, dig, nslookup.")
