import sys
import argparse
import re

# --- Nmap Port Advice ---
port_advice = {
    "20": "FTP Data – Same as FTP (port 21), check data transfer vulnerabilities.",
    "21": "FTP – Check anonymous login, brute-force with Hydra, directory traversal.",
    "22": "SSH – Brute-force Hydra/Ncrack, weak keys, outdated versions.",
    "23": "Telnet – Try default creds, sniff clear-text traffic.",
    "25": "SMTP – Open relay check, user enumeration (smtp-user-enum).",
    "53": "DNS – Zone transfer (dig axfr), DNS spoof/version leaks.",
    "67": "DHCP – Rogue servers/spoofing detection.",
    "69": "TFTP – Download configs, anonymous access.",
    "80": "HTTP – Nikto, WhatWeb, Gobuster for directories and panels.",
    "88": "Kerberos – AS-REP roasting, Kerberoasting in AD.",
    "110": "POP3 – Brute-force, plaintext creds.",
    "111": "RPC – Enumerate NFS shares.",
    "123": "NTP – Monlist amplification, version leaks.",
    "135": "MSRPC – DCOM/DCERPC vulns.",
    "137": "NetBIOS – enum4linux, nbtstat info gathering.",
    "139": "SMB – EternalBlue, Null sessions, share enumeration.",
    "143": "IMAP – Brute-force, SSL cert inspection.",
    "161": "SNMP – snmpwalk, brute-force community strings.",
    "389": "LDAP – User/group enumeration, referral abuse.",
    "443": "HTTPS – Test SSL/TLS ciphers, cert validity, vulnerabilities.",
    "445": "SMB – crackmapexec, enum4linux, pass-the-hash.",
    "512": "exec – RCE testing.",
    "513": "login – R-services auth testing.",
    "514": "shell – Insecure remote shell check.",
    "543": "Klogin – Test r-commands for weak auth.",
    "544": "Kshell – Same as 543.",
    "548": "AFP – Check for unauth access (Apple Filing Protocol).",
    "5900": "VNC – Check for no or weak password.",
    "593": "HTTP RPC – MSRPC over HTTP, test for vulnerabilities.",
    "631": "IPP – Printer exploitation, CUPS vulnerability scans.",
    "636": "LDAPS – Encrypted LDAP, user enumeration.",
    "989": "FTPS (data) – Check SSL/TLS implementation.",
    "990": "FTPS (control) – Same as 989.",
    "1080": "SOCKS Proxy – Abuse open proxy for pivoting.",
    "1194": "OpenVPN – Check for misconfigurations.",
    "1433": "MSSQL – Brute-force, xp_cmdshell exploit.",
    "1521": "Oracle DB – Default creds, SQL injection.",
    "1723": "PPTP VPN – Vulnerable to MS-CHAPv2 attacks.",
    "2049": "NFS – showmount -e, writable shares.",
    "2082": "cPanel – Brute-force admin login.",
    "2083": "cPanel SSL – Same as 2082 but encrypted.",
    "3128": "Squid Proxy – Open proxy abuse.",
    "3306": "MySQL – Test default creds, SQL injection.",
    "3389": "RDP – Brute-force Ncrack, BlueKeep exploit.",
    "3690": "SVN – Check for anonymous checkout.",
    "4369": "Erlang Port Mapper – Service enumeration.",
    "4444": "Metasploit Payload – Check listener activity.",
    "5000": "UPnP – Exploit misconfigured services.",
    "5432": "PostgreSQL – Brute-force, SQL injection.",
    "5900": "VNC – No password check.",
    "5985": "WinRM – Use evil-winrm with creds.",
    "6379": "Redis – Unauthorized access, RCE.",
    "8080": "HTTP Alternate – Directory busting, vuln scans.",
    "8443": "HTTPS Alternate – Same as 443.",
    "8888": "Alternate HTTP – Same as 8080.",
    "9200": "Elasticsearch – Unauth access, data leaks, RCE.",
    "11211": "Memcached – Amplification attacks, abuse.",
    "27017": "MongoDB – No auth access, data dump.",
    "50070": "HDFS Namenode – Information disclosure.",
    "5901": "VNC (alternate) – Same checks as 5900.",
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
    print("\n🧲 Analyzing Nmap output...")
    with open(file, "r") as f:
        content = f.read()
        reports = re.split(r"Nmap scan report for ", content)[1:]
        for report in reports:
            lines = report.strip().split("\n")
            ip = lines[0].strip()
            print(f"\n🔍 Target: {ip}")
            for line in lines:
                match = re.match(r"(\d+)/tcp\s+open", line)
                if match:
                    port = match.group(1)
                    advice = port_advice.get(port, f"Port {port} open – No specific advice.")
                    print(f"  - {advice}")

def parse_nikto(file):
    print("\n🧪 Analyzing Nikto output...")
    seen = set()
    with open(file, "r") as f:
        for line in f:
            for pattern, advice in nikto_patterns.items():
                if pattern.lower() in line.lower() and pattern not in seen:
                    print(f"  - Found: {pattern} → {advice}")
                    seen.add(pattern)

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
        found = False
        for pattern, advice in dns_patterns.items():
            if pattern in content:
                print(f"  - Found: {pattern} → {advice}")
                found = True
        if not found:
            print("  - No actionable DNS information found.")

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
    elif tool in ["dig", "nslookup"]:
        parse_dns(args.file)
    else:
        print("❌ Tool not supported. Use: nmap, nikto, sqlmap, whatweb, dig, nslookup")

                        
