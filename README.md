# ARGUS 👁️ — Network Recon & Vulnerability Assessment

```
     ◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
    ◉                       ◉
   ◉      ┌───────────┐      ◉
  ◉       │  A R G U S│       ◉
   ◉      └───────────┘      ◉
    ◉    All-Seeing Recon    ◉
     ◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
```

> *"All-seeing. Nothing escapes."*

ARGUS is a fast, terminal-first network reconnaissance and vulnerability assessment tool for penetration testers. It combines **nmap** and **hping3** into a clean, structured workflow — no XML, no web UI, just signal. Built for HTB, THM, eJPT labs and real-world assessments.

---

## Features

**Scanning**
- **Two-phase TCP scanning** — Phase 1 discovers open ports and services; Phase 2 runs targeted nmap NSE vuln scripts per port
- **UDP scanning** — automatic scan of key UDP ports (SNMP, TFTP, DNS, NTP, NetBIOS)
- **OS detection** — nmap OS fingerprinting with hping3 TTL fallback (Linux/Windows/Cisco)
- **Firewall detection** — hping3 ICMP/TCP probes detect filtered hosts
- **Smart hostname resolution** — PTR records, SSL cert commonName, DNS SAN, SMB computer name, reverse DNS, NetBIOS

**Enumeration**
- **Share enumeration** — smbclient null session and credentialed share listing with per-share read access check
- **SMB / Windows** — enum4linux-ng full AD enumeration (users, groups, shares, password policy)
- **LDAP** — anonymous bind and authenticated AD user dump (namingContexts, dnsHostName, sAMAccountName)
- **Web** — whatweb fingerprint, curl headers, robots.txt, sitemap.xml check, nikto hint
- **SNMP** — snmpwalk community `public`, onesixtyone community brute
- **MySQL / PostgreSQL** — anonymous and empty-password login check, credentialed database listing
- **WinRM** — crackmapexec credential test, evil-winrm command pre-filled
- **Redis** — unauthenticated and authenticated access check, RCE tip
- **FTP** — anonymous login check, file listing via curl
- **SSH** — banner grab, supported auth methods
- **NFS** — showmount export listing
- **RPC** — rpcinfo portmapper dump
- **rsync** — module listing
- **IRC** — banner grab, UnrealIRCd 3.2.8.1 backdoor detection
- **Finger** — user enumeration
- **Elasticsearch** — unauthenticated cluster health and index dump
- **Jenkins / Tomcat** — auto-detects on port 8080, prints Groovy console / manager hints

**Vulnerability Coverage**
- EternalBlue (MS17-010), MS08-067, SMBGhost (CVE-2020-0796)
- BlueKeep (CVE-2019-0708), MS12-020 RDP
- Heartbleed, POODLE, TLS Ticketbleed, SSL CCS Injection
- ShellShock, Struts CVE-2017-5638, CVE-2015-1635
- VSFTPD / ProFTPD backdoor, UnrealIRCd backdoor
- HTTP: SQLi, passwd disclosure, backup files, default accounts, PHP version
- Tomcat RCE (CVE-2017-12617), Drupalgeddon (CVE-2014-3704)
- MySQL CVE-2012-2122, Redis unauthenticated RCE vector
- SNMP, Memcached, MongoDB unauthenticated access

**Active Directory**
- Auto-detects AD environment (ports 88 + 389)
- Extracts domain name from LDAP naming context automatically
- Prints ready-to-run commands: AS-REP Roasting, Kerberoasting, kerbrute, crackmapexec, BloodHound — with real credentials pre-filled when `-U`/`--pass` is provided

**Other**
- **Credential support** (`-U`/`--pass`) — propagates to SMB, LDAP, MySQL, PostgreSQL, WinRM, Redis, nmap scripts
- **Searchsploit integration** (`--searchsploit`) — queries ExploitDB for every detected service version
- **Attack surface hints** — ready-to-run commands per open port with target IP pre-filled
- **Auto /etc/hosts** (`--add-hosts`) — adds discovered hostname to /etc/hosts
- **Save report** (`-o <file>`) — saves clean plain-text report to file
- **Summary** — per-host hostname, OS, open port count, vulnerability count

---

## Requirements

### Mandatory
| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning, OS detection, NSE scripts |
| `root / sudo` | Required for SYN scan (`-sS`) and OS detection (`-O`) |

### Optional (install for full functionality)
| Tool | Purpose |
|------|---------|
| `hping3` | ICMP/TCP probing, TTL-based OS guessing, firewall detection |
| `smbclient` | Share listing and access check |
| `enum4linux-ng` | Full SMB/AD enumeration |
| `ldap-utils` | LDAP anonymous and authenticated queries |
| `snmp` + `snmp-mibs-downloader` | SNMP walk |
| `onesixtyone` | SNMP community string brute force |
| `redis-tools` | Redis unauthenticated/authenticated access check |
| `mysql-client` | MySQL empty/anonymous login check |
| `postgresql-client` | PostgreSQL empty login check |
| `evil-winrm` / `crackmapexec` | WinRM access check |
| `rsync` | Rsync module enumeration |
| `whatweb` | Web technology fingerprinting |
| `nfs-common` | NFS share listing (showmount) |
| `smtp-user-enum` | SMTP user enumeration |
| `exploitdb` | Searchsploit integration |
| `impacket` | AD attack tools (GetNPUsers, GetUserSPNs) |
| `bloodhound-python` | BloodHound AD collection |
| `kerbrute` | Kerberos user enumeration |

### Install all optional tools on Kali / Debian
```bash
sudo apt install hping3 smbclient enum4linux-ng ldap-utils snmp snmp-mibs-downloader \
  onesixtyone redis-tools default-mysql-client postgresql-client evil-winrm \
  crackmapexec rsync whatweb nfs-common smtp-user-enum exploitdb python3-impacket \
  bloodhound-python -y
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Guess-Who-sec/argus-enum.git
cd argus-enum

# Make executable and install system-wide
chmod +x argus.sh
sudo cp argus.sh /usr/local/bin/argus
```

After installation, run from anywhere:
```bash
sudo argus -t 192.168.1.0/24
```

---

## Usage

```
sudo argus -t <target> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-t <target>` | Target — single IP, CIDR, range, or hostname |
| `-p <ports>` | Custom port list (default: all). Example: `-p 22,80,443,8080` |
| `-T <0-5>` | nmap timing template (default: 4) |
| `-o <file>` | Save plain-text report to file |
| `-v` | Verbose — show raw nmap output during scan |
| `-U <user>` | Username for authenticated enumeration |
| `--pass <pass>` | Password for authenticated enumeration |
| `--no-vuln` | Skip Phase 2 vulnerability scripts (faster) |
| `--no-hping` | Skip hping3 probes |
| `--no-enum` | Skip extra enumeration (NFS, SMB, LDAP, Redis, etc.) |
| `--udp` | Enable UDP scan (SNMP/TFTP/DNS/NTP — off by default) |
| `--add-hosts` | Auto-add discovered hostname to `/etc/hosts` |
| `--searchsploit` | Run searchsploit against all detected service versions |
| `-h` | Show help |

### Examples

```bash
# Full recon on a single host
sudo argus -t 10.10.10.5

# Scan a subnet (UDP off by default)
sudo argus -t 192.168.1.0/24

# Authenticated scan — credentials propagate to SMB, LDAP, WinRM, MySQL, Redis
sudo argus -t 10.10.10.5 -U john --pass Password123

# Run searchsploit against all detected versions
sudo argus -t 10.10.10.5 --searchsploit

# Stealthy scan — slow timing, no hping3
sudo argus -t 10.10.10.100 -T 2 --no-hping

# Full scan including UDP (SNMP, TFTP, DNS)
sudo argus -t 10.10.10.5 --udp

# Quick sweep — no vuln scripts, no enumeration
sudo argus -t 192.168.56.0/24 --no-vuln --no-enum

# Full scan, save report, auto-update /etc/hosts
sudo argus -t 10.10.10.5 --add-hosts -o report.txt

# Scan specific ports only
sudo argus -t 10.10.10.5 -p 22,80,443,445,3389,5985
```

---

## Sample Output

```
══════════════════════════════════════════════════════════════════════
  HOST     : 10.10.10.5  (DC01.pirate.htb)
  hping3   : ICMP=no reply  TCP/80=open  TCP/443=open  TTL=127 (Windows)
  OS       : Windows (TTL guess)
──────────────────────────────────────────────────────────────────────
  PORT               SERVICE              VERSION
──────────────────────────────────────────────────────────────────────
  53/tcp             domain               Simple DNS Plus
  88/tcp             kerberos-sec         Microsoft Windows Kerberos
  389/tcp            ldap                 Microsoft Windows Active Directory
  445/tcp            microsoft-ds         Windows Server 2019
  3389/tcp           ms-wbt-server        Microsoft Terminal Services
  5985/tcp           http                 Microsoft HTTPAPI httpd 2.0
──────────────────────────────────────────────────────────────────────
  SCRIPTS & VULNERABILITIES
──────────────────────────────────────────────────────────────────────
  [445/tcp]
    smb-vuln-ms17-010 : VULNERABLE — Remote Code Execution in SMBv1
    smb-enum-shares   : ADMIN$, C$, IPC$

──────────────────────────────────────────────────────────────────────
  EXTRA ENUMERATION
──────────────────────────────────────────────────────────────────────
  [shares / 445]
    Shares found:
    \\10.10.10.5\ADMIN$
    \\10.10.10.5\C$
    \\10.10.10.5\IPC$    [!] READABLE

  [ldap / 389]
    naming contexts:
      DC=pirate,DC=htb
    dnsHostName : DC01.pirate.htb

──────────────────────────────────────────────────────────────────────
  ACTIVE DIRECTORY ATTACKS  (domain: pirate.htb)
──────────────────────────────────────────────────────────────────────
  AS-REP Roasting:
    impacket-GetNPUsers pirate.htb/ -usersfile users.txt -no-pass -dc-ip 10.10.10.5
  Kerberoasting:
    impacket-GetUserSPNs pirate.htb/john:Password123 -dc-ip 10.10.10.5
  BloodHound:
    bloodhound-python -u john -p Password123 -ns 10.10.10.5 -d pirate.htb -c all

══════════════════════════════════════════════════════════════════════
  SUMMARY
──────────────────────────────────────────────────────────────────────
  HOST    : 10.10.10.5  (DC01.pirate.htb)
  OS      : Windows (TTL guess)
  PORTS   : 24 open
  ISSUES  : 2 potential vulnerability/misconfiguration(s) found
══════════════════════════════════════════════════════════════════════
```

---

## Vulnerability Coverage

| Port | Service | Scripts |
|------|---------|---------|
| 21 | FTP | vsftpd backdoor, proftpd backdoor, anonymous login |
| 22 | SSH | SSHv1, auth methods, host key |
| 25/587 | SMTP | Open relay, user enumeration, Shellshock |
| 79 | Finger | User enumeration |
| 80/443/8080/8443 | HTTP/S | Shellshock, Struts, CVE-2015-1635, SQLi, passwd, backup files, default accounts, PHP version |
| 139/445 | SMB | **EternalBlue (MS17-010)**, MS08-067, **SMBGhost (CVE-2020-0796)**, share/user enum |
| 161/udp | SNMP | Community string brute, system info dump |
| 389/636 | LDAP | Root DSE, anonymous bind, AD user dump |
| 443/8443 | HTTPS | **Heartbleed**, POODLE, TLS Ticketbleed, SSL CCS Injection |
| 1433 | MSSQL | Empty password, xp_cmdshell, NTLM info |
| 3306 | MySQL | Empty password, anonymous login, CVE-2012-2122 |
| 3389 | RDP | **BlueKeep (CVE-2019-0708)**, **MS12-020** |
| 5432 | PostgreSQL | Empty password, database listing |
| 5900 | VNC | Auth bypass, brute |
| 5985 | WinRM | Credential validation, evil-winrm hint |
| 6379 | Redis | Unauthenticated access, RCE via config set |
| 6667 | IRC | **UnrealIRCd backdoor (CVE-2010-2075)** |
| 8080 | HTTP | **Tomcat RCE (CVE-2017-12617)**, Jenkins detection |
| 9200 | Elasticsearch | Unauthenticated access, index dump |
| 10000 | Webmin | CVE-2019-15107 hint |
| 27017 | MongoDB | Unauthenticated access |
| 2049/111 | NFS/RPC | Share listing, NFS stats |
| 873 | rsync | Module listing, brute |

---

## Legal Disclaimer

> **ARGUS is intended for authorized penetration testing and security assessments only.**
>
> Running this tool against systems you do not own or have explicit written permission to test is **illegal** and may violate local, national, or international law (e.g. Computer Fraud and Abuse Act, Computer Misuse Act).
>
> The author assumes **no liability** for misuse or damage caused by this tool. Always obtain proper written authorization before conducting any security testing.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first.

If you add new service enumeration modules or port mappings, follow the existing patterns in the `PORT_SCRIPTS` and `SERVICE_HINTS` arrays.

---

Named after Argus Panoptes — the hundred-eyed giant of Greek mythology. All-seeing. Nothing escapes.
