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

ARGUS is a fast, terminal-first network reconnaissance and vulnerability assessment tool for penetration testers. It combines **nmap** and **hping3** into a clean, structured workflow — no XML, no web UI, just signal.

---

## Features

- **Two-phase scanning** — Phase 1 discovers open ports and services; Phase 2 runs targeted nmap vuln scripts per port
- **OS detection** — nmap OS fingerprinting with hping3 TTL fallback
- **Firewall detection** — hping3 probes detect filtered/firewalled hosts
- **Clean terminal output** — structured per-host blocks: `HOST | OS | PORT | SERVICE | VERSION`
- **Vulnerability scripts** — 30+ ports mapped to specific nmap NSE scripts (EternalBlue, Heartbleed, MS17-010, RDP, VSFTPD backdoor, etc.)
- **Linux enumeration** — NFS shares (showmount), RPC (rpcinfo), rsync modules, Redis unauthenticated access, web fingerprinting (whatweb)
- **Windows / AD enumeration** — SMB shares/users (enum4linux-ng), LDAP anonymous bind (namingContexts, dnsHostName)
- **FTP enumeration** — anonymous login check, file listing via curl
- **SSH enumeration** — banner grab, supported auth methods
- **SMTP enumeration** — banner grab, user enumeration hint
- **Attack surface hints** — ready-to-run commands per open port with the target IP pre-filled
- **Auto /etc/hosts update** — extracts hostnames from PTR records, SSL certs, and SMB computer names (opt-in)
- **Summary report** — per-host open port count and total vulnerability findings

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
| `enum4linux-ng` | SMB/Windows enumeration (AD environments) |
| `ldap-utils` | LDAP anonymous bind queries |
| `redis-tools` | Redis unauthenticated access check |
| `rsync` | Rsync module enumeration |
| `whatweb` | Web technology fingerprinting |
| `nfs-common` | NFS share listing (showmount) |
| `smtp-user-enum` | SMTP user enumeration |

### Install all optional tools on Kali / Debian
```bash
sudo apt install hping3 enum4linux-ng ldap-utils redis-tools rsync whatweb nfs-common smtp-user-enum -y
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/argus.git
cd argus

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
sudo bash argus.sh -t <target> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-t <target>` | Target — single IP, range (192.168.1.1-50), CIDR (10.0.0.0/24), or hostname |
| `-p <ports>` | Custom port list (default: top 1000). Example: `-p 22,80,443,8080` |
| `-o <file>` | Save raw nmap output to file |
| `--no-vuln` | Skip Phase 2 vulnerability scripts (faster scan) |
| `--no-hping` | Skip hping3 probes |
| `--no-enum` | Skip extra enumeration (NFS, SMB, LDAP, Redis, etc.) |
| `--add-hosts` | Auto-update `/etc/hosts` with discovered hostnames |
| `-T <0-5>` | nmap timing template (default: 4) |
| `-v` | Verbose — show raw nmap output during scan |
| `-h` | Show help |

### Examples

```bash
# Scan a single host (full recon)
sudo argus -t 192.168.1.10

# Scan a subnet
sudo argus -t 192.168.1.0/24

# Scan specific ports only, skip vuln scripts
sudo argus -t 10.10.10.5 -p 22,80,443,445,3389 --no-vuln

# Full scan, auto-add hostnames to /etc/hosts
sudo argus -t 10.0.0.0/24 --add-hosts

# Stealthy scan (slower timing, skip hping3)
sudo argus -t 10.10.10.100 -T 2 --no-hping

# Quick port sweep, no enumeration
sudo argus -t 192.168.56.0/24 --no-vuln --no-enum
```

---

## Sample Output

```
══════════════════════════════════════════════════════════════════════
  HOST   192.168.1.50  (DC01.corp.local)
══════════════════════════════════════════════════════════════════════
  OS     Windows Server 2019  (TTL=127 → Windows)
  HPING  ICMP reachable  |  TCP/80 open  |  OS guess: Windows (TTL=127)

──────────────────────────────────────────────────────────────────────
  PORT    SERVICE        VERSION
──────────────────────────────────────────────────────────────────────
  53/tcp  domain         Simple DNS Plus
  88/tcp  kerberos-sec   Microsoft Windows Kerberos
  135/tcp msrpc          Microsoft Windows RPC
  139/tcp netbios-ssn    Microsoft Windows netbios-ssn
  389/tcp ldap           Microsoft Windows Active Directory
  445/tcp microsoft-ds   Windows Server 2019 microsoft-ds
  3389/tcp ms-wbt-server Microsoft Terminal Services
──────────────────────────────────────────────────────────────────────

  VULN SCRIPTS
  [445] smb-vuln-ms17-010:
    VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1
    State: VULNERABLE
    Risk factor: HIGH
  [3389] rdp-vuln-ms12-020:
    State: NOT VULNERABLE

  SMB ENUM (enum4linux-ng)
  [*] Domain: CORP  DC: DC01  OS: Windows Server 2019

  LDAP ENUM
  [+] namingContext: DC=corp,DC=local
  [+] dnsHostName: DC01.corp.local

  ATTACK SURFACE
  [445]  smbclient -L //192.168.1.50 -N  |  enum4linux-ng -A 192.168.1.50
  [389]  ldapsearch -x -H ldap://192.168.1.50 -b "DC=corp,DC=local"
  [3389] xfreerdp /u:administrator /v:192.168.1.50
  [88]   GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip 192.168.1.50
```

---

## Vulnerability Coverage

| Port | Service | Scripts |
|------|---------|---------|
| 21 | FTP | vsftpd backdoor, proftpd backdoor, anonymous login |
| 22 | SSH | SSHv1, auth methods, host key |
| 25/587 | SMTP | Open relay, user enumeration, Shellshock |
| 80/8080 | HTTP | Shellshock, MS17-010 (Struts), CVE-2015-1635, auth |
| 139/445 | SMB | **EternalBlue (MS17-010)**, MS08-067, share/user enumeration |
| 389/636 | LDAP | Root DSE, anonymous bind, Novell getpass |
| 443/8443 | HTTPS | **Heartbleed**, POODLE, DROWN, TLS ticketbleed |
| 1433 | MSSQL | Empty password, xp_cmdshell, NTLM info |
| 3306 | MySQL | Empty password, CVE-2012-2122 |
| 3389 | RDP | **MS12-020** |
| 5900 | VNC | Auth bypass, brute |
| 6379 | Redis | Unauthenticated access |
| 27017 | MongoDB | Unauthenticated access |
| 2049/111 | NFS/RPC | Share listing, NFS stats |

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

## License

[MIT](LICENSE)

---

*Named after Argus Panoptes — the hundred-eyed giant of Greek mythology. All-seeing. Nothing escapes.*
