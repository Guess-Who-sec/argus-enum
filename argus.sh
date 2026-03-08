#!/usr/bin/env bash
# =============================================================================
#  argus.sh — Network Recon & Vulnerability Assessment
#  "All-seeing. Nothing escapes."
#  Requires: nmap (mandatory) | Optional: hping3
#  Usage:    sudo bash argus.sh -t <target> [options]
# =============================================================================

# ── Colours (minimal — only used where meaningful) ────────────────────────────
RED='\033[91m'; GREEN='\033[92m'; GRAY='\033[38;5;245m'
CYAN='\033[96m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
W=70

# ── Temp workspace ────────────────────────────────────────────────────────────
SCAN_TMP=$(mktemp -d /tmp/pentestscan.XXXXXX)
trap 'rm -rf "$SCAN_TMP"' EXIT

GNMAP="$SCAN_TMP/scan.gnmap"     # grepable (ports / OS)
NMAP_N="$SCAN_TMP/scan.nmap"     # normal   (scripts / details)
UDP_N="$SCAN_TMP/udp.nmap"       # UDP scan normal output
UDP_G="$SCAN_TMP/udp.gnmap"      # UDP scan grepable output
VULN_N="$SCAN_TMP/vuln.nmap"     # vuln-script normal output

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET=""; PORTS=""; NO_VULN=0; NO_HPING=0; NO_ENUM=0; ADD_HOSTS=0
TIMING="4"; OUTPUT=""; VERBOSE=0; NO_UDP=0; DO_SEARCHSPLOIT=0
CRED_USER=""; CRED_PASS=""

# ── Vulnerability scripts per port ────────────────────────────────────────────
declare -A PORT_SCRIPTS
PORT_SCRIPTS[21]="ftp-anon,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie"
PORT_SCRIPTS[22]="ssh-auth-methods,ssh-hostkey,sshv1,ssh2-enum-algos"
PORT_SCRIPTS[23]="telnet-ntlm-info,telnet-encryption"
PORT_SCRIPTS[25]="smtp-open-relay,smtp-commands,smtp-vuln-cve2010-4344,smtp-ntlm-info"
PORT_SCRIPTS[53]="dns-zone-transfer,dns-recursion,dns-cache-snoop,dns-update"
PORT_SCRIPTS[79]="finger"
PORT_SCRIPTS[80]="http-vuln-cve2017-5638,http-vuln-cve2015-1635,http-vuln-cve2014-3704,http-shellshock,http-methods,http-auth-finder,http-title,http-headers,http-server-header,http-open-proxy,http-sql-injection,http-passwd,http-backup-finder,http-default-accounts,http-php-version"
PORT_SCRIPTS[88]="krb5-enum-users"
PORT_SCRIPTS[110]="pop3-capabilities,pop3-ntlm-info"
PORT_SCRIPTS[111]="rpcinfo,nfs-showmount,nfs-ls,nfs-statfs"
PORT_SCRIPTS[135]="msrpc-enum"
PORT_SCRIPTS[139]="smb-vuln-ms17-010,smb-vuln-ms08-067,smb-security-mode,smb-enum-shares,smb-enum-users,smb-os-discovery,nbstat"
PORT_SCRIPTS[143]="imap-capabilities,imap-ntlm-info"
PORT_SCRIPTS[161]="snmp-info,snmp-sysdescr,snmp-interfaces,snmp-processes"
PORT_SCRIPTS[389]="ldap-rootdse,ldap-search,ldap-novell-getpass"
PORT_SCRIPTS[443]="ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-cert,tls-ticketbleed,ssl-ccs-injection,http-shellshock,http-vuln-cve2017-5638,http-sql-injection,http-passwd,http-backup-finder,http-default-accounts"
PORT_SCRIPTS[445]="smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve2009-3103,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-regsvc-dos,smb-vuln-cve2020-0796,smb-security-mode,smb2-security-mode,smb-enum-shares,smb-enum-users,smb-os-discovery"
PORT_SCRIPTS[464]="krb5-enum-users"
PORT_SCRIPTS[587]="smtp-open-relay,smtp-commands,smtp-ntlm-info"
PORT_SCRIPTS[593]="msrpc-enum"
PORT_SCRIPTS[636]="ssl-heartbleed,ssl-cert,ldap-rootdse"
PORT_SCRIPTS[873]="rsync-list-modules,rsync-brute"
PORT_SCRIPTS[993]="ssl-heartbleed,ssl-cert,imap-capabilities"
PORT_SCRIPTS[995]="ssl-heartbleed,ssl-cert,pop3-capabilities"
PORT_SCRIPTS[1433]="ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-ntlm-info,ms-sql-config"
PORT_SCRIPTS[2049]="nfs-showmount,nfs-ls,nfs-statfs"
PORT_SCRIPTS[2375]="http-title"
PORT_SCRIPTS[3268]="ldap-rootdse,ldap-search"
PORT_SCRIPTS[3269]="ssl-heartbleed,ssl-cert,ldap-rootdse"
PORT_SCRIPTS[3306]="mysql-empty-password,mysql-info,mysql-enum,mysql-vuln-cve2012-2122"
PORT_SCRIPTS[3389]="rdp-vuln-ms12-020,rdp-vuln-cve2019-0708,rdp-enum-encryption"
PORT_SCRIPTS[5432]="pgsql-brute"
PORT_SCRIPTS[5900]="vnc-info,vnc-brute,vnc-title"
PORT_SCRIPTS[5985]="http-auth-finder,http-title"
PORT_SCRIPTS[5986]="ssl-heartbleed,ssl-cert"
PORT_SCRIPTS[6379]="redis-info"
PORT_SCRIPTS[6667]="irc-info,irc-unrealircd-backdoor,irc-botnet-channels"
PORT_SCRIPTS[8080]="http-vuln-cve2017-5638,http-vuln-cve2015-1635,http-shellshock,http-methods,http-title,http-auth-finder,http-open-proxy,http-vuln-cve2017-12617,http-sql-injection,http-backup-finder,http-default-accounts"
PORT_SCRIPTS[8443]="ssl-heartbleed,ssl-poodle,ssl-cert,http-shellshock,http-vuln-cve2017-5638,http-sql-injection,http-backup-finder,http-default-accounts"
PORT_SCRIPTS[9200]="http-open-proxy,http-title,http-headers"
PORT_SCRIPTS[10000]="http-title,http-auth-finder,http-shellshock"
PORT_SCRIPTS[11211]="memcached-info"
PORT_SCRIPTS[27017]="mongodb-info,mongodb-databases"

# ── Attack hints per port ─────────────────────────────────────────────────────
declare -A SERVICE_HINTS
SERVICE_HINTS[21]="ftp <IP>  (anonymous?)  |  curl ftp://<IP>/ --user anonymous:anonymous"
SERVICE_HINTS[22]="ssh -v <IP>  |  hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<IP>"
SERVICE_HINTS[23]="telnet <IP>"
SERVICE_HINTS[25]="smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <IP>"
SERVICE_HINTS[53]="dig axfr @<IP> <domain>  |  dnsrecon -d <domain> -t axfr"
SERVICE_HINTS[79]="finger @<IP>  |  finger -l @<IP>  |  finger root@<IP>"
SERVICE_HINTS[80]="gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  |  nikto -h http://<IP>"
SERVICE_HINTS[88]="GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <IP>  |  kerbrute userenum --dc <IP> -d <domain> users.txt"
SERVICE_HINTS[111]="rpcinfo -p <IP>  |  showmount -e <IP>"
SERVICE_HINTS[139]="smbclient -L //<IP> -N  |  enum4linux-ng -A <IP>"
SERVICE_HINTS[161]="snmpwalk -c public -v1 <IP>  |  onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP>"
SERVICE_HINTS[389]="ldapsearch -x -H ldap://<IP> -b 'DC=domain,DC=local'  |  bloodhound-python -u user -p pass -ns <IP> -d domain.local -c all"
SERVICE_HINTS[443]="gobuster dir -u https://<IP> -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  |  nikto -h https://<IP> -ssl"
SERVICE_HINTS[445]="smbclient -L //<IP> -N  |  enum4linux-ng -A <IP>  |  crackmapexec smb <IP> --shares -u '' -p ''"
SERVICE_HINTS[873]="rsync --list-only rsync://<IP>/"
SERVICE_HINTS[1433]="crackmapexec mssql <IP> -u sa -p ''  |  impacket-mssqlclient sa@<IP>"
SERVICE_HINTS[2049]="showmount -e <IP>  |  mount -t nfs <IP>:/ /mnt/nfs"
SERVICE_HINTS[3306]="mysql -h <IP> -u root --password=''  |  mysql -h <IP> -u '' --password=''"
SERVICE_HINTS[3389]="xfreerdp /v:<IP>  |  rdesktop <IP>  |  hydra -l administrator -P rockyou.txt rdp://<IP>"
SERVICE_HINTS[5432]="psql -h <IP> -U postgres  |  psql -h <IP> -U postgres -c '\list'"
SERVICE_HINTS[5900]="vncviewer <IP>  |  hydra -P /usr/share/wordlists/rockyou.txt vnc://<IP>"
SERVICE_HINTS[5985]="evil-winrm -i <IP> -u administrator -p Password123  |  crackmapexec winrm <IP> -u users.txt -p passwords.txt"
SERVICE_HINTS[6379]="redis-cli -h <IP>  |  redis-cli -h <IP> config get dir  (check for RCE via config set)"
SERVICE_HINTS[6667]="nc -nv <IP> 6667  |  (UnrealIRCd 3.2.8.1 backdoor — check irc-unrealircd-backdoor script)"
SERVICE_HINTS[8080]="gobuster dir -u http://<IP>:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  |  curl http://<IP>:8080/ (Jenkins? Tomcat?)"
SERVICE_HINTS[8443]="gobuster dir -u https://<IP>:8443 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
SERVICE_HINTS[9200]="curl http://<IP>:9200/_cat/indices?v  |  curl http://<IP>:9200/_cluster/health"
SERVICE_HINTS[10000]="curl http://<IP>:10000/  |  (Webmin — check CVE-2019-15107 unauthenticated RCE)"
SERVICE_HINTS[11211]="echo 'stats' | nc -q1 <IP> 11211  |  (Memcached — check for unauthenticated access)"
SERVICE_HINTS[27017]="mongosh <IP>  |  mongo <IP> --eval 'db.adminCommand({listDatabases:1})'"
SERVICE_HINTS[2375]="docker -H tcp://<IP>:2375 ps  (unauthenticated Docker daemon!)"

# ── Helpers ───────────────────────────────────────────────────────────────────
sep()  { printf "${GRAY}"; printf '─%.0s' $(seq 1 $W); printf "${RESET}\n"; }
sep2() { printf '═%.0s' $(seq 1 $W); printf '\n'; }

# ── Banner ────────────────────────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}${BOLD}"
    echo '        ██████╗ '
    echo '       ██╔═══██╗'
    echo '  ██╗  ██║   ██║'
    echo '  ╚═╝  ██║   ██║  ◉  ◉  ◉  ◉  ◉  ◉  ◉  ◉  ◉  ◉'
    echo '  ██╗  ╚██████╔╝'
    echo '  ╚═╝   ╚═════╝ '
    echo -e "${RESET}${BOLD}"
    echo '   █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗'
    echo '  ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝'
    echo '  ███████║██████╔╝██║  ███╗██║   ██║███████╗'
    echo '  ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║'
    echo '  ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║'
    echo '  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝'
    echo -e "${RESET}"
    echo -e "${GRAY}  ◉ All-seeing. Nothing escapes.${RESET}"
    echo -e "${GRAY}  ◉ Network Recon & Vulnerability Assessment  |  nmap + hping3${RESET}"
    echo -e "${GRAY}  ◉ Use only on systems you own or have written permission to test.${RESET}"
    echo
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}Usage:${RESET}  sudo bash $0 -t <target> [options]\n"
    echo -e "  ${CYAN}-t${RESET}  <target>   IP, CIDR, or comma-separated IPs"
    echo -e "  ${CYAN}-p${RESET}  <ports>    Ports to scan (default: all). E.g. 22,80,443,445"
    echo -e "  ${CYAN}-T${RESET}  <1-5>      nmap timing (1=stealthy … 5=aggressive). Default: 4"
    echo -e "  ${CYAN}-o${RESET}  <file>     Save plain-text report to file"
    echo -e "  ${CYAN}-v${RESET}             Verbose: show raw nmap output while scanning"
    echo -e "  ${CYAN}--no-vuln${RESET}      Skip vulnerability scripts (faster)"
    echo -e "  ${CYAN}--no-hping${RESET}     Skip hping3 probes"
    echo -e "  ${CYAN}--no-enum${RESET}      Skip extra enumeration (NFS, rsync, Redis, etc.)"
    echo -e "  ${CYAN}--no-udp${RESET}          Skip UDP scan (SNMP/TFTP/DNS)"
    echo -e "  ${CYAN}--add-hosts${RESET}       Auto-add discovered hostname to /etc/hosts"
    echo -e "  ${CYAN}--searchsploit${RESET}    Run searchsploit against all detected service versions"
    echo -e "  ${CYAN}-U${RESET}  <user>        Username for authenticated enumeration"
    echo -e "  ${CYAN}--pass${RESET} <pass>     Password for authenticated enumeration"
    echo
    echo -e "${BOLD}Examples:${RESET}"
    echo "  sudo bash $0 -t 192.168.1.1"
    echo "  sudo bash $0 -t 192.168.1.0/24 --no-vuln -T 3"
    echo "  sudo bash $0 -t 10.0.0.5 --add-hosts -o report.txt"
    echo "  sudo bash $0 -t 10.10.10.5 --no-udp --no-hping"
    exit 0
}

# ── Arg parsing ───────────────────────────────────────────────────────────────
[[ $# -eq 0 ]] && { banner; usage; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t)         TARGET="$2";  shift 2 ;;
        -p)         PORTS="$2";   shift 2 ;;
        -T)         TIMING="$2";  shift 2 ;;
        -o)         OUTPUT="$2";  shift 2 ;;
        -v)         VERBOSE=1;    shift   ;;
        --no-vuln)  NO_VULN=1;    shift   ;;
        --no-hping) NO_HPING=1;   shift   ;;
        --no-enum)  NO_ENUM=1;    shift   ;;
        --no-udp)      NO_UDP=1;          shift   ;;
        --add-hosts)   ADD_HOSTS=1;       shift   ;;
        --searchsploit)DO_SEARCHSPLOIT=1; shift   ;;
        -U|--user)     CRED_USER="$2";    shift 2 ;;
        --pass)        CRED_PASS="$2";    shift 2 ;;
        -h|--help)  banner; usage ;;
        *) echo -e "${RED}[!] Unknown option: $1${RESET}"; usage ;;
    esac
done

# ── Checks ────────────────────────────────────────────────────────────────────
[[ -z "$TARGET" ]] && { echo -e "${RED}[!] Target required. Use -t <target>${RESET}"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}[!] Requires root for SYN scan and OS detection.${RESET}"
    echo -e "${CYAN}    Run: sudo bash $0 $*${RESET}"
    exit 1
fi

if ! command -v nmap &>/dev/null; then
    echo -e "${RED}[!] nmap not found. Install: apt install nmap${RESET}"
    exit 1
fi

HPING_OK=0
if command -v hping3 &>/dev/null && [[ $NO_HPING -eq 0 ]]; then
    HPING_OK=1
fi

# ── Output helper (tee to file if -o set) ─────────────────────────────────────
REPORT_LINES=()
rprint() {
    echo -e "$1"
    if [[ -n "$OUTPUT" ]]; then
        REPORT_LINES+=("$(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')")
    fi
}

# ── hping3 probe ──────────────────────────────────────────────────────────────
hping_probe() {
    local ip="$1"
    local icmp_ok=0 tcp80_ok=0 tcp443_ok=0 ttl=""

    local raw
    raw=$(hping3 --icmp -c 3 --fast "$ip" 2>&1)
    echo "$raw" | grep -qi "bytes from"   && icmp_ok=1
    [[ -z "$ttl" ]] && ttl=$(echo "$raw" | grep -oiP 'ttl=\K[0-9]+' | head -1)

    raw=$(hping3 -S -p 80 -c 3 --fast "$ip" 2>&1)
    echo "$raw" | grep -qiP 'flags=S?A'   && tcp80_ok=1
    [[ -z "$ttl" ]] && ttl=$(echo "$raw" | grep -oiP 'ttl=\K[0-9]+' | head -1)

    raw=$(hping3 -S -p 443 -c 3 --fast "$ip" 2>&1)
    echo "$raw" | grep -qiP 'flags=S?A'   && tcp443_ok=1
    [[ -z "$ttl" ]] && ttl=$(echo "$raw" | grep -oiP 'ttl=\K[0-9]+' | head -1)

    local os_guess="Unknown"
    if [[ -n "$ttl" ]]; then
        if   [[ $ttl -le 64  ]]; then os_guess="Linux / macOS"
        elif [[ $ttl -le 128 ]]; then os_guess="Windows"
        elif [[ $ttl -le 255 ]]; then os_guess="Cisco / Network Device"
        fi
    fi

    local fw_hint=0
    [[ $tcp80_ok -eq 0 && $tcp443_ok -eq 0 ]] && fw_hint=1

    echo "${icmp_ok}:${tcp80_ok}:${tcp443_ok}:${ttl:-?}:${os_guess}:${fw_hint}"
}

# ── Build vuln script list for a set of open ports ───────────────────────────
build_script_list() {
    local -a open_ports=("$@")
    local scripts="" seen=":"
    for port in "${open_ports[@]}"; do
        if [[ -n "${PORT_SCRIPTS[$port]+_}" ]]; then
            IFS=',' read -ra sarr <<< "${PORT_SCRIPTS[$port]}"
            for s in "${sarr[@]}"; do
                if [[ "$seen" != *":${s}:"* ]]; then
                    seen="${seen}${s}:"
                    scripts="${scripts:+$scripts,}$s"
                fi
            done
        fi
    done
    echo "$scripts"
}

# ── Run nmap phase 1 (TCP) ────────────────────────────────────────────────────
run_nmap_phase1() {
    local port_args=()
    if [[ -n "$PORTS" ]]; then
        port_args=(-p "$PORTS")
    else
        port_args=(-p- --min-rate 1000)
    fi

    local cmd=(
        nmap -sS -sV -O --osscan-guess -sC
        -T"$TIMING"
        --open
        "${port_args[@]}"
        -oG "$GNMAP"
        -oN "$NMAP_N"
        "$TARGET"
    )

    rprint ""
    rprint "${DIM}[*] Phase 1 — TCP discovery scan running...${RESET}"
    rprint "${DIM}    ${cmd[*]}${RESET}"
    rprint ""

    if [[ $VERBOSE -eq 1 ]]; then
        "${cmd[@]}"
    else
        "${cmd[@]}" &>/dev/null
    fi
}

# ── Run nmap UDP scan on key ports ────────────────────────────────────────────
run_nmap_udp() {
    [[ $NO_UDP -eq 1 ]] && return
    local UDP_PORTS="53,67,68,69,111,123,137,161,162,500,514,623,1900,4500,5353"

    local cmd=(
        nmap -sU
        -T"$TIMING"
        -p "$UDP_PORTS"
        --open
        -oG "$UDP_G"
        -oN "$UDP_N"
        "$TARGET"
    )

    rprint "${DIM}[*] Phase 1b — UDP scan (SNMP/TFTP/DNS/NTP/NetBIOS)...${RESET}"
    rprint "${DIM}    ${cmd[*]}${RESET}"
    rprint ""

    if [[ $VERBOSE -eq 1 ]]; then
        "${cmd[@]}"
    else
        "${cmd[@]}" &>/dev/null
    fi
}

# ── Run nmap phase 2 (vuln scripts per host) ──────────────────────────────────
run_nmap_phase2() {
    local ip="$1"
    shift
    local -a open_ports=("$@")
    local scripts
    scripts=$(build_script_list "${open_ports[@]}")
    [[ -z "$scripts" ]] && return

    local ports_str
    ports_str=$(IFS=','; echo "${open_ports[*]}")

    local vuln_out="$SCAN_TMP/vuln_${ip//./_}.nmap"

    local script_args=""
    if [[ -n "$CRED_USER" ]]; then
        script_args="--script-args=smbusername=${CRED_USER},smbpassword=${CRED_PASS},smbdomain=."
        [[ -n "$CRED_PASS" ]] || script_args="--script-args=smbusername=${CRED_USER},smbpassword='',smbdomain=."
    fi

    local cmd=(
        nmap -sS
        -T"$TIMING"
        -p "$ports_str"
        --script="$scripts"
        ${script_args:+$script_args}
        -oN "$vuln_out"
        "$ip"
    )

    rprint "${DIM}[*] Phase 2 — vuln scripts for ${ip}...${RESET}"
    rprint "${DIM}    ${scripts:0:90}${RESET}"
    rprint ""

    if [[ $VERBOSE -eq 1 ]]; then
        "${cmd[@]}"
    else
        "${cmd[@]}" &>/dev/null
    fi
}

# ── Get list of IPs found in grepable scan ────────────────────────────────────
get_scanned_ips() {
    grep "^Host:" "$GNMAP" 2>/dev/null \
        | grep -v "^# " \
        | awk '{print $2}' \
        | sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n
}

# ── Get open TCP ports for an IP ──────────────────────────────────────────────
get_open_ports() {
    local ip="$1"
    grep "^Host: ${ip} " "$GNMAP" \
        | grep "Ports:" \
        | sed 's/.*Ports: //' \
        | sed 's/\t.*//' \
        | tr ',' '\n' \
        | awk -F'/' '$2=="open"{print $1}' \
        | sort -n
}

# ── Get open UDP ports for an IP ──────────────────────────────────────────────
get_open_udp_ports() {
    local ip="$1"
    [[ ! -f "$UDP_G" ]] && return
    grep "^Host: ${ip} " "$UDP_G" \
        | grep "Ports:" \
        | sed 's/.*Ports: //' \
        | sed 's/\t.*//' \
        | tr ',' '\n' \
        | awk -F'/' '$2=="open" && $3=="udp"{print $1}' \
        | sort -n
}

# ── Parse a port entry from grepable ─────────────────────────────────────────
parse_port_entry() {
    local entry
    entry=$(echo "$1" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
    local portid state proto service version
    portid=$(echo "$entry"  | cut -d'/' -f1)
    state=$(echo "$entry"   | cut -d'/' -f2)
    proto=$(echo "$entry"   | cut -d'/' -f3)
    service=$(echo "$entry" | cut -d'/' -f5)
    version=$(echo "$entry" | cut -d'/' -f7- | sed 's|/$||' | sed 's/^[[:space:]]*//')
    echo "${portid}|${state}|${proto}|${service}|${version}"
}

# ── Get OS info for an IP ─────────────────────────────────────────────────────
get_os_info() {
    local ip="$1"
    grep "^Host: ${ip} " "$GNMAP" \
        | grep -oP '(?<=OS: )[^\t]+' \
        | head -1
}

# ── Get hostname for an IP ────────────────────────────────────────────────────
get_hostname() {
    local ip="$1"
    grep "^Host: ${ip} " "$GNMAP" \
        | head -1 \
        | grep -oP '(?<=Host: '"${ip}"' \().*(?=\))' \
        | head -1
}

# ── Extract script output section for a given IP and nmap normal output file ──
extract_scripts() {
    local ip="$1"
    local nmap_file="$2"
    awk -v ip="$ip" '
        /Nmap scan report for / { in_host = ($0 ~ ip) ? 1 : 0; next }
        in_host && /^[0-9]+\/(tcp|udp)[[:space:]]/ {
            split($1, a, "/")
            cur_port = a[1]; cur_proto = a[2]
        }
        in_host && /^\|/ {
            print cur_port "/" cur_proto "|" $0
        }
    ' "$nmap_file" 2>/dev/null
}

# ── Extract best hostname from all scan sources ───────────────────────────────
get_best_hostname() {
    local ip="$1"
    local h; h=$(get_hostname "$ip")
    [[ -n "$h" ]] && echo "$h" && return
    local cn
    cn=$(awk -v ip="$ip" '
        /Nmap scan report for / { in_host=($0 ~ ip)?1:0 }
        in_host && /commonName=/ {
            match($0,/commonName=([^ ,\/]+)/,a)
            if (a[1]!="" && a[1]!~/^\*/) { print a[1]; exit }
        }
    ' "$NMAP_N" 2>/dev/null | head -1)
    [[ -n "$cn" ]] && echo "$cn" && return
    grep -i "Computer name:" "$NMAP_N" 2>/dev/null \
        | grep -oP '(?<=Computer name: )\S+' | head -1
}

# ── Add IP + hostname to /etc/hosts ──────────────────────────────────────────
update_hosts_file() {
    local ip="$1" hostname="$2"
    [[ -z "$hostname" || "$hostname" != *"."* ]] && return
    if grep -qP "^${ip}\s" /etc/hosts 2>/dev/null; then
        rprint "  hosts    : ${ip} already in /etc/hosts"
        return
    fi
    if grep -qP "\s${hostname}(\s|$)" /etc/hosts 2>/dev/null; then
        rprint "  hosts    : ${hostname} already in /etc/hosts"
        return
    fi
    echo "${ip}    ${hostname}" >> /etc/hosts
    rprint "  ${GREEN}[+] /etc/hosts : added  ${ip}  ${hostname}${RESET}"
}

# ══════════════════════════════════════════════════════════════════════════════
#  ENUMERATION FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

# ── FTP: try anonymous login, list files ──────────────────────────────────────
enum_ftp() {
    local ip="$1" port="${2:-21}"
    rprint "  [ftp / ${port}]"
    local banner
    banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/${ip}/${port}; read -t3 b <&3; echo \"\$b\"; exec 3>&-" 2>/dev/null | head -1)
    [[ -n "$banner" ]] && rprint "    banner  : ${banner}"
    if command -v curl &>/dev/null; then
        local listing
        listing=$(timeout 8 curl -s --connect-timeout 5 \
            "ftp://${ip}:${port}/" --user anonymous:anonymous -l 2>/dev/null)
        if [[ -n "$listing" ]]; then
            rprint "    ${RED}${BOLD}[!] anonymous login allowed${RESET}"
            rprint "    files   :"
            while IFS= read -r f; do rprint "      ${f}"; done <<< "$(echo "$listing" | head -20)"
        else
            rprint "    anonymous login: denied"
        fi
    else
        rprint "    install curl to test anonymous login"
    fi
}

# ── SSH: banner, auth methods ─────────────────────────────────────────────────
enum_ssh() {
    local ip="$1" port="${2:-22}"
    rprint "  [ssh / ${port}]"
    local banner
    banner=$(timeout 5 bash -c \
        "exec 3<>/dev/tcp/${ip}/${port}; read -t3 b <&3; echo \"\$b\"; exec 3>&-" 2>/dev/null)
    [[ -n "$banner" ]] && rprint "    banner  : ${banner}"
    local auth
    auth=$(awk -v ip="$ip" -v p="$port" '
        /Nmap scan report for / { in_host=($0~ip)?1:0 }
        in_host && /^'"$port"'\/tcp/ { in_port=1 }
        in_port && /ssh-auth-methods/ { getline; print; in_port=0 }
    ' "$NMAP_N" 2>/dev/null | sed 's/^[| ]*//')
    [[ -n "$auth" ]] && rprint "    auth    : ${auth}"
}

# ── SNMP: snmpwalk + community string brute hint ──────────────────────────────
enum_snmp() {
    local ip="$1" port="${2:-161}"
    rprint "  [snmp / ${port}/udp]"
    if command -v snmpwalk &>/dev/null; then
        local out
        out=$(timeout 10 snmpwalk -c public -v1 "$ip" 2>/dev/null \
            | grep -E "sysDescr|sysContact|sysName|sysLocation|hrSWRunName" \
            | head -10)
        if [[ -n "$out" ]]; then
            rprint "    ${RED}${BOLD}[!] SNMP community 'public' accepted${RESET}"
            while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
        else
            rprint "    community 'public' failed or SNMP unreachable"
            rprint "    try: onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt ${ip}"
        fi
    else
        rprint "    snmpwalk not found — apt install snmp snmp-mibs-downloader"
        rprint "    try: snmpwalk -c public -v1 ${ip}"
    fi
    if command -v onesixtyone &>/dev/null; then
        rprint "    ${DIM}brute-forcing community strings...${RESET}"
        local communities
        communities=$(timeout 15 onesixtyone "$ip" 2>/dev/null | grep -v "^$" | head -5)
        [[ -n "$communities" ]] && while IFS= read -r line; do rprint "    ${line}"; done <<< "$communities"
    fi
}

# ── NFS: list exports ─────────────────────────────────────────────────────────
enum_nfs() {
    local ip="$1"
    rprint "  [nfs / 2049]"
    if ! command -v showmount &>/dev/null; then
        rprint "    showmount not found — apt install nfs-common"
        rprint "    try: showmount -e ${ip}"
        return
    fi
    local exports
    exports=$(timeout 10 showmount -e "$ip" 2>/dev/null)
    if [[ -n "$exports" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "/"; then
                rprint "    ${RED}${BOLD}${line}${RESET}"
            else
                rprint "    ${line}"
            fi
        done <<< "$exports"
    else
        rprint "    no exports found"
    fi
}

# ── RPC: portmapper dump ──────────────────────────────────────────────────────
enum_rpc() {
    local ip="$1"
    rprint "  [rpc / 111]"
    if ! command -v rpcinfo &>/dev/null; then
        rprint "    rpcinfo not found — apt install rpcbind"
        rprint "    try: rpcinfo -p ${ip}"
        return
    fi
    local out
    out=$(timeout 10 rpcinfo -p "$ip" 2>/dev/null | tail -n +2 | head -20)
    if [[ -n "$out" ]]; then
        while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
    else
        rprint "    portmapper not responding"
    fi
}

# ── rsync: list modules ───────────────────────────────────────────────────────
enum_rsync() {
    local ip="$1"
    rprint "  [rsync / 873]"
    local modules
    modules=$(timeout 10 rsync --list-only "rsync://${ip}/" 2>/dev/null)
    if [[ -n "$modules" ]]; then
        rprint "    ${RED}${BOLD}[!] modules available:${RESET}"
        while IFS= read -r line; do rprint "    ${line}"; done <<< "$modules"
    else
        rprint "    no modules found (auth required or unavailable)"
    fi
}

# ── Redis: unauthenticated or authenticated check ─────────────────────────────
enum_redis() {
    local ip="$1" port="${2:-6379}"
    rprint "  [redis / ${port}]"
    if ! command -v redis-cli &>/dev/null; then
        rprint "    redis-cli not found — apt install redis-tools"
        rprint "    try: redis-cli -h ${ip} -p ${port} info"
        return
    fi

    local redis_args=(-h "$ip" -p "$port")
    [[ -n "$CRED_PASS" ]] && redis_args+=(-a "$CRED_PASS")

    local pong
    pong=$(timeout 5 redis-cli "${redis_args[@]}" ping 2>/dev/null)
    if [[ "$pong" == "PONG" ]]; then
        if [[ -n "$CRED_PASS" ]]; then
            rprint "    ${RED}${BOLD}[!] authenticated access confirmed (${CRED_USER:-password provided})${RESET}"
        else
            rprint "    ${RED}${BOLD}[!] unauthenticated access — no password required${RESET}"
        fi
        local info
        info=$(timeout 5 redis-cli "${redis_args[@]}" info server 2>/dev/null \
            | grep -E "redis_version|os:|arch_bits|tcp_port" | head -5)
        while IFS= read -r line; do rprint "    ${line}"; done <<< "$info"
        rprint "    ${RED}tip: redis-cli -h ${ip} config set dir /root/.ssh && config set dbfilename authorized_keys${RESET}"
    else
        rprint "    auth required or unavailable"
        [[ -z "$CRED_PASS" ]] && rprint "    tip: use --pass <password> to authenticate"
    fi
}

# ── MySQL: anonymous / empty root / credentialed login ───────────────────────
enum_mysql() {
    local ip="$1" port="${2:-3306}"
    rprint "  [mysql / ${port}]"
    if command -v mysql &>/dev/null; then
        local out

        # Try with provided credentials first
        if [[ -n "$CRED_USER" ]]; then
            rprint "    ${DIM}trying ${CRED_USER}...${RESET}"
            out=$(timeout 8 mysql -h "$ip" -P "$port" \
                -u "$CRED_USER" "--password=${CRED_PASS}" \
                -e "SHOW DATABASES;" 2>/dev/null)
            if [[ -n "$out" ]]; then
                rprint "    ${RED}${BOLD}[!] login successful as ${CRED_USER}${RESET}"
                while IFS= read -r line; do rprint "    ${line}"; done <<< "$(echo "$out" | head -15)"
                return
            fi
        fi

        # Try root empty password
        out=$(timeout 8 mysql -h "$ip" -P "$port" -u root --password='' \
            -e "SHOW DATABASES;" 2>/dev/null)
        if [[ -n "$out" ]]; then
            rprint "    ${RED}${BOLD}[!] root login with empty password accepted${RESET}"
            while IFS= read -r line; do rprint "    ${line}"; done <<< "$(echo "$out" | head -15)"
        else
            out=$(timeout 8 mysql -h "$ip" -P "$port" -u '' --password='' \
                -e "SHOW DATABASES;" 2>/dev/null)
            if [[ -n "$out" ]]; then
                rprint "    ${RED}${BOLD}[!] anonymous login accepted${RESET}"
                while IFS= read -r line; do rprint "    ${line}"; done <<< "$(echo "$out" | head -15)"
            else
                rprint "    auth required"
                [[ -z "$CRED_USER" ]] && rprint "    tip: use -U <user> --pass <pass> to authenticate"
            fi
        fi
    else
        rprint "    mysql client not found — apt install default-mysql-client"
        rprint "    try: mysql -h ${ip} -u root --password=''"
    fi
}

# ── PostgreSQL: try postgres user or provided credentials ─────────────────────
enum_postgres() {
    local ip="$1" port="${2:-5432}"
    rprint "  [postgresql / ${port}]"
    if command -v psql &>/dev/null; then
        local out

        if [[ -n "$CRED_USER" ]]; then
            rprint "    ${DIM}trying ${CRED_USER}...${RESET}"
            out=$(timeout 8 PGPASSWORD="$CRED_PASS" psql -h "$ip" -p "$port" \
                -U "$CRED_USER" -c '\list' 2>/dev/null)
            if [[ -n "$out" ]]; then
                rprint "    ${RED}${BOLD}[!] login successful as ${CRED_USER}${RESET}"
                while IFS= read -r line; do rprint "    ${line}"; done <<< "$(echo "$out" | head -15)"
                return
            fi
        fi

        out=$(timeout 8 PGPASSWORD='' psql -h "$ip" -p "$port" -U postgres \
            -c '\list' 2>/dev/null)
        if [[ -n "$out" ]]; then
            rprint "    ${RED}${BOLD}[!] postgres user accessible (no/empty password)${RESET}"
            while IFS= read -r line; do rprint "    ${line}"; done <<< "$(echo "$out" | head -15)"
        else
            rprint "    auth required"
            [[ -z "$CRED_USER" ]] && rprint "    tip: use -U <user> --pass <pass> to authenticate"
        fi
    else
        rprint "    psql not found — apt install postgresql-client"
        rprint "    try: psql -h ${ip} -U postgres"
    fi
}

# ── WinRM: check access ───────────────────────────────────────────────────────
enum_winrm() {
    local ip="$1" port="${2:-5985}"
    rprint "  [winrm / ${port}]"

    if [[ -n "$CRED_USER" ]]; then
        rprint "    ${DIM}testing credentials ${CRED_USER}...${RESET}"
        if command -v crackmapexec &>/dev/null; then
            local out
            out=$(timeout 15 crackmapexec winrm "$ip" -u "$CRED_USER" -p "$CRED_PASS" 2>/dev/null | head -5)
            if [[ -n "$out" ]]; then
                while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
                echo "$out" | grep -qi "Pwn3d\|SUCCESS" && \
                    rprint "    ${RED}${BOLD}[!] Valid credentials — run: evil-winrm -i ${ip} -u ${CRED_USER} -p '${CRED_PASS}'${RESET}"
            fi
        else
            rprint "    try: evil-winrm -i ${ip} -u ${CRED_USER} -p '${CRED_PASS}'"
        fi
    else
        if command -v crackmapexec &>/dev/null; then
            local out
            out=$(timeout 15 crackmapexec winrm "$ip" -u '' -p '' 2>/dev/null | head -5)
            [[ -n "$out" ]] && while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
        fi
        rprint "    tip: use -U <user> --pass <pass> to test credentials"
        rprint "    try: evil-winrm -i ${ip} -u administrator -p <password>"
    fi
}

# ── Web: fingerprint + robots.txt + quick checks ──────────────────────────────
enum_web() {
    local ip="$1" port="$2" scheme="${3:-http}"
    rprint "  [web / ${port}]"
    local base_url="${scheme}://${ip}:${port}"

    # Headers + title via curl
    if command -v curl &>/dev/null; then
        local headers
        headers=$(timeout 8 curl -sk -I --max-time 5 "${base_url}/" 2>/dev/null \
            | grep -iE "^server:|^x-powered-by:|^content-type:|^location:" | head -5)
        [[ -n "$headers" ]] && while IFS= read -r line; do rprint "    ${GRAY}${line}${RESET}"; done <<< "$headers"

        # Check robots.txt
        local robots
        robots=$(timeout 8 curl -sk --max-time 5 "${base_url}/robots.txt" 2>/dev/null \
            | grep -iE "^(dis|al)low:" | head -10)
        if [[ -n "$robots" ]]; then
            rprint "    ${BOLD}robots.txt entries:${RESET}"
            while IFS= read -r line; do rprint "    ${line}"; done <<< "$robots"
        fi

        # Check sitemap.xml presence
        local sitemap_code
        sitemap_code=$(timeout 5 curl -sk -o /dev/null -w "%{http_code}" \
            --max-time 5 "${base_url}/sitemap.xml" 2>/dev/null)
        [[ "$sitemap_code" == "200" ]] && rprint "    ${GREEN}sitemap.xml found: ${base_url}/sitemap.xml${RESET}"
    fi

    # whatweb fingerprint
    if command -v whatweb &>/dev/null; then
        local out
        out=$(timeout 20 whatweb -a 1 --no-errors "${base_url}" 2>/dev/null \
            | sed 's/, /\n    /g' | sed 's/^http[^ ]* //' | grep -v '^$' | head -10)
        [[ -n "$out" ]] && while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
    fi

    # nikto hint
    rprint "    ${DIM}hint: nikto -h ${base_url}${RESET}"
}

# ── SMB: share listing via smbclient ─────────────────────────────────────────
enum_shares() {
    local ip="$1"
    rprint "  [shares / 445]"
    if ! command -v smbclient &>/dev/null; then
        rprint "    smbclient not found — apt install samba-client"
        return
    fi

    local auth_args=()
    if [[ -n "$CRED_USER" ]]; then
        auth_args=(-U "${CRED_USER}%${CRED_PASS}")
        rprint "    ${DIM}listing shares as ${CRED_USER}...${RESET}"
    else
        auth_args=(-N)
        rprint "    ${DIM}listing shares (null session)...${RESET}"
    fi

    local share_list
    share_list=$(timeout 15 smbclient -L "//${ip}" "${auth_args[@]}" 2>/dev/null \
        | grep -E "Disk|IPC|Printer" | awk '{print $1, $2}')

    if [[ -n "$share_list" ]]; then
        rprint "    ${BOLD}Shares found:${RESET}"
        while IFS= read -r share_line; do
            local sname
            sname=$(echo "$share_line" | awk '{print $1}')
            rprint "    ${GREEN}  \\\\${ip}\\${sname}${RESET}"

            # Try to connect to each share
            local access
            if [[ -n "$CRED_USER" ]]; then
                access=$(timeout 8 smbclient "//${ip}/${sname}" \
                    -U "${CRED_USER}%${CRED_PASS}" -c "ls" 2>/dev/null | head -8)
            else
                access=$(timeout 8 smbclient "//${ip}/${sname}" \
                    -N -c "ls" 2>/dev/null | head -8)
            fi

            if [[ -n "$access" ]]; then
                rprint "      ${RED}${BOLD}[!] READABLE${RESET}"
                while IFS= read -r f; do rprint "        ${f}"; done <<< "$access"
            fi
        done <<< "$share_list"
    else
        rprint "    null session denied or no shares visible"
        if [[ -z "$CRED_USER" ]]; then
            rprint "    tip: use -U <user> --pass <pass> to enumerate with credentials"
        fi
    fi
}

# ── SMB/Windows: enum4linux-ng ────────────────────────────────────────────────
enum_smb() {
    local ip="$1"
    rprint "  [smb / 445]"
    if command -v enum4linux-ng &>/dev/null; then
        rprint "    ${DIM}running enum4linux-ng...${RESET}"
        local auth_args=()
        [[ -n "$CRED_USER" ]] && auth_args=(-u "$CRED_USER" -p "$CRED_PASS")
        local out
        out=$(timeout 90 enum4linux-ng -A "${auth_args[@]}" "$ip" 2>/dev/null \
            | grep -E "^\[|Domain|Group|User|Share|Password|Policy|Workgroup|NetBIOS" \
            | grep -v "^\[V\]" | head -40)
        [[ -n "$out" ]] && while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
    elif command -v enum4linux &>/dev/null; then
        rprint "    ${DIM}running enum4linux...${RESET}"
        local auth_args=""
        [[ -n "$CRED_USER" ]] && auth_args="-u ${CRED_USER} -p ${CRED_PASS}"
        local out
        out=$(timeout 90 enum4linux $auth_args -a "$ip" 2>/dev/null \
            | grep -E "Domain|Group|User|Share|Password|Policy|Workgroup|NetBIOS" | head -30)
        [[ -n "$out" ]] && while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
    else
        rprint "    enum4linux-ng not found — apt install enum4linux-ng"
        rprint "    try: enum4linux-ng -A ${ip}"
    fi
}

# ── LDAP: anonymous or authenticated bind ─────────────────────────────────────
enum_ldap() {
    local ip="$1" port="${2:-389}"
    rprint "  [ldap / ${port}]"
    if ! command -v ldapsearch &>/dev/null; then
        rprint "    ldapsearch not found — apt install ldap-utils"
        rprint "    try: ldapsearch -x -H ldap://${ip} -b '' -s base namingContexts"
        return
    fi

    # Build auth args
    local auth_args=(-x)
    if [[ -n "$CRED_USER" ]]; then
        auth_args=(-x -D "$CRED_USER" -w "$CRED_PASS")
        rprint "    ${DIM}binding as ${CRED_USER}...${RESET}"
    fi

    local nc
    nc=$(timeout 10 ldapsearch "${auth_args[@]}" -H "ldap://${ip}:${port}" \
        -b '' -s base namingContexts 2>/dev/null \
        | grep "namingContexts:" | sed 's/namingContexts: //')
    if [[ -n "$nc" ]]; then
        rprint "    naming contexts:"
        while IFS= read -r line; do rprint "      ${line}"; done <<< "$nc"
        local base_dn; base_dn=$(echo "$nc" | head -1)

        local dns_host
        dns_host=$(timeout 10 ldapsearch "${auth_args[@]}" -H "ldap://${ip}:${port}" \
            -b "$base_dn" -s base dnsHostName 2>/dev/null \
            | grep "dnsHostName:" | sed 's/dnsHostName: //' | head -1)
        [[ -n "$dns_host" ]] && rprint "    dnsHostName : ${dns_host}"

        # With credentials — dump users
        if [[ -n "$CRED_USER" ]]; then
            rprint "    ${DIM}dumping AD users...${RESET}"
            local users
            users=$(timeout 20 ldapsearch "${auth_args[@]}" -H "ldap://${ip}:${port}" \
                -b "$base_dn" "(&(objectClass=user)(sAMAccountName=*))" \
                sAMAccountName userPrincipalName memberOf 2>/dev/null \
                | grep -E "sAMAccountName:|userPrincipalName:" | head -30)
            if [[ -n "$users" ]]; then
                rprint "    ${BOLD}AD users:${RESET}"
                while IFS= read -r line; do rprint "      ${line}"; done <<< "$users"
            fi
        fi
    else
        rprint "    anonymous bind failed or LDAP unavailable"
        [[ -z "$CRED_USER" ]] && rprint "    tip: use -U <user> --pass <pass> for authenticated LDAP"
    fi
}

# ── SMTP: banner + user enum hint ─────────────────────────────────────────────
enum_smtp() {
    local ip="$1" port="${2:-25}"
    rprint "  [smtp / ${port}]"
    local banner
    banner=$(timeout 5 bash -c \
        "exec 3<>/dev/tcp/${ip}/${port}; read -t3 b <&3; echo \"\$b\"; exec 3>&-" \
        2>/dev/null | head -1)
    [[ -n "$banner" ]] && rprint "    banner  : ${banner}"
    if command -v smtp-user-enum &>/dev/null; then
        rprint "    try: smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t ${ip}"
    fi
}

# ── IRC: banner + unrealircd check ────────────────────────────────────────────
enum_irc() {
    local ip="$1" port="${2:-6667}"
    rprint "  [irc / ${port}]"
    local banner
    banner=$(timeout 5 bash -c \
        "exec 3<>/dev/tcp/${ip}/${port}; read -t3 b <&3; echo \"\$b\"; exec 3>&-" \
        2>/dev/null | head -1)
    [[ -n "$banner" ]] && rprint "    banner  : ${banner}"
    if echo "$banner" | grep -qi "unrealircd\|3.2.8.1"; then
        rprint "    ${RED}${BOLD}[!] Possible UnrealIRCd — check for backdoor (CVE-2010-2075)${RESET}"
        rprint "    exploit: use irc-unrealircd-backdoor nmap script or Metasploit unreal_ircd_3281_backdoor"
    fi
    rprint "    try: nc -nv ${ip} ${port}"
}

# ── Finger: user enumeration ──────────────────────────────────────────────────
enum_finger() {
    local ip="$1"
    rprint "  [finger / 79]"
    if command -v finger &>/dev/null; then
        local out
        out=$(timeout 8 finger "@${ip}" 2>/dev/null | head -10)
        if [[ -n "$out" ]]; then
            while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
        else
            rprint "    no response to finger @${ip}"
        fi
        rprint "    try: finger root@${ip}  |  finger admin@${ip}"
    else
        rprint "    finger not found — apt install finger"
        rprint "    try: finger @${ip}  |  finger root@${ip}"
    fi
}

# ── Elasticsearch: index dump ─────────────────────────────────────────────────
enum_elasticsearch() {
    local ip="$1" port="${2:-9200}"
    rprint "  [elasticsearch / ${port}]"
    if command -v curl &>/dev/null; then
        local health
        health=$(timeout 8 curl -sk --max-time 5 "http://${ip}:${port}/_cluster/health" 2>/dev/null)
        if [[ -n "$health" ]]; then
            rprint "    ${RED}${BOLD}[!] Elasticsearch accessible without authentication${RESET}"
            rprint "    ${health}"
            local indices
            indices=$(timeout 8 curl -sk --max-time 5 "http://${ip}:${port}/_cat/indices?v" 2>/dev/null | head -10)
            if [[ -n "$indices" ]]; then
                rprint "    indices:"
                while IFS= read -r line; do rprint "    ${line}"; done <<< "$indices"
            fi
        else
            rprint "    no response or auth required"
        fi
    fi
}

# ── Jenkins/Tomcat detection on web port ──────────────────────────────────────
enum_jenkins() {
    local ip="$1" port="${2:-8080}"
    if command -v curl &>/dev/null; then
        local title
        title=$(timeout 8 curl -sk --max-time 5 "http://${ip}:${port}/" 2>/dev/null \
            | grep -oiP '(?<=<title>).*(?=</title>)' | head -1)
        if echo "$title" | grep -qi "jenkins"; then
            rprint "    ${RED}${BOLD}[!] Jenkins detected — check for unauthenticated script console${RESET}"
            rprint "    url: http://${ip}:${port}/script  (Groovy RCE if accessible)"
            rprint "    try: curl http://${ip}:${port}/api/json?pretty=true"
        elif echo "$title" | grep -qi "apache tomcat"; then
            rprint "    ${RED}${BOLD}[!] Apache Tomcat detected — check /manager/html${RESET}"
            rprint "    default creds: tomcat:tomcat  |  admin:admin  |  admin:s3cr3t"
            rprint "    try: curl http://${ip}:${port}/manager/html"
        fi
    fi
}

# ── Active Directory: attack path hints ───────────────────────────────────────
print_ad_hints() {
    local ip="$1"
    shift
    local -a open_ports=("$@")

    # Detect AD environment: needs 88 + 389 or 445
    local has_88=0 has_389=0 has_445=0
    for p in "${open_ports[@]}"; do
        [[ $p -eq 88  ]] && has_88=1
        [[ $p -eq 389 ]] && has_389=1
        [[ $p -eq 445 ]] && has_445=1
    done

    [[ $has_88 -eq 0 && $has_389 -eq 0 ]] && return

    local domain="<domain>"
    # Try to extract domain from LDAP naming context
    if [[ $has_389 -eq 1 ]] && command -v ldapsearch &>/dev/null; then
        local nc
        nc=$(timeout 8 ldapsearch -x -H "ldap://${ip}" -b '' -s base namingContexts 2>/dev/null \
            | grep "namingContexts:" | head -1 | sed 's/namingContexts: //')
        if [[ -n "$nc" ]]; then
            domain=$(echo "$nc" | grep -oP '(?<=DC=)[^,]+' | tr '\n' '.' | sed 's/\.$//')
        fi
    fi

    rprint ""
    sep
    rprint "  ACTIVE DIRECTORY ATTACKS  (domain: ${domain})"
    sep

    rprint "  ${BOLD}AS-REP Roasting${RESET} (no preauth required):"
    rprint "    impacket-GetNPUsers ${domain}/ -usersfile users.txt -no-pass -dc-ip ${ip} -outputfile hashes.asreproast"
    rprint "    hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt"
    rprint ""
    local cred_str="user:pass"
    [[ -n "$CRED_USER" ]] && cred_str="${CRED_USER}:${CRED_PASS}"

    rprint "  ${BOLD}Kerberoasting${RESET} (valid credentials needed):"
    rprint "    impacket-GetUserSPNs ${domain}/${cred_str} -dc-ip ${ip} -outputfile hashes.kerberoast"
    rprint "    hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt"
    rprint ""
    rprint "  ${BOLD}User Enumeration${RESET}:"
    rprint "    kerbrute userenum --dc ${ip} -d ${domain} /usr/share/seclists/Usernames/Names/names.txt"
    rprint ""
    if [[ $has_445 -eq 1 ]]; then
        rprint "  ${BOLD}SMB / Password Policy${RESET}:"
        if [[ -n "$CRED_USER" ]]; then
            rprint "    crackmapexec smb ${ip} --pass-pol -u '${CRED_USER}' -p '${CRED_PASS}'"
            rprint "    crackmapexec smb ${ip} -u '${CRED_USER}' -p '${CRED_PASS}' --shares"
        else
            rprint "    crackmapexec smb ${ip} --pass-pol -u '' -p ''"
            rprint "    crackmapexec smb ${ip} -u users.txt -p passwords.txt --continue-on-success"
        fi
        rprint ""
    fi
    rprint "  ${BOLD}BloodHound Collection${RESET} (valid credentials needed):"
    rprint "    bloodhound-python -u ${cred_str//:/ -p } -ns ${ip} -d ${domain} -c all"
    rprint "    neo4j start && bloodhound &  (import the ZIP to visualise)"
}

# ── Service hints table ───────────────────────────────────────────────────────
print_service_hints() {
    local ip="$1"
    shift
    local -a open_ports=("$@")
    local printed=0

    for port in "${open_ports[@]}"; do
        if [[ -n "${SERVICE_HINTS[$port]+_}" ]]; then
            if [[ $printed -eq 0 ]]; then
                rprint ""
                sep
                rprint "  ATTACK SURFACE"
                sep
                printed=1
            fi
            local hint="${SERVICE_HINTS[$port]//<IP>/$ip}"
            rprint "$(printf '  %-12s %s' "${port}/tcp" "→ ${hint}")"
        fi
    done
}

# ── Run extra enumeration based on open ports ─────────────────────────────────
run_extra_enum() {
    local ip="$1"
    shift
    local -a open_ports=("$@")
    [[ $NO_ENUM -eq 1 ]] && return

    local ran=0
    _ensure_header() {
        if [[ $ran -eq 0 ]]; then
            rprint ""
            sep
            rprint "  EXTRA ENUMERATION"
            sep
            ran=1
        fi
    }

    for port in "${open_ports[@]}"; do
        case "$port" in
            21)   _ensure_header; enum_ftp "$ip" "$port" ;;
            22)   _ensure_header; enum_ssh "$ip" "$port" ;;
            25|587) _ensure_header; enum_smtp "$ip" "$port" ;;
            79)   _ensure_header; enum_finger "$ip" ;;
            80)   _ensure_header; enum_web "$ip" "$port" "http" ;;
            111)  _ensure_header; enum_rpc "$ip" ;;
            161)  _ensure_header; enum_snmp "$ip" "$port" ;;
            389)  _ensure_header; enum_ldap "$ip" "$port" ;;
            443)  _ensure_header; enum_web "$ip" "$port" "https" ;;
            445)  _ensure_header; enum_shares "$ip"; enum_smb "$ip" ;;
            873)  _ensure_header; enum_rsync "$ip" ;;
            2049) _ensure_header; enum_nfs "$ip" ;;
            3306) _ensure_header; enum_mysql "$ip" "$port" ;;
            5432) _ensure_header; enum_postgres "$ip" "$port" ;;
            5985) _ensure_header; enum_winrm "$ip" "$port" ;;
            6379) _ensure_header; enum_redis "$ip" "$port" ;;
            6667) _ensure_header; enum_irc "$ip" "$port" ;;
            8080) _ensure_header; enum_web "$ip" "$port" "http"
                                  enum_jenkins "$ip" "$port" ;;
            8443|8888) _ensure_header
                  local scheme="http"; [[ $port -eq 8443 ]] && scheme="https"
                  enum_web "$ip" "$port" "$scheme" ;;
            9200) _ensure_header; enum_elasticsearch "$ip" "$port" ;;
        esac
    done
}

# ── Searchsploit: query exploitdb against detected service versions ───────────
run_searchsploit() {
    local ip="$1"
    [[ $DO_SEARCHSPLOIT -eq 0 ]] && return

    if ! command -v searchsploit &>/dev/null; then
        rprint "  ${RED}[!] searchsploit not found — apt install exploitdb${RESET}"
        return
    fi

    rprint ""
    sep
    rprint "  SEARCHSPLOIT RESULTS"
    sep

    # Parse nmap normal output for this host — extract service + version lines
    local in_host=0
    local found_any=0

    while IFS= read -r line; do
        # Detect host section
        if echo "$line" | grep -q "Nmap scan report for"; then
            echo "$line" | grep -q "$ip" && in_host=1 || in_host=0
            continue
        fi
        [[ $in_host -eq 0 ]] && continue
        # Stop at next host or end of scan
        [[ "$line" =~ ^"Nmap scan report" ]] && break

        # Match open port lines: 80/tcp  open  http  Apache httpd 2.4.41
        if echo "$line" | grep -qP '^\d+/(tcp|udp)\s+open'; then
            local port_proto service version query
            port_proto=$(echo "$line" | awk '{print $1}')
            service=$(echo "$line"   | awk '{print $3}')
            version=$(echo "$line"   | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//')

            # Skip if no version info
            [[ -z "$version" || "$version" =~ ^[[:space:]]*$ ]] && continue

            # Clean version for searchsploit query
            # e.g. "Apache httpd 2.4.41" → "Apache 2.4.41"
            query=$(echo "$version" | sed 's/  */ /g' | cut -c1-60)

            rprint ""
            rprint "  ${BOLD}[${port_proto}] ${service} — ${version}${RESET}"

            local results
            results=$(searchsploit --colour "$query" 2>/dev/null \
                | grep -v "^--\|^Exploit\|^Shellcode\|^$" \
                | head -10)

            if [[ -n "$results" ]]; then
                found_any=1
                while IFS= read -r r; do
                    rprint "    ${r}"
                done <<< "$results"
            else
                # Try shorter query: just product name (first 2 words)
                local short_query
                short_query=$(echo "$query" | awk '{print $1, $2}')
                results=$(searchsploit --colour "$short_query" 2>/dev/null \
                    | grep -v "^--\|^Exploit\|^Shellcode\|^$" \
                    | head -8)
                if [[ -n "$results" ]]; then
                    found_any=1
                    rprint "    ${DIM}(broad match: ${short_query})${RESET}"
                    while IFS= read -r r; do
                        rprint "    ${r}"
                    done <<< "$results"
                else
                    rprint "    ${GRAY}no results${RESET}"
                fi
            fi
        fi
    done < "$NMAP_N"

    # Also search OS
    local os_raw
    os_raw=$(get_os_info "$ip")
    if [[ -n "$os_raw" ]]; then
        local os_query
        os_query=$(echo "$os_raw" | cut -d',' -f1 | cut -c1-50)
        rprint ""
        rprint "  ${BOLD}[OS] ${os_query}${RESET}"
        local os_results
        os_results=$(searchsploit --colour "$os_query" 2>/dev/null \
            | grep -v "^--\|^Exploit\|^Shellcode\|^$" \
            | head -8)
        if [[ -n "$os_results" ]]; then
            found_any=1
            while IFS= read -r r; do rprint "    ${r}"; done <<< "$os_results"
        else
            rprint "    ${GRAY}no results${RESET}"
        fi
    fi

    [[ $found_any -eq 0 ]] && rprint "  no exploits found in ExploitDB for detected versions"
}

# ── Colour-code a script output line ─────────────────────────────────────────
colour_script_line() {
    local line="$1"
    local lo="${line,,}"
    if echo "$lo" | grep -qiE 'vulnerable|exploit|backdoor|state: vulnerable'; then
        echo -e "    ${RED}${BOLD}${line}${RESET}"
    elif echo "$lo" | grep -qiE 'not vulnerable|not affected|no vuln'; then
        echo -e "    ${GREEN}${line}${RESET}"
    else
        echo -e "    ${line}"
    fi
}

# ── Display a full host report ────────────────────────────────────────────────
display_host() {
    local ip="$1"
    local hostname os_raw hping_data=""
    local hping_os_guess=""

    hostname=$(get_hostname "$ip")
    os_raw=$(get_os_info "$ip")

    # ── Host header ──────────────────────────────────────────────────────────
    rprint ""
    sep2
    rprint "  HOST     : ${ip}$( [[ -n "$hostname" ]] && echo "  ($hostname)" )"

    # ── hping3 ────────────────────────────────────────────────────────────────
    if [[ $HPING_OK -eq 1 ]]; then
        rprint "${DIM}  [*] hping3 probing ${ip}...${RESET}"
        hping_data=$(hping_probe "$ip")
        IFS=':' read -r icmp_ok tcp80 tcp443 ttl os_ttl fw_hint <<< "$hping_data"
        hping_os_guess="$os_ttl"
        rprint "  hping3   : ICMP=$( [[ $icmp_ok -eq 1 ]] && echo "up" || echo "no reply" )  TCP/80=$( [[ $tcp80 -eq 1 ]] && echo "open" || echo "closed" )  TCP/443=$( [[ $tcp443 -eq 1 ]] && echo "open" || echo "closed" )  TTL=${ttl} (${os_ttl})"
        [[ $fw_hint -eq 1 ]] && rprint "  [!] Possible firewall / packet filtering detected"
    fi

    # ── OS detection ──────────────────────────────────────────────────────────
    if [[ -n "$os_raw" ]]; then
        local os_top
        os_top=$(echo "$os_raw" | cut -d',' -f1)
        rprint "  OS       : ${os_top}"
    elif [[ -n "$hping_os_guess" ]] && [[ "$hping_os_guess" != "Unknown" ]]; then
        rprint "  OS       : ${hping_os_guess} (hping3 TTL guess)"
    else
        rprint "  OS       : could not determine"
    fi

    # ── TCP Port table ────────────────────────────────────────────────────────
    rprint ""
    sep
    rprint "$(printf '  %-18s %-20s %s' 'PORT' 'SERVICE' 'VERSION')"
    sep

    local ports_raw
    ports_raw=$(grep "^Host: ${ip} " "$GNMAP" \
        | grep "Ports:" \
        | sed 's/.*Ports: //' \
        | sed 's/\t.*//')

    local found_open=0
    while IFS= read -r entry; do
        [[ -z "${entry// }" ]] && continue
        local parsed portid state proto service version
        parsed=$(parse_port_entry "$entry")
        IFS='|' read -r portid state proto service version <<< "$parsed"
        [[ "$state" != "open" ]] && continue
        found_open=1
        local ver_display="${version:-—}"
        [[ ${#ver_display} -gt 35 ]] && ver_display="${ver_display:0:32}..."
        rprint "$(printf '  %-18s %-20s %s' "${portid}/${proto}" "${service:-?}" "${ver_display}")"
    done < <(echo "$ports_raw" | tr ',' '\n')

    # ── UDP Port table (if UDP scan ran) ──────────────────────────────────────
    if [[ $NO_UDP -eq 0 ]] && [[ -f "$UDP_G" ]]; then
        local udp_ports_raw
        udp_ports_raw=$(grep "^Host: ${ip} " "$UDP_G" \
            | grep "Ports:" \
            | sed 's/.*Ports: //' \
            | sed 's/\t.*//')
        if [[ -n "$udp_ports_raw" ]]; then
            while IFS= read -r entry; do
                [[ -z "${entry// }" ]] && continue
                local parsed portid state proto service version
                parsed=$(parse_port_entry "$entry")
                IFS='|' read -r portid state proto service version <<< "$parsed"
                [[ "$state" != "open" ]] && continue
                found_open=1
                local ver_display="${version:-—}"
                [[ ${#ver_display} -gt 35 ]] && ver_display="${ver_display:0:32}..."
                rprint "$(printf '  %-18s %-20s %s' "${portid}/udp" "${service:-?}" "${ver_display}")"
            done < <(echo "$udp_ports_raw" | tr ',' '\n')
        fi
    fi

    [[ $found_open -eq 0 ]] && rprint "  no open ports found"

    # ── Script / Vuln results ─────────────────────────────────────────────────
    if [[ $NO_VULN -eq 0 ]]; then
        local all_scripts=""
        local script_file_phase2="$SCAN_TMP/vuln_${ip//./_}.nmap"

        [[ -f "$NMAP_N" ]]             && all_scripts+=$(extract_scripts "$ip" "$NMAP_N")$'\n'
        [[ -f "$script_file_phase2" ]] && all_scripts+=$(extract_scripts "$ip" "$script_file_phase2")$'\n'

        rprint ""
        sep
        rprint "  SCRIPTS & VULNERABILITIES"
        sep

        if [[ -z "$(echo "$all_scripts" | tr -d '[:space:]')" ]]; then
            rprint "  no script results"
        else
            local last_port="" current_script=""
            while IFS='|' read -r port_proto pipe_line; do
                [[ -z "$port_proto" ]] && continue
                local stripped_line
                stripped_line=$(echo "$pipe_line" | sed 's/^\s*//')
                if [[ "$port_proto" != "$last_port" ]]; then
                    last_port="$port_proto"
                    rprint ""
                    rprint "  [${port_proto}]"
                fi
                if echo "$stripped_line" | grep -qP '^\| [a-z][\w\-]+:'; then
                    current_script=$(echo "$stripped_line" | grep -oP '(?<=\| )[a-z][\w\-]+(?=:)')
                    local rest
                    rest=$(echo "$stripped_line" | sed "s/^| ${current_script}://")
                    rest=$(echo "$rest" | sed 's/^[[:space:]]*//')
                    rprint "    ${BOLD}${current_script}${RESET}$( [[ -n "$rest" ]] && echo " : ${rest}" )"
                    continue
                fi
                local content
                content=$(echo "$stripped_line" | sed 's/^|_\?[[:space:]]*//')
                [[ -z "$content" ]] && continue
                colour_script_line "$content"
            done <<< "$(echo "$all_scripts" | grep -v '^$')"
        fi
    fi

    # ── Searchsploit ──────────────────────────────────────────────────────────
    run_searchsploit "$ip"

    # ── Extra enumeration ─────────────────────────────────────────────────────
    mapfile -t _open_arr < <(get_open_ports "$ip")
    mapfile -t _udp_arr  < <(get_open_udp_ports "$ip")
    local _all_ports=("${_open_arr[@]}" "${_udp_arr[@]}")

    if [[ ${#_all_ports[@]} -gt 0 ]]; then
        run_extra_enum "$ip" "${_all_ports[@]}"
    fi

    # ── AD attack hints ───────────────────────────────────────────────────────
    if [[ ${#_open_arr[@]} -gt 0 ]]; then
        print_ad_hints "$ip" "${_open_arr[@]}"
        print_service_hints "$ip" "${_open_arr[@]}"
    fi

    # ── /etc/hosts update ────────────────────────────────────────────────────
    if [[ $ADD_HOSTS -eq 1 ]]; then
        local best_host
        best_host=$(get_best_hostname "$ip")
        if [[ -n "$best_host" ]]; then
            rprint ""
            sep
            update_hosts_file "$ip" "$best_host"
        fi
    fi

    rprint ""
    sep2
}

# ── Summary ───────────────────────────────────────────────────────────────────
display_summary() {
    local -a ips=("$@")
    local total_open=0 total_hosts=0 total_vulns=0

    rprint ""
    sep2
    rprint "  SUMMARY"
    sep

    for ip in "${ips[@]}"; do
        [[ -z "$ip" ]] && continue
        ((total_hosts++))

        local hostname os_raw open_count=0
        hostname=$(get_hostname "$ip")
        os_raw=$(get_os_info "$ip")
        local os_top="${os_raw:-(unknown)}"
        [[ ${#os_top} -gt 35 ]] && os_top="${os_top:0:32}..."
        os_top=$(echo "$os_top" | cut -d',' -f1)

        mapfile -t open_arr < <(get_open_ports "$ip")
        open_count=${#open_arr[@]}
        ((total_open += open_count))

        local vuln_file_phase2="$SCAN_TMP/vuln_${ip//./_}.nmap"
        local vcount=0
        for f in "$NMAP_N" "$vuln_file_phase2"; do
            if [[ -f "$f" ]]; then
                local fcount
                fcount=$(grep -ci "VULNERABLE\|backdoor" "$f" 2>/dev/null) || fcount=0
                vcount=$(( vcount + fcount ))
            fi
        done
        ((total_vulns += vcount))

        rprint ""
        rprint "  HOST    : ${ip}$( [[ -n "$hostname" ]] && echo " (${hostname})" )"
        rprint "  OS      : ${os_top}"
        rprint "  PORTS   : ${open_count} open"
        if [[ $vcount -gt 0 ]]; then
            rprint "  ISSUES  : ${RED}${BOLD}${vcount} potential vulnerability/misconfiguration(s) found${RESET}"
        else
            rprint "  ISSUES  : ${GREEN}none detected${RESET}"
        fi
    done

    rprint ""
    sep
    rprint "  Hosts scanned  : ${total_hosts}"
    rprint "  Open ports     : ${total_open}"
    rprint "  Potential vulns: $( [[ $total_vulns -gt 0 ]] && echo "${RED}${BOLD}${total_vulns}${RESET}" || echo "${GREEN}0${RESET}" )"
    sep2
    rprint ""
}

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════
banner

rprint "$(sep)"
rprint "  target    : ${TARGET}"
rprint "  ports     : ${PORTS:-all}"
rprint "  timing    : T${TIMING}"
rprint "  vuln scan : $( [[ $NO_VULN -eq 1 ]] && echo "off" || echo "on" )"
rprint "  udp scan  : $( [[ $NO_UDP -eq 1 ]] && echo "off" || echo "on" )"
rprint "  extra enum: $( [[ $NO_ENUM -eq 1 ]] && echo "off" || echo "on" )"
rprint "  add-hosts : $( [[ $ADD_HOSTS -eq 1 ]] && echo "on" || echo "off" )"
rprint "  hping3    : $( [[ $HPING_OK -eq 1 ]] && echo "on" || echo "off")"
rprint "  searchsploit: $( [[ $DO_SEARCHSPLOIT -eq 1 ]] && echo "on" || echo "off")"
rprint "  credentials : $( [[ -n "$CRED_USER" ]] && echo "${CRED_USER}:***" || echo "none (unauthenticated)" )"
rprint "$(sep)"

# ── Phase 1: TCP discovery ────────────────────────────────────────────────────
run_nmap_phase1

if [[ ! -f "$GNMAP" ]] || ! grep -q "^Host:" "$GNMAP" 2>/dev/null; then
    rprint "${RED}[!] No hosts found. Check target, permissions, and connectivity.${RESET}"
    exit 0
fi

mapfile -t ALL_IPS < <(get_scanned_ips)

if [[ ${#ALL_IPS[@]} -eq 0 ]]; then
    rprint "${RED}[!] No responsive hosts found.${RESET}"
    exit 0
fi

# ── Phase 1b: UDP scan ────────────────────────────────────────────────────────
run_nmap_udp

# ── Phase 2: Vuln scripts (per host) ─────────────────────────────────────────
if [[ $NO_VULN -eq 0 ]]; then
    for ip in "${ALL_IPS[@]}"; do
        [[ -z "$ip" ]] && continue
        mapfile -t open_ports < <(get_open_ports "$ip")
        [[ ${#open_ports[@]} -eq 0 ]] && continue
        run_nmap_phase2 "$ip" "${open_ports[@]}"
    done
fi

# ── Display per-host results ──────────────────────────────────────────────────
for ip in "${ALL_IPS[@]}"; do
    [[ -z "$ip" ]] && continue
    display_host "$ip"
done

# ── Summary ───────────────────────────────────────────────────────────────────
display_summary "${ALL_IPS[@]}"

# ── Save to file ──────────────────────────────────────────────────────────────
if [[ -n "$OUTPUT" ]]; then
    printf '%s\n' "${REPORT_LINES[@]}" > "$OUTPUT"
    echo -e "${GREEN}[✓] Report saved: ${OUTPUT}${RESET}"
fi
