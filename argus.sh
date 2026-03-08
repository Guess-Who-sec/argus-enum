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
VULN_N="$SCAN_TMP/vuln.nmap"     # vuln-script normal output

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET=""; PORTS=""; NO_VULN=0; NO_HPING=0; NO_ENUM=0; ADD_HOSTS=0
TIMING="4"; OUTPUT=""; VERBOSE=0

# ── Vulnerability scripts per port ────────────────────────────────────────────
declare -A PORT_SCRIPTS
PORT_SCRIPTS[21]="ftp-anon,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie"
PORT_SCRIPTS[22]="ssh-auth-methods,ssh-hostkey,sshv1,ssh2-enum-algos"
PORT_SCRIPTS[23]="telnet-ntlm-info,telnet-encryption"
PORT_SCRIPTS[25]="smtp-open-relay,smtp-commands,smtp-vuln-cve2010-4344,smtp-ntlm-info"
PORT_SCRIPTS[53]="dns-zone-transfer,dns-recursion,dns-cache-snoop,dns-update"
PORT_SCRIPTS[80]="http-vuln-cve2017-5638,http-vuln-cve2015-1635,http-vuln-cve2014-3704,http-shellshock,http-methods,http-auth-finder,http-title,http-headers,http-server-header"
PORT_SCRIPTS[110]="pop3-capabilities,pop3-ntlm-info"
PORT_SCRIPTS[88]="krb5-enum-users"
PORT_SCRIPTS[135]="msrpc-enum"
PORT_SCRIPTS[139]="smb-vuln-ms17-010,smb-vuln-ms08-067,smb-security-mode,smb-enum-shares,smb-enum-users,smb-os-discovery,nbstat"
PORT_SCRIPTS[389]="ldap-rootdse,ldap-search,ldap-novell-getpass"
PORT_SCRIPTS[464]="krb5-enum-users"
PORT_SCRIPTS[143]="imap-capabilities,imap-ntlm-info"
PORT_SCRIPTS[161]="snmp-info,snmp-sysdescr,snmp-interfaces,snmp-processes"
PORT_SCRIPTS[443]="ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-cert,tls-ticketbleed,ssl-ccs-injection,http-shellshock,http-vuln-cve2017-5638"
PORT_SCRIPTS[445]="smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve2009-3103,smb-vuln-ms10-054,smb-vuln-ms10-061,smb-vuln-regsvc-dos,smb-security-mode,smb2-security-mode,smb-enum-shares,smb-enum-users,smb-os-discovery"
PORT_SCRIPTS[593]="msrpc-enum"
PORT_SCRIPTS[636]="ssl-heartbleed,ssl-cert,ldap-rootdse"
PORT_SCRIPTS[3268]="ldap-rootdse,ldap-search"
PORT_SCRIPTS[3269]="ssl-heartbleed,ssl-cert,ldap-rootdse"
PORT_SCRIPTS[587]="smtp-open-relay,smtp-commands,smtp-ntlm-info"
PORT_SCRIPTS[993]="ssl-heartbleed,ssl-cert,imap-capabilities"
PORT_SCRIPTS[995]="ssl-heartbleed,ssl-cert,pop3-capabilities"
PORT_SCRIPTS[1433]="ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-ntlm-info,ms-sql-config"
PORT_SCRIPTS[3306]="mysql-empty-password,mysql-info,mysql-enum,mysql-vuln-cve2012-2122"
PORT_SCRIPTS[3389]="rdp-vuln-ms12-020,rdp-enum-encryption"
PORT_SCRIPTS[5432]="pgsql-brute"
PORT_SCRIPTS[5900]="vnc-info,vnc-brute,vnc-title"
PORT_SCRIPTS[5985]="http-auth-finder,http-title"
PORT_SCRIPTS[5986]="ssl-heartbleed,ssl-cert"
PORT_SCRIPTS[8080]="http-vuln-cve2017-5638,http-vuln-cve2015-1635,http-shellshock,http-methods,http-title,http-auth-finder"
PORT_SCRIPTS[8443]="ssl-heartbleed,ssl-poodle,ssl-cert,http-shellshock,http-vuln-cve2017-5638"
PORT_SCRIPTS[111]="rpcinfo,nfs-showmount,nfs-ls,nfs-statfs"
PORT_SCRIPTS[873]="rsync-list-modules,rsync-brute"
PORT_SCRIPTS[2049]="nfs-showmount,nfs-ls,nfs-statfs"
PORT_SCRIPTS[6379]="redis-info"
PORT_SCRIPTS[9200]="http-open-proxy,http-title,http-headers"
PORT_SCRIPTS[11211]="memcached-info"
PORT_SCRIPTS[27017]="mongodb-info,mongodb-databases"
PORT_SCRIPTS[2375]="http-title"

# ── Attack hints per port ─────────────────────────────────────────────────────
declare -A SERVICE_HINTS
SERVICE_HINTS[21]="ftp <IP>  (anonymous?)  |  curl ftp://<IP>/ --user anonymous:anonymous"
SERVICE_HINTS[22]="ssh -v <IP>  |  hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<IP>"
SERVICE_HINTS[23]="telnet <IP>"
SERVICE_HINTS[25]="smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <IP>"
SERVICE_HINTS[53]="dig axfr @<IP> <domain>  |  dnsrecon -d <domain> -t axfr"
SERVICE_HINTS[80]="gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
SERVICE_HINTS[111]="rpcinfo -p <IP>  |  showmount -e <IP>"
SERVICE_HINTS[139]="smbclient -L //<IP> -N  |  enum4linux-ng -A <IP>"
SERVICE_HINTS[443]="gobuster dir -u https://<IP> -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
SERVICE_HINTS[445]="smbclient -L //<IP> -N  |  enum4linux-ng -A <IP>  |  crackmapexec smb <IP>"
SERVICE_HINTS[873]="rsync --list-only rsync://<IP>/"
SERVICE_HINTS[1433]="crackmapexec mssql <IP> -u sa -p ''  |  sqsh -S <IP> -U sa"
SERVICE_HINTS[2049]="showmount -e <IP>  |  mount -t nfs <IP>:/ /mnt/nfs"
SERVICE_HINTS[3306]="mysql -h <IP> -u root --password=''  |  mysqldump"
SERVICE_HINTS[3389]="xfreerdp /v:<IP>  |  rdesktop <IP>"
SERVICE_HINTS[5432]="psql -h <IP> -U postgres  |  pg_dumpall"
SERVICE_HINTS[5900]="vncviewer <IP>  |  hydra -P /usr/share/wordlists/rockyou.txt vnc://<IP>"
SERVICE_HINTS[5985]="evil-winrm -i <IP> -u <user> -p <pass>"
SERVICE_HINTS[6379]="redis-cli -h <IP>  |  redis-cli -h <IP> info server"
SERVICE_HINTS[8080]="gobuster dir -u http://<IP>:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
SERVICE_HINTS[8443]="gobuster dir -u https://<IP>:8443 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
SERVICE_HINTS[9200]="curl http://<IP>:9200/_cat/indices  |  curl http://<IP>:9200/_cluster/health"
SERVICE_HINTS[11211]="echo 'stats' | nc -q1 <IP> 11211"
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
    echo -e "${RESET}${BOLD}${WHITE}"
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
    echo -e "  ${YELLOW}-t${RESET}  <target>   IP, CIDR, or comma-separated IPs"
    echo -e "  ${YELLOW}-p${RESET}  <ports>    Ports to scan (default: all). E.g. 22,80,443,445"
    echo -e "  ${YELLOW}-T${RESET}  <1-5>      nmap timing (1=stealthy … 5=aggressive). Default: 4"
    echo -e "  ${YELLOW}-o${RESET}  <file>     Save plain-text report to file"
    echo -e "  ${YELLOW}-v${RESET}             Verbose: show raw nmap output while scanning"
    echo -e "  ${YELLOW}--no-vuln${RESET}      Skip vulnerability scripts (faster)"
    echo -e "  ${YELLOW}--no-hping${RESET}     Skip hping3 probes"
    echo -e "  ${YELLOW}--no-enum${RESET}      Skip extra enumeration (NFS, rsync, Redis, etc.)"
    echo -e "  ${YELLOW}--add-hosts${RESET}    Auto-add discovered hostname to /etc/hosts"
    echo
    echo -e "${BOLD}Examples:${RESET}"
    echo "  sudo bash $0 -t 192.168.1.1"
    echo "  sudo bash $0 -t 192.168.1.0/24 --no-vuln -T 3"
    echo "  sudo bash $0 -t 10.0.0.5 --add-hosts -o report.txt"
    exit 0
}

# ── Arg parsing ───────────────────────────────────────────────────────────────
[[ $# -eq 0 ]] && { banner; usage; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t)        TARGET="$2";  shift 2 ;;
        -p)        PORTS="$2";   shift 2 ;;
        -T)        TIMING="$2";  shift 2 ;;
        -o)        OUTPUT="$2";  shift 2 ;;
        -v)        VERBOSE=1;    shift   ;;
        --no-vuln)  NO_VULN=1;    shift   ;;
        --no-hping) NO_HPING=1;   shift   ;;
        --no-enum)  NO_ENUM=1;    shift   ;;
        --add-hosts)ADD_HOSTS=1;  shift   ;;
        -h|--help) banner; usage ;;
        *) echo -e "${RED}[!] Unknown option: $1${RESET}"; usage ;;
    esac
done

# ── Checks ────────────────────────────────────────────────────────────────────
[[ -z "$TARGET" ]] && { echo -e "${RED}[!] Target required. Use -t <target>${RESET}"; exit 1; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}[!] Requires root for SYN scan and OS detection.${RESET}"
    echo -e "${YELLOW}    Run: sudo bash $0 $*${RESET}"
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
    # Strip ANSI for file output
    if [[ -n "$OUTPUT" ]]; then
        REPORT_LINES+=("$(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')")
    fi
}

# ── hping3 probe ──────────────────────────────────────────────────────────────
hping_probe() {
    local ip="$1"
    local icmp_ok=0 tcp80_ok=0 tcp443_ok=0 ttl=""

    # ICMP
    local raw
    raw=$(hping3 --icmp -c 3 --fast "$ip" 2>&1)
    echo "$raw" | grep -qi "bytes from"   && icmp_ok=1
    [[ -z "$ttl" ]] && ttl=$(echo "$raw" | grep -oiP 'ttl=\K[0-9]+' | head -1)

    # TCP SYN 80
    raw=$(hping3 -S -p 80 -c 3 --fast "$ip" 2>&1)
    echo "$raw" | grep -qiP 'flags=S?A'   && tcp80_ok=1
    [[ -z "$ttl" ]] && ttl=$(echo "$raw" | grep -oiP 'ttl=\K[0-9]+' | head -1)

    # TCP SYN 443
    raw=$(hping3 -S -p 443 -c 3 --fast "$ip" 2>&1)
    echo "$raw" | grep -qiP 'flags=S?A'   && tcp443_ok=1
    [[ -z "$ttl" ]] && ttl=$(echo "$raw" | grep -oiP 'ttl=\K[0-9]+' | head -1)

    # Guess OS from TTL
    local os_guess="Unknown"
    if [[ -n "$ttl" ]]; then
        if   [[ $ttl -le 64  ]]; then os_guess="Linux / macOS"
        elif [[ $ttl -le 128 ]]; then os_guess="Windows"
        elif [[ $ttl -le 255 ]]; then os_guess="Cisco / Network Device"
        fi
    fi

    # Firewall hint: both TCP ports not responding
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

# ── Run nmap phase 1 ──────────────────────────────────────────────────────────
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
    rprint "${DIM}[*] Phase 1/2 — discovery scan running...${RESET}"
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

    local cmd=(
        nmap -sS
        -T"$TIMING"
        -p "$ports_str"
        --script="$scripts"
        -oN "$vuln_out"
        "$ip"
    )

    rprint "${DIM}[*] Phase 2/2 — vuln scripts for ${ip}...${RESET}"
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

# ── Get open ports for an IP from grepable file ───────────────────────────────
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

# ── Parse a port entry from grepable (portid|state|proto|service|version) ─────
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

# ── Get OS info for an IP from grepable file ──────────────────────────────────
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

# ── Extract script output section for an IP and port from a normal output file ─
extract_scripts() {
    local ip="$1"
    local nmap_file="$2"
    # Pull out lines from this host's section; track port; emit port-tagged script lines
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
    # 1. nmap PTR hostname
    local h; h=$(get_hostname "$ip")
    [[ -n "$h" ]] && echo "$h" && return
    # 2. SSL cert commonName (skip wildcards)
    local cn
    cn=$(awk -v ip="$ip" '
        /Nmap scan report for / { in_host=($0 ~ ip)?1:0 }
        in_host && /commonName=/ {
            match($0,/commonName=([^ ,\/]+)/,a)
            if (a[1]!="" && a[1]!~/^\*/) { print a[1]; exit }
        }
    ' "$NMAP_N" 2>/dev/null | head -1)
    [[ -n "$cn" ]] && echo "$cn" && return
    # 3. SMB computer name
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

# ── FTP: try anonymous login, list files ──────────────────────────────────────
enum_ftp() {
    local ip="$1" port="${2:-21}"
    rprint "  [ftp / ${port}]"
    # Banner grab
    local banner
    banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/${ip}/${port}; read -t3 b <&3; echo \"\$b\"; exec 3>&-" 2>/dev/null | head -1)
    [[ -n "$banner" ]] && rprint "    banner  : ${banner}"
    # Anonymous login via curl
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
    # Auth methods from nmap script output (already run in phase 1)
    local auth
    auth=$(awk -v ip="$ip" -v p="$port" '
        /Nmap scan report for / { in_host=($0~ip)?1:0 }
        in_host && /^'"$port"'\/tcp/ { in_port=1 }
        in_port && /ssh-auth-methods/ { getline; print; in_port=0 }
    ' "$NMAP_N" 2>/dev/null | sed 's/^[| ]*//')
    [[ -n "$auth" ]] && rprint "    auth    : ${auth}"
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

# ── Redis: unauthenticated check ──────────────────────────────────────────────
enum_redis() {
    local ip="$1" port="${2:-6379}"
    rprint "  [redis / ${port}]"
    if ! command -v redis-cli &>/dev/null; then
        rprint "    redis-cli not found — apt install redis-tools"
        rprint "    try: redis-cli -h ${ip} -p ${port} info"
        return
    fi
    local pong
    pong=$(timeout 5 redis-cli -h "$ip" -p "$port" ping 2>/dev/null)
    if [[ "$pong" == "PONG" ]]; then
        rprint "    ${RED}${BOLD}[!] unauthenticated access — no password required${RESET}"
        local info
        info=$(timeout 5 redis-cli -h "$ip" -p "$port" info server 2>/dev/null \
            | grep -E "redis_version|os:|arch_bits|tcp_port" | head -5)
        while IFS= read -r line; do rprint "    ${line}"; done <<< "$info"
    else
        rprint "    auth required or unavailable"
    fi
}

# ── Web: whatweb fingerprint ──────────────────────────────────────────────────
enum_web() {
    local ip="$1" port="$2" scheme="${3:-http}"
    rprint "  [web / ${port}]"
    if ! command -v whatweb &>/dev/null; then
        rprint "    whatweb not found — apt install whatweb"
        rprint "    try: whatweb ${scheme}://${ip}:${port}"
        return
    fi
    local out
    out=$(timeout 20 whatweb -a 1 --no-errors "${scheme}://${ip}:${port}" 2>/dev/null \
        | sed 's/, /\n    /g' | sed 's/^http[^ ]* //' | grep -v '^$' | head -15)
    [[ -n "$out" ]] && while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
}

# ── SMB/Windows: enum4linux-ng ────────────────────────────────────────────────
enum_smb() {
    local ip="$1"
    rprint "  [smb / 445]"
    if command -v enum4linux-ng &>/dev/null; then
        rprint "    ${DIM}running enum4linux-ng...${RESET}"
        local out
        out=$(timeout 90 enum4linux-ng -A "$ip" 2>/dev/null \
            | grep -E "^\[|Domain|Group|User|Share|Password|Policy|Workgroup|NetBIOS" \
            | grep -v "^\[V\]" | head -40)
        [[ -n "$out" ]] && while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
    elif command -v enum4linux &>/dev/null; then
        rprint "    ${DIM}running enum4linux...${RESET}"
        local out
        out=$(timeout 90 enum4linux -a "$ip" 2>/dev/null \
            | grep -E "Domain|Group|User|Share|Password|Policy|Workgroup|NetBIOS" | head -30)
        [[ -n "$out" ]] && while IFS= read -r line; do rprint "    ${line}"; done <<< "$out"
    else
        rprint "    enum4linux-ng not found — apt install enum4linux-ng"
        rprint "    try: enum4linux-ng -A ${ip}"
    fi
}

# ── LDAP: anonymous bind ──────────────────────────────────────────────────────
enum_ldap() {
    local ip="$1" port="${2:-389}"
    rprint "  [ldap / ${port}]"
    if ! command -v ldapsearch &>/dev/null; then
        rprint "    ldapsearch not found — apt install ldap-utils"
        rprint "    try: ldapsearch -x -H ldap://${ip} -b '' -s base namingContexts"
        return
    fi
    local nc
    nc=$(timeout 10 ldapsearch -x -H "ldap://${ip}:${port}" \
        -b '' -s base namingContexts 2>/dev/null \
        | grep "namingContexts:" | sed 's/namingContexts: //')
    if [[ -n "$nc" ]]; then
        rprint "    naming contexts:"
        while IFS= read -r line; do rprint "      ${line}"; done <<< "$nc"
        # Try to get domain/DNS from base DN
        local base_dn; base_dn=$(echo "$nc" | head -1)
        local dns_host
        dns_host=$(timeout 10 ldapsearch -x -H "ldap://${ip}:${port}" \
            -b "$base_dn" -s base dnsHostName 2>/dev/null \
            | grep "dnsHostName:" | sed 's/dnsHostName: //' | head -1)
        [[ -n "$dns_host" ]] && rprint "    dnsHostName : ${dns_host}"
    else
        rprint "    anonymous bind failed or LDAP unavailable"
    fi
}

# ── SMTP: user enumeration hint ───────────────────────────────────────────────
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
                rprint "$(sep)"
                rprint "  ATTACK SURFACE"
                rprint "$(sep)"
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
    for port in "${open_ports[@]}"; do
        case "$port" in
            21)  [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_ftp "$ip" "$port" ;;
            22)  [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_ssh "$ip" "$port" ;;
            25|587) [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_smtp "$ip" "$port" ;;
            80)  [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_web "$ip" "$port" "http" ;;
            111) [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_rpc "$ip" ;;
            389) [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_ldap "$ip" "$port" ;;
            443) [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_web "$ip" "$port" "https" ;;
            445) [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_smb "$ip" ;;
            873) [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_rsync "$ip" ;;
            2049)[[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_nfs "$ip" ;;
            6379)[[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 enum_redis "$ip" "$port" ;;
            8080|8443|8888)
                 [[ $ran -eq 0 ]] && { rprint ""; rprint "$(sep)"; rprint "  EXTRA ENUMERATION"; rprint "$(sep)"; ran=1; }
                 local scheme="http"; [[ $port -eq 8443 ]] && scheme="https"
                 enum_web "$ip" "$port" "$scheme" ;;
        esac
    done
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
    rprint "$(sep2)"
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

    # ── Port table ────────────────────────────────────────────────────────────
    rprint ""
    rprint "$(sep)"
    rprint "$(printf '  %-18s %-20s %s' 'PORT' 'SERVICE' 'VERSION')"
    rprint "$(sep)"

    local ports_raw
    ports_raw=$(grep "^Host: ${ip} " "$GNMAP" \
        | grep "Ports:" \
        | sed 's/.*Ports: //' \
        | sed 's/\t.*//')

    local found_open=0
    # Use tr to split on commas then read line by line — avoids IFS/read comma-split bug
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

    [[ $found_open -eq 0 ]] && rprint "  no open ports found"

    # ── Script / Vuln results ─────────────────────────────────────────────────
    if [[ $NO_VULN -eq 0 ]]; then
        local all_scripts=""
        local script_file_phase2="$SCAN_TMP/vuln_${ip//./_}.nmap"

        [[ -f "$NMAP_N" ]]             && all_scripts+=$(extract_scripts "$ip" "$NMAP_N")$'\n'
        [[ -f "$script_file_phase2" ]] && all_scripts+=$(extract_scripts "$ip" "$script_file_phase2")$'\n'

        rprint ""
        rprint "$(sep)"
        rprint "  SCRIPTS & VULNERABILITIES"
        rprint "$(sep)"

        if [[ -z "$(echo "$all_scripts" | tr -d '[:space:]')" ]]; then
            rprint "  no script results"
        else
            local last_port="" current_script=""
            while IFS='|' read -r port_proto pipe_line; do
                [[ -z "$port_proto" ]] && continue
                local stripped_line
                stripped_line=$(echo "$pipe_line" | sed 's/^\s*//')

                # New port group
                if [[ "$port_proto" != "$last_port" ]]; then
                    last_port="$port_proto"
                    rprint ""
                    rprint "  [${port_proto}]"
                fi

                # New script name line ( | scriptname: )
                if echo "$stripped_line" | grep -qP '^\| [a-z][\w\-]+:'; then
                    current_script=$(echo "$stripped_line" | grep -oP '(?<=\| )[a-z][\w\-]+(?=:)')
                    local rest
                    rest=$(echo "$stripped_line" | sed "s/^| ${current_script}://")
                    rest=$(echo "$rest" | sed 's/^[[:space:]]*//')
                    rprint "    ${BOLD}${current_script}${RESET}$( [[ -n "$rest" ]] && echo " : ${rest}" )"
                    continue
                fi

                # Content lines
                local content
                content=$(echo "$stripped_line" | sed 's/^|_\?[[:space:]]*//')
                [[ -z "$content" ]] && continue
                colour_script_line "$content"

            done <<< "$(echo "$all_scripts" | grep -v '^$')"
        fi
    fi

    # ── Extra enumeration & service hints ────────────────────────────────────
    mapfile -t _open_arr < <(get_open_ports "$ip")
    if [[ ${#_open_arr[@]} -gt 0 ]]; then
        run_extra_enum "$ip" "${_open_arr[@]}"
        print_service_hints "$ip" "${_open_arr[@]}"
    fi

    # ── /etc/hosts update ────────────────────────────────────────────────────
    if [[ $ADD_HOSTS -eq 1 ]]; then
        local best_host
        best_host=$(get_best_hostname "$ip")
        if [[ -n "$best_host" ]]; then
            rprint ""
            rprint "$(sep)"
            update_hosts_file "$ip" "$best_host"
        fi
    fi

    rprint ""
    rprint "$(sep2)"
}

# ── Summary ───────────────────────────────────────────────────────────────────
display_summary() {
    local -a ips=("$@")
    local total_open=0 total_hosts=0 total_vulns=0

    rprint ""
    rprint "$(sep2)"
    rprint "  SUMMARY"
    rprint "$(sep)"

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

        # Count vulns
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
    rprint "$(sep)"
    rprint "  Hosts scanned  : ${total_hosts}"
    rprint "  Open ports     : ${total_open}"
    rprint "  Potential vulns: $( [[ $total_vulns -gt 0 ]] && echo "${RED}${BOLD}${total_vulns}${RESET}" || echo "${GREEN}0${RESET}" )"
    rprint "$(sep2)"
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
rprint "  extra enum: $( [[ $NO_ENUM -eq 1 ]] && echo "off" || echo "on" )"
rprint "  add-hosts : $( [[ $ADD_HOSTS -eq 1 ]] && echo "on" || echo "off" )"
rprint "  hping3    : $( [[ $HPING_OK -eq 1 ]] && echo "on" || echo "off")"
rprint "$(sep)"

# ── Phase 1: Discovery scan ───────────────────────────────────────────────────
run_nmap_phase1

if [[ ! -f "$GNMAP" ]] || ! grep -q "^Host:" "$GNMAP" 2>/dev/null; then
    rprint "${YELLOW}[!] No hosts found. Check target, permissions, and connectivity.${RESET}"
    exit 0
fi

# ── Collect IPs from scan ─────────────────────────────────────────────────────
mapfile -t ALL_IPS < <(get_scanned_ips)

if [[ ${#ALL_IPS[@]} -eq 0 ]]; then
    rprint "${YELLOW}[!] No responsive hosts found.${RESET}"
    exit 0
fi

# ── Phase 2: Vuln scripts (per host) ──────────────────────────────────────────
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
