#!/bin/bash

# ============================================================
#  recon.sh — CTF recon automation
#  Usage: ./recon.sh -t <ip> [options]
# ============================================================

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

cat << "EOF"
                                                                 /$$      
                                                                | $$      
  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$       /$$$$$$$| $$$$$$$ 
 /$$__  $$ /$$__  $$ /$$_____/ /$$__  $$| $$__  $$     /$$_____/| $$__  $$
| $$  \__/| $$$$$$$$| $$      | $$  \ $$| $$  \ $$    |  $$$$$$ | $$  \ $$
| $$      | $$_____/| $$      | $$  | $$| $$  | $$     \____  $$| $$  | $$
| $$      |  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$ /$$ /$$$$$$$/| $$  | $$
|__/       \_______/ \_______/ \______/ |__/  |__/|__/|_______/ |__/  |__/
                                                                          
                                                                          
EOF


# Always store results relative to the script itself, not the calling directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ip_address=""
output_dir=""
dns=""
http_ports=()
https_ports=()
open_ports=()
interesting_paths=()
yes_mode=false
quiet_mode=false

# Best subdomain wordlist available on Kali by default
wordlist_sub="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
wordlist_dir="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"

# ── Helpers ──────────────────────────────────────────────────

usage() {
    echo -e "Usage: $0 -t <ip> [options]"
    echo -e ""
    echo -e "  -t   Target IP address (required)"
    echo -e "  -y   Yes to all — skip all prompts"
    echo -e "  -q   Quiet mode — suppress verbose output"
    echo -e "  -ws  Subdomain wordlist (default: subdomains-top1million-110000.txt)"
    echo -e "  -wd  Directory wordlist  (default: raft-medium-directories.txt)"
    echo -e "  -h   Show this help"
    echo -e ""
    echo -e "Examples:"
    echo -e "  $0 -t 10.10.10.10"
    echo -e "  $0 -t 10.10.10.10 -y"
    echo -e "  $0 -t 10.10.10.10 -y -q"
    echo -e "  $0 -t 10.10.10.10 -ws /opt/wordlists/subdomains.txt -wd /opt/wordlists/dirs.txt"
    exit 0
}

# Pre-parse multi-char flags before getopts (bash only supports single chars)
args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -ws) wordlist_sub="$2"; shift 2 ;;
        -wd) wordlist_dir="$2"; shift 2 ;;
        *)   args+=("$1"); shift ;;
    esac
done
set -- "${args[@]}"

while getopts ":t:yqh" opt; do
    case $opt in
        t) ip_address="$OPTARG" ;;
        y) yes_mode=true ;;
        q) quiet_mode=true ;;
        h) usage ;;
        :) echo -e "${RED}[-] Option -$OPTARG requires an argument.${NC}"; exit 1 ;;
        \?) echo -e "${RED}[-] Unknown option: -$OPTARG${NC}"; usage ;;
    esac
done

if [[ -z "$ip_address" ]]; then
    echo -e "${RED}[-] Target IP is required. Use -t <ip>${NC}"
    usage
fi

output_dir="$SCRIPT_DIR/results/$ip_address"

# Auto-answer Y when -y is set
confirm() {
    local prompt="$1"
    if [[ "$yes_mode" == true ]]; then
        echo -e "${YELLOW}[auto-y]${NC} $prompt"
        return 0
    fi
    read -rp "$prompt (Y/n) " answer
    [[ "$answer" == "y" || "$answer" == "Y" || -z "$answer" ]]
}

# Only print in verbose mode
log() {
    [[ "$quiet_mode" == false ]] && echo -e "$1"
}

check_command() {
    command -v "$1" &>/dev/null
}

# ── Startup ───────────────────────────────────────────────────

mkdir -p "$output_dir"
echo -e "${BLUE}[*] Output: ${GREEN}${output_dir}/${NC}"

echo ""
log "${BLUE}=== Checking tools ===${NC}"

has_nmap=false; has_ffuf=false; has_feroxbuster=false

check_command "nmap"        && { log "${GREEN}[+] nmap${NC}";        has_nmap=true;        } || echo -e "${RED}[-] nmap not found — port scanning skipped${NC}"
check_command "ffuf"        && { log "${GREEN}[+] ffuf${NC}";        has_ffuf=true;        } || echo -e "${YELLOW}[!] ffuf not found — subdomain scan skipped${NC}"
check_command "feroxbuster" && { log "${GREEN}[+] feroxbuster${NC}"; has_feroxbuster=true; } || echo -e "${YELLOW}[!] feroxbuster not found — directory scan skipped${NC}"

echo ""

# ── Functions ─────────────────────────────────────────────────

checkPing() {
    log "${BLUE}=== Checking target ===${NC}"
    if ping "$ip_address" -c 1 >/dev/null 2>&1; then
        log "${GREEN}[+] Target is up${NC}"
    else
        echo -e "${RED}[-] Target unreachable — check the IP and try again${NC}"
        exit 1
    fi
}

# Add a hostname to /etc/hosts, handling three cases:
#   1. Not present         → add it
#   2. Correct IP          → skip
#   3. Wrong IP            → update it
addToHosts() {
    local entry_ip="$1"
    local hostname="$2"
    local existing_line existing_ip

    existing_line=$(grep -P "\s${hostname}(\s|$)" /etc/hosts | head -1 | tr -d '\r')

    if [[ -z "$existing_line" ]]; then
        echo -e "$entry_ip    $hostname" | sudo tee -a /etc/hosts >/dev/null
        echo -e "${GREEN}[+] Added $hostname to /etc/hosts${NC}"
    else
        existing_ip=$(echo "$existing_line" | awk '{print $1}' | tr -d '\r')
        if [[ "$existing_ip" == "$entry_ip" ]]; then
            log "${YELLOW}[!] $hostname already in /etc/hosts — skipping${NC}"
        else
            echo -e "${YELLOW}[!] $hostname points to wrong IP ($existing_ip) — updating${NC}"
            sudo sed -i "/$hostname/d" /etc/hosts
            echo -e "$entry_ip    $hostname" | sudo tee -a /etc/hosts >/dev/null
            echo -e "${GREEN}[+] Updated $hostname → $entry_ip${NC}"
        fi
    fi
}

checkDns() {
    echo ""
    log "${BLUE}=== Checking for DNS redirect ===${NC}"

    local found_dns=""

    # Try HTTP then HTTPS
    found_dns=$(curl -sI --max-time 5 "http://$ip_address" \
        | awk -F'[/:]' '/^Location:/ {print $5}' | tr -d '\r')

    if [[ -z "$found_dns" ]]; then
        found_dns=$(curl -sIk --max-time 5 "https://$ip_address" \
            | awk -F'[/:]' '/^Location:/ {print $5}' | tr -d '\r')
    fi

    if [[ -z "$found_dns" ]]; then
        log "${YELLOW}[!] No redirect found — continuing without DNS${NC}"
        return
    fi

    dns="$found_dns"
    echo -e "${GREEN}[+] DNS found: $dns${NC}"
    addToHosts "$ip_address" "$dns"

    # Rename output folder to DNS name
    local new_dir="$SCRIPT_DIR/results/$dns"
    if [[ "$output_dir" != "$new_dir" ]]; then
        mv "$output_dir" "$new_dir"
        output_dir="$new_dir"
        echo -e "${GREEN}[+] Output folder → ${output_dir}/${NC}"
    fi
}

gatherPorts() {
    [[ "$has_nmap" == false ]] && { echo -e "${RED}[-] Skipping port scan (nmap missing)${NC}"; return; }

    echo ""
    log "${BLUE}=== Port scanning ===${NC}"

    local ports
    ports=($(nmap -p- --min-rate=5000 -T4 "$ip_address" \
        | grep -E "^[0-9]+/tcp\s+open\s" | awk '{print $1}' | cut -d'/' -f1))

    if [[ ${#ports[@]} -eq 0 ]]; then
        echo -e "${RED}[-] No open ports found${NC}"; return
    fi

    open_ports+=("${ports[@]}")
    local parsedPorts
    parsedPorts=$(IFS=,; echo "${ports[*]}")
    echo -e "[+] Open ports: ${BLUE}$parsedPorts${NC}"
    log "[*] Running detailed scan..."

    nmap -p "$parsedPorts" -sC -sV "$ip_address" > "$output_dir/nmap_results.txt"
    log "${GREEN}[+] Nmap results saved${NC}"
}

# Probe each open port by actually talking to it — more reliable than
# trusting nmap's service name guesses. Uses DNS hostname so virtual
# hosts respond correctly (hitting by IP alone often returns nothing).
probeWebPorts() {
    echo ""
    log "${BLUE}=== Probing for web services ===${NC}"

    [[ ${#open_ports[@]} -eq 0 ]] && { log "${YELLOW}[!] No ports to probe${NC}"; return; }

    local probe_host="${dns:-$ip_address}"

    for port in "${open_ports[@]}"; do
        local status_http status_https ssl_result
        local has_tls=false

        status_http=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 3 --connect-timeout 2 "http://$probe_host:$port" 2>/dev/null)

        status_https=$(curl -sk -o /dev/null -w "%{http_code}" \
            --max-time 3 --connect-timeout 2 "https://$probe_host:$port" 2>/dev/null)

        # ssl_verify_result is only populated when a real TLS handshake occurred
        ssl_result=$(curl -sk -o /dev/null -w "%{ssl_verify_result}" \
            --max-time 3 --connect-timeout 2 "https://$probe_host:$port" 2>/dev/null)
        [[ "$ssl_result" =~ ^[0-9]+$ ]] && has_tls=true

        if [[ "$has_tls" == true && "$status_https" =~ ^[1-5][0-9]{2}$ ]]; then
            echo -e "${GREEN}[+] Port $port → HTTPS ($status_https)${NC}"
            https_ports+=("$port")
        elif [[ "$status_http" =~ ^[1-5][0-9]{2}$ ]]; then
            echo -e "${GREEN}[+] Port $port → HTTP ($status_http)${NC}"
            http_ports+=("$port")
        else
            log "${YELLOW}[~] Port $port → no web response${NC}"
        fi
    done

    log "[*] HTTP:  ${http_ports[*]:-none}"
    log "[*] HTTPS: ${https_ports[*]:-none}"
}

subdomainScan() {
    echo ""
    log "${BLUE}=== Subdomain scan ===${NC}"

    [[ ${#http_ports[@]} -eq 0 && ${#https_ports[@]} -eq 0 ]] && { log "${RED}[-] No web ports — skipping${NC}"; return; }
    [[ -z "$dns" ]]       && { log "${YELLOW}[!] No DNS name — skipping${NC}"; return; }
    [[ "$has_ffuf" == false ]] && { log "${YELLOW}[!] ffuf missing — skipping${NC}"; return; }

    if ! confirm "Perform subdomain scan?"; then
        echo "[*] Skipping subdomain scan."; return
    fi

    # Verify wordlist exists
    if [[ ! -f "$wordlist_sub" ]]; then
        echo -e "${RED}[-] Subdomain wordlist not found: $wordlist_sub${NC}"
        return
    fi

    # Helper to run one ffuf pass and append results to subDomains.txt
    _ffuf_pass() {
        local scheme="$1"
        local port="$2"
        local tmp_csv="$output_dir/.subdomain_tmp_${scheme}.csv"

        echo "[*] Probing $scheme://$dns:$port for subdomains..."
        if [[ "$quiet_mode" == true ]]; then
            ffuf -c -s \
                -u "${scheme}://${ip_address}:${port}" \
                -H "Host: FUZZ.$dns" \
                -w "$wordlist_sub" \
                -ac \
                -mc 200,204,301,302,307,308,401,403,405 \
                -t 40 \
                -of csv -o "$tmp_csv" 2>/dev/null
        else
            ffuf -c \
                -u "${scheme}://${ip_address}:${port}" \
                -H "Host: FUZZ.$dns" \
                -w "$wordlist_sub" \
                -ac \
                -mc 200,204,301,302,307,308,401,403,405 \
                -t 40 \
                -of csv -o "$tmp_csv"
        fi

        if [[ -f "$tmp_csv" ]]; then
            cut -d',' -f1 "$tmp_csv" | tail -n +2 >> "$output_dir/subDomains.txt"
            rm "$tmp_csv"
        fi
    }

    # Run over HTTP and/or HTTPS depending on what ports are open.
    # Some subdomains only exist on one protocol so we scan both when available.
    : > "$output_dir/subDomains.txt"   # reset/create file

    [[ ${#http_ports[@]} -gt 0 ]]  && _ffuf_pass "http"  "${http_ports[0]}"
    [[ ${#https_ports[@]} -gt 0 ]] && _ffuf_pass "https" "${https_ports[0]}"

    # Deduplicate across both passes
    if [[ -s "$output_dir/subDomains.txt" ]]; then
        sort -u "$output_dir/subDomains.txt" -o "$output_dir/subDomains.txt"
    else
        echo -e "${YELLOW}[!] No subdomains found${NC}"; return
    fi

    local found_count
    found_count=$(wc -l < "$output_dir/subDomains.txt")
    echo -e "[+] Found ${BLUE}${found_count}${NC} subdomain(s):"
    sed 's/^/    /' "$output_dir/subDomains.txt"

    # Safety cap — >10 results is suspicious, confirm before writing /etc/hosts
    if [[ "$found_count" -gt 10 && "$yes_mode" == false ]]; then
        echo -e "${YELLOW}[!] $found_count subdomains found — this seems high${NC}"
        read -rp "    Add all to /etc/hosts? (y/N) " hosts_answer
        [[ "$hosts_answer" != "y" && "$hosts_answer" != "Y" ]] && {
            echo -e "${YELLOW}[!] Skipping /etc/hosts — review ${output_dir}/subDomains.txt manually${NC}"
            return
        }
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        addToHosts "$ip_address" "$line.$dns"
    done < "$output_dir/subDomains.txt"

    echo -e "${GREEN}[+] Subdomains saved to ${output_dir}/subDomains.txt${NC}"
}

# Run feroxbuster on a target URL and harvest interesting paths
_runFerox() {
    local target="$1"
    local outfile="$2"
    local extra_flags="${3:-}"

    echo -e "[*] Scanning $target — press ${YELLOW}ENTER${NC} for scan menu"
    # shellcheck disable=SC2086
    feroxbuster \
        --url "$target" \
        --wordlist "$wordlist_dir" \
        --status-codes 200,204,301,302,307,401,403 \
        --no-recursion \
        --no-state \
        --auto-bail \
        --timeout 7 \
        $extra_flags \
        --output "$outfile"

    if [[ -f "$outfile" ]]; then
        while IFS= read -r path_line; do
            if [[ "$path_line" =~ ^([0-9]{3})[[:space:]].*[[:space:]](https?://[^[:space:]=>]+) ]]; then
                interesting_paths+=("${BASH_REMATCH[1]}  ${BASH_REMATCH[2]}")
            fi
        done < "$outfile"
    fi
}

directoryScan() {
    echo ""
    log "${BLUE}=== Directory scan ===${NC}"

    [[ ${#http_ports[@]} -eq 0 && ${#https_ports[@]} -eq 0 ]] && { echo -e "${RED}[-] No web ports — skipping${NC}"; return; }
    [[ "$has_feroxbuster" == false ]] && { echo -e "${YELLOW}[!] feroxbuster missing — skipping${NC}"; return; }

    # Verify wordlist exists
    if [[ ! -f "$wordlist_dir" ]]; then
        echo -e "${RED}[-] Directory wordlist not found: $wordlist_dir${NC}"
        return
    fi

    if ! confirm "Perform directory scan?"; then
        echo "[*] Skipping directory scan."; return
    fi

    for i in "${http_ports[@]}"; do
        _runFerox "http://${dns:-$ip_address}:$i" "$output_dir/ferox_http_$i.txt"
    done

    for i in "${https_ports[@]}"; do
        _runFerox "https://${dns:-$ip_address}:$i" "$output_dir/ferox_https_$i.txt" "--insecure"
    done

    if [[ -s "$output_dir/subDomains.txt" ]]; then
        echo "[*] Scanning subdomains..."
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local scheme="http"
            [[ ${#https_ports[@]} -gt 0 ]] && scheme="https"
            _runFerox "${scheme}://$line.$dns" \
                "$output_dir/ferox_sub_${line}.txt" \
                "--time-limit 2m"
        done < "$output_dir/subDomains.txt"
    fi
}

writeSummary() {
    local summary_file="$output_dir/summary.txt"
    local http_ports_str="${http_ports[*]:-none}"
    local https_ports_str="${https_ports[*]:-none}"
    local subdomain_count=0

    [[ -s "$output_dir/subDomains.txt" ]] && subdomain_count=$(wc -l < "$output_dir/subDomains.txt")

    # Deduplicate interesting paths
    local -a unique_paths
    while IFS= read -r line; do
        unique_paths+=("$line")
    done < <(printf '%s\n' "${interesting_paths[@]}" | sort -u)

    {
        echo "============================================"
        echo "  RECON SUMMARY"
        echo "  Target:    $ip_address"
        echo "  DNS:       ${dns:-none}"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "============================================"
        echo ""

        # ── 1. INTERESTING PATHS FIRST (most actionable) ─────────────────
        echo "--------------------------------------------"
        echo "  INTERESTING PATHS"
        echo "--------------------------------------------"
        if [[ ${#unique_paths[@]} -eq 0 ]]; then
            echo "  none"
        else
            # Group paths by origin (port + scheme)
            declare -A path_groups
            for p in "${unique_paths[@]}"; do
                # p format: "STATUS  http(s)://host:port/path"
                local url
                url=$(echo "$p" | awk '{print $2}')
                local origin
                # Extract scheme + host + port as group key
                origin=$(echo "$url" | grep -oP '^https?://[^/]+')
                path_groups["$origin"]+="$p"$'\n'
            done

            for origin in $(echo "${!path_groups[@]}" | tr ' ' '\n' | sort); do
                echo ""
                echo "  [ $origin ]"
                while IFS= read -r entry; do
                    [[ -z "$entry" ]] && continue
                    local status url path
                    status=$(echo "$entry" | awk '{print $1}')
                    url=$(echo "$entry"    | awk '{print $2}')
                    path=$(echo "$url" | grep -oP '(?<=://[^/]{1,100})/.+' || echo "/")

                    # Colour-code status for terminals that support it
                    case "$status" in
                        200)       printf "    ${GREEN}%-5s${NC} %s\n" "$status" "$path" ;;
                        301|302)   printf "    ${YELLOW}%-5s${NC} %s\n" "$status" "$path" ;;
                        401|403)   printf "    ${RED}%-5s${NC} %s\n" "$status" "$path" ;;
                        *)         printf "    %-5s %s\n" "$status" "$path" ;;
                    esac
                done <<< "${path_groups[$origin]}"
            done
            unset path_groups
        fi
        echo ""

        # ── 2. SUBDOMAINS ────────────────────────────────────────────────
        echo "--------------------------------------------"
        echo "  SUBDOMAINS  ($subdomain_count found)"
        echo "--------------------------------------------"
        if [[ "$subdomain_count" -gt 0 ]]; then
            while IFS= read -r sub; do
                [[ -n "$sub" ]] && echo "  $sub.$dns"
            done < "$output_dir/subDomains.txt"
        else
            echo "  none"
        fi
        echo ""

        # ── 3. OPEN PORTS & SERVICES ─────────────────────────────────────
        echo "--------------------------------------------"
        echo "  OPEN PORTS & SERVICES"
        echo "--------------------------------------------"
        if [[ -f "$output_dir/nmap_results.txt" ]]; then
            grep -E "^[0-9]+/tcp\s+open" "$output_dir/nmap_results.txt" \
                | awk '{printf "  %-10s %-14s %s\n", $1, $3, substr($0, index($0,$4))}'
        else
            echo "  (nmap results not available)"
        fi
        echo ""

        # ── 4. WEB PORTS (quick ref) ─────────────────────────────────────
        echo "--------------------------------------------"
        echo "  WEB PORTS"
        echo "--------------------------------------------"
        echo "  HTTP:   $http_ports_str"
        echo "  HTTPS:  $https_ports_str"
        echo ""

        echo "============================================"
    } > "$summary_file"

    echo -e "${GREEN}[+] Summary written to ${summary_file}${NC}"
}

previewResults() {
    echo ""
    if ! confirm "Preview all results?"; then
        echo ""; cat "$output_dir/summary.txt"; return
    fi

    for file in "$output_dir"/*; do
        [[ -f "$file" ]] || continue
        [[ "$file" == *"summary.txt" ]] && continue
        echo ""
        echo -e "${BLUE}== $(basename "$file") ==${NC}"
        if [[ "$file" == *"ferox"* ]]; then
            grep -E "^[0-9]{3}[[:space:]]" "$file" | sort -u || echo "  (no results)"
        else
            cat "$file"
        fi
    done

    echo ""
    cat "$output_dir/summary.txt"
}

# ── Run ───────────────────────────────────────────────────────

checkPing
checkDns
gatherPorts
probeWebPorts
subdomainScan
directoryScan
writeSummary
previewResults

echo ""
echo -e "${GREEN}=== Done! Results: ${output_dir}/ ===${NC}"
