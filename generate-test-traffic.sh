#!/bin/bash

# Advanced Traffic Generator for Suricata Testing
# Generates diverse network traffic to trigger various Suricata rules

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Suricata Traffic Generator${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check dependencies
for cmd in curl wget nc nslookup; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${YELLOW}[WARNING] $cmd not found, some tests may be skipped${NC}"
    fi
done

# ====================
# HTTP/HTTPS Traffic
# ====================
echo -e "${GREEN}[1] Generating HTTP/HTTPS Traffic${NC}"

echo -e "${YELLOW}  → Standard HTTP request...${NC}"
curl -s -m 5 http://example.com > /dev/null 2>&1 || true

echo -e "${YELLOW}  → HTTPS/TLS request...${NC}"
curl -s -m 5 https://www.google.com > /dev/null 2>&1 || true

echo -e "${YELLOW}  → Multiple HTTP requests...${NC}"
for i in {1..5}; do
    curl -s -m 5 http://example.com > /dev/null 2>&1 || true
done

# ====================
# Malicious User Agents
# ====================
echo -e "${GREEN}[2] Generating Malicious User Agent Alerts${NC}"

MALICIOUS_UAS=(
    "BlackSun"
    "sqlmap"
    "Nikto"
    "Metasploit"
    "nmap"
    "masscan"
    "ZmEu"
    "DirBuster"
)

for ua in "${MALICIOUS_UAS[@]}"; do
    echo -e "${YELLOW}  → Testing user agent: $ua${NC}"
    curl -s -A "$ua" -m 5 http://testmynids.org/uid/index.html > /dev/null 2>&1 || true
    sleep 1
done

# ====================
# DNS Queries
# ====================
echo -e "${GREEN}[3] Generating DNS Traffic${NC}"

DOMAINS=(
    "google.com"
    "amazon.com"
    "cloudflare.com"
    "github.com"
    "stackoverflow.com"
)

for domain in "${DOMAINS[@]}"; do
    echo -e "${YELLOW}  → DNS query for $domain${NC}"
    nslookup $domain > /dev/null 2>&1 || true
    sleep 1
done

# ====================
# Emerging Threats Test Site
# ====================
echo -e "${GREEN}[4] Testing with ET Test Infrastructure${NC}"

echo -e "${YELLOW}  → ET INFO signature test...${NC}"
curl -s -m 5 http://testmynids.org/uid/index.html > /dev/null 2>&1 || true

echo -e "${YELLOW}  → ET MALWARE signature test...${NC}"
curl -s -m 5 -A "BlackSun" http://testmynids.org/uid/index.html > /dev/null 2>&1 || true

# ====================
# Port Scanning Simulation
# ====================
echo -e "${GREEN}[5] Simulating Port Scan Activity${NC}"

SCAN_TARGET="scanme.nmap.org"
PORTS=(22 80 443 8080 3306)

for port in "${PORTS[@]}"; do
    echo -e "${YELLOW}  → Testing connection to $SCAN_TARGET:$port${NC}"
    timeout 2 nc -zv $SCAN_TARGET $port > /dev/null 2>&1 || true
    sleep 1
done

# ====================
# Suspicious Patterns
# ====================
echo -e "${GREEN}[6] Generating Suspicious HTTP Patterns${NC}"

# SQL Injection patterns
echo -e "${YELLOW}  → SQL injection pattern in URL...${NC}"
curl -s -m 5 "http://testmynids.org/?id=1' OR '1'='1" > /dev/null 2>&1 || true

# XSS patterns
echo -e "${YELLOW}  → XSS pattern in URL...${NC}"
curl -s -m 5 "http://testmynids.org/?search=<script>alert('xss')</script>" > /dev/null 2>&1 || true

# Directory traversal
echo -e "${YELLOW}  → Directory traversal pattern...${NC}"
curl -s -m 5 "http://testmynids.org/../../etc/passwd" > /dev/null 2>&1 || true

# ====================
# Large Data Transfer
# ====================
echo -e "${GREEN}[7] Generating Large Data Transfer${NC}"

echo -e "${YELLOW}  → Downloading large file...${NC}"
curl -s -m 10 https://speed.hetzner.de/1MB.bin > /dev/null 2>&1 || true

# ====================
# TLS/SSL Traffic
# ====================
echo -e "${GREEN}[8] Generating TLS/SSL Traffic${NC}"

TLS_SITES=(
    "https://www.google.com"
    "https://www.github.com"
    "https://www.cloudflare.com"
)

for site in "${TLS_SITES[@]}"; do
    echo -e "${YELLOW}  → TLS connection to $site${NC}"
    curl -s -m 5 $site > /dev/null 2>&1 || true
    sleep 1
done

# ====================
# Multiple Protocols
# ====================
echo -e "${GREEN}[9] Mixed Protocol Traffic${NC}"

echo -e "${YELLOW}  → HTTP + DNS + HTTPS sequence...${NC}"
curl -s -m 5 http://example.com > /dev/null 2>&1 || true
nslookup github.com > /dev/null 2>&1 || true
curl -s -m 5 https://www.github.com > /dev/null 2>&1 || true

# ====================
# Rapid Fire Requests
# ====================
echo -e "${GREEN}[10] Rapid Fire Requests (DoS simulation)${NC}"

echo -e "${YELLOW}  → Sending 20 rapid requests...${NC}"
for i in {1..20}; do
    curl -s -m 2 http://example.com > /dev/null 2>&1 &
done
wait

# ====================
# File Download Patterns
# ====================
echo -e "${GREEN}[11] File Download Patterns${NC}"

EXTENSIONS=("exe" "zip" "pdf" "jpg")

for ext in "${EXTENSIONS[@]}"; do
    echo -e "${YELLOW}  → Requesting .$ext file...${NC}"
    curl -s -m 5 "http://testmynids.org/test.$ext" > /dev/null 2>&1 || true
done

# ====================
# Custom Payloads
# ====================
echo -e "${GREEN}[12] Custom HTTP Payloads${NC}"

# POST request
echo -e "${YELLOW}  → POST request with data...${NC}"
curl -s -m 5 -X POST -d "username=admin&password=password" http://testmynids.org/login > /dev/null 2>&1 || true

# Custom headers
echo -e "${YELLOW}  → Request with suspicious headers...${NC}"
curl -s -m 5 -H "X-Forwarded-For: 127.0.0.1" -H "X-Scanner: Nmap" http://testmynids.org > /dev/null 2>&1 || true

# ====================
# Wait for Processing
# ====================
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Traffic Generation Complete${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${YELLOW}Waiting 10 seconds for Suricata to process events...${NC}"
sleep 10

echo -e "${GREEN}✓ Done! Check /var/log/suricata/eve.json for results${NC}"
echo ""
echo -e "${YELLOW}Quick Stats:${NC}"

if [ -f /var/log/suricata/eve.json ]; then
    ALERTS=$(grep -c '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null || echo 0)
    HTTP=$(grep -c '"event_type":"http"' /var/log/suricata/eve.json 2>/dev/null || echo 0)
    DNS=$(grep -c '"event_type":"dns"' /var/log/suricata/eve.json 2>/dev/null || echo 0)
    TLS=$(grep -c '"event_type":"tls"' /var/log/suricata/eve.json 2>/dev/null || echo 0)

    echo -e "${GREEN}  → Alerts:  $ALERTS${NC}"
    echo -e "${GREEN}  → HTTP:    $HTTP${NC}"
    echo -e "${GREEN}  → DNS:     $DNS${NC}"
    echo -e "${GREEN}  → TLS:     $TLS${NC}"
    echo ""

    echo -e "${YELLOW}View alerts:${NC}"
    echo -e "${BLUE}  tail -f /var/log/suricata/eve.json | jq 'select(.event_type==\"alert\")'${NC}"
else
    echo -e "${RED}  ✗ eve.json not found at /var/log/suricata/eve.json${NC}"
fi

echo ""
