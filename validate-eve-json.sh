#!/bin/bash

# EVE.json Validator and Analyzer
# Validates Suricata's EVE JSON format for Wazuh compatibility

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

EVE_FILE="${1:-/var/log/suricata/eve.json}"

if [ ! -f "$EVE_FILE" ]; then
    echo -e "${RED}[ERROR] File not found: $EVE_FILE${NC}"
    echo "Usage: $0 [path/to/eve.json]"
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  EVE.json Validator & Analyzer${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${CYAN}File: $EVE_FILE${NC}"
echo ""

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo -e "${RED}[ERROR] jq is required but not installed${NC}"
    echo "Install: sudo apt-get install jq"
    exit 1
fi

# ====================
# File Health Check
# ====================
echo -e "${GREEN}[1] File Health Check${NC}"

FILE_SIZE=$(stat -f%z "$EVE_FILE" 2>/dev/null || stat -c%s "$EVE_FILE" 2>/dev/null)
FILE_SIZE_MB=$(echo "scale=2; $FILE_SIZE / 1024 / 1024" | bc)
LINE_COUNT=$(wc -l < "$EVE_FILE")

echo -e "${CYAN}  → File Size: ${FILE_SIZE_MB} MB ($FILE_SIZE bytes)${NC}"
echo -e "${CYAN}  → Line Count: $LINE_COUNT${NC}"

if [ "$FILE_SIZE" -gt 0 ]; then
    echo -e "${GREEN}  ✓ File is not empty${NC}"
else
    echo -e "${RED}  ✗ File is empty${NC}"
    exit 1
fi

# Check if file is actively being written
MTIME=$(stat -f%m "$EVE_FILE" 2>/dev/null || stat -c%Y "$EVE_FILE" 2>/dev/null)
CURRENT_TIME=$(date +%s)
TIME_DIFF=$((CURRENT_TIME - MTIME))

if [ "$TIME_DIFF" -lt 300 ]; then
    echo -e "${GREEN}  ✓ File was modified recently (${TIME_DIFF}s ago)${NC}"
else
    echo -e "${YELLOW}  ⚠ File last modified ${TIME_DIFF}s ago${NC}"
fi

# ====================
# JSON Syntax Validation
# ====================
echo ""
echo -e "${GREEN}[2] JSON Syntax Validation${NC}"

INVALID_LINES=0
VALID_LINES=0

echo -e "${YELLOW}  Validating JSON syntax for all lines...${NC}"

while IFS= read -r line; do
    if echo "$line" | jq . > /dev/null 2>&1; then
        VALID_LINES=$((VALID_LINES + 1))
    else
        INVALID_LINES=$((INVALID_LINES + 1))
        if [ "$INVALID_LINES" -le 5 ]; then
            echo -e "${RED}  ✗ Invalid JSON at line: $line${NC}"
        fi
    fi
done < "$EVE_FILE"

echo -e "${CYAN}  → Valid Lines: $VALID_LINES${NC}"
echo -e "${CYAN}  → Invalid Lines: $INVALID_LINES${NC}"

if [ "$INVALID_LINES" -eq 0 ]; then
    echo -e "${GREEN}  ✓ All lines contain valid JSON${NC}"
else
    echo -e "${RED}  ✗ Found $INVALID_LINES invalid JSON lines${NC}"
fi

# ====================
# Event Type Distribution
# ====================
echo ""
echo -e "${GREEN}[3] Event Type Distribution${NC}"

echo -e "${YELLOW}  Analyzing event types...${NC}"

declare -A EVENT_COUNTS
while IFS= read -r line; do
    EVENT_TYPE=$(echo "$line" | jq -r '.event_type // "unknown"' 2>/dev/null)
    ((EVENT_COUNTS[$EVENT_TYPE]++)) || EVENT_COUNTS[$EVENT_TYPE]=1
done < "$EVE_FILE"

echo -e "${CYAN}  Event Type Breakdown:${NC}"
for event_type in "${!EVENT_COUNTS[@]}"; do
    count=${EVENT_COUNTS[$event_type]}
    printf "${CYAN}    %-15s : %d${NC}\n" "$event_type" "$count"
done

# ====================
# Required Field Validation
# ====================
echo ""
echo -e "${GREEN}[4] Required Field Validation${NC}"

# Test alerts
ALERT_COUNT=$(grep -c '"event_type":"alert"' "$EVE_FILE" 2>/dev/null || echo 0)
echo -e "${CYAN}  Validating Alert Events ($ALERT_COUNT found)${NC}"

if [ "$ALERT_COUNT" -gt 0 ]; then
    ALERT_SAMPLE=$(grep '"event_type":"alert"' "$EVE_FILE" | head -1)

    REQUIRED_FIELDS=("timestamp" "event_type" "src_ip" "dest_ip" "proto" "alert")
    MISSING_FIELDS=()

    for field in "${REQUIRED_FIELDS[@]}"; do
        if echo "$ALERT_SAMPLE" | jq -e ".$field" > /dev/null 2>&1; then
            echo -e "${GREEN}    ✓ $field${NC}"
        else
            echo -e "${RED}    ✗ $field (MISSING)${NC}"
            MISSING_FIELDS+=("$field")
        fi
    done

    # Check nested alert fields
    if echo "$ALERT_SAMPLE" | jq -e '.alert.signature' > /dev/null 2>&1; then
        echo -e "${GREEN}    ✓ alert.signature${NC}"
    else
        echo -e "${RED}    ✗ alert.signature (MISSING)${NC}"
        MISSING_FIELDS+=("alert.signature")
    fi

    if echo "$ALERT_SAMPLE" | jq -e '.alert.category' > /dev/null 2>&1; then
        echo -e "${GREEN}    ✓ alert.category${NC}"
    else
        echo -e "${RED}    ✗ alert.category (MISSING)${NC}"
        MISSING_FIELDS+=("alert.category")
    fi

    if [ ${#MISSING_FIELDS[@]} -eq 0 ]; then
        echo -e "${GREEN}  ✓ All required fields present in alerts${NC}"
    else
        echo -e "${RED}  ✗ Missing fields: ${MISSING_FIELDS[*]}${NC}"
    fi
else
    echo -e "${YELLOW}  ⚠ No alert events found to validate${NC}"
fi

# ====================
# Timestamp Validation
# ====================
echo ""
echo -e "${GREEN}[5] Timestamp Validation${NC}"

FIRST_TS=$(head -1 "$EVE_FILE" | jq -r '.timestamp // "null"')
LAST_TS=$(tail -1 "$EVE_FILE" | jq -r '.timestamp // "null"')

echo -e "${CYAN}  → First Event: $FIRST_TS${NC}"
echo -e "${CYAN}  → Last Event:  $LAST_TS${NC}"

if [[ "$FIRST_TS" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2} ]]; then
    echo -e "${GREEN}  ✓ Timestamps are in valid ISO 8601 format${NC}"
else
    echo -e "${RED}  ✗ Timestamps are not in valid format${NC}"
fi

# ====================
# Alert Signature Analysis
# ====================
echo ""
echo -e "${GREEN}[6] Alert Signature Analysis${NC}"

if [ "$ALERT_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}  Top 10 Alert Signatures:${NC}"
    grep '"event_type":"alert"' "$EVE_FILE" | jq -r '.alert.signature' | sort | uniq -c | sort -rn | head -10 | while read count sig; do
        printf "${CYAN}    %5d × %s${NC}\n" "$count" "$sig"
    done

    echo ""
    echo -e "${YELLOW}  Alert Categories:${NC}"
    grep '"event_type":"alert"' "$EVE_FILE" | jq -r '.alert.category' | sort | uniq -c | sort -rn | while read count cat; do
        printf "${CYAN}    %5d × %s${NC}\n" "$count" "$cat"
    done
else
    echo -e "${YELLOW}  ⚠ No alerts found${NC}"
fi

# ====================
# Protocol Distribution
# ====================
echo ""
echo -e "${GREEN}[7] Protocol Distribution${NC}"

echo -e "${YELLOW}  Protocol Breakdown:${NC}"
jq -r '.proto // "unknown"' "$EVE_FILE" | sort | uniq -c | sort -rn | head -10 | while read count proto; do
    printf "${CYAN}    %5d × %s${NC}\n" "$count" "$proto"
done

# ====================
# IP Address Analysis
# ====================
echo ""
echo -e "${GREEN}[8] IP Address Analysis${NC}"

echo -e "${YELLOW}  Top 5 Source IPs:${NC}"
jq -r '.src_ip // empty' "$EVE_FILE" | sort | uniq -c | sort -rn | head -5 | while read count ip; do
    printf "${CYAN}    %5d × %s${NC}\n" "$count" "$ip"
done

echo ""
echo -e "${YELLOW}  Top 5 Destination IPs:${NC}"
jq -r '.dest_ip // empty' "$EVE_FILE" | sort | uniq -c | sort -rn | head -5 | while read count ip; do
    printf "${CYAN}    %5d × %s${NC}\n" "$count" "$ip"
done

# ====================
# HTTP Analysis
# ====================
echo ""
echo -e "${GREEN}[9] HTTP Traffic Analysis${NC}"

HTTP_COUNT=$(grep -c '"event_type":"http"' "$EVE_FILE" 2>/dev/null || echo 0)
echo -e "${CYAN}  → HTTP Events: $HTTP_COUNT${NC}"

if [ "$HTTP_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}  Top HTTP Hostnames:${NC}"
    grep '"event_type":"http"' "$EVE_FILE" | jq -r '.http.hostname // empty' | sort | uniq -c | sort -rn | head -5 | while read count host; do
        printf "${CYAN}    %5d × %s${NC}\n" "$count" "$host"
    done

    echo ""
    echo -e "${YELLOW}  HTTP Methods:${NC}"
    grep '"event_type":"http"' "$EVE_FILE" | jq -r '.http.http_method // empty' | sort | uniq -c | sort -rn | while read count method; do
        printf "${CYAN}    %5d × %s${NC}\n" "$count" "$method"
    done
fi

# ====================
# DNS Analysis
# ====================
echo ""
echo -e "${GREEN}[10] DNS Traffic Analysis${NC}"

DNS_COUNT=$(grep -c '"event_type":"dns"' "$EVE_FILE" 2>/dev/null || echo 0)
echo -e "${CYAN}  → DNS Events: $DNS_COUNT${NC}"

if [ "$DNS_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}  Top DNS Queries:${NC}"
    grep '"event_type":"dns"' "$EVE_FILE" | jq -r '.dns.rrname // empty' | sort | uniq -c | sort -rn | head -10 | while read count domain; do
        printf "${CYAN}    %5d × %s${NC}\n" "$count" "$domain"
    done
fi

# ====================
# TLS Analysis
# ====================
echo ""
echo -e "${GREEN}[11] TLS/SSL Traffic Analysis${NC}"

TLS_COUNT=$(grep -c '"event_type":"tls"' "$EVE_FILE" 2>/dev/null || echo 0)
echo -e "${CYAN}  → TLS Events: $TLS_COUNT${NC}"

if [ "$TLS_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}  TLS Server Names (SNI):${NC}"
    grep '"event_type":"tls"' "$EVE_FILE" | jq -r '.tls.sni // empty' | sort | uniq -c | sort -rn | head -5 | while read count sni; do
        printf "${CYAN}    %5d × %s${NC}\n" "$count" "$sni"
    done
fi

# ====================
# Wazuh Compatibility Check
# ====================
echo ""
echo -e "${GREEN}[12] Wazuh Compatibility Check${NC}"

COMPAT_SCORE=0
MAX_SCORE=8

# Check 1: JSON format
if [ "$INVALID_LINES" -eq 0 ]; then
    echo -e "${GREEN}  ✓ Valid JSON format${NC}"
    COMPAT_SCORE=$((COMPAT_SCORE + 1))
else
    echo -e "${RED}  ✗ Invalid JSON lines found${NC}"
fi

# Check 2: Event types present
if [ "${#EVENT_COUNTS[@]}" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Event types present${NC}"
    COMPAT_SCORE=$((COMPAT_SCORE + 1))
else
    echo -e "${RED}  ✗ No event types found${NC}"
fi

# Check 3: Alerts exist
if [ "$ALERT_COUNT" -gt 0 ]; then
    echo -e "${GREEN}  ✓ Alerts present${NC}"
    COMPAT_SCORE=$((COMPAT_SCORE + 1))
else
    echo -e "${YELLOW}  ⚠ No alerts found (may be normal)${NC}"
fi

# Check 4: Timestamps valid
if [[ "$FIRST_TS" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]; then
    echo -e "${GREEN}  ✓ Valid timestamps${NC}"
    COMPAT_SCORE=$((COMPAT_SCORE + 1))
else
    echo -e "${RED}  ✗ Invalid timestamps${NC}"
fi

# Check 5: File permissions
if [ -r "$EVE_FILE" ]; then
    echo -e "${GREEN}  ✓ File is readable${NC}"
    COMPAT_SCORE=$((COMPAT_SCORE + 1))
else
    echo -e "${RED}  ✗ File is not readable${NC}"
fi

# Check 6: Recent activity
if [ "$TIME_DIFF" -lt 600 ]; then
    echo -e "${GREEN}  ✓ Recent activity (file updated)${NC}"
    COMPAT_SCORE=$((COMPAT_SCORE + 1))
else
    echo -e "${YELLOW}  ⚠ No recent activity${NC}"
fi

# Check 7: Multiple event types
if [ "${#EVENT_COUNTS[@]}" -ge 3 ]; then
    echo -e "${GREEN}  ✓ Diverse event types${NC}"
    COMPAT_SCORE=$((COMPAT_SCORE + 1))
else
    echo -e "${YELLOW}  ⚠ Limited event diversity${NC}"
fi

# Check 8: Standard location
if [ "$EVE_FILE" = "/var/log/suricata/eve.json" ]; then
    echo -e "${GREEN}  ✓ Standard file location${NC}"
    COMPAT_SCORE=$((COMPAT_SCORE + 1))
else
    echo -e "${YELLOW}  ⚠ Non-standard file location${NC}"
fi

COMPAT_PERCENT=$((COMPAT_SCORE * 100 / MAX_SCORE))

echo ""
echo -e "${BLUE}  Wazuh Compatibility Score: $COMPAT_SCORE/$MAX_SCORE (${COMPAT_PERCENT}%)${NC}"

if [ "$COMPAT_PERCENT" -ge 80 ]; then
    echo -e "${GREEN}  ✓ EXCELLENT - Ready for Wazuh integration${NC}"
elif [ "$COMPAT_PERCENT" -ge 60 ]; then
    echo -e "${YELLOW}  ⚠ GOOD - Minor issues, should work${NC}"
else
    echo -e "${RED}  ✗ POOR - Requires attention${NC}"
fi

# ====================
# Summary Statistics
# ====================
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Summary Statistics${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${CYAN}  File Size:        ${FILE_SIZE_MB} MB${NC}"
echo -e "${CYAN}  Total Events:     $LINE_COUNT${NC}"
echo -e "${CYAN}  Alert Events:     $ALERT_COUNT${NC}"
echo -e "${CYAN}  HTTP Events:      $HTTP_COUNT${NC}"
echo -e "${CYAN}  DNS Events:       $DNS_COUNT${NC}"
echo -e "${CYAN}  TLS Events:       $TLS_COUNT${NC}"
echo -e "${CYAN}  Event Types:      ${#EVENT_COUNTS[@]}${NC}"
echo -e "${CYAN}  JSON Validity:    ${VALID_LINES}/${LINE_COUNT} valid${NC}"
echo -e "${CYAN}  Compatibility:    ${COMPAT_PERCENT}%${NC}"
echo ""

# Generate report file
REPORT_FILE="/tmp/eve-validation-report-$(date +%Y%m%d_%H%M%S).txt"
cat > "$REPORT_FILE" << EOF
EVE.JSON VALIDATION REPORT
Generated: $(date)
File: $EVE_FILE

SUMMARY:
  File Size: ${FILE_SIZE_MB} MB
  Total Events: $LINE_COUNT
  Alert Events: $ALERT_COUNT
  HTTP Events: $HTTP_COUNT
  DNS Events: $DNS_COUNT
  TLS Events: $TLS_COUNT
  Event Types: ${#EVENT_COUNTS[@]}
  JSON Validity: ${VALID_LINES}/${LINE_COUNT}
  Wazuh Compatibility: ${COMPAT_PERCENT}%

TIMESTAMPS:
  First: $FIRST_TS
  Last: $LAST_TS
  Last Modified: ${TIME_DIFF}s ago

STATUS: $([ "$COMPAT_PERCENT" -ge 80 ] && echo "EXCELLENT" || ([ "$COMPAT_PERCENT" -ge 60 ] && echo "GOOD" || echo "NEEDS ATTENTION"))
EOF

echo -e "${GREEN}Detailed report saved to: $REPORT_FILE${NC}"
echo ""

exit 0
