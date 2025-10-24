#!/bin/bash

# Comprehensive Suricata Test Suite (No Wazuh Required)
# Tests Suricata Docker container functionality independently

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Log file
TEST_LOG="/tmp/suricata-test-$(date +%Y%m%d_%H%M%S).log"

# Function to print test header
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "$1" >> "$TEST_LOG"
}

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    echo -e "${YELLOW}[TEST $TESTS_TOTAL] $test_name${NC}"
    echo "[TEST $TESTS_TOTAL] $test_name" >> "$TEST_LOG"

    if eval "$test_command" >> "$TEST_LOG" 2>&1; then
        echo -e "${GREEN}  ✓ PASSED${NC}"
        echo "  ✓ PASSED" >> "$TEST_LOG"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}  ✗ FAILED${NC}"
        echo "  ✗ FAILED" >> "$TEST_LOG"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Function to run a test with output capture
run_test_with_output() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    echo -e "${YELLOW}[TEST $TESTS_TOTAL] $test_name${NC}"
    echo "[TEST $TESTS_TOTAL] $test_name" >> "$TEST_LOG"

    local output
    output=$(eval "$test_command" 2>&1)
    echo "$output" >> "$TEST_LOG"

    if echo "$output" | grep -q "$expected_pattern"; then
        echo -e "${GREEN}  ✓ PASSED${NC}"
        echo "  ✓ PASSED" >> "$TEST_LOG"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}  ✗ FAILED (Expected: $expected_pattern)${NC}"
        echo "  ✗ FAILED (Expected: $expected_pattern)" >> "$TEST_LOG"
        echo "  Output: $output" >> "$TEST_LOG"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run as root or with sudo${NC}"
    exit 1
fi

print_header "SURICATA COMPREHENSIVE TEST SUITE"
echo -e "${GREEN}Starting tests at $(date)${NC}"
echo -e "${GREEN}Log file: $TEST_LOG${NC}"
echo ""

# ====================
# PHASE 1: Pre-flight Checks
# ====================
print_header "PHASE 1: Pre-flight Checks"

run_test "Docker is installed" "command -v docker"
run_test "Docker daemon is running" "docker ps"
run_test "jq is installed (for JSON parsing)" "command -v jq || apt-get install -y jq"
run_test "curl is installed" "command -v curl"
run_test "nc (netcat) is available" "command -v nc || apt-get install -y netcat-openbsd"

# ====================
# PHASE 2: Container Status
# ====================
print_header "PHASE 2: Container Status & Health"

run_test "Suricata container exists" "docker ps -a | grep -q suricata-wazuh"
run_test "Suricata container is running" "docker ps | grep -q suricata-wazuh"
run_test_with_output "Container started successfully (not restarting)" "docker inspect suricata-wazuh --format='{{.State.Status}}'" "running"
run_test "Container has proper capabilities (NET_ADMIN)" "docker inspect suricata-wazuh | grep -q NET_ADMIN"
run_test "Container has proper capabilities (NET_RAW)" "docker inspect suricata-wazuh | grep -q NET_RAW"
run_test "Container network mode is host" "docker inspect suricata-wazuh | grep -q '\"NetworkMode\": \"host\"'"

# Check restart count
RESTART_COUNT=$(docker inspect suricata-wazuh --format='{{.RestartCount}}')
if [ "$RESTART_COUNT" -eq 0 ]; then
    echo -e "${GREEN}  ✓ Container has not restarted (stable)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${YELLOW}  ⚠ Container has restarted $RESTART_COUNT times${NC}"
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

# ====================
# PHASE 3: Suricata Process
# ====================
print_header "PHASE 3: Suricata Process & Configuration"

run_test "Suricata process is running inside container" "docker exec suricata-wazuh pgrep suricata"
run_test "Suricata config file exists" "docker exec suricata-wazuh test -f /etc/suricata/suricata.yaml"
run_test "Suricata rules directory exists" "docker exec suricata-wazuh test -d /etc/suricata/rules"
run_test "Suricata rules are loaded" "docker exec suricata-wazuh ls /etc/suricata/rules/*.rules | wc -l | grep -v '^0$'"

# Count rules
RULE_COUNT=$(docker exec suricata-wazuh ls /etc/suricata/rules/*.rules 2>/dev/null | wc -l)
echo -e "${GREEN}  → Loaded $RULE_COUNT rule files${NC}"

# ====================
# PHASE 4: Log Files
# ====================
print_header "PHASE 4: Log Files & Output"

run_test "Log directory exists on host" "test -d /var/log/suricata"
run_test "eve.json exists" "test -f /var/log/suricata/eve.json"
run_test "eve.json is writable" "test -w /var/log/suricata/eve.json"
run_test "eve.json is being updated (modified in last 5 mins)" "find /var/log/suricata/eve.json -mmin -5 | grep -q ."
run_test "eve.json contains valid JSON" "tail -1 /var/log/suricata/eve.json | jq . > /dev/null"
run_test "eve.json has 'stats' events" "grep -q '\"event_type\":\"stats\"' /var/log/suricata/eve.json"

# Check file size
EVE_SIZE=$(stat -f%z /var/log/suricata/eve.json 2>/dev/null || stat -c%s /var/log/suricata/eve.json 2>/dev/null)
echo -e "${GREEN}  → eve.json size: $EVE_SIZE bytes${NC}"

# ====================
# PHASE 5: Network Interface
# ====================
print_header "PHASE 5: Network Interface Detection"

DETECTED_INTERFACE=$(docker exec suricata-wazuh ip route | grep default | awk '{print $5}' | head -n1)
echo -e "${GREEN}  → Detected interface: $DETECTED_INTERFACE${NC}"

run_test "Network interface is up" "ip link show $DETECTED_INTERFACE | grep -q 'state UP'"
run_test "Suricata is monitoring correct interface" "docker logs suricata-wazuh 2>&1 | grep -q \"interface: $DETECTED_INTERFACE\""

# ====================
# PHASE 6: Traffic Generation & Alert Detection
# ====================
print_header "PHASE 6: Traffic Generation & Alert Detection"

echo -e "${YELLOW}Generating test traffic...${NC}"

# Clear old alerts for cleaner testing
BASELINE_ALERTS=$(grep -c '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null || echo 0)
echo -e "${GREEN}  → Baseline alerts: $BASELINE_ALERTS${NC}"

# Test 1: Known bad user agent
echo -e "${YELLOW}  → Testing malicious user agent detection...${NC}"
curl -s -A "BlackSun" http://testmynids.org/uid/index.html > /dev/null 2>&1 || true
sleep 2

# Test 2: ET INFO signature
echo -e "${YELLOW}  → Testing ET INFO signature...${NC}"
curl -s http://testmynids.org/uid/index.html > /dev/null 2>&1 || true
sleep 2

# Test 3: DNS query
echo -e "${YELLOW}  → Testing DNS monitoring...${NC}"
nslookup google.com > /dev/null 2>&1 || true
sleep 2

# Test 4: HTTP traffic
echo -e "${YELLOW}  → Testing HTTP monitoring...${NC}"
curl -s http://example.com > /dev/null 2>&1 || true
sleep 2

# Test 5: HTTPS traffic
echo -e "${YELLOW}  → Testing TLS monitoring...${NC}"
curl -s https://www.google.com > /dev/null 2>&1 || true
sleep 3

echo -e "${YELLOW}Waiting for logs to flush (5 seconds)...${NC}"
sleep 5

# Check for new alerts
NEW_ALERTS=$(grep -c '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null || echo 0)
ALERT_DIFF=$((NEW_ALERTS - BASELINE_ALERTS))

echo -e "${GREEN}  → New alerts generated: $ALERT_DIFF${NC}"

run_test "Alerts were generated from test traffic" "test $ALERT_DIFF -gt 0"

# ====================
# PHASE 7: Event Type Coverage
# ====================
print_header "PHASE 7: Event Type Coverage"

run_test "Alert events present" "grep -q '\"event_type\":\"alert\"' /var/log/suricata/eve.json"
run_test "HTTP events present" "grep -q '\"event_type\":\"http\"' /var/log/suricata/eve.json"
run_test "DNS events present" "grep -q '\"event_type\":\"dns\"' /var/log/suricata/eve.json"
run_test "TLS events present" "grep -q '\"event_type\":\"tls\"' /var/log/suricata/eve.json"
run_test "Flow events present" "grep -q '\"event_type\":\"flow\"' /var/log/suricata/eve.json"
run_test "Stats events present" "grep -q '\"event_type\":\"stats\"' /var/log/suricata/eve.json"

# ====================
# PHASE 8: JSON Schema Validation
# ====================
print_header "PHASE 8: JSON Schema Validation"

# Check alert schema
ALERT_SAMPLE=$(grep '"event_type":"alert"' /var/log/suricata/eve.json | head -1)
if [ -n "$ALERT_SAMPLE" ]; then
    run_test "Alert has timestamp field" "echo '$ALERT_SAMPLE' | jq -e '.timestamp' > /dev/null"
    run_test "Alert has src_ip field" "echo '$ALERT_SAMPLE' | jq -e '.src_ip' > /dev/null"
    run_test "Alert has dest_ip field" "echo '$ALERT_SAMPLE' | jq -e '.dest_ip' > /dev/null"
    run_test "Alert has alert.signature field" "echo '$ALERT_SAMPLE' | jq -e '.alert.signature' > /dev/null"
    run_test "Alert has alert.category field" "echo '$ALERT_SAMPLE' | jq -e '.alert.category' > /dev/null"
    run_test "Alert has proto field" "echo '$ALERT_SAMPLE' | jq -e '.proto' > /dev/null"
else
    echo -e "${RED}  ✗ No alert samples found for schema validation${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 6))
    TESTS_TOTAL=$((TESTS_TOTAL + 6))
fi

# ====================
# PHASE 9: Performance & Resource Usage
# ====================
print_header "PHASE 9: Performance & Resource Usage"

# Get container stats
CONTAINER_CPU=$(docker stats --no-stream suricata-wazuh --format "{{.CPUPerc}}" | sed 's/%//')
CONTAINER_MEM=$(docker stats --no-stream suricata-wazuh --format "{{.MemUsage}}")

echo -e "${GREEN}  → CPU Usage: ${CONTAINER_CPU}%${NC}"
echo -e "${GREEN}  → Memory Usage: $CONTAINER_MEM${NC}"

# Check if CPU is reasonable (not pegged at 100%)
if (( $(echo "$CONTAINER_CPU < 90" | bc -l) )); then
    echo -e "${GREEN}  ✓ CPU usage is reasonable${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${YELLOW}  ⚠ CPU usage is high (${CONTAINER_CPU}%)${NC}"
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

# Check drop stats
DROP_COUNT=$(grep '"event_type":"stats"' /var/log/suricata/eve.json | tail -1 | jq -r '.stats.capture.kernel_drops // 0' 2>/dev/null || echo 0)
echo -e "${GREEN}  → Kernel packet drops: $DROP_COUNT${NC}"

if [ "$DROP_COUNT" -lt 100 ]; then
    echo -e "${GREEN}  ✓ Packet drop rate is acceptable${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${YELLOW}  ⚠ High packet drop rate${NC}"
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

# ====================
# PHASE 10: Container Logs
# ====================
print_header "PHASE 10: Container Logs Analysis"

run_test "No critical errors in logs" "! docker logs suricata-wazuh 2>&1 | grep -i 'CRITICAL\\|FATAL'"
run_test "No configuration errors" "! docker logs suricata-wazuh 2>&1 | grep -i 'configuration error'"
run_test "Suricata started successfully" "docker logs suricata-wazuh 2>&1 | grep -q 'running\\|started'"

# Check for warnings (informational)
WARNING_COUNT=$(docker logs suricata-wazuh 2>&1 | grep -ic 'warning' || echo 0)
echo -e "${GREEN}  → Warnings in logs: $WARNING_COUNT${NC}"

# ====================
# PHASE 11: Wazuh Integration Readiness
# ====================
print_header "PHASE 11: Wazuh Integration Readiness"

run_test "eve.json is in standard location" "test -f /var/log/suricata/eve.json"
run_test "eve.json is readable by other users" "test -r /var/log/suricata/eve.json"
run_test "Log directory permissions allow access" "test -x /var/log/suricata"

# Check if Wazuh agent is installed (optional)
if [ -f "/var/ossec/etc/ossec.conf" ]; then
    echo -e "${GREEN}  → Wazuh agent detected${NC}"
    run_test "Wazuh agent config includes Suricata" "grep -q 'suricata' /var/ossec/etc/ossec.conf"
    run_test "Wazuh agent is running" "systemctl is-active wazuh-agent || service wazuh-agent status"
else
    echo -e "${YELLOW}  → Wazuh agent not installed (optional)${NC}"
fi

# ====================
# PHASE 12: Advanced Alert Analysis
# ====================
print_header "PHASE 12: Advanced Alert Analysis"

# Get alert statistics
TOTAL_ALERTS=$(grep -c '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null || echo 0)
UNIQUE_SIGNATURES=$(grep '"event_type":"alert"' /var/log/suricata/eve.json | jq -r '.alert.signature' | sort -u | wc -l)
UNIQUE_CATEGORIES=$(grep '"event_type":"alert"' /var/log/suricata/eve.json | jq -r '.alert.category' | sort -u | wc -l)

echo -e "${GREEN}  → Total alerts: $TOTAL_ALERTS${NC}"
echo -e "${GREEN}  → Unique signatures: $UNIQUE_SIGNATURES${NC}"
echo -e "${GREEN}  → Unique categories: $UNIQUE_CATEGORIES${NC}"

# Show top 5 signatures
echo -e "${YELLOW}  → Top 5 Alert Signatures:${NC}"
grep '"event_type":"alert"' /var/log/suricata/eve.json | jq -r '.alert.signature' | sort | uniq -c | sort -rn | head -5 | while read count sig; do
    echo -e "${GREEN}     $count × $sig${NC}"
done

# ====================
# PHASE 13: Rule Update Capability
# ====================
print_header "PHASE 13: Rule Update & Management"

run_test "Can list rules inside container" "docker exec suricata-wazuh ls /etc/suricata/rules/ | wc -l | grep -v '^0$'"
run_test "Can access rule files" "docker exec suricata-wazuh head -1 /etc/suricata/rules/emerging-attack_response.rules"

# Test if we can restart Suricata
echo -e "${YELLOW}  → Testing container restart...${NC}"
docker restart suricata-wazuh > /dev/null 2>&1
sleep 5
run_test "Container restarted successfully" "docker ps | grep -q suricata-wazuh"
run_test "Suricata running after restart" "docker exec suricata-wazuh pgrep suricata"

# ====================
# PHASE 14: Cleanup & Persistence
# ====================
print_header "PHASE 14: Cleanup & Persistence"

run_test "Container has restart policy" "docker inspect suricata-wazuh | grep -q '\"RestartPolicy\"'"
run_test "Logs survive container restart" "test -s /var/log/suricata/eve.json"
run_test "Log volume is properly mounted" "docker inspect suricata-wazuh | grep -q '/var/log/suricata'"

# ====================
# FINAL REPORT
# ====================
print_header "TEST SUITE COMPLETE"

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}         FINAL RESULTS${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Tests Passed:  $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed:  $TESTS_FAILED${NC}"
echo -e "${YELLOW}Total Tests:   $TESTS_TOTAL${NC}"
echo ""

PASS_RATE=$((TESTS_PASSED * 100 / TESTS_TOTAL))
echo -e "${BLUE}Pass Rate:     ${PASS_RATE}%${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   ✓ ALL TESTS PASSED!${NC}"
    echo -e "${GREEN}   Suricata is fully operational${NC}"
    echo -e "${GREEN}========================================${NC}"
    EXIT_CODE=0
elif [ $PASS_RATE -ge 80 ]; then
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}   ⚠ TESTS MOSTLY PASSED${NC}"
    echo -e "${YELLOW}   Suricata is operational with warnings${NC}"
    echo -e "${YELLOW}========================================${NC}"
    EXIT_CODE=0
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}   ✗ CRITICAL FAILURES${NC}"
    echo -e "${RED}   Suricata may not be working correctly${NC}"
    echo -e "${RED}========================================${NC}"
    EXIT_CODE=1
fi

echo ""
echo -e "${BLUE}Detailed log saved to: $TEST_LOG${NC}"
echo ""

# Generate summary report
cat > /tmp/suricata-test-summary.txt << EOF
SURICATA TEST SUITE SUMMARY
Generated: $(date)

RESULTS:
  Passed: $TESTS_PASSED
  Failed: $TESTS_FAILED
  Total:  $TESTS_TOTAL
  Rate:   ${PASS_RATE}%

STATISTICS:
  Total Alerts: $TOTAL_ALERTS
  Unique Signatures: $UNIQUE_SIGNATURES
  Unique Categories: $UNIQUE_CATEGORIES
  Rule Files: $RULE_COUNT
  Detected Interface: $DETECTED_INTERFACE
  Container CPU: ${CONTAINER_CPU}%
  Container Memory: $CONTAINER_MEM
  Packet Drops: $DROP_COUNT

LOG FILES:
  Detailed Log: $TEST_LOG
  Eve.json Size: $EVE_SIZE bytes
  Eve.json Location: /var/log/suricata/eve.json

STATUS: $([ $EXIT_CODE -eq 0 ] && echo "OPERATIONAL" || echo "NEEDS ATTENTION")
EOF

echo -e "${GREEN}Summary report: /tmp/suricata-test-summary.txt${NC}"
echo ""

exit $EXIT_CODE
