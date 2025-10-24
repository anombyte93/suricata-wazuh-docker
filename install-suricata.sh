#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

clear

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                            ║${NC}"
echo -e "${BLUE}║  ${BOLD}${GREEN}Suricata + Wazuh Integration - Student Edition${NC}${BLUE}      ║${NC}"
echo -e "${BLUE}║                                                            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}${BOLD}What this script does:${NC}"
echo -e "${CYAN}  1. Installs Docker (if not already installed)${NC}"
echo -e "${CYAN}  2. Builds a Suricata IDS container${NC}"
echo -e "${CYAN}  3. Configures it to monitor your network${NC}"
echo -e "${CYAN}  4. Integrates with your Wazuh agent${NC}"
echo -e "${CYAN}  5. Starts monitoring network traffic${NC}"
echo ""
echo -e "${YELLOW}${BOLD}Prerequisites:${NC}"
echo -e "${YELLOW}  ✓ Kali Linux (or Debian-based system)${NC}"
echo -e "${YELLOW}  ✓ Wazuh agent already installed${NC}"
echo -e "${YELLOW}  ✓ Internet connection${NC}"
echo -e "${YELLOW}  ✓ Running as root/sudo${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}${BOLD}[ERROR] Please run as root or with sudo${NC}"
    echo -e "${YELLOW}Try: sudo ./install-suricata.sh${NC}"
    exit 1
fi

echo -e "${GREEN}${BOLD}Ready to proceed?${NC}"
echo -e "${YELLOW}This will take 5-10 minutes depending on your internet speed.${NC}"
echo ""
read -p "Press ENTER to continue or Ctrl+C to cancel... "
echo ""

# Function to check if Docker is installed
check_docker() {
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}[✓] Docker is already installed${NC}"
        return 0
    else
        return 1
    fi
}

# Function to install Docker
install_docker() {
    echo -e "${YELLOW}[!] Docker not found. Installing Docker...${NC}"

    # Update package index
    apt-get update -qq

    # Install prerequisites
    apt-get install -y -qq \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

    # Add Docker's official GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Set up the repository
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker Engine
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    # Start Docker service
    systemctl start docker
    systemctl enable docker

    echo -e "${GREEN}[✓] Docker installed successfully${NC}"
}

# Check and install Docker if needed
if ! check_docker; then
    install_docker
fi

# Prompt for Wazuh manager IP/hostname
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  ${BOLD}${GREEN}Step 1: Configure Wazuh Manager${NC}${BLUE}                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Enter your Wazuh Manager IP address or hostname.${NC}"
echo -e "${CYAN}This is the server where your Wazuh dashboard is running.${NC}"
echo ""
echo -e "${YELLOW}Examples:${NC}"
echo -e "${YELLOW}  • 192.168.1.100${NC}"
echo -e "${YELLOW}  • wazuh-manager.local${NC}"
echo -e "${YELLOW}  • 10.0.0.50${NC}"
echo ""
read -p "Wazuh Manager IP/Hostname: " WAZUH_MANAGER

if [ -z "$WAZUH_MANAGER" ]; then
    echo -e "${RED}${BOLD}[ERROR] Wazuh Manager IP/hostname cannot be empty${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}[✓] Using Wazuh Manager: ${BOLD}$WAZUH_MANAGER${NC}"
echo ""
echo -e "${YELLOW}Proceeding with installation...${NC}"
sleep 2

# Create temporary directory for Docker build
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download Dockerfile
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  ${BOLD}${GREEN}Step 2: Building Suricata Container${NC}${BLUE}                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Building Docker image with:${NC}"
echo -e "${YELLOW}  • Suricata IDS/IPS${NC}"
echo -e "${YELLOW}  • Emerging Threats ruleset (50+ rule files)${NC}"
echo -e "${YELLOW}  • Auto-configuration scripts${NC}"
echo ""
echo -e "${CYAN}This may take 2-5 minutes...${NC}"
echo ""

cat > Dockerfile << 'DOCKERFILE_END'
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install Suricata and dependencies
RUN apt-get update && \
    apt-get install -y \
    software-properties-common \
    curl \
    wget \
    gnupg \
    lsb-release \
    iproute2 \
    net-tools \
    jq \
    ca-certificates \
    suricata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /var/log/suricata /etc/suricata/rules /var/run/suricata

# Download Emerging Threats rules
RUN cd /tmp && \
    curl -LO https://rules.emergingthreats.net/open/suricata-7.0.0/emerging.rules.tar.gz && \
    tar -xzf emerging.rules.tar.gz && \
    mv rules/*.rules /etc/suricata/rules/ 2>/dev/null || true && \
    rm -rf /tmp/emerging.rules.tar.gz /tmp/rules

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose Suricata log directory as volume
VOLUME ["/var/log/suricata"]

ENTRYPOINT ["/entrypoint.sh"]
DOCKERFILE_END

cat > entrypoint.sh << 'ENTRYPOINT_END'
#!/bin/bash
set -e

# Get the primary network interface if not specified
if [ -z "$NETWORK_INTERFACE" ]; then
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    echo "[INFO] Auto-detected network interface: $NETWORK_INTERFACE"
fi

# Create minimal Suricata config focused on eve.json output
cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "any"
    EXTERNAL_NET: "any"

af-packet:
  - interface: $NETWORK_INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: no
        - drop:
            alerts: yes
        - smtp:
        - flow:
        - stats:
            totals: yes
            threads: no

default-rule-path: /etc/suricata/rules
rule-files:
  - "*.rules"

logging:
  default-log-level: notice
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      level: info
      filename: /var/log/suricata/suricata.log
EOF

echo "[INFO] Starting Suricata on interface: $NETWORK_INTERFACE"
echo "[INFO] Logs will be written to /var/log/suricata/eve.json"
echo "[INFO] Wazuh agent should be configured to read this file"

# Start Suricata
exec suricata -c /etc/suricata/suricata.yaml -i "$NETWORK_INTERFACE" --pidfile /var/run/suricata.pid
ENTRYPOINT_END

chmod +x entrypoint.sh

# Build Docker image
echo -e "${YELLOW}[INFO] Building Suricata Docker image (this may take a few minutes)...${NC}"
docker build -t suricata-wazuh:latest . -q

# Stop and remove existing container if it exists
if docker ps -a | grep -q suricata-wazuh; then
    echo -e "${YELLOW}[INFO] Removing existing Suricata container...${NC}"
    docker stop suricata-wazuh >/dev/null 2>&1 || true
    docker rm suricata-wazuh >/dev/null 2>&1 || true
fi

# Run the container
echo -e "${YELLOW}[INFO] Starting Suricata container...${NC}"
docker run -d \
    --name suricata-wazuh \
    --network host \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --cap-add=SYS_NICE \
    -v /var/log/suricata:/var/log/suricata \
    --restart unless-stopped \
    suricata-wazuh:latest

# Wait for container to start
sleep 3

# Check if container is running
if docker ps | grep -q suricata-wazuh; then
    echo -e "${GREEN}[✓] Suricata container started successfully!${NC}"
else
    echo -e "${RED}[ERROR] Suricata container failed to start${NC}"
    docker logs suricata-wazuh
    exit 1
fi

# Configure Wazuh agent to read Suricata logs
echo ""
echo -e "${YELLOW}[INFO] Configuring Wazuh agent to read Suricata logs...${NC}"

OSSEC_CONF="/var/ossec/etc/ossec.conf"

if [ -f "$OSSEC_CONF" ]; then
    # Check if Suricata log is already configured
    if grep -q "/var/log/suricata/eve.json" "$OSSEC_CONF"; then
        echo -e "${GREEN}[✓] Suricata log already configured in Wazuh agent${NC}"
    else
        # Backup original config
        cp "$OSSEC_CONF" "${OSSEC_CONF}.backup.$(date +%Y%m%d_%H%M%S)"

        # Add Suricata log configuration before closing </ossec_config>
        sed -i '/<\/ossec_config>/i \
  <localfile>\
    <log_format>json</log_format>\
    <location>/var/log/suricata/eve.json</location>\
  </localfile>\
' "$OSSEC_CONF"

        echo -e "${GREEN}[✓] Added Suricata log configuration to Wazuh agent${NC}"

        # Restart Wazuh agent
        echo -e "${YELLOW}[INFO] Restarting Wazuh agent...${NC}"
        systemctl restart wazuh-agent || service wazuh-agent restart
        echo -e "${GREEN}[✓] Wazuh agent restarted${NC}"
    fi
else
    echo -e "${YELLOW}[WARNING] Wazuh agent config not found at $OSSEC_CONF${NC}"
    echo -e "${YELLOW}[INFO] Please manually add this to your Wazuh agent configuration:${NC}"
    echo ""
    echo "  <localfile>"
    echo "    <log_format>json</log_format>"
    echo "    <location>/var/log/suricata/eve.json</location>"
    echo "  </localfile>"
    echo ""
fi

# Cleanup
cd /
rm -rf "$TEMP_DIR"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${GREEN}Suricata is now running and integrated with your Wazuh agent!${NC}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo -e "  • View Suricata logs:        ${GREEN}docker logs -f suricata-wazuh${NC}"
echo -e "  • View eve.json:             ${GREEN}tail -f /var/log/suricata/eve.json${NC}"
echo -e "  • Stop Suricata:             ${GREEN}docker stop suricata-wazuh${NC}"
echo -e "  • Start Suricata:            ${GREEN}docker start suricata-wazuh${NC}"
echo -e "  • Restart Suricata:          ${GREEN}docker restart suricata-wazuh${NC}"
echo -e "  • Check Wazuh agent status:  ${GREEN}systemctl status wazuh-agent${NC}"
echo ""
echo -e "${YELLOW}View alerts in your Wazuh Dashboard at: http://$WAZUH_MANAGER${NC}"
echo -e "${YELLOW}Filter by: rule.groups:suricata${NC}"
echo ""

