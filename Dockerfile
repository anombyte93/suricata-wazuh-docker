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
    ca-certificates && \
    # Add Suricata repository
    add-apt-repository -y ppa:oisf/suricata-stable || \
    (echo "deb http://deb.debian.org/debian $(lsb_release -sc)-backports main" > /etc/apt/sources.list.d/backports.list) && \
    apt-get update && \
    apt-get install -y suricata && \
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

# Update Suricata configuration
RUN sed -i 's/HOME_NET: "\[192.168.0.0\/16,10.0.0.0\/8,172.16.0.0\/12\]"/HOME_NET: "any"/' /etc/suricata/suricata.yaml && \
    sed -i 's/EXTERNAL_NET: "!$HOME_NET"/EXTERNAL_NET: "any"/' /etc/suricata/suricata.yaml && \
    sed -i 's/  enabled: no/  enabled: yes/' /etc/suricata/suricata.yaml && \
    sed -i 's/default-rule-path: \/etc\/suricata\/rules/default-rule-path: \/etc\/suricata\/rules/' /etc/suricata/suricata.yaml

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose Suricata log directory as volume
VOLUME ["/var/log/suricata"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]
