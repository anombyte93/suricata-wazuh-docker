#!/bin/bash
set -e

# Get the primary network interface if not specified
if [ -z "$NETWORK_INTERFACE" ]; then
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    echo "[INFO] Auto-detected network interface: $NETWORK_INTERFACE"
fi

# Update Suricata config with the correct interface
sed -i "s/interface: .*/interface: $NETWORK_INTERFACE/" /etc/suricata/suricata.yaml

# Ensure eve.json is in the right format for Wazuh
cat > /etc/suricata/suricata.yaml.tmp << 'EOF'
%YAML 1.1
---
EOF

# Create minimal Suricata config focused on eve.json output
cat >> /etc/suricata/suricata.yaml.tmp << EOF
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

mv /etc/suricata/suricata.yaml.tmp /etc/suricata/suricata.yaml

echo "[INFO] Starting Suricata on interface: $NETWORK_INTERFACE"
echo "[INFO] Logs will be written to /var/log/suricata/eve.json"
echo "[INFO] Make sure your Wazuh agent is configured to read this file"

# Start Suricata
exec suricata -c /etc/suricata/suricata.yaml -i "$NETWORK_INTERFACE" --pidfile /var/run/suricata.pid
