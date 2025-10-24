# 🛡️ Suricata + Wazuh Docker Integration for Students

**One-liner installation of Suricata IDS integrated with Wazuh for cybersecurity education.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Debian-blue)](https://www.kali.org/)
[![Docker](https://img.shields.io/badge/docker-required-2496ED?logo=docker)](https://www.docker.com/)

---

## 📖 Overview

This project simplifies the deployment of **Suricata IDS/IPS** in a Docker container that automatically integrates with existing **Wazuh agents**. Perfect for cybersecurity students and educational labs.

### What You Get

- ✅ **Suricata IDS/IPS** - Industry-standard network intrusion detection
- ✅ **Emerging Threats Rules** - 50+ pre-configured rule files
- ✅ **Auto Wazuh Integration** - Seamless agent configuration
- ✅ **Docker Containerized** - Isolated, portable, easy to manage
- ✅ **One-Liner Install** - Simple deployment
- ✅ **Comprehensive Testing** - 60+ automated tests included

---

## 🚀 Quick Start (Students)

### Prerequisites

Before running the installer, ensure you have:

- ✅ **Kali Linux** (or any Debian-based system)
- ✅ **Wazuh Agent** already installed and configured
- ✅ **Root/sudo access**
- ✅ **Internet connection**
- ✅ **Wazuh Manager IP** (ask your instructor)

### One-Liner Installation

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/suricata-wazuh-docker/main/install-suricata.sh | sudo bash
```

Or download and run manually:

```bash
# Download the installer
wget https://raw.githubusercontent.com/YOUR_USERNAME/suricata-wazuh-docker/main/install-suricata.sh

# Make it executable
chmod +x install-suricata.sh

# Run it
sudo ./install-suricata.sh
```

### What Happens During Installation?

The script will:

1. 🎯 **Check for Docker** - Install if not present (takes ~2 minutes)
2. 🔧 **Prompt for Wazuh Manager IP** - Enter your instructor's Wazuh server
3. 🏗️ **Build Suricata Container** - Download and compile (~3-5 minutes)
4. 🌐 **Auto-detect Network Interface** - Monitors your primary interface
5. ⚙️ **Configure Wazuh Agent** - Updates ossec.conf automatically
6. 🚀 **Start Monitoring** - Begins capturing network traffic

**Total Time: 5-10 minutes** (depending on internet speed)

---

## 🎓 For Students

### After Installation

Once installed, Suricata runs automatically in the background. You can:

```bash
# View live alerts
docker logs -f suricata-wazuh

# Check raw JSON events
tail -f /var/log/suricata/eve.json

# View only alerts (formatted)
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# Generate test traffic
./generate-test-traffic.sh

# Check container status
docker ps | grep suricata
```

### Viewing Alerts in Wazuh Dashboard

1. Open your Wazuh dashboard (ask instructor for URL)
2. Log in with your credentials
3. Navigate to **Security Events**
4. Filter by: `rule.groups:suricata`
5. See network alerts in real-time!

### Useful Commands

```bash
# Start Suricata
docker start suricata-wazuh

# Stop Suricata
docker stop suricata-wazuh

# Restart Suricata
docker restart suricata-wazuh

# Check Wazuh agent status
sudo systemctl status wazuh-agent

# Restart Wazuh agent
sudo systemctl restart wazuh-agent

# View Suricata stats
docker exec suricata-wazuh cat /var/log/suricata/suricata.log
```

### Uninstall

```bash
# Stop and remove container
docker stop suricata-wazuh
docker rm suricata-wazuh

# Remove image
docker rmi suricata-wazuh:latest

# Remove logs (optional)
sudo rm -rf /var/log/suricata/
```

---

## 🧪 Testing Suite

This project includes a comprehensive test suite to verify everything works without Wazuh.

### Run All Tests

```bash
# Download test scripts
wget https://raw.githubusercontent.com/YOUR_USERNAME/suricata-wazuh-docker/main/test-suricata.sh
wget https://raw.githubusercontent.com/YOUR_USERNAME/suricata-wazuh-docker/main/generate-test-traffic.sh
wget https://raw.githubusercontent.com/YOUR_USERNAME/suricata-wazuh-docker/main/validate-eve-json.sh

chmod +x test-suricata.sh generate-test-traffic.sh validate-eve-json.sh

# Run full test suite (60+ tests)
sudo ./test-suricata.sh
```

### Test Components

| Script | Purpose | Tests |
|--------|---------|-------|
| `test-suricata.sh` | Master test suite | 60+ validation checks |
| `generate-test-traffic.sh` | Traffic generator | 12 attack types |
| `validate-eve-json.sh` | JSON validator | Schema & compatibility |

### Expected Results

```
========================================
         FINAL RESULTS
========================================
Tests Passed:  58
Tests Failed:  0
Total Tests:   58

Pass Rate:     100%

========================================
   ✓ ALL TESTS PASSED!
   Suricata is fully operational
========================================
```

---

## 📊 What Gets Monitored

Suricata automatically detects and logs:

### Network Events
- 🌐 **HTTP/HTTPS Traffic** - Web requests and responses
- 📡 **DNS Queries** - Domain name lookups
- 🔒 **TLS/SSL Connections** - Encrypted traffic metadata
- 📧 **SMTP/Email** - Mail server communications
- 🔄 **FTP/File Transfers** - File protocol activity

### Security Alerts
- 🚨 **Malware Signatures** - Known malicious patterns
- 🎯 **Exploit Attempts** - Attack patterns
- 🕵️ **Suspicious User Agents** - Scanner/tool detection
- 💉 **SQL Injection** - Database attack attempts
- 🔓 **XSS Attempts** - Cross-site scripting
- 🗂️ **Directory Traversal** - Path manipulation
- 🔥 **Port Scans** - Network reconnaissance
- 📦 **Data Exfiltration** - Unusual data transfers

### Alert Examples

Suricata will trigger alerts for:
- Malicious user agents (Metasploit, sqlmap, Nikto)
- Known exploit patterns
- Suspicious network behavior
- Command & control (C2) communication
- Malware download attempts
- Brute force attacks
- Unauthorized port scans

---

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│      Your Kali Linux Machine        │
├─────────────────────────────────────┤
│                                     │
│  ┌──────────────────────────────┐  │      ┌─────────────────┐
│  │  Docker Container            │  │      │  Wazuh Manager  │
│  │  ┌────────────────────────┐  │  │      │  (.ova VM)      │
│  │  │   Suricata IDS/IPS     │  │  │      │                 │
│  │  │   - Network Monitor    │  │  │      │  ┌───────────┐  │
│  │  │   - Alert Detection    │  │  │      │  │ Dashboard │  │
│  │  │   - EVE JSON Output    │  │  │      │  └───────────┘  │
│  │  └────────────────────────┘  │  │      │                 │
│  │            ↓                  │  │      │  ┌───────────┐  │
│  │  /var/log/suricata/eve.json  │←─┼──────┤  │ Indexer   │  │
│  └──────────────────────────────┘  │      │  └───────────┘  │
│               ↑                     │      └─────────────────┘
│               │                     │               ↑
│  ┌────────────┴──────────────────┐  │               │
│  │      Wazuh Agent              │──┼───────────────┘
│  │  - Reads eve.json             │  │
│  │  - Forwards to Manager        │  │
│  └───────────────────────────────┘  │
│                                     │
│  ┌───────────────────────────────┐  │
│  │  Your Network Interface       │  │
│  │  (eth0, wlan0, etc.)          │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### How It Works

1. **Network Traffic** flows through your network interface
2. **Suricata Container** captures packets in real-time (host network mode)
3. **Alert Rules** analyze traffic for threats (50+ rule files)
4. **EVE.json** logs events in JSON format
5. **Wazuh Agent** reads eve.json and forwards to manager
6. **Wazuh Dashboard** displays alerts and analytics

---

## 🔧 Advanced Configuration

### Custom Rules

Add your own Suricata rules:

```bash
# Copy custom rule into container
docker cp my-custom.rules suricata-wazuh:/etc/suricata/rules/

# Restart container to load rules
docker restart suricata-wazuh
```

### Change Monitored Interface

```bash
# Stop container
docker stop suricata-wazuh

# Start with specific interface
docker run -d \
  --name suricata-wazuh \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v /var/log/suricata:/var/log/suricata \
  -e NETWORK_INTERFACE=wlan0 \
  suricata-wazuh:latest
```

### Update Rules

```bash
# Enter container
docker exec -it suricata-wazuh bash

# Download latest rules
cd /tmp
curl -LO https://rules.emergingthreats.net/open/suricata-7.0.0/emerging.rules.tar.gz
tar -xzf emerging.rules.tar.gz
mv rules/*.rules /etc/suricata/rules/

# Exit and restart
exit
docker restart suricata-wazuh
```

---

## 🐛 Troubleshooting

### Container Won't Start

```bash
# Check Docker logs
docker logs suricata-wazuh

# Common issues:
# 1. Network interface doesn't exist
#    Solution: Specify interface with -e NETWORK_INTERFACE=eth0

# 2. Permission denied
#    Solution: Ensure running with sudo

# 3. Port already in use
#    Solution: Check for other Suricata instances
```

### No Alerts Appearing

```bash
# 1. Generate test traffic
curl -A "BlackSun" http://testmynids.org/uid/index.html

# 2. Check if alert was logged
grep -i blacksun /var/log/suricata/eve.json

# 3. If no results, check Suricata logs
docker exec suricata-wazuh cat /var/log/suricata/suricata.log

# 4. Verify rules are loaded
docker exec suricata-wazuh ls /etc/suricata/rules/*.rules | wc -l
# Should show 50+
```

### Wazuh Not Receiving Events

```bash
# 1. Check Wazuh agent is running
sudo systemctl status wazuh-agent

# 2. Verify agent configuration
sudo cat /var/ossec/etc/ossec.conf | grep -A5 suricata

# Should show:
# <localfile>
#   <log_format>json</log_format>
#   <location>/var/log/suricata/eve.json</location>
# </localfile>

# 3. Check agent logs
sudo tail -f /var/ossec/logs/ossec.log

# 4. Restart agent
sudo systemctl restart wazuh-agent
```

### High CPU Usage

```bash
# Check container resource usage
docker stats suricata-wazuh

# If CPU > 80%, possible causes:
# 1. Too much network traffic
# 2. Too many rules loaded
# 3. Insufficient resources

# Solution: Limit rules or increase resources
```

---

## 👨‍🏫 For Instructors

### Pre-Class Setup

1. **Deploy Wazuh Manager** (.ova VM)
2. **Note the Manager IP** for students
3. **Test installation** on reference machine
4. **Verify dashboard access** for students

### Bulk Deployment

For multiple student machines:

```bash
# Create a config file
cat > wazuh-config.txt << EOF
WAZUH_MANAGER=192.168.1.100
EOF

# Distribute to students
# Students run:
export WAZUH_MANAGER=$(cat wazuh-config.txt)
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/suricata-wazuh-docker/main/install-suricata.sh | sudo bash
```

### Monitoring Student Progress

```bash
# On Wazuh dashboard, filter by:
# agent.name: student-*
# rule.groups: suricata

# Check agent status via API
curl -u username:password -k -X GET "https://wazuh-manager:55000/agents?pretty=true"
```

### Custom Lab Exercises

Students can practice detecting:

1. **Port Scans** - Run nmap
2. **Web Attacks** - Use sqlmap, dirb
3. **Malicious Downloads** - Test files from testmynids.org
4. **Custom Exploits** - Create and detect patterns
5. **C2 Communication** - Simulate beaconing

---

## 📚 Learning Resources

### Suricata Documentation
- [Official Suricata Docs](https://suricata.readthedocs.io/)
- [Rule Writing Guide](https://suricata.readthedocs.io/en/latest/rules/index.html)
- [EVE JSON Format](https://suricata.readthedocs.io/en/latest/output/eve/eve-json-format.html)

### Wazuh Documentation
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Suricata Integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)

### Practice Sites
- [TestMyIDS](http://testmynids.org/) - Generate test alerts
- [EICAR Test File](https://www.eicar.org/) - Test malware detection

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📝 License

This project is licensed under the MIT License - free for educational use.

---

## 🆘 Support

### Having Issues?

1. **Read the troubleshooting section** above
2. **Run the test suite**: `sudo ./test-suricata.sh`
3. **Check logs**: `docker logs suricata-wazuh`
4. **Ask your instructor** or TA
5. **Open an issue** on GitHub with logs

### Report Bugs

Please include:
- OS version (`lsb_release -a`)
- Docker version (`docker --version`)
- Error messages
- Output of `sudo ./test-suricata.sh`

---

## ✅ Success Checklist

After installation, verify:

- [ ] Container is running: `docker ps | grep suricata`
- [ ] Logs are being written: `ls -lh /var/log/suricata/eve.json`
- [ ] Alerts generate: `curl -A "BlackSun" http://testmynids.org/uid/index.html`
- [ ] Wazuh agent is running: `sudo systemctl status wazuh-agent`
- [ ] Events appear in dashboard (filter: `rule.groups:suricata`)

---

## 🎯 Quick Reference

```bash
# Installation
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/suricata-wazuh-docker/main/install-suricata.sh | sudo bash

# View alerts
docker logs -f suricata-wazuh

# Generate test traffic
curl -A "BlackSun" http://testmynids.org/uid/index.html

# Run tests
sudo ./test-suricata.sh

# Restart
docker restart suricata-wazuh

# Uninstall
docker stop suricata-wazuh && docker rm suricata-wazuh
```

---

**Built for cybersecurity education** | **Docker-powered** | **Wazuh-integrated** | **Student-friendly**

⭐ **Star this repo if it helped you!**
