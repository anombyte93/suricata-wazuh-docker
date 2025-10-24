# GitHub Setup Instructions

## Creating and Pushing to GitHub

Since GitHub CLI is not installed, follow these manual steps:

### Option 1: Using GitHub Web Interface (Easiest)

1. **Go to GitHub** and log in to your account
   - Visit: https://github.com/

2. **Create a new repository**
   - Click the "+" icon in top right
   - Select "New repository"
   - Name: `suricata-wazuh-docker`
   - Description: "Suricata + Wazuh Docker integration for cybersecurity students"
   - Set to **Public**
   - **DO NOT** initialize with README (we have one)
   - Click "Create repository"

3. **Copy the repository URL** shown on the next page
   - It will look like: `https://github.com/YOUR_USERNAME/suricata-wazuh-docker.git`

4. **Push your code** from the terminal:

```bash
cd /home/anombyte/suricata-wazuh-docker

# Add the remote
git remote add origin https://github.com/YOUR_USERNAME/suricata-wazuh-docker.git

# Push to GitHub
git push -u origin main
```

5. **Enter your GitHub credentials** when prompted
   - Username: your GitHub username
   - Password: use a **Personal Access Token** (not your password)
     - Generate token at: https://github.com/settings/tokens
     - Select scopes: `repo`

### Option 2: Using SSH (If you have SSH keys)

```bash
cd /home/anombyte/suricata-wazuh-docker

# Add remote with SSH
git remote add origin git@github.com:YOUR_USERNAME/suricata-wazuh-docker.git

# Push
git push -u origin main
```

### After Pushing

Your repository will be available at:
```
https://github.com/YOUR_USERNAME/suricata-wazuh-docker
```

### Update the README

After creating the repo, update the URLs in README.md:

```bash
# Replace YOUR_USERNAME with your actual GitHub username
sed -i 's/YOUR_USERNAME/your-actual-username/g' README.md

# Commit and push the change
git add README.md
git commit -m "Update GitHub username in README"
git push
```

### One-Liner for Students

Once pushed, students can install with:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/suricata-wazuh-docker/main/install-suricata.sh | sudo bash
```

Replace `YOUR_USERNAME` with your actual GitHub username.

## Quick Command Reference

```bash
# Check remote
git remote -v

# View commit history
git log --oneline

# View current status
git status

# Push updates
git add .
git commit -m "Update message"
git push

# Clone to another machine
git clone https://github.com/YOUR_USERNAME/suricata-wazuh-docker.git
```

## Sharing with Students

Once pushed, share:

1. **Repository URL**: `https://github.com/YOUR_USERNAME/suricata-wazuh-docker`

2. **One-liner installation**:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/suricata-wazuh-docker/main/install-suricata.sh | sudo bash
   ```

3. **Or manual download**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/suricata-wazuh-docker.git
   cd suricata-wazuh-docker
   sudo ./install-suricata.sh
   ```

## Making Updates

To update the repository after changes:

```bash
cd /home/anombyte/suricata-wazuh-docker

# Make your changes...

# Stage and commit
git add -A
git commit -m "Description of changes"

# Push to GitHub
git push
```

Students will automatically get the latest version when they run the one-liner.
