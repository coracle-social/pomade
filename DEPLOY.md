# Pomade Signer — Deploy Guide

A complete step-by-step guide for provisioning and hardening a fresh Ubuntu server to run Pomade signers. Pomade uses threshold cryptography (FROST) to provide encrypted nostr key custody — the `POMADE_SECRET` on each signer is the most sensitive asset on the machine and must be protected accordingly.

The recommended production topology is **three independent servers**, each running a different signer implementation (TypeScript, Rust, Go), so that a single exploit or implementation bug cannot compromise the full key. This guide applies equally to all three.

> **Before you begin:** Always have an out-of-band recovery method available (cloud provider console, VNC, or physical keyboard) in case you lock yourself out. Test every SSH config change in a second terminal before closing your current session.

---

## 1. Initial Access & User Setup

### 1.1 Create a non-root sudo user

```bash
adduser nonroot
usermod -aG sudo nonroot
```

### 1.2 Copy your SSH public key to the new user

From your **local machine**:

```bash
ssh-copy-id nonroot@<server-ip>
```

Or manually on the server:

```bash
su - nonroot
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "<your-public-key>" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### 1.3 Verify you can log in as the new user

Open a **new terminal** and confirm before proceeding:

```bash
ssh nonroot@<server-ip>
sudo whoami   # should print: root
```

---

## 2. SSH Hardening

```bash
sudo nano /etc/ssh/sshd_config
```

Apply the following settings (add or change as needed):

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
AllowUsers nonroot
Banner /etc/issue.net
Port 2222
```

Validate the config and restart:

```bash
sudo sshd -t
sudo systemctl disable --now ssh.socket
sudo systemctl restart ssh
```

> **Test in a new terminal** that you can still log in before closing your existing session:

```bash
ssh -p 2222 nonroot@<your-ip-address>
```

---

## 3. Firewall (UFW)

Pomade signers only need to be reachable via nginx (HTTP/HTTPS). Their internal ports (3000) are never exposed directly.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp   # SSH
sudo ufw allow 80/tcp     # HTTP — nginx
sudo ufw allow 443/tcp    # HTTPS — nginx
sudo ufw enable
sudo ufw status verbose
```

The signer port (3000) is intentionally **not** opened — nginx proxies to it over localhost only.

---

## 4. Fail2Ban

### 4.1 Install

```bash
sudo apt install fail2ban -y
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

### 4.2 Configure jails

Edit `/etc/fail2ban/jail.local` and enter the following:

```ini
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port    = 2222
logpath = %(sshd_log)s
backend = %(sshd_backend)s

[nginx-http-auth]
enabled = true

# Rate-limit repeated 400/401 from the signer API
[nginx-limit-req]
enabled  = true
filter   = nginx-limit-req
logpath  = /var/log/nginx/pomade-error.log
maxretry = 10
```

```bash
sudo systemctl enable --now fail2ban
sudo fail2ban-client status
```

---

## 5. Automatic Security Updates

```bash
sudo apt install unattended-upgrades apt-listchanges -y
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

Edit `/etc/apt/apt.conf.d/50unattended-upgrades`:

```
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
```

Edit `/etc/apt/apt.conf.d/20auto-upgrades`:

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
```

Test with:

```bash
sudo unattended-upgrade --dry-run --debug
```

---

## 6. Docker

### 6.1 Install Docker Engine

```bash
sudo apt install ca-certificates curl -y
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin -y
sudo systemctl enable --now docker
```

### 6.2 Add your user to the docker group

```bash
sudo usermod -aG docker nonroot
newgrp docker
docker run hello-world
```

### 6.3 Harden the Docker daemon

Create `/etc/docker/daemon.json`:

```json
{
  "dns": ["8.8.8.8", "1.1.1.1"],
  "dns-opts": ["single-request", "timeout:2"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "5"
  },
  "no-new-privileges": true,
  "live-restore": true
}
```

```bash
sudo systemctl restart docker
```

- `no-new-privileges` prevents processes inside containers from gaining extra privileges via setuid binaries.
- `live-restore` keeps containers running across Docker daemon restarts (useful during auto-updates).
- `dns` and `dns-opts` prevent docker DNS loop

---

## 7. Deploy a Pomade Signer

Each server hosts one signer. The three pre-built images are published to GHCR:

| Implementation | Image |
|---|---|
| TypeScript | `ghcr.io/coracle-social/pomade-signer-ts:latest` |
| Rust       | `ghcr.io/coracle-social/pomade-signer-rust:latest` |
| Go         | `ghcr.io/coracle-social/pomade-signer-go:latest` |

### 7.1 Prepare the environment file

The `POMADE_SECRET` is the signer's nostr identity key and the master key from which all at-rest encryption is derived. Treat it like a private key — generate it once, store it in a password manager or secrets vault, and never commit it to version control.

```bash
sudo mkdir -p /etc/pomade
sudo chmod 700 /etc/pomade
sudo nano /etc/pomade/env
```

```ini
# Required
POMADE_SECRET=<64-char hex secret key — generate with: openssl rand -hex 32>
POMADE_URL=https://signer1.example.com

# Optional
POMADE_PORT=3000
POMADE_DATABASE=/data/signer.db

# Email settings
MAIL_FROM_EMAIL=noreply@example.com
MAIL_FROM_NAME="<app name> Mailer"

# Configure an email provider:
# MAIL_PROVIDER=postmark    POSTMARK_API_TOKEN=...
# MAIL_PROVIDER=sendgrid    SENDGRID_API_KEY=...
# MAIL_PROVIDER=mailgun     MAILGUN_API_KEY=...  MAILGUN_DOMAIN=...  MAILGUN_API_REGION=us
# MAIL_PROVIDER=sendlayer   SENDLAYER_API_KEY=...
# MAIL_PROVIDER=resend      RESEND_API_KEY=...
# MAIL_PROVIDER=smtp        SMTP_HOST=...  SMTP_PORT=587  SMTP_USER=...  SMTP_PASSWORD=...
```

```bash
sudo chmod 600 /etc/pomade/env
```

### 7.2 Create the data directory

```bash
sudo mkdir -p /var/lib/pomade
sudo chown nonroot:nonroot /var/lib/pomade
sudo chmod 700 /var/lib/pomade
```

### 7.3 Pull the image and run

Replace `pomade-signer-ts` with `pomade-signer-rust` or `pomade-signer-go` as appropriate for this server.

```bash
sudo docker pull ghcr.io/coracle-social/pomade-signer-ts:latest

sudo docker run -d \
  --name pomade-signer \
  --restart unless-stopped \
  --env-file /etc/pomade/env \
  --read-only \
  --tmpfs /tmp \
  -v /var/lib/pomade:/data \
  -p 127.0.0.1:3000:3000 \
  ghcr.io/coracle-social/pomade-signer-ts:latest
```

Key flags:
- `-p 127.0.0.1:3000:3000` — binds only on loopback; nginx is the only entry point.
- `--read-only --tmpfs /tmp` — the container filesystem is immutable; only `/data` is writable.
- `--restart unless-stopped` — survives reboots and crashes.

Verify it is running:

```bash
sudo docker ps
sudo docker logs pomade-signer
curl http://127.0.0.1:3000/
```

---

## 8. Nginx as a TLS-Terminating Reverse Proxy

The signer must be served over HTTPS because `POMADE_URL` is used as an argon2id salt in password hashing — it must match the URL clients use exactly, and must not change after users have registered.

### 8.1 Install nginx and Certbot

```bash
sudo apt install nginx certbot python3-certbot-nginx -y
sudo systemctl enable --now nginx
```

### 8.2 Create the signer vhost

```bash
sudo nano /etc/nginx/sites-available/pomade-signer
```

```nginx
server {
    listen 80;
    server_name signer1.example.com;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/pomade-signer /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 8.3 Obtain a TLS certificate

```bash
sudo certbot --nginx -d signer1.example.com
```

### 8.4 Add the rate-limit zone

Certbot rewrites the vhost automatically. Before applying the full config below, add the rate-limit zone to the `http` block in `/etc/nginx/nginx.conf`:

```bash
sudo nano /etc/nginx/nginx.conf
```

Inside `http { ... }`:

```nginx
limit_req_zone $binary_remote_addr zone=signer:10m rate=60r/m;
```

### 8.5 Apply the full hardened vhost config

```bash
sudo nano /etc/nginx/sites-available/pomade-signer
```

```nginx
# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name signer1.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name signer1.example.com;

    # TLS — managed by Certbot
    ssl_certificate     /etc/letsencrypt/live/signer1.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/signer1.example.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options    "nosniff"                                       always;
    add_header X-Frame-Options           "DENY"                                           always;
    add_header Referrer-Policy           "no-referrer"                                   always;

    # Signer API accepts only POST and OPTIONS (CORS preflight)
    if ($request_method !~ ^(POST|OPTIONS)$) {
        return 405;
    }

    # Rate limiting — 60 requests/min per IP, burst of 60
    limit_req zone=signer burst=60 nodelay;
    limit_req_status 429;

    # Proxy to the container
    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Argon2id on first registration is CPU-intensive — allow enough time
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;

        # Enforce a reasonable request body size
        client_max_body_size 64k;
    }

    access_log /var/log/nginx/pomade-access.log;
    error_log  /var/log/nginx/pomade-error.log warn;
}
```

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 8.6 Verify

```bash
# Expect 405 Method Not Allowed (correct — only POST is allowed)
curl -v https://signer1.example.com/

# Expect a real response
curl -s -X POST https://signer1.example.com/nonexistent
```

### 8.7 Certbot auto-renewal

```bash
sudo systemctl status certbot.timer
sudo certbot renew --dry-run
```

---

## 9. Kernel & Network Hardening

```bash
sudo nano /etc/sysctl.conf
```

```ini
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
```

```bash
sudo sysctl -p
```

---

## 10. System Hardening

### 10.1 Remove unnecessary packages

```bash
sudo apt autoremove -y
sudo apt purge telnet ftp rsh-client -y
```

### 10.2 Secure /tmp and shared memory

Add to `/etc/fstab`:

```
tmpfs /tmp     tmpfs defaults,noexec,nosuid,nodev 0 0
tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0
```

These take effect on next reboot. Unattended-upgrades will trigger one automatically when a kernel update is installed.

