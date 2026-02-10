<div align="center">

# 🐧 linux-ad-domain-join

**Enterprise-grade automation for joining Linux hosts to Active Directory**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/Shell-Bash_4%2B-green.svg)]()
[![Version](https://img.shields.io/badge/Version-3.1.0-orange.svg)]()

A single-script solution that handles the entire AD join lifecycle - from package installation to sudoers hardening - across every major enterprise Linux distribution.

---

[Quick Start](#-quick-start) · [Features](#-what-it-does) · [Supported Platforms](#-supported-platforms) · [Parameters](#-parameters) · [Security Model](#-security-model) · [Exit Codes](#-exit-codes) · [Contributing](#-contributing)

</div>

---

## ⚡ Quick Start

**One-liner (interactive mode):**

```bash
tmp=$(mktemp) && \
  ( command -v curl >/dev/null && curl -fsSL https://raw.githubusercontent.com/soulucasbonfim/linux-ad-domain-join/main/linux-ad-domain-join.sh > "$tmp" \
    || wget -qO "$tmp" https://raw.githubusercontent.com/soulucasbonfim/linux-ad-domain-join/main/linux-ad-domain-join.sh ) && \
  chmod +x "$tmp" && sudo "$tmp"
```

**Non-interactive (CI/CD, Ansible, Terraform):**

```bash
sudo DOMAIN="acme.corp" \
     OU="OU=Linux,OU=Servers,DC=ACME,DC=CORP" \
     DC_SERVER="dc01.acme.corp" \
     NTP_SERVER="ntp.acme.corp" \
     DOMAIN_USER="svc-join" \
     DOMAIN_PASS="$VAULT_SECRET" \
     GLOBAL_ADMIN_GROUPS="infra-admins" \
     SESSION_TIMEOUT_SECONDS="900" \
     PERMIT_ROOT_LOGIN="no" \
     ./linux-ad-domain-join.sh --yes
```

---

## 🔧 What It Does

The script executes a **10-stage pipeline** that transforms a standalone Linux host into a fully integrated AD member:

```
 ┌──────────────────────────────────────────────────────────────────┐
 │  1. ENVIRONMENT     Detect distro, validate Bash 4+, check root  │
 │  2. PACKAGES        Auto-install missing deps (apt/dnf/zypper)   │
 │  3. NETWORK         DNS, KDC, LDAP, NTP reachability tests       │
 │  4. CREDENTIALS     Kerberos TGT + error classification          │
 │  5. COMPUTER OBJ    Pre-check, OU alignment, auto-move           │
 │  6. DOMAIN JOIN     adcli join with SPN registration             │
 │  7. TRUST REPAIR    Re-enable disabled objects, sync keytab      │
 │  8. SSSD + NSS      Generate sssd.conf, patch nsswitch.conf      │
 │  9. SSH + PAM        AllowGroups, mkhomedir, session timeout     │
 │ 10. SUDOERS          Role-based privilege model (SEC/ADM/SUPER)  │
 └──────────────────────────────────────────────────────────────────┘
```

### Highlights

**Intelligent dependency management** - Detects missing packages and installs them automatically. Handles RPM database corruption, broken apt states, and offline environments with clear diagnostics.

**Multi-strategy DNS persistence** - Configures DNS through whichever subsystem is active on the host, with automatic fallback:

| Priority | Method | Distros |
|----------|--------|---------|
| 1 | NetworkManager (`nmcli`) | RHEL 7+, Ubuntu 20.04+ |
| 2 | systemd-resolved (`resolvectl`) | Ubuntu 18.04+, Fedora |
| 3 | Netplan drop-in | Ubuntu 18.04+ (server) |
| 4 | dhclient hooks | RHEL 6, legacy Debian |
| 5 | Static `/etc/resolv.conf` | Universal fallback |

**Computer object lifecycle** - Before joining, the script queries AD for existing computer objects. If found in the wrong OU, it moves the object automatically via LDAP. If the object is disabled (`ACCOUNTDISABLE` bit), it re-enables it. Handles `Insufficient Access Rights` gracefully.

**Chrony time sync** - Configures time synchronization against domain controllers using NTP pool discovery. Supports both `confdir` drop-in and direct config modes, preserving existing chrony settings.

**Cloud-init hostname preservation** - Writes a drop-in to prevent cloud-init from resetting the hostname after reboot. Detects existing configurations to avoid duplicates.

**Dynamic DNS (GSS-TSIG)** - Configures SSSD to register forward and reverse DNS records using secure Kerberos-authenticated updates, with configurable refresh intervals.

---

## 🛡️ Security Model

The script deploys a **role-based sudoers model** with strict separation of duties:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRIVILEGE SEPARATION                         │
├──────────────┬──────────────────────────────────────────────────┤
│  SUPER       │ Full sudo (ALL). Break-glass only.               │
│  grp-super-* │                                                  │
├──────────────┼──────────────────────────────────────────────────┤
│  SEC         │ Sudoers, PAM, SSH, SSSD, Kerberos, NSS.          │
│  grp-sec-*   │ Cannot get interactive root shell.               │
├──────────────┼──────────────────────────────────────────────────┤
│  ADM         │ Services, packages, logs, networking, storage.   │
│  grp-adm-*   │ Cannot alter security posture or get root shell. │
├──────────────┼──────────────────────────────────────────────────┤
│  SSH         │ Login access only. No sudo privileges.           │
│  grp-ssh-*   │                                                  │
└──────────────┴──────────────────────────────────────────────────┘
```

Each role has **two scopes** managed in Active Directory:

- **Host-level** (`grp-adm-<hostname>`) - applies to a single server
- **Global** (`grp-adm-all-linux-servers`) - applies to all joined hosts

### SSH Hardening

- `AllowGroups` restricts login to authorized AD groups + `root` + `wheel`/`sudo`
- `PermitRootLogin` configurable (default: `no`)
- `PasswordAuthentication` configurable (default: `yes`)
- `ClientAliveInterval` enforced from `SESSION_TIMEOUT_SECONDS`
- `TMOUT` set and locked via `/etc/profile.d/` (shell idle timeout)

### Secrets Handling

- Domain password stored in tmpfs-backed temp file (`/run` or `/dev/shm`), never on disk
- File created with `umask 077` - no TOCTOU race between create and chmod
- Password validated against newline/CR injection before use
- `DOMAIN_PASS` unset from memory immediately after file creation
- Temp file shredded on exit (EXIT/HUP/INT/TERM trap)
- Password never appears in command arguments (always via stdin or `-y` file)

---

## 🖥️ Supported Platforms

| Distribution | Versions | Package Manager |
|-------------|----------|-----------------|
| **Ubuntu** | 16.04, 18.04, 20.04, 22.04, 24.04 | apt |
| **Debian** | 9, 10, 11, 12 | apt |
| **RHEL / CentOS** | 7, 8, 9 | yum / dnf |
| **AlmaLinux / Rocky** | 8, 9 | dnf |
| **Oracle Linux** | 7, 8, 9 | yum / dnf |
| **Fedora** | Latest | dnf |
| **Amazon Linux** | 2, 2023 | dnf |
| **SLES** | 12, 15 | zypper |
| **openSUSE Leap** | 15.x | zypper |

---

## 📋 Parameters

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--yes`, `-y` | Non-interactive mode. All inputs must be provided as environment variables. |
| `--dry-run` | Simulate all actions. No files are modified, no services restarted. |
| `--verbose`, `-v` | Enable debug output including LDAP traces, Kerberos diagnostics, and full command logging. |
| `--validate-only` | Validate prerequisites and configuration without making any changes. |

### Environment Variables

#### Required (non-interactive mode)

| Variable | Example | Description |
|----------|---------|-------------|
| `DOMAIN` | `acme.corp` | AD domain FQDN |
| `OU` | `OU=Linux,DC=ACME,DC=CORP` | Target Organizational Unit (LDAP DN) |
| `DC_SERVER` | `dc01.acme.corp` | Domain Controller FQDN |
| `NTP_SERVER` | `ntp.acme.corp` | NTP server for time sync |
| `DOMAIN_USER` | `svc-join` | AD account with join privileges |
| `DOMAIN_PASS` | *(secret)* | Password for `DOMAIN_USER` |
| `GLOBAL_ADMIN_GROUPS` | `infra-admins devops` | Space-separated AD groups for SSH AllowGroups |
| `SESSION_TIMEOUT_SECONDS` | `900` | SSH + shell idle timeout (30–86400 seconds) |
| `PERMIT_ROOT_LOGIN` | `no` | SSH PermitRootLogin (`yes` / `no`) |

#### Optional (with smart defaults)

| Variable | Default | Description |
|----------|---------|-------------|
| `ADM_GROUP` | `grp-adm-<hostname>` | Host-level operational admin group |
| `ADM_GROUP_ALL` | `grp-adm-all-linux-servers` | Global operational admin group |
| `SSH_GROUP` | `grp-ssh-<hostname>` | Host-level SSH access group |
| `SSH_GROUP_ALL` | `grp-ssh-all-linux-servers` | Global SSH access group |
| `SEC_GROUP` | `grp-sec-<hostname>` | Host-level security admin group |
| `SEC_GROUP_ALL` | `grp-sec-all-linux-servers` | Global security admin group |
| `SUPER_GROUP` | `grp-super-<hostname>` | Host-level full-sudo group |
| `SUPER_GROUP_ALL` | `grp-super-all-linux-servers` | Global full-sudo group |
| `PASSWORD_AUTHENTICATION` | `yes` | SSH PasswordAuthentication (`yes` / `no`) |
| `LDAP_TIMEOUT` | `30` | Timeout in seconds for LDAP operations |
| `LOG_RETENTION` | `30` | Number of log files to retain |
| `KRB5_KEYTAB` | `/etc/krb5.keytab` | Path to the Kerberos keytab file |

---

## 📁 What Gets Modified

Every file modified by the script is **backed up automatically** before changes are applied.

| File/Path | Action |
|-----------|--------|
| `/etc/krb5.conf` | Generated (realm + KDC config) |
| `/etc/sssd/sssd.conf` | Generated (identity, auth, DNS update) |
| `/etc/nsswitch.conf` | Patched (add `sss` to passwd, group, shadow, etc.) |
| `/etc/ssh/sshd_config` | Patched (AllowGroups, PermitRootLogin, timeouts) |
| `/etc/sudoers.d/10-ad-linux-privilege-model` | Generated (SEC/ADM/SUPER roles) |
| `/etc/sudoers.d/00-ad-base-variables` | Generated (Cmnd_Alias definitions) |
| `/etc/hostname` | Set to match AD hostname |
| `/etc/hosts` | Patched (FQDN + short name) |
| `/etc/profile.d/tmout.sh` | Generated (TMOUT enforcement) |
| `/etc/chrony.conf` or drop-in | Patched (NTP server) |
| `/etc/pam.d/common-session` | Patched (mkhomedir) |
| `/etc/cloud/cloud.cfg.d/99-hostname.cfg` | Generated (preserve_hostname) |

**Backup location:** `/var/backups/linux-ad-domain-join/<timestamp>_<hostname>_<pid>/`
Old backups are pruned automatically (last 20 retained).

**Logs:** `/var/log/linux-ad-domain-join.log` (last 30 retained).

---

## 🚦 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (missing deps, not root, invalid parameters) |
| `2` | Invalid credentials (Kerberos authentication failed) |
| `3` | Domain join failure (adcli) |
| `4` | LDAP operation failure (object move/modify) |
| `8` | RPM database rebuild failure |
| `9` | RPM database still corrupted after rebuild |
| `10` | DNS resolution failure |
| `11` | Network / KDC unreachable |
| `12` | LDAP port unreachable |
| `13` | Time synchronization failure |
| `14` | Unknown Kerberos failure |
| `15` | No active network interface or IP detected |
| `16` | Another instance already running (lock) |
| `21` | AD account locked or disabled |
| `22` | AD password expired |
| `23` | AD principal not found |
| `30` | Backup directory creation failure |
| `31` | Parent directory creation failure |
| `32` | File copy/backup failure |
| `100` | Missing packages and system offline |
| `101` | Unsupported Linux distribution |
| `127` | Required command not found |

---

## 🔄 Operational Modes

### Dry Run

```bash
sudo ./linux-ad-domain-join.sh --dry-run
```

Simulates the entire pipeline. Every action is logged as `[DRY-RUN] Would ...` - no files are modified, no services restarted, no AD objects created. Use this to preview what the script will do in your environment.

### Validate Only

```bash
sudo ./linux-ad-domain-join.sh --validate-only
```

Checks prerequisites (packages, network, DNS, credentials, OU existence) without making any changes. Useful for pre-flight validation in deployment pipelines.

### Verbose

```bash
sudo ./linux-ad-domain-join.sh --verbose
```

Enables full diagnostic output: Kerberos traces, LDAP raw responses, command execution details, and timing information. Combine with `--dry-run` for safe troubleshooting.

---

## 📦 Requirements

The script **auto-installs** most dependencies. The only hard requirement is:

- **Bash 4+** (RHEL 7+, Ubuntu 16.04+, Debian 9+, SLES 12+)
- **Root access** (`sudo` or direct root)
- **Network access** to Domain Controller (ports 53, 88, 389, 464)

Packages installed automatically (if missing):

```
realmd  sssd  sssd-tools  adcli  oddjob  oddjob-mkhomedir
krb5-workstation (RHEL) / krb5-user (Debian)  chrony
ldap-utils (Debian) / openldap-clients (RHEL)  dialog
```

---

## 🤝 Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

---

## 📄 License

[MIT](LICENSE) - Lucas Bonfim de Oliveira Lima
