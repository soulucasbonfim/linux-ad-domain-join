#!/bin/bash
# -------------------------------------------------------------------------------------------------
# Script Name:        linux-ad-domain-join.sh
# -------------------------------------------------------------------------------------------------
# Author:      Lucas Bonfim de Oliveira Lima
# LinkedIn:    https://www.linkedin.com/in/soulucasbonfim
# GitHub:      https://github.com/soulucasbonfim
# Created:     2025-04-27
# Version:     3.1.1
# License:     MIT
# -------------------------------------------------------------------------------------------------
# Description:
#   Automates the process of joining a Linux host to an Active Directory (AD) domain.
#   Provides full multi-distro compatibility (RHEL-like, Debian-like, SUSE), with support for:
#     • Realmd/adcli/SSSD integration
#     • Dynamic DNS updates
#     • PAM, SSH, and sudoers configuration
#     • Kerberos authentication and keytab validation
#     • Chrony time synchronization using domain-based discovery
#     • Automatic detection and remediation of missing dependencies
#     • Intelligent network connectivity checks and error classification
#
#   Designed for enterprise-grade automation and compliance, this script performs:
#     1. Environment and package validation
#     2. Kerberos authentication test (user credentials)
#     3. Computer object pre-validation and OU alignment
#     4. Domain join via adcli (without realm)
#     5. Trust verification and keytab synchronization
#     6. Auto-repair of disabled computer objects in AD
#     7. SSSD configuration and validation (sssctl config-check)
#     8. PAM, SSH, and sudoers integration with AD groups
#     9. Dynamic DNS and chrony setup for secure updates
#    10. Comprehensive logging and backup of modified files
#
# -------------------------------------------------------------------------------------------------
# Usage:
#   sudo ./linux-ad-domain-join.sh [options]
#
# Options:
#   --dry-run         Simulate all actions without applying changes
#   --yes, -y         Non-interactive mode (requires DOMAIN, OU, DC_SERVER,
#                     DOMAIN_USER, DOMAIN_PASS, GLOBAL_ADMIN_GROUPS as env vars)
#   --verbose, -v     Enable full command output and debugging traces
#   --validate-only   Validate configuration and prerequisites without making changes
#
# -------------------------------------------------------------------------------------------------
# Requirements:
#   Base packages:
#       realmd, sssd, sssd-tools, adcli, oddjob, oddjob-mkhomedir,
#       krb5-user (Debian) or krb5-workstation (RHEL), chrony, ldap-utils,
#       realm, kinit, kdestroy, sed, grep, tput, systemctl, hostname, timeout
#
#   Optional (enhanced validation):
#       sssctl (for SSSD syntax check)
#       samba-common-bin (optional dependency in some Ubuntu builds)
#
#   Permissions:
#       Must be executed as root.
#
# -------------------------------------------------------------------------------------------------
# Logging:
#   All actions and outputs are logged to:
#       /var/log/linux-ad-domain-join.log
#   Log symbols are normalized to ASCII (no Unicode dependencies).
#
# -------------------------------------------------------------------------------------------------
# Backup:
#   Backups of modified configuration files are stored in:
#       /var/backups/linux-ad-domain-join/<timestamp>_<hostname>_<pid>/
#   Old backups are pruned automatically (keeping last 20 runs).
#
# -------------------------------------------------------------------------------------------------
# Supported Linux distributions:
#     - RHEL/CentOS/AlmaLinux/RockyLinux 7, 8, 9
#     - Ubuntu 16.04, 18.04, 20.04, 22.04, 24.04
#     - Debian 9, 10, 11, 12
#     - SUSE Linux Enterprise Server (SLES) 12, 15
#     - openSUSE Leap 15.x
#
# -------------------------------------------------------------------------------------------------
# Exit Codes:
#   0  - Success
#   1  - General error / missing dependencies / not root / invalid parameters
#   2  - Invalid credentials (Kerberos)
#   3  - Domain join failure (adcli)
#   4  - LDAP operation failure (object move/modify)
#   8  - RPM database rebuild failure
#   9  - RPM database remains corrupted after rebuild
#   10 - DNS resolution failure
#   11 - Network / KDC unreachable
#   12 - LDAP port unreachable
#   13 - Time synchronization failure
#   14 - Unknown Kerberos failure
#   15 - No active network interface or IP address detected
#   16 - Another instance is already running
#   21 - AD account locked/disabled
#   22 - AD password expired
#   23 - AD principal not found
#   30 - Backup directory creation failure
#   31 - Parent directory creation failure
#   32 - File copy/backup failure
#  100 - Missing packages and system offline (no installation possible)
#  101 - Unsupported Linux distribution
#  127 - Command not found
#
# -------------------------------------------------------------------------------------------------

# Define script version
scriptVersion="$(grep -m1 "^# Version:" "${BASH_SOURCE[0]:-$0}" 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "unknown")"

# Strict mode: fail fast, track errors, prevent unset vars, propagate pipe failures
set -Eeuo pipefail

# Ignore SIGPIPE (broken pipe) — prevents silent death when output is piped
trap '' PIPE 2>/dev/null || true

# Safe IFS: prevent word splitting issues (space-only IFS for controlled behavior)
IFS=$' \t\n'

# Require Bash 4+ (associative arrays, mapfile).
if [[ -z "${BASH_VERSINFO[0]:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo "[$(date '+%F %T')] [ERROR] Bash 4+ required. Current: ${BASH_VERSION:-unknown}" >&2
    exit 1
fi

# -------------------------------------------------------------------------
# Choose a portable sed extended-regex flag (-E preferred, fallback to -r)
# -------------------------------------------------------------------------
if echo | sed -E 's/(.*)//' >/dev/null 2>&1; then
	SED_EXT='-E'
elif echo | sed -r 's/(.*)//' >/dev/null 2>&1; then
	SED_EXT='-r'
else
	echo "[$(date '+%F %T')] [ERROR] sed without extended regex support (-E/-r) - install a compatible sed." >&2; exit 1
fi

# -------------------------------------------------------------------------
# Terminal Colors (AUTO, TTY-safe, NO_COLOR aware)
# -------------------------------------------------------------------------
ENABLE_COLORS=0

if [[ "${NO_COLOR:-}" != "1" ]]; then
  if [[ -t 1 && -n "${TERM:-}" && "${TERM:-}" != "dumb" ]]; then
    if command -v tput >/dev/null 2>&1; then
      _tput_colors="$(tput colors 2>/dev/null || echo 0)"
      if [[ "${_tput_colors}" =~ ^[0-9]+$ ]] && (( _tput_colors >= 8 )); then
        ENABLE_COLORS=1
      fi
    else
      ENABLE_COLORS=1
    fi
  fi
fi

if (( ENABLE_COLORS )); then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'

  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
  C_MAGENTA=$'\033[35m'
else
  C_RESET=""; C_DIM=""; C_BOLD=""
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_MAGENTA=""
fi

# Compute best available UTF-8 locale once (avoids repeated locale -a calls)
_CACHED_SED_LOCALE="C"
if locale -a 2>/dev/null | grep -qiE '^(C\.UTF-8|en_US\.UTF-8|pt_BR\.UTF-8)$'; then
    if locale -a 2>/dev/null | grep -qi '^C\.UTF-8$'; then
        _CACHED_SED_LOCALE="C.UTF-8"
    elif locale -a 2>/dev/null | grep -qi '^en_US\.UTF-8$'; then
        _CACHED_SED_LOCALE="en_US.UTF-8"
    else
        _CACHED_SED_LOCALE="pt_BR.UTF-8"
    fi
fi

# =========================================================================
# Terminal Initialization & Screen Clear (MAXIMUM COMPATIBILITY)
# =========================================================================
init_terminal_safe() {
    # Silently fail in non-interactive environments
    [[ -t 1 ]] || return 0
    
    # Only use widely supported commands
    clear 2>/dev/null || printf '\033[2J\033[H' 2>/dev/null || true
    
    return 0
}

init_terminal_safe || true

# -------------------------------------------------------------------------
# Log message sanitizer - replaces emojis with ASCII equivalents + colorization
# -------------------------------------------------------------------------
sanitize_log_msg() {
    # shellcheck disable=SC2086
    LC_ALL="$_CACHED_SED_LOCALE" sed $SED_EXT '
        # Warnings / Alerts
        s/⚠|⚠️|❗|❕|🚨|📛|🧯|🔥|💣|🧨/[!]/g;
        # Informational / Neutral
        s/ℹ|ℹ️|✔|🧵|🕒|📌|📡|🌐|💡|🧬|🧭|⏰|🧾|🪪|🧠|🪶|🔢|💬|📘|🔋|🧮|🟡/[i]/g;
        # Operational / Progress / Configuration
        s/📋|🖥️|🖥|🔁|🔧|🛠|📄|🛠️|🧩|🏷|💾|♻|🚚|⚙️|⚙|🏷️|🧹|🔗|🔌|🔄|↪|🛡️|🧱|🗂|🗂️|🧰|🛡|📦|📎|🪄/[>]/g;
        # Errors / Failures
        s/🛑|🚫|❌|🪫/[x]/g;
        # Success / Completion
        s/🔑|🔐|✅|🌟|🔒|➕|🚀|🔓/[+]/g;
        # Lookup / Tests
        s/🔍|🧪|🔎|⏳/[*]/g;
        # Neutral separators
        s/🚪/[-]/g;
        # Remove invisible variation selectors
        s/\ufe0f//g
    '
}

# -------------------------------------------------------------------------
# Colorize log tags based on content
# -------------------------------------------------------------------------
colorize_tag() {
    local msg="$1"
    
    if (( ENABLE_COLORS == 0 )); then
        echo "$msg"
        return
    fi
    
    # Colorize tags based on type
    msg="${msg//\[x\]/${C_RED}[x]${C_RESET}}"      # Errors
    msg="${msg//\[!\]/${C_YELLOW}[!]${C_RESET}}"   # Warnings
    msg="${msg//\[+\]/${C_GREEN}[+]${C_RESET}}"    # Success
    msg="${msg//\[i\]/${C_BLUE}[i]${C_RESET}}"     # Info
    msg="${msg//\[>\]/${C_CYAN}[>]${C_RESET}}"     # Operations
    msg="${msg//\[\*\]/${C_MAGENTA}[*]${C_RESET}}" # Tests/Lookup
    
    echo "$msg"
}

# Log functions: ALL output goes to stderr (never pollute stdout)
log_info() {
    local msg="$1"
    local ts="${C_DIM}[$(date '+%F %T')]${C_RESET}"

    # Fast path: skip sanitization if no emoji bytes (0xE2-0xF0 range)
    if [[ "$msg" == *$'\xe2'* || "$msg" == *$'\xf0'* ]]; then
        msg="$(sanitize_log_msg <<< "$msg")"
    fi

    if (( ENABLE_COLORS )); then
        msg="${msg//\[x\]/${C_RED}[x]${C_RESET}}"
        msg="${msg//\[!\]/${C_YELLOW}[!]${C_RESET}}"
        msg="${msg//\[+\]/${C_GREEN}[+]${C_RESET}}"
        msg="${msg//\[i\]/${C_BLUE}[i]${C_RESET}}"
        msg="${msg//\[>\]/${C_CYAN}[>]${C_RESET}}"
        msg="${msg//\[\*\]/${C_MAGENTA}[*]${C_RESET}}"
    fi

    echo "${ts} ${msg}" >&2
}

log_error() {
    local msg="$1"
    local code="${2:-1}"
    local ts="${C_DIM}[$(date '+%F %T')]${C_RESET}"
    
    trap - ERR
    
    local line1="${ts} ${C_RED}[x]${C_RESET} ${C_BOLD}[ERROR]${C_RESET} $msg"
    local line2="${ts} ${C_BLUE}[i]${C_RESET} Exiting with code $code"
    
    line1="$(sanitize_log_msg <<< "$line1")"
    line2="$(sanitize_log_msg <<< "$line2")"
    
    echo "$line1" >&2
    echo "$line2" >&2
    
    sync; sleep 0.05
    exit "$code"
}

# -------------------------------------------------------------------------
# Read wrapper with safe emoji sanitization
# -------------------------------------------------------------------------
read_sanitized() {
    local prompt sanitized var_name ts
    prompt="${1:-}"
    var_name="${2:-}"
    
    [[ -z "$var_name" ]] && log_error "read_sanitized: missing var_name" 1
    
    ts="${C_DIM}[$(date '+%F %T')]${C_RESET}"
    sanitized="$(sanitize_log_msg <<< "$prompt")"
    sanitized="$(colorize_tag "$sanitized")"
    
    # Use declare -n for safe reference under set -u
    local -n __var_ref="$var_name"
    read -rp "${ts} ${sanitized}" __var_ref
}

# -------------------------------------------------------------------------
# Utility: Print a safe divider, resistant to SSH/tmux/resize mismatches.
# -------------------------------------------------------------------------
print_divider() {
    local cols

    # Terminal width detection with multiple fallbacks
    cols=$(tput cols 2>/dev/null) || \
    cols=$(stty size 2>/dev/null | awk '{print $2}') || \
    cols=""

    # Safety threshold — also catches non-numeric values
    [[ "$cols" =~ ^[0-9]+$ && "$cols" -ge 20 ]] || cols=80

    # Divider generation + sync (flush tee pipeline)
    sync
    printf '%s' "$C_DIM"
    printf '%*s\n' "$cols" '' | tr ' ' '-' >&2
    printf '%s' "$C_RESET"
}

# -------------------------------------------------------------------------
# Validate AD group name (sAMAccountName compatible)
# -------------------------------------------------------------------------
validate_ad_group_name() {
    local name="$1"
    local context="${2:-group}"

    # Empty is valid (will use default)
    [[ -z "$name" ]] && return 0

    # Check length (sAMAccountName max 256, but practical limit is 64)
    if [[ ${#name} -gt 64 ]]; then
        log_info "⚠️ ${context} name too long (max 64 chars): $name"
        return 1
    fi

    # Check valid characters (AD sAMAccountName allows: A-Z a-z 0-9 . _ - @ $ #)
    # We restrict to: A-Z a-z 0-9 . _ - (safer subset)
    if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then
        log_info "⚠️ ${context} contains invalid characters: $name"
        log_info "   Allowed: letters, digits, dot (.), underscore (_), hyphen (-)"
        return 1
    fi

    # Reserved prefixes check (optional warning)
    if [[ "$name" =~ ^(CN|OU|DC)= ]]; then
        log_info "⚠️ ${context} starts with LDAP DN prefix: $name"
        return 1
    fi

    # Cannot start or end with hyphen or dot (AD restriction)
    if [[ "$name" =~ ^[-.]|[-.]$ ]]; then
        log_info "⚠️ ${context} cannot start/end with hyphen or dot: $name"
        return 1
    fi

    return 0
}

# LDAP filter escaping per RFC 4515: escape * ( ) \ NUL as \XX hex
ldap_escape_filter() {
    local input="$1"
    local output=""
    local char
    local i

    for (( i=0; i<${#input}; i++ )); do
        char="${input:$i:1}"
        case "$char" in
            '(')   output+='\28' ;;
            ')')   output+='\29' ;;
            \\)    output+='\5c' ;;
            '*')   output+='\2a' ;;
            $'\0') output+='\00' ;;
            *)     output+="$char" ;;
        esac
    done

    printf '%s' "$output"
}

# Escape ERE (Extended Regular Expression) metacharacters for safe use in regex patterns
regex_escape_ere() {
    local s="$1"
    # Escape backslash first (prevents double-escaping other characters)
    s="${s//\\/\\\\}"
    s="${s//./\\.}"
    s="${s//\[/\\[}"
    s="${s//\]/\\]}"
    s="${s//\*/\\*}"
    s="${s//^/\\^}"
    s="${s//$/\\$}"
    s="${s//+/\\+}"
    s="${s//\?/\\?}"
    s="${s//(/\\(}"
    s="${s//)/\\)}"
    s="${s//\{/\\{}"
    s="${s//\}/\\}}"
    s="${s//|/\\|}"
    printf '%s' "$s"
}

# Validate DNS domain name (RFC 1035: FQDN, alphanumeric+hyphen, no leading/trailing dots/hyphens)
validate_domain_name() {
    local domain="$1"

    [[ -z "$domain" ]] && return 1
    (( ${#domain} > 255 )) && { log_info "⚠ Domain name too long (max 255): $domain"; return 1; }
    [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] && { log_info "⚠ Invalid domain format: $domain"; return 1; }
    [[ ! "$domain" =~ \. ]] && { log_info "⚠ Domain must be FQDN (e.g., example.com)"; return 1; }
    return 0
}

# Validate AD username: alphanumeric+._-, no leading/trailing dots/hyphens, max 256 chars
validate_username() {
    local username="${1:-}" user_part
    
    [[ -z "$username" ]] && return 1
    (( ${#username} > 256 )) && { log_info "⚠ Username too long (max 256): $username"; return 1; }

    # Strip domain prefix: DOMAIN\user or user@domain
    if [[ "$username" =~ ^[^\\]+\\(.+)$ ]]; then
        user_part="${BASH_REMATCH[1]}"
    elif [[ "$username" =~ ^([^@]+)@.+$ ]]; then
        user_part="${BASH_REMATCH[1]}"
    else
        # If no prefix, use the username as-is
        user_part="$username"
    fi

    [[ ! "$user_part" =~ ^[A-Za-z0-9._-]+$ ]] && { log_info "⚠ Username has invalid characters: $user_part"; return 1; }
    
    [[ "${user_part:-}" =~ ^[.-] ]] && { log_info "⚠ Username cannot start with . or -: $user_part"; return 1; }
    [[ "${user_part:-}" =~ [.-]$ ]] && { log_info "⚠ Username cannot end with . or -: $user_part"; return 1; }

    return 0
}

# -------------------------------------------------------------------------
# Global error trap - catches any unexpected command failure
# -------------------------------------------------------------------------
ERROR_TRAP_CMD='log_error "Unexpected error at line $LINENO in \"$BASH_COMMAND\"" $?'
trap "$ERROR_TRAP_CMD" ERR

# -------------------------------------------------------------------------
# Privilege check
# -------------------------------------------------------------------------
if (( EUID != 0 )); then
    log_error "Must run as root"
fi

# -------------------------------------------------------------------------
# Hostname validation (15-char NetBIOS limit + valid chars)
# -------------------------------------------------------------------------
HOSTNAME_SHORT=$(hostname -s)
HOSTNAME_LEN=${#HOSTNAME_SHORT}

if (( HOSTNAME_LEN > 15 )); then
    log_info  "⚠ Active Directory allows a maximum of 15 characters for computer names (NetBIOS limit)."
    log_info  "🛑 ACTION REQUIRED:"
    echo ""
    echo "    1. Rename this host to a shorter name (≤15 chars)."
    echo "       Example: sudo hostnamectl set-hostname <new_hostname>"
    echo ""
    echo "    2. Log off and back on (or restart the session) to apply the change."
    echo ""
    log_error "Hostname '$HOSTNAME_SHORT' has ${HOSTNAME_LEN} characters and cannot be used for domain join."
fi

if [[ ! "$HOSTNAME_SHORT" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$ ]]; then
    log_error "Hostname '$HOSTNAME_SHORT' contains invalid characters for AD join. Use only letters, digits, and hyphen (-)." 1
fi

DRY_RUN=false
NONINTERACTIVE=false
VERBOSE=false
VALIDATE_ONLY=false

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)    DRY_RUN=true ;;
        --yes|-y)     NONINTERACTIVE=true ;;
        --verbose|-v) VERBOSE=true ;;
        --validate-only) VALIDATE_ONLY=true ;;
        *)
            log_error "Unknown option: $1" 1
            ;;
    esac
    shift
done

# -------------------------------------------------------------------------
# Default values for optional flags (safe for set -u environments)
# -------------------------------------------------------------------------
YES="${YES:-false}"
FORCE="${FORCE:-false}"
DRY_RUN="${DRY_RUN:-false}"
NONINTERACTIVE="${NONINTERACTIVE:-false}"
VERBOSE="${VERBOSE:-false}"
VALIDATE_ONLY="${VALIDATE_ONLY:-false}"
LDAP_TIMEOUT="${LDAP_TIMEOUT:-30}"
KRB5_KEYTAB="${KRB5_KEYTAB:-/etc/krb5.keytab}"

# -------------------------------------------------------------------------
# Logging + Backup roots (after flags/defaults)
# - Logs go to /var/log/linux-ad-domain-join/ with timestamped filenames
# - VALIDATE_ONLY uses /tmp to keep the run non-invasive
# -------------------------------------------------------------------------
LOG_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_HOSTNAME="$(hostname -s 2>/dev/null || echo "localhost")"

if $VALIDATE_ONLY || $DRY_RUN; then
    LOG_DIR="${LOG_DIR:-/tmp/linux-ad-domain-join}"
    BACKUP_ROOT="${BACKUP_ROOT:-/tmp/linux-ad-domain-join-backups}"
else
    LOG_DIR="${LOG_DIR:-/var/log/linux-ad-domain-join}"
    BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/linux-ad-domain-join}"
fi

# Build timestamped log filename
LOG_FILE="${LOG_DIR}/${LOG_TIMESTAMP}_${LOG_HOSTNAME}.log"

# Ensure log directory exists (best-effort) + ensure log is writable
mkdir -p "$LOG_DIR" 2>/dev/null || true
if ! : >>"$LOG_FILE" 2>/dev/null; then
    # Fallback if /var/log is not writable
    LOG_DIR="/tmp/linux-ad-domain-join"
    LOG_FILE="${LOG_DIR}/${LOG_TIMESTAMP}_${LOG_HOSTNAME}.log"
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    : >>"$LOG_FILE" 2>/dev/null || { echo "[$(date '+%F %T')] [ERROR] Cannot write LOG_FILE=$LOG_FILE" >&2; exit 1; }
fi

# Prune old log files (keep last 30 logs)
LOG_RETENTION="${LOG_RETENTION:-30}"
_prune_old_logs() {
    local log_dir="$1" keep="$2"
    [[ -d "$log_dir" ]] || return 0
    local count
    count="$(find "$log_dir" -maxdepth 1 -type f -name '*.log' 2>/dev/null | wc -l)"
    (( count > keep )) || return 0
    # NUL-delimited to handle paths with spaces safely
    find "$log_dir" -maxdepth 1 -type f -name '*.log' -printf '%T@\t%p\0' 2>/dev/null \
        | sort -z -t$'\t' -k1,1n | head -z -n "$(( count - keep ))" \
        | while IFS=$'\t' read -r -d '' _ts old_log; do rm -f -- "$old_log" 2>/dev/null; done
}
_prune_old_logs "$LOG_DIR" "$LOG_RETENTION"

# -------------------------------------------------------------------------
# Single-instance lock (prevents concurrent executions)
# - Must run before log truncation to avoid clobbering an active run log.
# -------------------------------------------------------------------------
LOCK_BASE="/run/lock"
[[ -d "$LOCK_BASE" ]] || LOCK_BASE="/var/lock"
mkdir -p "$LOCK_BASE" 2>/dev/null || true

LOCK_FILE="${LOCK_BASE}/linux-ad-domain-join.lock"
LOCK_DIR_FALLBACK="${LOCK_FILE}.d"
LOCK_MODE=""

if command -v flock >/dev/null 2>&1; then
    # Use an fd-based lock (auto-released on process exit).
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        echo "[$(date '+%F %T')] [ERROR] Another instance is already running (lock: $LOCK_FILE)" >&2
        exit 16
    fi
    # Store PID for troubleshooting (best-effort).
    printf '%s\n' "$$" 1>&200 2>/dev/null || true
    LOCK_MODE="flock"
else
    # Portable fallback: atomic mkdir lock with stale detection
    if ! mkdir "$LOCK_DIR_FALLBACK" 2>/dev/null; then
        # Check if the holder PID is still alive
        _lock_pid=""
        _lock_pid="$(cat "${LOCK_DIR_FALLBACK}/pid" 2>/dev/null || true)"
        if [[ -n "$_lock_pid" ]] && kill -0 "$_lock_pid" 2>/dev/null; then
            echo "[$(date '+%F %T')] [ERROR] Another instance is already running (PID $_lock_pid, lock: $LOCK_DIR_FALLBACK)" >&2
            exit 16
        fi
        # Stale lock: previous run crashed without cleanup
        echo "[$(date '+%F %T')] [WARN] Removing stale lock from PID ${_lock_pid:-unknown} (lock: $LOCK_DIR_FALLBACK)" >&2
        rm -rf "$LOCK_DIR_FALLBACK" 2>/dev/null || true
        if ! mkdir "$LOCK_DIR_FALLBACK" 2>/dev/null; then
            echo "[$(date '+%F %T')] [ERROR] Failed to acquire lock after stale cleanup (lock: $LOCK_DIR_FALLBACK)" >&2
            exit 16
        fi
    fi
    printf '%s\n' "$$" >"${LOCK_DIR_FALLBACK}/pid" 2>/dev/null || true
    LOCK_MODE="mkdir"
fi

# Redirect stdout/stderr to log; mirror to console only if tee exists
if command -v tee >/dev/null 2>&1; then
    : >"$LOG_FILE" 2>/dev/null || true
    exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)
    # Brief pause to let tee process substitutions initialize
    sleep 0.1
    # Verify log pipeline is functional (catches disk-full / permission issues early)
    if ! echo "[$(date '+%F %T')] [i] Log pipeline initialized" >>"$LOG_FILE" 2>/dev/null; then
        echo "[$(date '+%F %T')] [!] Warning: LOG_FILE may not be writable ($LOG_FILE)" >&2
    fi
else
    : >"$LOG_FILE" 2>/dev/null || true
    exec >>"$LOG_FILE" 2>&1
fi

log_info "💾 Log file: $LOG_FILE"

# -------------------------------------------------------------------------
# Backup root (centralized) - one directory per execution
# -------------------------------------------------------------------------
BACKUP_RUN_ID="$(date +%Y%m%d_%H%M%S)_$(hostname -s)_$$"
BACKUP_DIR="${BACKUP_ROOT}/${BACKUP_RUN_ID}"

to_lower() { echo "$1" | tr '[:upper:]' '[:lower:]'; }

# Trim leading/trailing whitespace (pure bash, xargs-safe)
trim_ws() {
    local v="$1"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    printf '%s' "$v"
}

# Standardized mktemp wrapper: validates result, consistent errors, works with set -eu
safe_mktemp() {
    local tmpfile template="${1:-}"
    tmpfile="$(mktemp "$@" 2>&1)" || log_error "mktemp failed${template:+ (template: $template)}" 1
    [[ -z "$tmpfile" ]] && log_error "mktemp returned empty path" 1
    printf '%s' "$tmpfile"
}

trim_line() {
    # shellcheck disable=SC2086  # SED_EXT must be expanded as a flag (-E/-r)
    sed $SED_EXT \
        -e 's/^[[:space:]]+//' \
        -e 's/^[[:space:]]*[-*•][[:space:]]+//' \
        -e 's/[[:space:]]+$//' \
        -e '/[Cc]url error/ s/[[:space:]]\[[^]]*][[:space:]]*$//'
}

# Service mgmt wrapper: systemctl -> service -> /etc/init.d/ (auto-detects; supports start/stop/restart/enable/disable/status)
service_control() {
    local svc_name="$1"
    local action="$2"
    local rc=0

    # Modern systemd-based systems (RHEL 7+, Ubuntu 16.04+, Debian 8+)
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        case "$action" in
            start)   systemctl start "$svc_name" || rc=$? ;;
            stop)    systemctl stop "$svc_name" || rc=$? ;;
            restart) systemctl restart "$svc_name" || rc=$? ;;
            enable)  systemctl enable "$svc_name" || rc=$? ;;
            disable) systemctl disable "$svc_name" || rc=$? ;;
            status)  systemctl status "$svc_name" || rc=$? ;;
            enable-now) systemctl enable --now "$svc_name" || rc=$? ;;
            *)       log_error "Unknown service action: $action" 1 ;;
        esac
        return $rc
    fi

    # Legacy systems with service wrapper (RHEL 6, older Ubuntu/Debian)
    if command -v service >/dev/null 2>&1; then
        case "$action" in
            start|stop|restart|status)
                service "$svc_name" "$action" || rc=$?
                ;;
            enable)
                # Use chkconfig on RHEL-like systems
                if command -v chkconfig >/dev/null 2>&1; then
                    chkconfig "$svc_name" on || rc=$?
                # Use update-rc.d on Debian-like systems
                elif command -v update-rc.d >/dev/null 2>&1; then
                    update-rc.d "$svc_name" defaults || rc=$?
                    update-rc.d "$svc_name" enable || rc=$?
                else
                    log_info "⚠ Cannot enable service $svc_name: no chkconfig or update-rc.d found"
                    rc=1
                fi
                ;;
            disable)
                if command -v chkconfig >/dev/null 2>&1; then
                    chkconfig "$svc_name" off || rc=$?
                elif command -v update-rc.d >/dev/null 2>&1; then
                    update-rc.d "$svc_name" disable || rc=$?
                else
                    log_info "⚠ Cannot disable service $svc_name: no chkconfig or update-rc.d found"
                    rc=1
                fi
                ;;
            enable-now)
                # Enable and start in two steps for legacy systems
                service_control "$svc_name" enable || rc=$?
                service_control "$svc_name" start || rc=$?
                ;;
            *)
                log_error "Unknown service action: $action" 1
                ;;
        esac
        return $rc
    fi

    # Direct init.d script invocation (last resort for very old systems)
    if [[ -x "/etc/init.d/$svc_name" ]]; then
        case "$action" in
            start|stop|restart|status)
                "/etc/init.d/$svc_name" "$action" || rc=$?
                ;;
            enable|disable|enable-now)
                log_info "⚠ Service $svc_name must be enabled manually (no service management tools found)"
                if [[ "$action" == "enable-now" ]]; then
                    "/etc/init.d/$svc_name" start || true
                fi
                rc=0
                ;;
            *)
                log_error "Unknown service action: $action" 1
                ;;
        esac
        return $rc
    fi

    # No service management method available
    log_error "Cannot manage service $svc_name: no systemctl, service, or init.d script found" 1
}

# Init timestamped backup dir (0700, one per run, suppressed in VALIDATE_ONLY/DRY_RUN)
init_backup_dir() {
    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Backup directory creation suppressed: $BACKUP_DIR"
        return 0
    fi

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would create backup directory: $BACKUP_DIR"
        return 0
    fi

    mkdir -p -- "$BACKUP_DIR" || log_error "Failed to create backup directory: $BACKUP_DIR" 30
    chmod 700 -- "$BACKUP_DIR" 2>/dev/null || true
    log_info "💾 Backup directory: $BACKUP_DIR"
}

# Prune old backups (keep N newest, best-effort, safe under set -eEuo)
backup_prune_old_runs() {
    local keep="${1:-20}"

    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Backup pruning suppressed"
        return 0
    fi

    $DRY_RUN && { log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would prune backups in $BACKUP_ROOT (keep last $keep)"; return 0; }
    [[ -d "$BACKUP_ROOT" ]] || return 0

    local tmp_list
    tmp_list="$(safe_mktemp)" || return 0

    # List subdirs by mtime (newest first). No failure if empty.
    find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
      | sort -nr >"$tmp_list" || true

    local total
    total="$(wc -l <"$tmp_list" 2>/dev/null || echo 0)"
    [[ "$total" =~ ^[0-9]+$ ]] || total=0

    if (( total > keep )); then
        tail -n +"$((keep+1))" "$tmp_list" | awk '{print $2}' | while IFS= read -r d || [[ -n "$d" ]]; do
            if [[ -n "$d" ]]; then
                rm -rf -- "$d" 2>/dev/null || true
            fi
        done
    fi

    rm -f "$tmp_list"
}

# initialize backup directory
init_backup_dir

# delete old backups, keep only last N runs
backup_prune_old_runs 20

# -------------------------------------------------------------------------
# Session timeout inputs (SSH + Shell)
# -------------------------------------------------------------------------

is_uint() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

require_uint_range() {
    local name="$1" val="$2" min="$3" max="$4"
    is_uint "$val" || log_error "$name must be an integer (seconds). Got: '$val'" 1
    (( val >= min && val <= max )) || log_error "$name must be between $min and $max seconds. Got: $val" 1
}

normalize_yes_no() {
    local v
    v="$(to_lower "${1:-}")"
    # Trim leading/trailing whitespace without xargs (safe for special chars)
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    case "$v" in
        y|yes|s|sim|true|1|on)    echo "yes" ;;
        n|no|nao|não|false|0|off) echo "no"  ;;
        *) echo "" ;;
    esac
}

# Remove/disable TMOUT duplicates inside /etc/profile.d to avoid conflicts
disable_tmout_in_profile_d() {
    local f bk

    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Suppressed TMOUT cleanup in /etc/profile.d (non-invasive mode)"
        return 0
    fi

    shopt -s nullglob

    for f in /etc/profile.d/*.sh; do
        # detect common TMOUT patterns (assign/export/readonly)
        grep -qE '^[[:space:]]*(readonly[[:space:]]+)?TMOUT=|^[[:space:]]*export[[:space:]]+TMOUT\b|^[[:space:]]*readonly[[:space:]]+TMOUT\b' "$f" || continue

        # Backup before modifying
        backup_file "$f" bk

        if $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would disable TMOUT lines in $f"
            continue
        fi

        # Comment only TMOUT-related lines (do not destroy file logic)
        cmd_must sed -i $SED_EXT \
            -e 's/\r$//' \
            -e '/^[[:space:]]*(readonly[[:space:]]+)?TMOUT=/{s/^/# disabled-by-linux-ad-domain-join: /;}' \
            -e '/^[[:space:]]*export[[:space:]]+TMOUT\b/{s/^/# disabled-by-linux-ad-domain-join: /;}' \
            -e '/^[[:space:]]*readonly[[:space:]]+TMOUT\b/{s/^/# disabled-by-linux-ad-domain-join: /;}' \
            "$f"

        log_info "🧹 Disabled existing TMOUT lines in $f"
    done

    shopt -u nullglob
}

apply_tmout_profile() {
    local timeout="$1"
    local target="/etc/profile.d/99-session-timeout.sh"

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would write $target enforcing TMOUT=$timeout"
        return 0
    fi

    install -m 0644 -D /dev/stdin "$target" <<EOF
# Generated by linux-ad-domain-join.sh on $(date '+%F %T')
# Session idle timeout (seconds) for interactive shells.

# Only for interactive shells
case "\$-" in
  *i*) ;;
  *) return 0 ;;
esac

TMOUT=$timeout
export TMOUT
readonly TMOUT
EOF

    log_info "✅ TMOUT enforced via $target (TMOUT=$timeout seconds)"
}

sshd_set_directive_dedup() {
    # Ensures the directive is set once in the global section (before any Match blocks),
    # while preserving any Match-specific overrides. Preserves perms/owner.
    local key="$1" value="$2" file="$3"
    local tmp

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would set global '$key $value' in $file (deduplicated, preserving Match blocks)"
        return 0
    fi

    tmp="$(safe_mktemp "${file}.XXXXXX")"

    awk -v k="$key" -v v="$value" '
        BEGIN { in_match=0; inserted=0 }
        /^[[:space:]]*Match[[:space:]]+/ {
            if (inserted==0) { print k " " v; inserted=1 }
            in_match=1
            print
            next
        }
        {
            if (in_match==0) {
                line = $0
                sub(/^[[:space:]]+/, "", line)
                n = split(line, parts, /[[:space:]]+/)
                if (n >= 1 && parts[1] == k) next
            }
            print
        }
        END { if (inserted==0) print k " " v }
    ' "$file" >"$tmp" || { rm -f "$tmp"; log_error "Failed to render new sshd_config content for $file" 1; }

    chown --reference="$file" "$tmp" 2>/dev/null || true
    chmod --reference="$file" "$tmp" 2>/dev/null || true

    mv -f "$tmp" "$file" || { rm -f "$tmp"; log_error "Failed to install updated $file" 1; }
}

validate_sshd_config_or_die() {
    local file="$1"

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would validate sshd config: sshd -t -f $file"
        return 0
    fi

    local sshd_bin=""
    if command -v sshd >/dev/null 2>&1; then
        sshd_bin="$(command -v sshd)"
    elif [[ -x /usr/sbin/sshd ]]; then
        sshd_bin="/usr/sbin/sshd"
    elif [[ -x /sbin/sshd ]]; then
        sshd_bin="/sbin/sshd"
    fi

    [[ -z "$sshd_bin" ]] && log_error "sshd binary not found; cannot validate $file safely" 1

    # Capture stderr/stdout from sshd -t for debugging without tripping `set -e`
    local had_errexit=false
    [[ $- == *e* ]] && had_errexit=true

    local sshd_check_output=""
    local sshd_rc=0

    set +e
    sshd_check_output="$("$sshd_bin" -t -f "$file" 2>&1)"
    sshd_rc=$?
    $had_errexit && set -e

    if (( sshd_rc != 0 )); then
        log_info "❌ sshd config validation failed for: $file"
        if [[ -n "$sshd_check_output" ]]; then
            while IFS= read -r _sshd_line; do
                [[ -n "$_sshd_line" ]] && log_info "   sshd -t: $_sshd_line"
            done <<< "$sshd_check_output"
        fi

        # Restore latest backup and refuse to proceed
        local rel="${file#/}"
        local backup_path="${BACKUP_DIR}/${rel}"

        if [[ -f "$backup_path" ]]; then
            log_info "Restoring backup: $backup_path -> $file"
            cp -f "$backup_path" "$file" || log_error "Failed to restore backup from $backup_path" 1
            log_error "sshd_config restored from backup. Refusing to proceed." 1
        else
            log_error "No backup found at $backup_path. Refusing to proceed with broken config." 1
        fi
    fi
}

detect_service_unit() {
    local u
    command -v systemctl >/dev/null 2>&1 || { echo ""; return 1; }

    for u in "$@"; do
        if systemctl list-unit-files --no-legend --no-pager "$u" 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
            echo "$u"; return 0
        fi
        # Also check direct file existence (for masked/static units)
        if [[ -f "/etc/systemd/system/$u" || -f "/usr/lib/systemd/system/$u" || -f "/lib/systemd/system/$u" ]]; then
            echo "$u"; return 0
        fi
    done

    echo ""
    return 1
}

# Extract the first real command (ignores env wrapper, flags, and VAR=VAL)
first_bin_from_cmd() {
    local arg
    local timeout_skip_next_nonflag=false

    for arg in "$@"; do
        # wrappers comuns (ignorar)
        case "$arg" in
            env|command|sudo|nohup|setsid|nice|ionice)
                continue
                ;;
            timeout)
                timeout_skip_next_nonflag=true
                continue
                ;;
        esac

        # timeout: skip options (-k, --foreground, etc) and duration (e.g., 90, 90s, 0.5, 2m)
        if $timeout_skip_next_nonflag; then
            if [[ "$arg" == -* ]]; then
                continue
            fi
            # Likely a duration argument
            if [[ "$arg" =~ ^[0-9]+([.][0-9]+)?([smhd])?$ ]]; then
                timeout_skip_next_nonflag=false
                continue
            fi
            # If it didn't look like a duration, then it's the real binary
            timeout_skip_next_nonflag=false
        fi

        [[ "$arg" == -- ]] && continue
        [[ "$arg" == -* ]] && continue
        [[ "$arg" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && continue

        echo "$arg"
        return 0
    done

    echo ""
    return 1
}

# Package manager error parser
parse_pkg_error() {
    local log="$1" bin="$2"

    # GPG / Signature
    if grep -qiE '(GPG check FAILED|NO_PUBKEY|Signature verification failed|public key .* not installed|bad signature)' "$log"; then
        log_info "❗ Error: GPG/Signature verification failed"

        # DNF/YUM: “Public key for ... is not installed”
        local pk_dnf
        pk_dnf=$(grep -m1 -E 'Public key for .* is not installed' "$log" | trim_line)
        [[ -n "$pk_dnf" ]] && log_info "🔑 $pk_dnf"

        # APT: “NO_PUBKEY <KEYID>”
        local pk_apt
        pk_apt=$(grep -m1 -oE 'NO_PUBKEY[[:space:]]+[0-9A-Fa-f]+' "$log" | trim_line)
        [[ -n "$pk_apt" ]] && log_info "🔑 Missing key: ${pk_apt#NO_PUBKEY }"

        # Common Zypper messages
        local zyp
        zyp=$(grep -m1 -E 'Signature verification failed|Public key is not installed' "$log" | trim_line)
        [[ -n "$zyp" ]] && log_info "🔑 $zyp"

        # DNF: “GPG Keys are configured as: …”
        local keycfg
        keycfg=$(grep -m1 -E 'GPG Keys are configured as:' "$log")
        [[ -n "$keycfg" ]] && log_info "ℹ $keycfg"
		
        log_info "💡 Import the correct repo GPG key and retry."
        return 0
    fi

    # Missing package / wrong name
    if grep -qiE '(No match for argument|nothing provides|Unable to locate package|has no installation candidate|not found in package names)' "$log"; then
        local l
        l=$(grep -m1 -Ei 'No match for argument|nothing provides|Unable to locate package|has no installation candidate|not found in package names' "$log" | trim_line)
        log_info "❗ $l"
        log_info "💡 Check package name and enabled repos."
        return 0
    fi

    # Unresolved dependencies
    if grep -qiE '(conflict(s)?|conflicting requests|unmet dependencies|broken packages|requires.*but none of the providers can be installed)' "$log"; then
        local l
        l=$(grep -m1 -Ei 'conflict(s)?|conflicting requests|unmet dependencies|broken packages|requires.*none of the providers' "$log" | trim_line)
        log_info "❗ $l"
        case "$bin" in
          apt|apt-get) log_info "💡 Try: apt-get -f install  OR  apt-get install --fix-broken";;
          dnf|yum)     log_info "💡 Try: dnf repoquery --deplist <pkg>  OR  dnf install --best --allowerasing";;
          zypper)      log_info "💡 Try: zypper in --force-resolution <pkg>";;
        esac
        return 0
    fi

    # Repository / network issues
    if grep -qiE '(Cannot find a valid baseurl|No URLs in mirrorlist|Could not resolve host|Temporary failure resolving|Connection timed out|SSL certificate problem|curl error \([0-9]+\)|404 Not Found|Valid metadata not found|Repository .* is invalid|repodata.* does not match checksum)' "$log"; then
        local l
        l=$(grep -m1 -Ei 'Cannot find a valid baseurl|No URLs in mirrorlist|Could not resolve host|Temporary failure resolving|Connection timed out|SSL certificate problem|curl error \([0-9]+\)|404 Not Found|Valid metadata not found|Repository .* is invalid|repodata.* does not match checksum' "$log" | trim_line)
        log_info "❗ $l"
        case "$bin" in
          apt|apt-get) log_info "💡 Try: apt-get update (or fix sources.list/proxy/CA)";;
          dnf|yum)     log_info "💡 Try: dnf clean all && dnf makecache (check baseurl/proxy/CA)";;
          zypper)      log_info "💡 Try: zypper refresh (check repo URL/proxy/CA)";;
        esac
        return 0
    fi

    # Fallback: first line "Error/Problem/Failed/Failure/E:"
    local l
    l=$(grep -m1 -E '^(Error:|Problem:|Failed|Failure|E:)' "$log" | trim_line)
    [[ -n "$l" ]] && { log_info "❗ $l"; return 0; }

    return 1
}

print_cmd_quoted() {
    local a out=()
    for a in "$@"; do
        out+=( "$(printf '%q' "$a")" )
    done
    printf '%s' "${out[*]}"
}

_cmd_bin_exists() {
    # Accepts either "name" or "/path/name"
    local b="$1"
    [[ -z "$b" ]] && return 1
    if [[ "$b" == */* ]]; then
        [[ -x "$b" ]]
    else
        command -v "$b" >/dev/null 2>&1
    fi
}

_cmd_run_capture() {
    # Internal: runs a command (array), captures stdout+stderr into tmpfile, returns RC.
    # Usage: _cmd_run_capture <tmp_out_path> <cmd...>
    local tmp_out="$1"; shift
    local -a cmd=( "$@" )

    # Force C locale for predictable parsing
    LC_ALL=C LANG=C "${cmd[@]}" >"$tmp_out" 2>&1
    return $?
}

is_mutating_cmd() {
    # Determines if a command can modify the system. If yes, it will be suppressed in VALIDATE_ONLY mode.
    local first_bin="$1"; shift
    local -a args=( "$@" )

    # Typically mutating binaries
    case "$first_bin" in
        rm|mv|cp|install|chmod|chown|chgrp|ln|truncate|dd|tee|visudo|useradd|usermod|groupadd|groupmod|passwd)
            return 0
            ;;
        systemctl|service|chkconfig|update-rc.d)
            # start/stop/restart/enable/disable are mutating operations
            for a in "${args[@]}"; do
                case "$a" in
                    start|stop|restart|reload|enable|disable|mask|unmask|daemon-reload|daemon-reexec)
                        return 0
                        ;;
                esac
            done
            ;;
        sed)
            # sed -i is mutating (in-place edit)
            for a in "${args[@]}"; do
                [[ "$a" == -i* ]] && return 0
            done
            ;;
        hostnamectl)
            return 0
            ;;
        hostname)
            # Only mutating when setting hostname (rare here); reads are not mutating.
            for a in "${args[@]}"; do
                [[ "$a" == -* ]] && continue
                # If a non-flag argument exists, treat as mutating (hostname NEWNAME).
                return 0
            done
            return 1
            ;;
        realm)
            for a in "${args[@]}"; do
                case "$a" in
                    join|leave) return 0 ;;
                esac
            done
            ;;
        adcli)
            for a in "${args[@]}"; do
                case "$a" in
                    join) return 0 ;;
                esac
            done
            ;;
        authconfig|authselect|pam-auth-update|pam-config)
            return 0
            ;;
        ldapmodify)
            return 0
            ;;
        mkdir|rmdir|touch)
            return 0
            ;;
    esac

    return 1
}

cmd_run() {
    # Usage: cmd_run <cmd> [args...]
    # Non-fatal: returns command RC. Logs failures (classified for pkg managers).
    local -a cmd=( "$@" )
    local first_bin exec_bin tmp_out rc

    [[ ${#cmd[@]} -gt 0 ]] || { log_info "cmd_run(): empty command"; return 2; }

    exec_bin="${cmd[0]}"
    first_bin="$(first_bin_from_cmd "${cmd[@]}")"
    [[ -z "$first_bin" ]] && first_bin="$exec_bin"

    # VALIDATE_ONLY: suppress mutating commands (read-only mode)
    if $VALIDATE_ONLY; then
        if is_mutating_cmd "$first_bin" "${cmd[@]:1}"; then
            log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Suppressed mutating command: $(print_cmd_quoted "${cmd[@]}")"
            return 0
        fi
    fi

    if $DRY_RUN; then
        echo -n "[DRY-RUN] "
        print_cmd_quoted "${cmd[@]}"
        echo
        return 0
    fi

    # Validate the "real" binary, not just env-wrapper
    if ! _cmd_bin_exists "$first_bin"; then
        log_info "❗ Command not found: $first_bin"
        return 127
    fi

    # Auto-handle immutable attribute for in-place sed operations
    if [[ "$first_bin" == "sed" ]]; then
        local _imf
        while IFS= read -r _imf; do
            [[ -n "$_imf" ]] && _file_ensure_mutable "$_imf"
        done < <(_extract_sed_target_files "${cmd[@]}")
    fi

    if $VERBOSE; then
        log_info "Executing: $(print_cmd_quoted "${cmd[@]}")"
        if LC_ALL=C LANG=C "${cmd[@]}"; then
            return 0
        else
            rc=$?
            log_info "❗ Command failed (exit $rc): $(print_cmd_quoted "${cmd[@]}")"
            return "$rc"
        fi
    fi

    tmp_out="$(mktemp)" || { log_info "❗ mktemp failed (cannot capture command output)"; return 1; }
    if _cmd_run_capture "$tmp_out" "${cmd[@]}"; then
        rm -f "$tmp_out"
        return 0
    fi

    rc=$?

    # Classified output for package manager errors when applicable
    if ! parse_pkg_error "$tmp_out" "$first_bin"; then
        # Fallback: show last non-empty line (and keep it short)
        local last
        last="$(sed -n '/./p' "$tmp_out" | tail -n 1 | trim_line)"
        [[ -n "$last" ]] && log_info "❗ $last"
    fi

    rm -f "$tmp_out"
    return "$rc"
}

# -------------------------------------------------------------------------
# Strict-mode safe execution layer
# - cmd_run/cmd_run_in: keep as-is (they return RC)
# - cmd_try/cmd_try_in: NEVER propagate non-zero to the shell (safe under set -e)
# - cmd_must/cmd_must_in: fatal wrappers based on CMD_LAST_RC
# -------------------------------------------------------------------------

CMD_LAST_RC=0

cmd_try() {
    local rc=0
    local had_errexit=false
    local _prev_err_trap=""

    [[ $- == *e* ]] && had_errexit=true

    # Capture current ERR trap verbatim (not just existence)
    _prev_err_trap="$(trap -p ERR)" || true

    trap - ERR
    set +e

    cmd_run "$@"
    rc=$?

    $had_errexit && set -e

    if [[ -n "$_prev_err_trap" ]]; then
        eval "$_prev_err_trap"
    fi

    CMD_LAST_RC=$rc
    return "$rc"
}

cmd_must() {
    # Must not leak non-zero from cmd_try under `set -e`, otherwise ERR trap fires
    # before we can emit a descriptive message.
    cmd_try "$@" || true

    local rc="$CMD_LAST_RC"
    if (( rc != 0 )); then
        log_error "Command failed (rc=$rc): $(print_cmd_quoted "$@")" 1
    fi
    return 0
}

cmd_run_in() {
    # Usage: cmd_run_in <stdin_file> <cmd> [args...]
    # Non-fatal: returns command RC.
    local stdin_file="$1"
    shift

    local -a cmd=( "$@" )
    local first_bin exec_bin tmp_out rc

    [[ -r "$stdin_file" ]] || { log_info "❗ stdin file not readable: $stdin_file"; return 2; }
    [[ ${#cmd[@]} -gt 0 ]] || { log_info "cmd_run_in(): empty command"; return 2; }

    exec_bin="${cmd[0]}"
    first_bin="$(first_bin_from_cmd "${cmd[@]}")"
    [[ -z "$first_bin" ]] && first_bin="$exec_bin"

    if $VALIDATE_ONLY; then
        if is_mutating_cmd "$first_bin" "${cmd[@]:1}"; then
            log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Suppressed mutating command: $(print_cmd_quoted "${cmd[@]}") < $stdin_file"
            return 0
        fi
    fi

    if $DRY_RUN; then
        echo -n "[DRY-RUN] "
        print_cmd_quoted "${cmd[@]}"
        echo " < $stdin_file"
        return 0
    fi

    if ! _cmd_bin_exists "$first_bin"; then
        log_info "❗ Command not found: $first_bin"
        return 127
    fi

    if $VERBOSE; then
        log_info "Executing: $(print_cmd_quoted "${cmd[@]}") < $stdin_file"
        if LC_ALL=C LANG=C "${cmd[@]}" <"$stdin_file"; then
            return 0
        else
            rc=$?
            log_info "❗ Command failed (exit $rc): $(print_cmd_quoted "${cmd[@]}")"
            return "$rc"
        fi
    fi

    tmp_out="$(mktemp)" || { log_info "❗ mktemp failed (cannot capture command output)"; return 1; }
    if LC_ALL=C LANG=C "${cmd[@]}" <"$stdin_file" >"$tmp_out" 2>&1; then
        rm -f "$tmp_out"
        return 0
    fi

    rc=$?
    if ! parse_pkg_error "$tmp_out" "$first_bin"; then
        local last
        last="$(sed -n '/./p' "$tmp_out" | tail -n 1 | trim_line)"
        [[ -n "$last" ]] && log_info "❗ $last"
    fi

    rm -f "$tmp_out"
    return "$rc"
}

cmd_try_in() {
    # Usage: cmd_try_in <stdin_file> <cmd> [args...]
    local rc=0
    local had_errexit=false
    local _prev_err_trap=""

    [[ $- == *e* ]] && had_errexit=true

    # Capture current ERR trap verbatim (consistent with cmd_try)
    _prev_err_trap="$(trap -p ERR)" || true

    trap - ERR
    set +e

    cmd_run_in "$@"
    rc=$?

    $had_errexit && set -e

    if [[ -n "$_prev_err_trap" ]]; then
        eval "$_prev_err_trap"
    fi

    CMD_LAST_RC=$rc
    return 0
}

cmd_must_in() {
    # Usage: cmd_must_in <stdin_file> <cmd> [args...]
    cmd_try_in "$@"
    (( CMD_LAST_RC == 0 )) || log_error "Command failed: $(print_cmd_quoted "${@:2}") < ${1} (exit $CMD_LAST_RC)" "$CMD_LAST_RC"
    return 0
}

check_cmd() {
    command -v "$1" >/dev/null 2>&1 || log_error "Required command '$1' not found" 1
}

# -------------------------------------------------------------------------
# Safe wrapper for realm list (handles systems without realmd or with DBus timeout)
# -------------------------------------------------------------------------
safe_realm_list() {
    local timeout_s=5
    local tmp_out
    tmp_out="$(mktemp)" || { echo ""; log_info "❗ mktemp failed in safe_realm_list()"; return 0; }

    if ! command -v realm >/dev/null 2>&1; then
        # Older systems: emulate empty result
        echo "" > "$tmp_out"
        log_info "ℹ realmd not installed; skipping realm enumeration" >&2
    else
        # Execute with timeout; suppress DBus activation logs
        local code=0
        timeout "$timeout_s" bash -c 'realm list 2>/dev/null' >"$tmp_out" 2>/dev/null || code=$?
        if (( code != 0 )); then
            log_info "ℹ realm list timed out or failed (code $code)" >&2
            : > "$tmp_out"
        fi
    fi

    # Output contents (may be empty)
    cat "$tmp_out"
    rm -f "$tmp_out"
}

# -------------------------------------------------------------------------
# File manipulation helpers
# -------------------------------------------------------------------------
backup_file() {
    # Usage:
    #   backup_file /path/file            -> prints backup path to stdout (ONLY)
    #   backup_file /path/file outvar     -> sets variable 'outvar' with backup path (no stdout)
    #
    # Behavior: idempotent per run (one backup per file path).
    local path="${1:-}"
    local __outvar="${2:-}"

    if [[ -z "$path" ]]; then
        log_error "backup_file: missing path argument" 30
    fi

    # Prevent path traversal attacks
    if [[ "$path" == *".."* ]]; then
        log_error "backup_file: path traversal detected in '$path'" 30
    fi

    # Validate outvar name if provided
    if [[ -n "$__outvar" && ! "$__outvar" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
        log_error "backup_file: invalid output variable name: '$__outvar'" 30
    fi

    local rel="${path#/}"  # remove leading /
    local bak_dir="${BACKUP_DIR}/$(dirname "$rel")"
    local bak="${BACKUP_DIR}/${rel}"

    # Helper: return backup path via stdout or assign to var
    # (inline to avoid creating global helper functions)
    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} 💾 Would backup '$path' -> '$bak' (suppressed)" >&2
        if [[ -n "$__outvar" ]]; then
            printf -v "$__outvar" '%s' "$bak"
        else
            printf '%s\n' "$bak"
        fi
        return 0
    fi

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} 💾 Would backup '$path' -> '$bak'" >&2
        if [[ -n "$__outvar" ]]; then
            printf -v "$__outvar" '%s' "$bak"
        fi
        return 0
    fi

    mkdir -p -- "$bak_dir" || log_error "Failed to create backup dir: $bak_dir" 31

    # If we already backed up this file in this run, do not copy again
    if [[ -f "$bak" ]]; then
        log_info "ℹ Backup already exists for this run: $bak" >&2
        if [[ -n "$__outvar" ]]; then
            printf -v "$__outvar" '%s' "$bak"
        fi
        return 0
    fi

    # If file doesn't exist, still return planned backup path
    if [[ ! -f "$path" ]]; then
        log_info "ℹ Backup skipped (file not found): '$path' -> (planned) '$bak'" >&2
        if [[ -n "$__outvar" ]]; then
            printf -v "$__outvar" '%s' "$bak"
        fi
        return 0
    fi

    # log before performing the copy
    log_info "💾 Backing up: '$path' -> '$bak'" >&2

    # Perform the backup copy, preserving attributes
    cp -p -- "$path" "$bak" || log_error "Failed to backup '$path' to '$bak'" 32

    if [[ -n "$__outvar" ]]; then
        printf -v "$__outvar" '%s' "$bak"
    fi
}

write_file() {
    local mode="$1"
    local path="$2"

    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would write $path (mode $mode) - suppressed"
        cat >/dev/null
        return 0
    fi

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would write $path (mode $mode)"
        cat >/dev/null
        return 0
    fi

    local parent_dir
    parent_dir="$(dirname "$path")"
    [[ -d "$parent_dir" ]] || mkdir -p "$parent_dir" || log_error "Failed to create parent directory: $parent_dir" 31

    _file_ensure_mutable "$path"
    install -m "$mode" -o root -g root -D /dev/stdin "$path"
    _file_restore_attr "$path"
}

append_line() {
    # Usage: append_line <path> <line>
    local path="$1"
    local line="$2"

    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would append to $path: $line - suppressed"
        return 0
    fi

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would append to $path: $line"
        return 0
    fi

    _file_ensure_mutable "$path"
    printf '%s\n' "$line" >>"$path"
    _file_restore_attr "$path"
}

write_line_file() {
    # Usage: write_line_file <mode> <path> <single_line>
    local mode="$1" path="$2" line="$3"
    printf '%s\n' "$line" | write_file "$mode" "$path"
}

append_line_unique() {
    # Usage: append_line_unique <path> <exact_line>
    local path="$1" line="$2"
    grep -Fxq -- "$line" "$path" 2>/dev/null && return 0
    append_line "$path" "$line"
}

# -------------------------------------------------------------------------
# Immutable attribute (chattr +i) - auto-handling infrastructure
# -------------------------------------------------------------------------
# Associative array tracking files whose immutable bit was removed.
# Key = file path, Value = "1". Restored automatically by file ops or on exit.
declare -A _IMMUTABLE_TRACKER=()

_chattr_available() { command -v lsattr >/dev/null 2>&1 && command -v chattr >/dev/null 2>&1; }

_file_has_immutable() {
    local f="$1"
    _chattr_available || return 1
    [[ -e "$f" ]] || return 1
    local flags
    flags="$(lsattr -d -- "$f" 2>/dev/null | awk '{print $1}' || true)"
    # Match 'i' only in ext2/3/4 attribute positions (4th char: ----i---)
    [[ -n "$flags" && "$flags" == *i* ]] && return 0
    return 1
}

# Transparently remove immutable bit before a file operation (idempotent)
_file_ensure_mutable() {
    local f="$1"
    [[ -e "$f" ]] || return 0
    [[ "${_IMMUTABLE_TRACKER[$f]:-}" == "1" ]] && return 0  # already handled
    _file_has_immutable "$f" || return 0
    if $DRY_RUN || $VALIDATE_ONLY; then return 0; fi
    chattr -i -- "$f" || { log_info "⚠ Failed to remove immutable bit from $f"; return 1; }
    _IMMUTABLE_TRACKER["$f"]="1"
    $VERBOSE && log_info "🔓 Temporarily removed immutable bit from $f"
    return 0
}

# Restore immutable bit for a single file (idempotent)
_file_restore_attr() {
    local f="$1"
    [[ "${_IMMUTABLE_TRACKER[$f]:-}" == "1" ]] || return 0
    if [[ -e "$f" ]]; then
        chattr +i -- "$f" 2>/dev/null || true
        $VERBOSE && log_info "🔒 Restored immutable bit on $f"
    fi
    unset '_IMMUTABLE_TRACKER[$f]'
}

# Restore all tracked immutable bits (called from cleanup trap)
_file_restore_all_attrs() {
    local f
    for f in "${!_IMMUTABLE_TRACKER[@]}"; do
        _file_restore_attr "$f"
    done
}

# Extract target file(s) from a sed -i command's argument list
_extract_sed_target_files() {
    local -a args=("$@")
    local -a files=()
    local skip_next=false has_inplace=false

    for arg in "${args[@]}"; do
        [[ "$arg" == -i* ]] && has_inplace=true
    done
    $has_inplace || return 0

    # The file arguments in sed come after all options/expressions
    # Walk backwards from the end: any arg that is an existing file or
    # not starting with '-' (and not an -e expression value) is a target
    local i
    for (( i=${#args[@]}-1; i>=0; i-- )); do
        local a="${args[$i]}"
        [[ "$a" == -* ]] && break
        # Skip expression values (arg after -e)
        if (( i > 0 )) && [[ "${args[$((i-1))]}" == "-e" ]]; then break; fi
        [[ -f "$a" ]] && files+=("$a")
    done

    printf '%s\n' "${files[@]}"
}

# Milliseconds timestamp with fallback
now_ms() {
    date +%s%3N 2>/dev/null || echo "$(( $(date +%s) * 1000 ))"
}

# -------------------------------------------------------------------------
# Netcat compatibility layer (nc vs ncat) + TCP probe helper
# -------------------------------------------------------------------------
detect_netcat_bin() {
    # Prefer nc (netcat-openbsd/traditional), fallback to ncat (nmap-ncat), else empty
    if command -v nc >/dev/null 2>&1; then
        echo "nc"
    elif command -v ncat >/dev/null 2>&1; then
        echo "ncat"
    else
        echo ""
    fi
}

tcp_port_open() {
    # Usage: tcp_port_open <host> <port> <timeout_seconds>
    local host="$1" port="$2" t="${3:-3}"
    local ncbin
    ncbin="$(detect_netcat_bin)"

    if [[ -n "$ncbin" ]]; then
        # Try "zero-I/O" mode first, then a legacy fallback
        if "$ncbin" -z -w "$t" "$host" "$port" >/dev/null 2>&1; then
            return 0
        fi
        if "$ncbin" -w "$t" "$host" "$port" </dev/null >/dev/null 2>&1; then
            return 0
        fi
    fi

    # Final fallback: bash /dev/tcp
    timeout "$t" bash -c "echo > /dev/tcp/${host}/${port}" >/dev/null 2>&1
}

# -------------------------------------------------------------------------
# OS metadata loader (os-release with legacy fallbacks)
# - Prefers /etc/os-release, then /usr/lib/os-release
# - Falls back to common legacy release files if os-release is missing
# -------------------------------------------------------------------------
load_os_release() {
    local f pretty ver

    for f in /etc/os-release /usr/lib/os-release; do
        if [[ -r "$f" ]]; then
            # shellcheck source=/dev/null
            . "$f"
            [[ -n "${ID:-}" ]] || log_error "OS release file loaded but ID is empty: $f" 1
            return 0
        fi
    done

    # Legacy fallbacks
    if [[ -r /etc/redhat-release ]]; then
        pretty="$(cat /etc/redhat-release)"
        ver="$(grep -Eo '[0-9]+(\.[0-9]+)?' /etc/redhat-release | head -n1)"
        PRETTY_NAME="$pretty"
        VERSION_ID="${ver:-0}"

        case "$pretty" in
            *Rocky*|*rocky*)       ID="rocky" ;;
            *AlmaLinux*|*alma*)    ID="almalinux" ;;
            *CentOS*|*centos*)     ID="centos" ;;
            *Oracle*|*oracle*)     ID="ol" ;;
            *Amazon*Linux*|*amzn*) ID="amzn" ;;
            *Red\ Hat*|*redhat*|*RHEL*|*rhel*) ID="rhel" ;;
            *) ID="rhel" ;;
        esac
        return 0
    fi

    if [[ -r /etc/oracle-release ]]; then
        PRETTY_NAME="$(cat /etc/oracle-release)"
        VERSION_ID="$(grep -Eo '[0-9]+(\.[0-9]+)?' /etc/oracle-release | head -n1)"
        ID="ol"
        return 0
    fi

    if [[ -r /etc/centos-release ]]; then
        PRETTY_NAME="$(cat /etc/centos-release)"
        VERSION_ID="$(grep -Eo '[0-9]+(\.[0-9]+)?' /etc/centos-release | head -n1)"
        ID="centos"
        return 0
    fi

    if [[ -r /etc/SuSE-release ]]; then
        PRETTY_NAME="$(head -n1 /etc/SuSE-release)"
        VERSION_ID="$(grep -Eo '[0-9]+(\.[0-9]+)?' /etc/SuSE-release | head -n1)"
        ID="sles"
        return 0
    fi

    log_error "Unable to detect OS release metadata (missing os-release and legacy release files)." 1
}

validate_allowgroups_tokens() {
    local raw="${1:-}"
    local bad=()

    [[ -z "$raw" || "$raw" == "(none)" ]] && return 0

    # Space-separated tokens
    for g in $raw; do
        # sshd AllowGroups and typical POSIX/SSSD names
        [[ "$g" =~ ^[A-Za-z0-9._-]+$ ]] || bad+=("$g")
    done

    if (( ${#bad[@]} > 0 )); then
        log_error "GLOBAL_ADMIN_GROUPS contains invalid token(s): ${bad[*]}. Use AD sAMAccountName (no spaces; allowed: A-Z a-z 0-9 . _ -)." 1
    fi
}

get_major_version_id() {
    local v="${VERSION_ID%%.*}"
    if [[ "$v" =~ ^[0-9]+$ ]]; then
        echo "$v"; return 0
    fi
    log_info "⚠ Could not determine major version from VERSION_ID='$VERSION_ID'" >&2
    echo 0
    return 1
}

# Get a user-friendly hostname for display/logging (FQDN if possible, else short hostname, else "unknown")
get_display_hostname() {
    local fqdn
    fqdn="$(hostname -f 2>/dev/null || true)"
    [[ "$fqdn" =~ ^localhost(\.localdomain)?$ || -z "$fqdn" ]] && fqdn="$(hostname -s 2>/dev/null || echo 'unknown')"
    echo "$fqdn"
}

# -------------------------------------------------------------------------
# OS detection
# -------------------------------------------------------------------------
load_os_release
case "$ID" in
    ubuntu|debian) OS_FAMILY=debian; PKG=apt; SSH_G=sudo; [[ "$ID" == "ubuntu" ]] && UBUNTU_MAJOR="$(get_major_version_id)" ;;
    rhel|rocky|almalinux|centos) OS_FAMILY=rhel; ver="$(get_major_version_id)"; RHEL_MAJOR="$ver"; PKG=$([[ "$ver" -lt 8 ]] && echo yum || echo dnf); SSH_G=wheel ;;
    oracle|ol) OS_FAMILY=rhel; ver="$(get_major_version_id)"; RHEL_MAJOR="$ver"; [[ "$ver" -eq 0 ]] && ver="$(grep -Eo '[0-9]+' /etc/oracle-release 2>/dev/null | head -n1 || echo 0)"; PKG=$([[ "$ver" -lt 8 ]] && echo yum || echo dnf); SSH_G=wheel ;;
    sles|suse|opensuse-leap|opensuse|opensuse-tumbleweed) OS_FAMILY=suse; PKG=zypper; SSH_G=wheel ;;
    fedora) OS_FAMILY=rhel; PKG=dnf; SSH_G=wheel ;;
    amzn) OS_FAMILY=rhel; PKG=dnf; SSH_G=wheel ;;
    *) log_error "Unsupported distro: $ID. You may need to extend the detection logic." ;;
esac
: "${UBUNTU_MAJOR:=0}"
: "${RHEL_MAJOR:=0}"
OS_NAME=${PRETTY_NAME:-$ID}
OS_VERSION=${VERSION_ID:-$(uname -r)}
OS_ARCH=$(uname -m)
KERNEL_VER=$(uname -r)

log_info "🧾 Starting linux-ad-domain-join.sh version $scriptVersion..."
log_info "🌐 Hostname: $(get_display_hostname) | IP: $(hostname -I 2>/dev/null | awk '{print $1}' || true)"
log_info "🧬 OS detected: $OS_NAME ($ID $OS_VERSION, kernel $KERNEL_VER, arch $OS_ARCH)"
log_info "🧬 OS family: $OS_FAMILY, Package Manager: $PKG, SSH group: $SSH_G"

# -------------------------------------------------------------------------
# Smart Internet Connectivity Detection (dynamic and autonomous)
# -------------------------------------------------------------------------
log_info "🌐 Detecting Internet connectivity intelligently"
HAS_INTERNET=false
CONNECT_DETAILS=()

# Detect default route / gateway
DEFAULT_ROUTE="$(ip route get 1.1.1.1 2>/dev/null | awk '/via/ {print $3; exit}' || true)"
if [[ -n "$DEFAULT_ROUTE" ]]; then
    CONNECT_DETAILS+=( "✅ Default route detected via gateway $DEFAULT_ROUTE" )
else
    CONNECT_DETAILS+=( "🛑 No default route - host likely isolated or LAN-only" )
fi

# Check DNS functionality (without relying on specific domains)
DNS_SERVER="$(grep -m1 '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' || true)"
if [[ -z "$DNS_SERVER" ]]; then
    CONNECT_DETAILS+=( "⚠️ No DNS servers configured in /etc/resolv.conf" )
else
    if timeout 3 getent hosts example.com >/dev/null 2>&1; then
        CONNECT_DETAILS+=( "✅ DNS resolution working (resolver: $DNS_SERVER)" )
    else
        CONNECT_DETAILS+=( "⚠️ DNS resolution failed using $DNS_SERVER" )
    fi
fi

# Test outbound reachability (generic TCP probe)
NET_TEST_HOSTS=( "1.1.1.1" "8.8.8.8" "9.9.9.9" )
NET_OK=false
for H in "${NET_TEST_HOSTS[@]}"; do
    if timeout 2 bash -c "echo > /dev/tcp/$H/443" 2>/dev/null; then
        CONNECT_DETAILS+=( "✅ TCP/443 reachable (host $H)" )
        NET_OK=true
        break
    elif timeout 2 bash -c "echo > /dev/tcp/$H/80" 2>/dev/null; then
        CONNECT_DETAILS+=( "✅ TCP/80 reachable (host $H)" )
        NET_OK=true
        break
    fi
done

if ! $NET_OK; then
    CONNECT_DETAILS+=( "🛑 No outbound TCP connectivity on ports 80/443" )
fi

# Decide final state
if [[ -n "$DEFAULT_ROUTE" && "$NET_OK" == true ]]; then
    HAS_INTERNET=true
    CONNECT_DETAILS+=( "🌐 Internet connectivity confirmed" )
else
    HAS_INTERNET=false
    CONNECT_DETAILS+=( "🚫 Internet unavailable (no route or no outbound access)" )
fi

# Logging connectivity summary
log_info "📡 Connectivity diagnostic summary:"
for line in "${CONNECT_DETAILS[@]}"; do
    # Sanitize first, then colorize
    line_sanitized="$(sanitize_log_msg <<< "$line")"
    line_colored="$(colorize_tag "$line_sanitized")"
    log_info "   ${line_colored}"
done

# -------------------------------------------------------------------------
# [Self-Healing] Detect and repair RPM database corruption (RHEL-like only)
# -------------------------------------------------------------------------
if [[ -f /etc/redhat-release || -f /etc/centos-release || -f /etc/oracle-release || -f /etc/rocky-release || -f /etc/almalinux-release ]]; then
    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Skipping RPM database integrity/repair block (non-invasive mode)"
    else
        log_info "🧩 Checking RPM database integrity"

        release_file=""
        for f in /etc/redhat-release /etc/centos-release /etc/oracle-release /etc/rocky-release /etc/almalinux-release; do
            [[ -f "$f" ]] && { release_file="$f"; break; }
        done

        if [[ -z "$release_file" ]]; then
            log_info "ℹ No release file found for rpm check, skipping RPM DB verification"
        elif $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would verify rpm ownership of $release_file and rebuild RPM DB if corrupted"
        else
            if ! rpm -qf "$release_file" &>/dev/null; then
                log_info "⚙ RPM database appears corrupted - initiating recovery"

                # Backup existing RPM database
                if [[ -d /var/lib/rpm ]]; then
                    backup_path="/var/lib/rpm.bak.$(date +%F_%H-%M)"
                    cp -a /var/lib/rpm "$backup_path" 2>/dev/null || true
                    log_info "💾 Backup created at: $backup_path"
                fi

                # Ensure no package manager process is running before touching rpmdb locks
                if pgrep -x yum >/dev/null 2>&1 || pgrep -x dnf >/dev/null 2>&1 || pgrep -x rpm >/dev/null 2>&1 || pgrep -x packagekitd >/dev/null 2>&1; then
                    log_error "RPM database repair aborted: a package manager process is running (yum/dnf/rpm/packagekitd). Stop it and retry." 1
                fi

                # Remove potential stale locks (Berkeley DB and stale rpm lock file)
                rm -f /var/lib/rpm/__db.* 2>/dev/null
                rm -f /var/lib/rpm/.rpm.lock 2>/dev/null

                # Attempt rebuild
                if timeout 300 rpm --rebuilddb &>/dev/null; then
                    log_info "✅ RPM database rebuilt successfully"
                else
                    log_error "Failed to rebuild RPM database. Please investigate manually at ${backup_path:-/var/lib/rpm.bak.*}" 8
                fi

                # Re-test after rebuild
                if ! rpm -qf "$release_file" &>/dev/null; then
                    log_error "RPM database still corrupted after rebuild. Aborting execution." 9
                fi
            else
                log_info "✅ RPM database integrity verified"
            fi
        fi
    fi
fi

# -------------------------------------------------------------------------
# Auto-install missing dependencies (connectivity-aware)
# -------------------------------------------------------------------------
install_missing_deps() {
    # Define the list of packages to install from the function arguments first
    local -a to_install=( "$@" )

    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Missing packages detected (not installing): ${to_install[*]}"
        return 0
    fi

    # Connectivity heuristics can fail in proxy/local-repo environments.
    # Still attempt installation; fail only if the package manager errors out.
    if [[ "${HAS_INTERNET}" == "false" ]]; then
        log_info "⚠️ Internet heuristic failed; attempting package install anyway (may work via proxy/local repo)."
    fi


    log_info "🔌 Installing missing packages: ${to_install[*]}"
    $VERBOSE && log_info "🧬 install_missing_deps() entered with args: $*"

    case "$PKG" in
        apt)
            cmd_must env DEBIAN_FRONTEND=noninteractive apt-get update -qq
            cmd_must env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${to_install[@]}"
            ;;
        yum|dnf)
            # Use flags as an array (no word-splitting issues)
            local -a extra_flags=()
            if [[ "${DISABLE_PKG_PLUGINS:-false}" == "true" ]]; then
                extra_flags+=( --noplugins )
            fi
            if [[ "$PKG" == "dnf" ]]; then
                extra_flags+=( -4 )
            fi
            cmd_must "$PKG" install "${extra_flags[@]}" -y "${to_install[@]}"
            ;;
        zypper)
            cmd_must "$PKG" install -n "${to_install[@]}"
            ;;
        *)
            log_error "Unsupported package manager: $PKG" 101
            ;;
    esac
}

# -------------------------------------------------------------------------
# List required tools
# -------------------------------------------------------------------------
tools=( realm adcli kinit kdestroy timedatectl systemctl sed grep tput timeout hostname cp chmod tee ldapsearch ldapmodify chronyc host dig ip pgrep install )

# Add PAM config tool based on OS family
case "$OS_FAMILY" in
    debian)
		tools+=( pam-auth-update )
		;;
    rhel)
		if (( RHEL_MAJOR < 8 )); then
			tools+=( authconfig )
		else
			tools+=( authselect )
		fi
		;;
    suse)
		tools+=( pam-config )
		;;
esac

# -------------------------------------------------------------------------
# Detect missing tools
# -------------------------------------------------------------------------
missing_cmds=()
for cmd in "${tools[@]}"; do
    ! command -v "$cmd" &>/dev/null && missing_cmds+=( "$cmd" )
done

[[ ${#missing_cmds[@]} -gt 0 ]] && log_info "⚠ Missing tools (pre-install): ${missing_cmds[*]}"

# -------------------------------------------------------------------------
# Package list by distro (Samba-free, SSSD-based)
# -------------------------------------------------------------------------
pkgs=()
case "$OS_FAMILY" in
    debian)
        pkgs=( realmd sssd sssd-tools adcli oddjob oddjob-mkhomedir \
               packagekit krb5-user libnss-sss libpam-sss libpam-runtime \
               ldap-utils chrony dialog dnsutils iproute2 procps )
        # Prefer netcat-openbsd, fallback to nmap-ncat
		if apt-cache show netcat-openbsd >/dev/null 2>&1; then
			pkgs+=( netcat-openbsd )
		elif apt-cache show nmap-ncat >/dev/null 2>&1; then
			pkgs+=( nmap-ncat )
		else
			pkgs+=( netcat )
		fi
		;;
	rhel)
		pkgs=( realmd sssd sssd-tools adcli oddjob oddjob-mkhomedir \
			   krb5-workstation chrony openldap-clients nmap-ncat bind-utils iproute procps-ng )
		if (( RHEL_MAJOR < 8 )); then
			pkgs+=( authconfig )
		else
			# RHEL 8 - authselect, package renamed
			pkgs+=( authselect )
		fi
		;;
    suse)
        pkgs=( realmd sssd adcli \
            krb5-client pam-config chrony iproute2 procps )

        # DNS utils (host/dig)
        if zypper se -x bind-utils >/dev/null 2>&1; then
            pkgs+=( bind-utils )
        fi

        # LDAP client naming differs across SUSE/SLES generations
        if zypper se -x openldap-clients >/dev/null 2>&1; then
            pkgs+=( openldap-clients )
        else
            pkgs+=( openldap2-client )
        fi

        # Netcat variants
        if zypper se -x netcat-openbsd >/dev/null 2>&1; then
            pkgs+=( netcat-openbsd )
        elif zypper se -x nmap-ncat >/dev/null 2>&1; then
            pkgs+=( nmap-ncat )
        else
            pkgs+=( netcat )
        fi

        # oddjob is not guaranteed on SUSE; add only if present
        if zypper se -x oddjob >/dev/null 2>&1; then
            pkgs+=( oddjob )
        fi
        if zypper se -x oddjob-mkhomedir >/dev/null 2>&1; then
            pkgs+=( oddjob-mkhomedir )
        fi
        ;;
esac

# -------------------------------------------------------------------------
# Package verification and installation
# -------------------------------------------------------------------------
log_info "🔍 Verifying required packages"
missing_pkgs=()
case "$PKG" in
    apt)
        for p in "${pkgs[@]}"; do dpkg -s "$p" &>/dev/null || missing_pkgs+=( "$p" ); done
        ;;
    yum|dnf|zypper)
        for p in "${pkgs[@]}"; do rpm -q "$p" &>/dev/null || missing_pkgs+=( "$p" ); done
        ;;
esac

if (( ${#missing_pkgs[@]} > 0 )); then
    log_info "🧩 Missing packages: ${missing_pkgs[*]}"
    install_missing_deps "${missing_pkgs[@]}"
else
    log_info "✅ All required packages are installed"
fi

# -------------------------------------------------------------------------
# Validate that required commands are now available
# -------------------------------------------------------------------------
for cmd in realm adcli kinit kdestroy timedatectl systemctl \
           sed grep tput timeout hostname cp chmod tee \
           ldapsearch ldapmodify chronyc; do
  check_cmd "$cmd"
done

case "$OS_FAMILY" in
	debian)
		check_cmd pam-auth-update
		;;
	rhel)
		if (( RHEL_MAJOR < 8 )); then
			check_cmd authconfig
		else
			check_cmd authselect
		fi
		;;
	suse)
		check_cmd pam-config
		;;
esac

# -------------------------------------------------------------------------
# Collect domain join inputs
# -------------------------------------------------------------------------
if $NONINTERACTIVE; then
    : "${DOMAIN:?DOMAIN required}"
    : "${OU:?OU required}"
    : "${DC_SERVER:?DC_SERVER required}"
	: "${NTP_SERVER:?NTP_SERVER required}"
    : "${DOMAIN_USER:?DOMAIN_USER required}"
    : "${DOMAIN_PASS:?DOMAIN_PASS required}"
	: "${GLOBAL_ADMIN_GROUPS:?GLOBAL_ADMIN_GROUPS required}"
    : "${SESSION_TIMEOUT_SECONDS:?SESSION_TIMEOUT_SECONDS required (seconds)}"
    : "${PERMIT_ROOT_LOGIN:?PERMIT_ROOT_LOGIN required (yes|no)}"

    # Administrative groups (optional with smart defaults)
    HOST_L=$(to_lower "$(hostname -s)")
    ADM="${ADM_GROUP:-grp-adm-$HOST_L}"
    ADM_ALL="${ADM_GROUP_ALL:-grp-adm-all-linux-servers}"
    GRP_SSH="${SSH_GROUP:-grp-ssh-$HOST_L}"
    GRP_SSH_ALL="${SSH_GROUP_ALL:-grp-ssh-all-linux-servers}"
    SEC="${SEC_GROUP:-grp-sec-$HOST_L}"
    SEC_ALL="${SEC_GROUP_ALL:-grp-sec-all-linux-servers}"
    SUPER="${SUPER_GROUP:-grp-super-$HOST_L}"
    SUPER_ALL="${SUPER_GROUP_ALL:-grp-super-all-linux-servers}"

    # Normalize and validate inputs
    validate_allowgroups_tokens "$GLOBAL_ADMIN_GROUPS"
    require_uint_range "SESSION_TIMEOUT_SECONDS" "$SESSION_TIMEOUT_SECONDS" 30 86400
    PERMIT_ROOT_LOGIN="$(normalize_yes_no "$PERMIT_ROOT_LOGIN")"
    [[ -n "$PERMIT_ROOT_LOGIN" ]] || log_error "PERMIT_ROOT_LOGIN must be yes or no" 1
    
    PASSWORD_AUTHENTICATION="${PASSWORD_AUTHENTICATION:-yes}"
    PASSWORD_AUTHENTICATION="$(normalize_yes_no "${PASSWORD_AUTHENTICATION:-yes}")"
    [[ -n "$PASSWORD_AUTHENTICATION" ]] || log_error "PASSWORD_AUTHENTICATION must be yes or no" 1

    # Validate group names
    for grp_var in ADM ADM_ALL GRP_SSH GRP_SSH_ALL SEC SEC_ALL SUPER SUPER_ALL; do
        grp_val="${!grp_var}"
        if ! validate_ad_group_name "$grp_val" "$grp_var"; then
            log_error "Invalid AD group name for $grp_var: $grp_val" 1
        fi
    done

    # Log configured groups (non-interactive mode)
    log_info "📋 Administrative groups configured:"
    log_info "   ADM (operational):     $ADM"
    log_info "   ADM_ALL (global):      $ADM_ALL"
    log_info "   SSH (access):          $GRP_SSH"
    log_info "   SSH_ALL (global):      $GRP_SSH_ALL"
    log_info "   SEC (security):        $SEC"
    log_info "   SEC_ALL (global):      $SEC_ALL"
    log_info "   SUPER (full):          $SUPER"
    log_info "   SUPER_ALL (global):    $SUPER_ALL"
else
    log_info "🧪 Collecting inputs"
    print_divider

    # Require DOMAIN with validation
    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} Domain (e.g., acme.net): " "$(date '+%F %T')"
        read -r DOMAIN
        DOMAIN="$(trim_ws "$DOMAIN")"

        # Check for empty input
        if [[ -z "$DOMAIN" ]]; then
            printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Domain is required.\n" "$(date '+%F %T')"
            continue
        fi

        # Validate domain name format
        if ! validate_domain_name "$DOMAIN"; then
            printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Please enter a valid domain name.\n" "$(date '+%F %T')"
            continue
        fi

        break
    done
    DOMAIN_SHORT="$(echo "$DOMAIN" | cut -d'.' -f1 | tr '[:lower:]' '[:upper:]')"

    # OU (optional, default filled)
    DOMAIN_DN=$(awk -F'.' '{
		for (i = 1; i <= NF; i++) printf "%sDC=%s", (i>1?",":""), toupper($i)
	}' <<< "$DOMAIN")

    default_OU="CN=Computers,${DOMAIN_DN}"
    printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} OU ${C_DIM}[default: ${default_OU}]${C_RESET}: " "$(date '+%F %T')"
    read -r OU
    OU="$(trim_ws "${OU:-}")"
    OU="${OU:-$default_OU}"

    # DC Server (optional, default filled)
    default_DC_SERVER="${DOMAIN_SHORT,,}-sp-ad01.${DOMAIN,,}"
    printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} DC server ${C_DIM}[default: ${default_DC_SERVER}]${C_RESET}: " "$(date '+%F %T')"
    read -r DC_SERVER
    DC_SERVER="$(trim_ws "${DC_SERVER:-}")"
    DC_SERVER="${DC_SERVER:-$default_DC_SERVER}"

	# NTP Server (optional, default filled)
    default_NTP_SERVER="ntp.${DOMAIN,,}"
    printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} NTP server ${C_DIM}[default: ${default_NTP_SERVER}]${C_RESET}: " "$(date '+%F %T')"
    read -r NTP_SERVER
    NTP_SERVER="$(trim_ws "${NTP_SERVER:-}")"
    NTP_SERVER="${NTP_SERVER:-$default_NTP_SERVER}"

    # Require Join User with validation
    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} Join user (e.g., administrator): " "$(date '+%F %T')"
        read -r DOMAIN_USER
        DOMAIN_USER="$(trim_ws "$DOMAIN_USER")"

        # Check for empty input
        if [[ -z "$DOMAIN_USER" ]]; then
            printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Join user is required.\n" "$(date '+%F %T')"
            continue
        fi

        # Validate username format
        if ! validate_username "$DOMAIN_USER"; then
            printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Please enter a valid username.\n" "$(date '+%F %T')"
            continue
        fi

        break
    done

    # Require Password
    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} Password for ${C_BOLD}${DOMAIN_USER}${C_RESET}: " "$(date '+%F %T')"
        read -rs DOMAIN_PASS
        echo
        [[ -n "$DOMAIN_PASS" ]] && break
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Password cannot be empty.\n" "$(date '+%F %T')"
    done

	# Set Global Admin group(s) for SSH AllowGroups
    printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} Define the global admin group(s) allowed SSH access (space-separated):\n" "$(date '+%F %T')" >&2
    printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} Global admin group(s): " "$(date '+%F %T')" >&2
    read -r GLOBAL_ADMIN_GROUPS
    GLOBAL_ADMIN_GROUPS="$(trim_ws "$GLOBAL_ADMIN_GROUPS")"

    # handle optional input gracefully
    [[ -z "$GLOBAL_ADMIN_GROUPS" ]] && GLOBAL_ADMIN_GROUPS="(none)"
    validate_allowgroups_tokens "$GLOBAL_ADMIN_GROUPS"

    # Session timeout (SSH + Shell) in seconds
    default_SESSION_TIMEOUT_SECONDS=900
    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} Session timeout in seconds (SSH + shell) ${C_DIM}[default: ${default_SESSION_TIMEOUT_SECONDS}]${C_RESET}: " "$(date '+%F %T')"
        read -r SESSION_TIMEOUT_SECONDS
        SESSION_TIMEOUT_SECONDS="$(trim_ws "${SESSION_TIMEOUT_SECONDS:-$default_SESSION_TIMEOUT_SECONDS}")"

        if is_uint "$SESSION_TIMEOUT_SECONDS" && (( SESSION_TIMEOUT_SECONDS >= 30 && SESSION_TIMEOUT_SECONDS <= 86400 )); then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid value. Use an integer between 30 and 86400.\n" "$(date '+%F %T')"
    done

    # PermitRootLogin
    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} PermitRootLogin over SSH? (yes/no) ${C_DIM}[default: no]${C_RESET}: " "$(date '+%F %T')"
        read -r _prl
        _prl="${_prl:-no}"
        PERMIT_ROOT_LOGIN="$(normalize_yes_no "$_prl")"
        [[ -n "$PERMIT_ROOT_LOGIN" ]] && break
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid value. Type 'yes' or 'no'.\n" "$(date '+%F %T')"
    done

    # Ask whether SSH password auth should be enabled.
    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} Allow SSH PasswordAuthentication? (yes/no) ${C_DIM}[default: yes]${C_RESET}: " "$(date '+%F %T')"
        read -r _pa
        _pa="${_pa:-yes}"
        PASSWORD_AUTHENTICATION="$(normalize_yes_no "$_pa")"
        [[ -n "$PASSWORD_AUTHENTICATION" ]] && break
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid input. Use yes or no.\n" "$(date '+%F %T')"
    done

    # Administrative Groups Configuration (Interactive)
    print_divider
    log_info "📋 Configuring Administrative Groups"
    log_info "ℹ️  AD groups control sudo privileges and SSH access on this host."
    log_info "ℹ️  Two scopes are supported:"
    log_info "    - Host-specific groups (e.g., grp-adm-hostname)"
    log_info "    - Global groups (e.g., grp-adm-all-linux-servers)"
    print_divider
    HOST_L=$(to_lower "$(hostname -s)")

    # ADM - Operational Administrators (host-specific)
    while true; do
        default_ADM="grp-adm-$HOST_L"
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} ADM group (operational, host-specific) ${C_DIM}[default: ${default_ADM}]${C_RESET}: " "$(date '+%F %T')"
        read -r ADM
        ADM="${ADM:-$default_ADM}"
        ADM="$(trim_ws "$ADM")"
        if validate_ad_group_name "$ADM" "ADM"; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid group name. Please retry.\n" "$(date '+%F %T')"
    done

    # ADM_ALL - Operational Administrators (global)
    while true; do
        default_ADM_ALL="grp-adm-all-linux-servers"
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} ADM_ALL group (operational, global) ${C_DIM}[default: ${default_ADM_ALL}]${C_RESET}: " "$(date '+%F %T')"
        read -r ADM_ALL
        ADM_ALL="${ADM_ALL:-$default_ADM_ALL}"
        ADM_ALL="$(trim_ws "$ADM_ALL")"
        if validate_ad_group_name "$ADM_ALL" "ADM_ALL"; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid group name. Please retry.\n" "$(date '+%F %T')"
    done

    # SSH - SSH Access (host-specific)
    while true; do
        default_SSH="grp-ssh-$HOST_L"
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} SSH group (access, host-specific) ${C_DIM}[default: ${default_SSH}]${C_RESET}: " "$(date '+%F %T')"
        read -r GRP_SSH
        GRP_SSH="${GRP_SSH:-$default_SSH}"
        GRP_SSH="$(trim_ws "$GRP_SSH")"
        if validate_ad_group_name "$GRP_SSH" "GRP_SSH"; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid group name. Please retry.\n" "$(date '+%F %T')"
    done

    # SSH_ALL - SSH Access (global)
    while true; do
        default_SSH_ALL="grp-ssh-all-linux-servers"
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} SSH_ALL group (access, global) ${C_DIM}[default: ${default_SSH_ALL}]${C_RESET}: " "$(date '+%F %T')"
        read -r GRP_SSH_ALL
        GRP_SSH_ALL="${GRP_SSH_ALL:-$default_SSH_ALL}"
        GRP_SSH_ALL="$(trim_ws "$GRP_SSH_ALL")"
        if validate_ad_group_name "$GRP_SSH_ALL" "GRP_SSH_ALL"; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid group name. Please retry.\n" "$(date '+%F %T')"
    done

    # SEC - Security Administrators (host-specific)
    while true; do
        default_SEC="grp-sec-$HOST_L"
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} SEC group (security, host-specific) ${C_DIM}[default: ${default_SEC}]${C_RESET}: " "$(date '+%F %T')"
        read -r SEC
        SEC="${SEC:-$default_SEC}"
        SEC="$(trim_ws "$SEC")"
        if validate_ad_group_name "$SEC" "SEC"; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid group name. Please retry.\n" "$(date '+%F %T')"
    done

    # SEC_ALL - Security Administrators (global)
    while true; do
        default_SEC_ALL="grp-sec-all-linux-servers"
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} SEC_ALL group (security, global) ${C_DIM}[default: ${default_SEC_ALL}]${C_RESET}: " "$(date '+%F %T')"
        read -r SEC_ALL
        SEC_ALL="${SEC_ALL:-$default_SEC_ALL}"
        SEC_ALL="$(trim_ws "$SEC_ALL")"
        if validate_ad_group_name "$SEC_ALL" "SEC_ALL"; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid group name. Please retry.\n" "$(date '+%F %T')"
    done

    # SUPER - Full Administrators (host-specific)
    while true; do
        default_SUPER="grp-super-$HOST_L"
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} SUPER group (full admin, host-specific) ${C_DIM}[default: ${default_SUPER}]${C_RESET}: " "$(date '+%F %T')"
        read -r SUPER
        SUPER="${SUPER:-$default_SUPER}"
        SUPER="$(trim_ws "$SUPER")"
        if validate_ad_group_name "$SUPER" "SUPER"; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid group name. Please retry.\n" "$(date '+%F %T')"
    done

    # SUPER_ALL - Full Administrators (global)
    while true; do
        default_SUPER_ALL="grp-super-all-linux-servers"
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} SUPER_ALL group (full admin, global) ${C_DIM}[default: ${default_SUPER_ALL}]${C_RESET}: " "$(date '+%F %T')"
        read -r SUPER_ALL
        SUPER_ALL="${SUPER_ALL:-$default_SUPER_ALL}"
        SUPER_ALL="$(trim_ws "$SUPER_ALL")"
        if validate_ad_group_name "$SUPER_ALL" "SUPER_ALL"; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid group name. Please retry.\n" "$(date '+%F %T')"
    done
fi
print_divider

# Only log if GLOBAL_ADMIN_GROUPS is defined and not "(none)"
if [ -n "$GLOBAL_ADMIN_GROUPS" ] && [ "$GLOBAL_ADMIN_GROUPS" != "(none)" ]; then
    log_info "🔐 Using global admin group(s) for SSH access: $GLOBAL_ADMIN_GROUPS"
fi

# Prepare environment
DOMAIN_LOWER="${DOMAIN,,}"
DOMAIN_UPPER="${DOMAIN^^}"
DOMAIN_SHORT="$(echo "$DOMAIN" | cut -d'.' -f1 | tr '[:lower:]' '[:upper:]')"
REALM=${DOMAIN^^}
HOST_FQDN="$(hostname -s).$(to_lower "$DOMAIN")"
DC_SERVER_INPUT="$DC_SERVER"
LDAP_SERVER="$DC_SERVER_INPUT"

# Hostname format for Kerberos (uppercase short name)
HOST_SHORT=$(hostname -s)
HOST_SHORT_U=$(echo "$HOST_SHORT" | tr '[:lower:]' '[:upper:]')

# Escaped version for LDAP filter injection protection (RFC 4515)
HOST_SHORT_U_ESCAPED=$(ldap_escape_filter "$HOST_SHORT_U")

MACHINE_PRINCIPAL="${HOST_SHORT_U}\$@${REALM}"

# -------------------------------------------------------------------------
# Hostname and FQDN Consistency Validation (/etc/hostname, /etc/hosts)
# -------------------------------------------------------------------------
log_info "🔍 Validating hostname and FQDN consistency"
HOSTS_FILE="/etc/hosts"

# Perform safe backup before modification
backup_file "$HOSTS_FILE"

# Skip Docker/Podman networks early
# Primary IP detection (multi-strategy fallback chain)
SKIP_IFACES="docker|br-|virbr|veth|cni|flannel|tun|tap|wg|vboxnet|vmnet"  # Skip virtual/container/VPN interfaces
PRIMARY_IP=""
PRIMARY_IFACE=""

# Strategy 0: Source IP used to reach DC (most reliable: guarantees AD connectivity, handles multi-homed)
DC_V4="$(getent ahostsv4 "$DC_SERVER" 2>/dev/null | awk 'NR==1{print $1; exit}')"

# Fallback: if getent fails, attempt resolution via dig/host
if [[ -z "$DC_V4" || ! "$DC_V4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    DC_V4="$(dig +short "$DC_SERVER" 2>/dev/null | grep -E '^[0-9]+\.' | head -n1)" || true
fi
if [[ -z "$DC_V4" || ! "$DC_V4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    DC_V4="$(host "$DC_SERVER" 2>/dev/null | awk '/has address/ {print $4; exit}')" || true
fi

# If DC_SERVER is already an IP address, use it directly
if [[ -z "$DC_V4" && "$DC_SERVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    DC_V4="$DC_SERVER"
fi

if [[ -n "$DC_V4" && "$DC_V4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    PRIMARY_IP="$(ip -4 route get "$DC_V4" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
else
    $VERBOSE && log_info "⚠ DC server resolution failed or invalid IP: '$DC_V4'"
fi

# Strategy 1: Default route interface (fallback if DC resolution fails)
if [[ -z "$PRIMARY_IP" ]]; then
    PRIMARY_IFACE="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    if [[ -n "$PRIMARY_IFACE" ]]; then
        PRIMARY_IP="$(ip -4 addr show dev "$PRIMARY_IFACE" scope global 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)"
    fi
fi

# Strategy 2: First global-scope address (excludes virtual/container interfaces)
if [[ -z "$PRIMARY_IP" ]]; then
    if ip -o -4 addr show scope global >/dev/null 2>&1; then
        PRIMARY_IFACE="$(ip -o -4 addr show scope global 2>/dev/null | awk '!/(docker|br-|virbr|veth|cni|flannel|tun|tap|wg|vboxnet|vmnet)/ {print $2; exit}')"
        PRIMARY_IP="$(ip -o -4 addr show scope global 2>/dev/null | awk -v skip="$SKIP_IFACES" '$2 !~ skip {print $4; exit}' | cut -d/ -f1)"
    fi
fi

# Strategy 3: ifconfig fallback (legacy systems: RHEL 6, Ubuntu 14.04, Debian 7)
if [[ -z "$PRIMARY_IP" ]] && command -v ifconfig >/dev/null 2>&1; then
    PRIMARY_IP="$(ifconfig 2>/dev/null | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | awk '{print $2}' | sed 's/addr://g' | head -n1 || true)"
fi

[[ -z "$PRIMARY_IP" ]] && log_error "Unable to detect primary IP address (no active NIC found)" 15

# Escape PRIMARY_IP for regex-safe matching (dots must be literal)
PRIMARY_IP_RE="${PRIMARY_IP//./\\.}"

$VERBOSE && log_info "ℹ Primary IP selected: ${PRIMARY_IP} (iface: ${PRIMARY_IFACE:-unknown})"


# Check for active web services (port 80 or 443)
if command -v ss >/dev/null 2>&1; then
    NETSTAT_CMD="ss -tulpen"
elif command -v netstat >/dev/null 2>&1; then
    NETSTAT_CMD="netstat -tulpen"
else
    NETSTAT_CMD=""
fi

if [[ -n "$NETSTAT_CMD" ]] && $NETSTAT_CMD 2>/dev/null | grep -qE ':(80|443)\b'; then
    log_info "🌐 Detected active web service (port 80/443 in use)"
fi

# Ensure /etc/hostname contains the correct short hostname
if [[ -f /etc/hostname ]]; then
    CURRENT_HOSTNAME_FILE=$(< /etc/hostname)
    if [[ "$CURRENT_HOSTNAME_FILE" != "$HOST_SHORT" ]]; then
        write_line_file 0644 /etc/hostname "$HOST_SHORT"
        log_info "🧩 Updated /etc/hostname to '$HOST_SHORT'"
    fi
else
    write_line_file 0644 /etc/hostname "$HOST_SHORT"
    log_info "🧩 Created /etc/hostname with '$HOST_SHORT'"
fi

# -------------------------------------------------------------------------
# Prepare /etc/hosts safely
# -------------------------------------------------------------------------
if [[ ! -f "$HOSTS_FILE" ]]; then
    log_info "⚙️ Creating new $HOSTS_FILE"
    write_file 0644 "$HOSTS_FILE" <<'EOF'
127.0.0.1   localhost
EOF
else
    # Ensure a basic IPv4 localhost line exists
    if ! grep -qE '^[[:space:]]*127\.0\.0\.1[[:space:]]+.*\blocalhost\b' "$HOSTS_FILE"; then
        append_line_unique "$HOSTS_FILE" "127.0.0.1   localhost"
    fi
fi

# Ensure IPv6 localhost line exists
if ! grep -qE '^::1[[:space:]]+localhost' "$HOSTS_FILE"; then
    append_line_unique "$HOSTS_FILE" "::1   localhost"
fi

# -------------------------------------------------------------------------
# Canonicalizes /etc/hosts for the primary IP while preserving aliases
# -------------------------------------------------------------------------

# Defensive initialization for strict mode (set -u)
CLOUD_ALIASES=""

# Collect ALL entries for this IP (not only the first one)
MATCHING_LINES=()
mapfile -t MATCHING_LINES < <(grep -E "^[[:space:]]*${PRIMARY_IP_RE}[[:space:]]+" "$HOSTS_FILE" || true)

if [[ ${#MATCHING_LINES[@]} -gt 0 ]]; then
    log_info "🧩 Found ${#MATCHING_LINES[@]} existing /etc/hosts entries for ${PRIMARY_IP}, consolidating aliases"

    declare -A ALIAS_MAP=()

    # Extract aliases from ALL lines
    for line in "${MATCHING_LINES[@]}"; do
        read -r -a TOKENS <<< "$line"
        for (( i=1; i<${#TOKENS[@]}; i++ )); do
            name="${TOKENS[i]}"

            # Skip canonical names
            [[ "$name" == "$HOST_FQDN" ]] && continue
            [[ "$name" == "$HOST_SHORT" ]] && continue

            # Validate hostname alias (RFC 952 / 1123 compliant)
			if [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)*$ ]]; then
                ALIAS_MAP["$name"]=1
            else
                log_info "⚠️ Ignoring invalid hostname alias: $name"
            fi
        done
    done

    # Build final alias list (deduplicated, sorted)
    if [[ ${#ALIAS_MAP[@]} -gt 0 ]]; then
        CLOUD_ALIASES="$(printf '%s\n' "${!ALIAS_MAP[@]}" | sort | tr '\n' ' ')"
    fi

    if [[ -n "$CLOUD_ALIASES" ]]; then
        log_info "🌐 Preserving cloud/DHCP aliases: $CLOUD_ALIASES"
    fi

    # Build canonical line using ONLY spaces
    CANONICAL_LINE="${PRIMARY_IP} ${HOST_FQDN} ${HOST_SHORT}"
    [[ -n "$CLOUD_ALIASES" ]] && CANONICAL_LINE+=" ${CLOUD_ALIASES}"

    # Remove any previous entries for this IP (avoid duplicates/drift)
    cmd_must sed -i "/^[[:space:]]*${PRIMARY_IP_RE}[[:space:]]\{1,\}/d" "$HOSTS_FILE"

    # Append canonical entry (spaces only, no TAB)
    append_line "$HOSTS_FILE" "$CANONICAL_LINE"

    log_info "✅ Applied canonical mapping: ${CANONICAL_LINE}"

else
    log_info "➕ No entry found for ${PRIMARY_IP}; adding canonical host mapping"
    append_line "$HOSTS_FILE" "${PRIMARY_IP} ${HOST_FQDN} ${HOST_SHORT}"
fi

# -------------------------------------------------------------------------
# Cleanup: remove obsolete Ubuntu/Debian 127.0.1.1 entries
# -------------------------------------------------------------------------
if grep -qE '^[[:space:]]*127\.0\.1\.1[[:space:]]+' "$HOSTS_FILE"; then
    log_info "⚙️ Removing obsolete 127.0.1.1 hostname entries (Ubuntu/Debian compatibility fix)"
    cmd_must sed -i '/^[[:space:]]*127\.0\.1\.1[[:space:]]\{1,\}/d' "$HOSTS_FILE"
fi

# Adjust default permissions
cmd_must chmod 644 "$HOSTS_FILE"

# Final validation
if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Skipping /etc/hosts validation because no changes were applied."
elif ! grep -qE "^[[:space:]]*${PRIMARY_IP_RE}[[:space:]]+${HOST_FQDN}" "$HOSTS_FILE"; then
    log_error "Host mapping not applied correctly in /etc/hosts"
else
    log_info "✅ Host mapping verified for ${HOST_FQDN} (${PRIMARY_IP})"
fi

# Ensure that the runtime hostname resolves correctly (hostname -f)
CURRENT_FQDN=$(hostname -f 2>/dev/null || echo "")
if [[ "$CURRENT_FQDN" != "$HOST_FQDN" ]]; then
    cmd_try hostnamectl set-hostname "$HOST_SHORT" 2>/dev/null || cmd_try hostname "$HOST_SHORT"
    log_info "⚙️ Adjusted runtime hostname for FQDN resolution"
fi

log_info "✅ Hostname/FQDN consistency validation complete"

# -------------------------------------------------------------------------
# Cloud-init hostname preservation (prevent reboot hostname reset)
# -------------------------------------------------------------------------
CLOUD_INIT_CFG="/etc/cloud/cloud.cfg"
CLOUD_INIT_DROPIN="/etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg"
if command -v cloud-init >/dev/null 2>&1 || [[ -f "$CLOUD_INIT_CFG" ]]; then
    log_info "🧩 Cloud-init detected - ensuring hostname is preserved across reboots"

    # Check if preserve_hostname is already set
    _preserve_set=false
    if [[ -f "$CLOUD_INIT_CFG" ]] && grep -qE '^preserve_hostname:[[:space:]]*true' "$CLOUD_INIT_CFG" 2>/dev/null; then
        _preserve_set=true
    fi
    if [[ -d /etc/cloud/cloud.cfg.d ]]; then
        for _cf in /etc/cloud/cloud.cfg.d/*.cfg; do
            [[ -f "$_cf" ]] && grep -qE '^preserve_hostname:[[:space:]]*true' "$_cf" 2>/dev/null && _preserve_set=true
        done
    fi

    if $_preserve_set; then
        log_info "✅ Cloud-init preserve_hostname already enabled"
    else
        if $VALIDATE_ONLY; then
            log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would write $CLOUD_INIT_DROPIN (preserve_hostname: true)"
        elif $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would write $CLOUD_INIT_DROPIN (preserve_hostname: true)"
        else
            mkdir -p /etc/cloud/cloud.cfg.d 2>/dev/null || true
            write_file 0644 "$CLOUD_INIT_DROPIN" <<'EOF'
# Managed by linux-ad-domain-join.sh - prevent cloud-init from resetting hostname
preserve_hostname: true
EOF
            log_info "✅ Cloud-init preserve_hostname configured via $CLOUD_INIT_DROPIN"
        fi
    fi
fi

# -------------------------------------------------------------------------
# systemd-resolved symlink fix (Ubuntu 20.04+)
# -------------------------------------------------------------------------
if [[ "$ID" == "ubuntu" ]]; then
    if (( UBUNTU_MAJOR >= 20 )); then
        RESOLV_CONF="/etc/resolv.conf"
        STUB_TARGET="/run/systemd/resolve/stub-resolv.conf"
        FULL_TARGET="/run/systemd/resolve/resolv.conf"

        if [[ -L "$RESOLV_CONF" ]]; then
            _link_target="$(readlink -f "$RESOLV_CONF" 2>/dev/null || true)"
            if [[ ! -e "$_link_target" ]]; then
                log_info "⚠ $RESOLV_CONF symlink is broken (target: $_link_target)"
                _file_ensure_mutable "$RESOLV_CONF"

                if $VALIDATE_ONLY; then
                    log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would fix $RESOLV_CONF symlink"
                elif $DRY_RUN; then
                    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would fix $RESOLV_CONF symlink -> $STUB_TARGET"
                else
                    if [[ -e "$STUB_TARGET" ]]; then
                        ln -sf "$STUB_TARGET" "$RESOLV_CONF"
                        log_info "✅ Fixed $RESOLV_CONF symlink -> $STUB_TARGET"
                    elif [[ -e "$FULL_TARGET" ]]; then
                        ln -sf "$FULL_TARGET" "$RESOLV_CONF"
                        log_info "✅ Fixed $RESOLV_CONF symlink -> $FULL_TARGET (fallback)"
                    else
                        log_info "⚠ Neither $STUB_TARGET nor $FULL_TARGET exist; cannot fix symlink"
                    fi
                fi

                _file_restore_attr "$RESOLV_CONF"
            else
                $VERBOSE && log_info "ℹ $RESOLV_CONF symlink OK (-> $_link_target)"
            fi
        fi
    fi
fi

# -------------------------------------------------------------------------
# DNS Persistence Configuration (NetworkManager, systemd-resolved, static)
# Ensures DC DNS server is configured and persists across reboots/restarts
# -------------------------------------------------------------------------
log_info "🔧 Configuring DNS persistence for Active Directory"

# Detect network management system and configure DNS accordingly
_dns_configured=false
DC_DNS_IP="${DC_DNS_IP:-$DC_V4}"  # Use DC IP as DNS server (if not explicitly set)
[[ -z "$DC_DNS_IP" ]] && DC_DNS_IP="$(getent ahostsv4 "$DC_SERVER" 2>/dev/null | awk 'NR==1{print $1; exit}')"

if [[ -z "$DC_DNS_IP" ]]; then
    log_info "⚠ Could not determine DC IP address for DNS configuration"
else
    log_info "ℹ Using DNS server: $DC_DNS_IP (DC: $DC_SERVER)"

    # Method 1: NetworkManager (nmcli) - most common on modern RHEL/Fedora/Ubuntu Desktop
    if command -v nmcli >/dev/null 2>&1 && systemctl is-active NetworkManager &>/dev/null; then
        log_info "🔧 NetworkManager detected - configuring DNS via nmcli"

        # Get active connection for primary interface
        _nm_conn=""
        if [[ -n "$PRIMARY_IFACE" ]]; then
            _nm_conn="$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | grep ":${PRIMARY_IFACE}$" | cut -d: -f1 | head -n1)"
        fi
        [[ -z "$_nm_conn" ]] && _nm_conn="$(nmcli -t -f NAME con show --active 2>/dev/null | head -n1)"

        if [[ -n "$_nm_conn" ]]; then
            if $VALIDATE_ONLY; then
                log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would configure DNS via nmcli for connection '$_nm_conn'"
                _dns_configured=true
            elif $DRY_RUN; then
                log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would run: nmcli con mod '$_nm_conn' ipv4.dns '$DC_DNS_IP' ipv4.dns-search '$DOMAIN'"
                _dns_configured=true
            else
                # Get current DNS to prepend DC (avoid overwriting all DNS)
                _current_dns="$(nmcli -g ipv4.dns con show "$_nm_conn" 2>/dev/null | tr ',' ' ')"
                _current_dns="$(trim_ws "$_current_dns")"
                if [[ "$_current_dns" != *"$DC_DNS_IP"* ]]; then
                    _new_dns="$DC_DNS_IP"
                    [[ -n "$_current_dns" ]] && _new_dns="$DC_DNS_IP $_current_dns"
                    nmcli con mod "$_nm_conn" ipv4.dns "$_new_dns" 2>/dev/null || true
                fi
                # Add search domain
                _current_search="$(nmcli -g ipv4.dns-search con show "$_nm_conn" 2>/dev/null | tr ',' ' ')"
                _current_search="$(trim_ws "$_current_search")"
                if [[ "$_current_search" != *"$DOMAIN"* ]]; then
                    _new_search="$DOMAIN"
                    [[ -n "$_current_search" ]] && _new_search="$DOMAIN $_current_search"
                    nmcli con mod "$_nm_conn" ipv4.dns-search "$_new_search" 2>/dev/null || true
                fi
                # Prevent DHCP from overwriting DNS (ignore-auto-dns)
                nmcli con mod "$_nm_conn" ipv4.ignore-auto-dns yes 2>/dev/null || true
                # Apply changes
                nmcli con up "$_nm_conn" 2>/dev/null || true
                log_info "✅ DNS configured via NetworkManager (connection: $_nm_conn)"
                _dns_configured=true
            fi
        else
            log_info "⚠ NetworkManager active but no connection found for interface $PRIMARY_IFACE"
        fi
    fi

    # Method 2: systemd-resolved (resolvectl) - Ubuntu 18.04+, Fedora, Arch
    if ! $_dns_configured && command -v resolvectl >/dev/null 2>&1 && systemctl is-active systemd-resolved &>/dev/null; then
        log_info "🔧 systemd-resolved detected - configuring DNS via resolvectl"

        _resolve_iface="${PRIMARY_IFACE:-$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
        if [[ -n "$_resolve_iface" ]]; then
            if $VALIDATE_ONLY; then
                log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would configure DNS via resolvectl for $_resolve_iface"
                _dns_configured=true
            elif $DRY_RUN; then
                log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would run: resolvectl dns $_resolve_iface $DC_DNS_IP"
                _dns_configured=true
            else
                resolvectl dns "$_resolve_iface" "$DC_DNS_IP" 2>/dev/null || true
                resolvectl domain "$_resolve_iface" "$DOMAIN" 2>/dev/null || true
                log_info "✅ DNS configured via systemd-resolved (interface: $_resolve_iface)"
                _dns_configured=true

                # Make persistent via resolved.conf.d drop-in
                _resolved_dropin="/etc/systemd/resolved.conf.d"
                mkdir -p "$_resolved_dropin" 2>/dev/null || true
                if [[ -d "$_resolved_dropin" ]]; then
                    write_file 0644 "${_resolved_dropin}/99-ad-domain.conf" <<EOF
# Managed by linux-ad-domain-join.sh - AD DNS configuration
[Resolve]
DNS=$DC_DNS_IP
Domains=$DOMAIN
EOF
                    systemctl restart systemd-resolved 2>/dev/null || true
                    log_info "✅ DNS persisted via ${_resolved_dropin}/99-ad-domain.conf"
                fi
            fi
        fi
    fi

    # Method 3: Netplan (Ubuntu Server 18.04+) - create override config
    if ! $_dns_configured && command -v netplan >/dev/null 2>&1 && [[ -d /etc/netplan ]]; then
        log_info "🔧 Netplan detected - configuring DNS via drop-in config"

        _netplan_dropin="/etc/netplan/99-ad-dns.yaml"
        if $VALIDATE_ONLY; then
            log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would create $_netplan_dropin"
            _dns_configured=true
        elif $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would create $_netplan_dropin with DNS $DC_DNS_IP"
            _dns_configured=true
        else
            # Netplan requires proper YAML indentation
            _np_iface="${PRIMARY_IFACE:-eth0}"
            write_file 0600 "$_netplan_dropin" <<EOF
# Managed by linux-ad-domain-join.sh - AD DNS override
network:
  version: 2
  ethernets:
    ${_np_iface}:
      nameservers:
        addresses: [$DC_DNS_IP]
        search: [$DOMAIN]
EOF
            chmod 0600 "$_netplan_dropin"
            netplan apply 2>/dev/null || log_info "⚠ netplan apply failed - manual review recommended"
            log_info "✅ DNS configured via Netplan ($_netplan_dropin)"
            _dns_configured=true
        fi
    fi

    # Method 4: dhclient hook (Debian/Ubuntu with traditional DHCP)
    if ! $_dns_configured && [[ -d /etc/dhcp/dhclient-enter-hooks.d ]]; then
        log_info "🔧 dhclient detected - configuring DNS via hook"

        _dhclient_hook="/etc/dhcp/dhclient-enter-hooks.d/ad-dns"
        if $VALIDATE_ONLY; then
            log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would create $_dhclient_hook"
            _dns_configured=true
        elif $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would create $_dhclient_hook"
            _dns_configured=true
        else
            write_file 0755 "$_dhclient_hook" <<EOF
#!/bin/bash
# Managed by linux-ad-domain-join.sh - prepend AD DNS server
make_resolv_conf() {
    echo "nameserver $DC_DNS_IP" > /etc/resolv.conf
    echo "search $DOMAIN" >> /etc/resolv.conf
    if [ -n "\$new_domain_name_servers" ]; then
        for ns in \$new_domain_name_servers; do
            [ "\$ns" != "$DC_DNS_IP" ] && echo "nameserver \$ns" >> /etc/resolv.conf
        done
    fi
}
EOF
            log_info "✅ DNS configured via dhclient hook ($_dhclient_hook)"
            _dns_configured=true
        fi
    fi

    # Method 5: Static /etc/resolv.conf (fallback for minimal systems)
    if ! $_dns_configured; then
        log_info "🔧 Fallback: configuring DNS directly in /etc/resolv.conf"

        RESOLV_CONF="/etc/resolv.conf"
        if $VALIDATE_ONLY; then
            log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would update $RESOLV_CONF with DNS $DC_DNS_IP"
            _dns_configured=true
        elif $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would update $RESOLV_CONF with DNS $DC_DNS_IP"
            _dns_configured=true
        else
            _file_ensure_mutable "$RESOLV_CONF"

            # Backup current resolv.conf
            backup_file "$RESOLV_CONF"

            # Check if already configured
            if ! grep -qE "^nameserver[[:space:]]+${DC_DNS_IP//./\\.}([[:space:]]|$)" "$RESOLV_CONF" 2>/dev/null; then
                # Prepend DC DNS to existing config
                _tmp_resolv="$(safe_mktemp)"
                {
                    echo "# Managed by linux-ad-domain-join.sh"
                    echo "nameserver $DC_DNS_IP"
                    echo "search $DOMAIN"
                    # Keep existing nameservers (excluding DC to avoid duplicates)
                    grep -E '^nameserver[[:space:]]' "$RESOLV_CONF" 2>/dev/null | grep -v "$DC_DNS_IP" | head -n 2 || true
                } > "$_tmp_resolv"
                cat "$_tmp_resolv" > "$RESOLV_CONF"
                rm -f "$_tmp_resolv"
                log_info "✅ DNS configured in $RESOLV_CONF"
            else
                log_info "✅ DNS already configured in $RESOLV_CONF"
            fi

            _file_restore_attr "$RESOLV_CONF"
            _dns_configured=true
        fi
    fi
fi

if $_dns_configured; then
    log_info "✅ DNS persistence configuration complete"
else
    log_info "⚠ DNS persistence could not be automatically configured - manual configuration may be required"
fi

# Pre-check: verify DNS and KDC connectivity
log_info "🔎 Performing pre-check for DNS and KDC reachability"

# Test DNS resolution
if ! host "$DC_SERVER" &>/dev/null; then
    log_error "Unable to resolve domain controller: $DC_SERVER (check DNS configuration)" 10
fi

# Test Kerberos (TCP/88)
if tcp_port_open "$DC_SERVER" 88 3; then
    :
else
    log_error "Cannot reach Kerberos port 88 on $DC_SERVER (network/firewall issue)" 11
fi

# Test LDAP (TCP/389 or TCP/636 for LDAPS)
if tcp_port_open "$DC_SERVER" 389 3 || tcp_port_open "$DC_SERVER" 636 3; then
    log_info "✅ LDAP connectivity verified (TCP/389 or TCP/636)"
else
    log_error "Cannot reach LDAP port 389 on $DC_SERVER (network/firewall issue)" 12
fi

log_info "✅ DNS and KDC reachability OK"

# -------------------------------------------------------------------------
# Time skew pre-check (fail fast before Kerberos - max 300s allowed by AD)
# -------------------------------------------------------------------------
log_info "🕒 Checking system clock skew before Kerberos authentication"
_time_skew_ok=false

# Strategy 1: ntpdate -q (query only, no adjustment)
if command -v ntpdate >/dev/null 2>&1 && [[ -n "${NTP_SERVER:-}" ]]; then
    _ntp_out="$(timeout 10 ntpdate -q "$NTP_SERVER" 2>/dev/null || true)"
    _ntp_offset="$(echo "$_ntp_out" | awk '/offset/ {for(i=1;i<=NF;i++) if($i=="offset") print $(i+1)}' | tail -n1)"
    if [[ -n "$_ntp_offset" ]]; then
        # Convert to absolute integer seconds
        _abs_offset="$(echo "$_ntp_offset" | awk '{v=($1<0)?-$1:$1; printf "%d", v}')"
        if (( _abs_offset > 300 )); then
            log_info "⚠ System clock skew is ${_ntp_offset}s (max 300s for Kerberos)"
            log_info "🔄 Attempting forced time sync via ntpdate"
            if ! $DRY_RUN && ! $VALIDATE_ONLY; then
                ntpdate -u "$NTP_SERVER" >/dev/null 2>&1 && log_info "✅ Time synchronized via ntpdate" \
                    || log_info "⚠ ntpdate sync failed; Kerberos may reject authentication"
            fi
        else
            log_info "✅ Clock skew within tolerance (${_ntp_offset}s)"
            _time_skew_ok=true
        fi
    fi
fi

# Strategy 2: HTTP Date header from DC (fallback when ntpdate unavailable)
if ! $_time_skew_ok && command -v curl >/dev/null 2>&1; then
    # FIX: Protect pipeline with || true to handle empty/missing Date header
    _http_date="$(timeout 5 curl -sI "http://${DC_SERVER}/" 2>/dev/null | awk -F': ' '/^[Dd]ate:/{print $2}' | tr -d '\r' || true)"
    if [[ -n "$_http_date" ]]; then
        _remote_epoch="$(date -d "$_http_date" +%s 2>/dev/null || true)"
        _local_epoch="$(date +%s)"
        if [[ -n "$_remote_epoch" ]]; then
            _diff=$(( _local_epoch - _remote_epoch ))
            _abs_diff=$(( _diff < 0 ? -_diff : _diff ))
            if (( _abs_diff > 300 )); then
                log_info "⚠ Clock skew detected via HTTP Date header: ${_diff}s (max 300s for Kerberos)"
            else
                log_info "✅ Clock skew within tolerance (${_diff}s, via HTTP header)"
                _time_skew_ok=true
            fi
        fi
    fi
fi

if ! $_time_skew_ok; then
    log_info "ℹ Time skew check inconclusive (ntpdate/curl unavailable or failed); proceeding"
fi

# Create secure password file (tmpfs, 0600, no TOCTOU race, no ps exposure)
create_secret_passfile() {
    local old_umask
    old_umask="$(umask)"              # Save current umask for restoration
    trap 'umask "$old_umask"; trap - RETURN' RETURN  # Restore umask when function returns

    # Set umask to 077 (file permissions will be 0600 = rw-------)
    # This prevents TOCTOU race conditions by ensuring secure permissions at creation time
    umask 077

    # Prefer tmpfs-backed directories (memory-only, no disk writes)
    # Fallback to /tmp for legacy systems or containers without tmpfs
    local base=""
    if [[ -d /run && -w /run ]]; then
        base="/run"                   # systemd standard tmpfs location
    elif [[ -d /dev/shm && -w /dev/shm ]]; then
        base="/dev/shm"               # POSIX shared memory tmpfs
    else
        base="/tmp"                   # Legacy fallback (may be disk-backed)
    fi

    # Create temp file with secure permissions (0600) atomically via umask
    # No separate chmod needed - umask 077 ensures correct permissions at creation
    PASS_FILE="$(mktemp "${base}/.adjoin.pass.XXXXXX")" || log_error "Failed to create temporary password file" 1

    # Store password as a single line (no trailing newline).
    # OpenLDAP -y reads the entire file as password; newline/CR would be treated as part of the secret.
    if [[ "${DOMAIN_PASS:-}" == *$'\n'* || "${DOMAIN_PASS:-}" == *$'\r'* ]]; then
        log_error "DOMAIN_PASS contains newline/CR characters; refusing because ldapsearch -y would treat them as part of the password." 1
    fi

    printf '%s' "$DOMAIN_PASS" > "$PASS_FILE" || log_error "Failed to write temporary password file" 1

    # Remove from memory ASAP
    unset DOMAIN_PASS

    # Ensure tools support safe password file usage (ldapsearch -y)
    if command -v ldapsearch >/dev/null 2>&1; then
        if ! (command ldapsearch --help 2>&1 || command ldapsearch -? 2>&1 || true) | grep -qE -- '(^|[[:space:]])-y([[:space:]]|,|$)'; then
            log_error "ldapsearch does not support -y (password file). Refusing insecure -w usage." 1
        fi
    fi
}

cleanup_secrets() {
    # Restore immutable bits on any files we unlocked
    _file_restore_all_attrs 2>/dev/null || true

    # Best-effort secure delete
    if [[ -n "${PASS_FILE:-}" && -f "${PASS_FILE:-}" ]]; then
        if command -v shred >/dev/null 2>&1; then
            shred -u -z -n 3 "$PASS_FILE" 2>/dev/null || rm -f "$PASS_FILE"
        elif command -v srm >/dev/null 2>&1; then
            srm -f "$PASS_FILE" 2>/dev/null || rm -f "$PASS_FILE"
        else
            rm -f "$PASS_FILE"
        fi
    fi

    # Release mkdir-based lock (if flock is unavailable).
    if [[ "${LOCK_MODE:-}" == "mkdir" && -n "${LOCK_DIR_FALLBACK:-}" ]]; then
        rm -rf "${LOCK_DIR_FALLBACK}" 2>/dev/null || true
    fi

    unset PASS_FILE

    # Just in case someone reintroduced it
    unset DOMAIN_PASS
}

# Install traps only once
trap cleanup_secrets EXIT HUP INT TERM

# Create secret file now (DOMAIN_PASS must exist at this moment)
create_secret_passfile

# -------------------------------------------------------------------------
# Kerberos credential validation (controlled error handling block)
# -------------------------------------------------------------------------
log_info "🔐 Verifying credentials for $DOMAIN_USER@$REALM"
KRB_TRACE=$(safe_mktemp)

# Temporarily relax -e and disable ERR trap to classify kinit failures
trap - ERR
set +e

KRB5_TRACE="$KRB_TRACE" kinit "$DOMAIN_USER@$REALM" <"$PASS_FILE" >/dev/null 2>&1
KINIT_CODE=$?

set -e
# Restore ERR trap safely
trap "$ERROR_TRAP_CMD" ERR

# analyze both return code AND trace contents
if (( KINIT_CODE == 0 )) && ! grep -qiE 'CLIENT_LOCKED_OUT|revoked|disabled|locked out|denied|expired' "$KRB_TRACE"; then
    kdestroy -q 2>/dev/null || true
    log_info "✅ Credentials verified successfully"
else
    if grep -qiE 'CLIENT_LOCKED_OUT|client.*locked out|credentials have been revoked|Client account disabled|STATUS_ACCOUNT_LOCKED_OUT' "$KRB_TRACE"; then
        log_error "Account is locked or disabled in Active Directory" 21
    elif grep -qiE 'expired|password expired' "$KRB_TRACE"; then
        log_error "Account password has expired - please reset via AD" 22
    elif grep -qiE 'Cannot contact any KDC|Server not found in Kerberos database|Name or service not known|Cannot resolve network address' "$KRB_TRACE"; then
        log_error "Cannot reach the domain controller or resolve the realm (DNS/KDC issue)" 11
    elif grep -qiE 'Clock skew too great|client not yet valid|not yet valid' "$KRB_TRACE"; then
        log_error "Kerberos time synchronization problem (check NTP/chrony)" 13
    elif grep -qiE 'Password incorrect|Preauthentication failed' "$KRB_TRACE"; then
        log_error "Invalid credentials (authentication rejected by KDC)" 2
	elif grep -qiE 'Client not found in Kerberos database' "$KRB_TRACE"; then
        log_error "User principal not found in Active Directory or wrong realm specified" 23
    else
        last_msg=$(grep -E 'krb5|KRB5|error|revoked|denied' "$KRB_TRACE" | tail -n 1 | sed -E 's/\s+/ /g')
        [[ -n "$last_msg" ]] && log_info "ℹ Last trace line: $last_msg"
        log_error "Kerberos authentication failed with unknown reason (exit $KINIT_CODE)" 14
    fi
fi
rm -f "$KRB_TRACE"

# -------------------------------------------------------------------------
# Convert DNS domain to LDAP DN: "example.com" -> "DC=EXAMPLE,DC=COM"
DOMAIN_DN=$(awk -F'.' '{
    for (i = 1; i <= NF; i++) printf "%sDC=%s", (i>1?",":""), toupper($i)
}' <<< "$DOMAIN")

BASE_DN="$DOMAIN_DN"

if [[ ! "$OU" =~ [Dd][Cc]= ]]; then
    log_info "⚠ OU missing DC= - using default Computers container"
    OU="CN=Computers,${DOMAIN_DN}"
fi

# -------------------------------------------------------------------------
# Validate OU existence (with fallback, simple bind)
# -------------------------------------------------------------------------
log_info "🔍 Checking OU: $OU"

LDAP_OUT="$(
    set +e +o pipefail
    timeout "$LDAP_TIMEOUT" ldapsearch -x -LLL -o ldif-wrap=no \
        -H "ldap://${LDAP_SERVER}" \
        -D "${DOMAIN_USER}@${DOMAIN}" -y "$PASS_FILE" \
        -b "$OU" "(|(objectClass=organizationalUnit)(objectClass=container))" 2>&1
)" && LDAP_CODE=0 || LDAP_CODE=$?

if [[ $LDAP_CODE -ne 0 || -z "$LDAP_OUT" ]]; then
    log_info "⚠ OU not found - applying fallback"
    OU="CN=Computers,${DOMAIN_DN}"
    log_info "↪ Using fallback: $OU"

    # Test fallback OU also under safe mode
    LDAP_OUT="$(
        set +e +o pipefail
        timeout "$LDAP_TIMEOUT" ldapsearch -x -LLL -o ldif-wrap=no \
            -H "ldap://${LDAP_SERVER}" \
            -D "${DOMAIN_USER}@${DOMAIN}" -y "$PASS_FILE" \
            -b "$OU" "(|(objectClass=organizationalUnit)(objectClass=container))" 2>&1
    )" && LDAP_CODE=0 || LDAP_CODE=$?

    [[ $LDAP_CODE -ne 0 || -z "$LDAP_OUT" ]] && log_error "Invalid OU and fallback missing - aborting" 4
fi

# checking existing realm
log_info "🧭 Verifying local realm join state"
REALM_JOINED=$(safe_realm_list | awk '/^[^ ]/ {print tolower($1)}' | grep -i "^$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]')" || true)

# -------------------------------------------------------------------------
# DOMAIN VALIDATION & REJOIN DECISION
# -------------------------------------------------------------------------
if [[ -n "$REALM_JOINED" ]]; then
    log_info "🔎 Realm configuration found for $DOMAIN (local state)"

    # Test Kerberos trust using the machine principal
    if kinit -kt "$KRB5_KEYTAB" "$MACHINE_PRINCIPAL" >/dev/null 2>&1; then
        kdestroy -q 2>/dev/null || true
        log_info "✅ Kerberos trust is intact (keytab is valid)"
        if ! $NONINTERACTIVE; then
          read_sanitized "⚠️ Joined locally with valid trust. Rejoin anyway? [y/N]: " REPLY
            if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
                log_info "🚪 Exiting without rejoin"
                exit 0
            fi
        else
            log_info "ℹ Non-interactive: proceeding with forced rejoin"
        fi
    else
        log_info "⚠️ Kerberos trust is broken (keytab test failed). Proceeding with rejoin and cleanup."
    fi

    # ---------------------------------------------------------------------
    # DOMAIN LEAVE & CLEANUP PHASE
    # ---------------------------------------------------------------------
    log_info "🚪 Preparing to leave existing domain configuration..."

    if safe_realm_list | grep -qi "$DOMAIN"; then
        log_info "↪ Host currently joined - performing safe leave..."

        # Detect if '--force' is supported (RHEL vs Ubuntu)
        if realm leave --help 2>&1 | grep -q -- '--force'; then
            REALM_LEAVE_CMD=( realm leave --force )
        else
            REALM_LEAVE_CMD=( realm leave --unattended )
        fi

        cmd_try "${REALM_LEAVE_CMD[@]}"
        REALMLEAVE_RC=$CMD_LAST_RC

        if [[ $REALMLEAVE_RC -eq 0 ]]; then
            log_info "✅ Successfully left current realm."
        else
            log_info "⚠️ Leave operation returned non-zero code ($REALMLEAVE_RC) - continuing with cleanup."
        fi
    else
        log_info "ℹ️ No active realm detected - performing residual cleanup to ensure a fresh join."
    fi

    # Always perform residual cleanup
    cmd_try rm -f "$KRB5_KEYTAB" /etc/sssd/sssd.conf /etc/realmd.conf
    log_info "🧹 Residual realm configuration cleaned."

else
    log_info "📛 Realm configuration not found. Host is not joined to $DOMAIN"
fi

# -------------------------------------------------------------------------
# Ensure /etc/krb5.conf consistency with current domain parameters
# -------------------------------------------------------------------------
log_info "🔧 Ensuring /etc/krb5.conf consistency for realm $REALM"

KRB_CONF="/etc/krb5.conf"
REALM_UPPER="${REALM^^}"

# Backup existing krb5.conf if present
if [[ -f "$KRB_CONF" ]]; then
    backup_file "$KRB_CONF"
fi

# If DC_SERVER is not set, attempt SRV autodiscovery
if [[ -z "$DC_SERVER" ]]; then
    log_info "ℹ DC_SERVER variable empty - attempting autodiscovery via SRV records"
    DC_SERVER=$(dig +short _ldap._tcp."$DOMAIN" SRV | awk '{print $4}' | head -n1)
    [[ -z "$DC_SERVER" ]] && log_error "Unable to autodiscover domain controller for $DOMAIN" 11
fi

# -------------------------------------------------------------------------
# Dynamic Kerberos configuration (krb5.conf) generation
# -------------------------------------------------------------------------
if dig +short _kerberos._tcp."$DOMAIN" SRV | grep -qE '^[0-9]'; then
    log_info "🌐 SRV records found for $DOMAIN - enabling DNS-based KDC discovery"
    write_file 0644 "$KRB_CONF" <<EOF
[libdefaults]
    default_realm = $REALM_UPPER
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true
    rdns = false

[realms]
    $REALM_UPPER = {
        default_domain = ${DOMAIN_LOWER}
    }

[domain_realm]
    .${DOMAIN_LOWER} = ${REALM_UPPER}
    ${DOMAIN_LOWER} = ${REALM_UPPER}
EOF
else
    log_info "⚠️ No SRV records found for $DOMAIN - using static KDC configuration ($DC_SERVER)"
    write_file 0644 "$KRB_CONF" <<EOF
[libdefaults]
    default_realm = $REALM_UPPER
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true
    rdns = false

[realms]
    $REALM_UPPER = {
        kdc = $DC_SERVER
        admin_server = $DC_SERVER
        default_domain = ${DOMAIN_LOWER}
    }

[domain_realm]
    .${DOMAIN_LOWER} = ${REALM_UPPER}
    ${DOMAIN_LOWER} = ${REALM_UPPER}
EOF
fi

# Apply standard permissions
cmd_must chmod 644 "$KRB_CONF"
log_info "✅ /etc/krb5.conf regenerated for realm $REALM_UPPER"

# -------------------------------------------------------------------------
# Enable SSSD and PAM mkhomedir (per-distro native)
# -------------------------------------------------------------------------
log_info "🔑 Configuring PAM for SSSD login and mkhomedir"

case $OS_FAMILY in
	debian)
		cmd_must pam-auth-update --enable sss mkhomedir --force
	;;
	rhel)
		if (( RHEL_MAJOR < 8 )); then
			# RHEL/CentOS/OL 6–7 -> authconfig
            cmd_must env LANG=C LC_ALL=C authconfig --enablesssd --enablesssdauth --enablemkhomedir --updateall
		else
			# RHEL/OL 8+ -> authselect
			cmd_must authselect select sssd with-mkhomedir --force
			cmd_must systemctl enable --now oddjobd
		fi
	;;
	suse)
		cmd_must pam-config -a --sss --mkhomedir
	;;
	*)
		log_info "⚠ Unsupported OS_FAMILY for PAM automation: $OS_FAMILY"
	;;
esac

# -------------------------------------------------------------------------
# Ensure oddjob mkhomedir D-Bus registration (RHEL/OL compatibility block)
# -------------------------------------------------------------------------
# Fully autonomous logic: performs D-Bus reload and, if needed, safe restart.
# Works across RHEL/OL 6–9 and automatically self-heals registration failures.
# -------------------------------------------------------------------------
if [[ "$OS_FAMILY" =~ ^(rhel)$ ]]; then
    log_info "🧩 Verifying oddjob mkhomedir D-Bus registration (no package installs)"

    DBUS_SVC="/usr/share/dbus-1/system-services/com.redhat.oddjob.service"
    ODDJOB_XML="/etc/oddjobd.conf.d/mkhomedir.conf"
    ODDJOB_SERVICE="oddjobd.service"
    ODDJOB_CHANGED=0

    cmd_try mkdir -p "$(dirname "$DBUS_SVC")" "$(dirname "$ODDJOB_XML")"

    # Create or repair the D-Bus service activation file
    if [[ ! -f "$DBUS_SVC" ]]; then
        log_info "🔧 Restoring D-Bus service file: $DBUS_SVC"
        write_file 0644 "$DBUS_SVC" <<'EOF'
[D-BUS Service]
Name=com.redhat.oddjob
Exec=/usr/sbin/oddjobd -n
User=root
SystemdService=oddjobd.service
EOF
        ODDJOB_CHANGED=1
    fi

    # Create or repair the oddjob mkhomedir XML interface
    if [[ ! -f "$ODDJOB_XML" ]]; then
        log_info "🔧 Restoring oddjob mkhomedir XML: $ODDJOB_XML"
        write_file 0644 "$ODDJOB_XML" <<'EOF'
<oddjobconfig version="1.0">
<service name="com.redhat.oddjob_mkhomedir">
    <object name="/">
    <interface name="com.redhat.oddjob_mkhomedir">
        <method name="CreateHome">
        <arg type="string" name="username"/>
        <arg type="string" name="homedir"/>
        <arg type="boolean" name="create_dir"/>
        <execute helper="/usr/sbin/oddjob-mkhomedir" user="root"/>
        </method>
    </interface>
    </object>
</service>
</oddjobconfig>
EOF
        ODDJOB_CHANGED=1
    fi

    # Apply SELinux contexts and reload systemd/dbus managers as needed
    if (( ODDJOB_CHANGED == 1 )); then
        if command -v restorecon >/dev/null 2>&1; then
            restorecon -F "$DBUS_SVC" "$ODDJOB_XML" 2>/dev/null || true
        fi

        log_info "🔄 Updating system management daemons (systemd and D-Bus)"
        cmd_try systemctl daemon-reexec || true
        cmd_try systemctl daemon-reload || true

        # Attempt to notify D-Bus to reload configuration
        if systemctl is-active --quiet dbus.service 2>/dev/null || systemctl is-active --quiet messagebus.service 2>/dev/null; then
            if command -v busctl >/dev/null 2>&1; then
                cmd_try busctl call org.freedesktop.DBus / org.freedesktop.DBus ReloadConfig 2>/dev/null || true
            else
                cmd_try dbus-send --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig >/dev/null 2>&1 || true
            fi
            log_info "✅ D-Bus configuration reloaded successfully"
        else
            log_info "ℹ️ D-Bus is not active - skipping configuration reload"
        fi
    fi

    # Ensure oddjobd service is enabled and active (RHEL/OL 6–9)
    if ! systemctl is-enabled --quiet "$ODDJOB_SERVICE" 2>/dev/null; then
        log_info "🔧 Enabling $ODDJOB_SERVICE"
        cmd_try systemctl enable "$ODDJOB_SERVICE" || true
    fi

    # Retry start sequence for legacy systemd versions (slow registration)
    retry_count=0
    max_retries=5
    while [ "$retry_count" -lt "$max_retries" ]; do
        if systemctl is-active --quiet "$ODDJOB_SERVICE"; then
            log_info "✅ $ODDJOB_SERVICE is active"
            break
        fi
        current_try=$((retry_count + 1))
        log_info "🔁 Starting $ODDJOB_SERVICE (attempt ${current_try}/${max_retries})"
        cmd_try systemctl start  "$ODDJOB_SERVICE" || true
        sleep 2
        retry_count=$((retry_count + 1))
    done

    # Verify operational status through D-Bus (auto-healing if broken)
    if dbus-send --system --dest=com.redhat.oddjob_mkhomedir --print-reply / com.redhat.oddjob_mkhomedir.Hello &>/dev/null; then
        log_info "✅ oddjob mkhomedir D-Bus service operational"
    else
        log_info "⚠️ D-Bus Hello denied or unavailable - attempting remediation"
        DBUS_SERVICE="$(detect_service_unit "dbus.service" "messagebus.service")"
        [[ -z "$DBUS_SERVICE" ]] && DBUS_SERVICE="dbus.service"

        # Warn if running over SSH (restart may affect active sessions)
        if [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_TTY:-}" ]]; then
            log_info "⚠️ Detected SSH session: restarting $DBUS_SERVICE may temporarily disrupt this session"
        fi

        # Try config reload first (cheaper/safer than restart)
        if command -v busctl >/dev/null 2>&1; then
            cmd_try busctl call org.freedesktop.DBus / org.freedesktop.DBus ReloadConfig >/dev/null 2>&1 || true
        else
            cmd_try dbus-send --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig >/dev/null 2>&1 || true
        fi

        # Re-test before full restart
        if dbus-send --system --dest=com.redhat.oddjob_mkhomedir --print-reply / com.redhat.oddjob_mkhomedir.Hello &>/dev/null; then
            log_info "✅ oddjob mkhomedir D-Bus service operational after ReloadConfig"
        else
            log_info "🔄 Restarting $DBUS_SERVICE silently (detached) as last resort"
            if $VALIDATE_ONLY; then
                log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Suppressed restart of $DBUS_SERVICE (non-invasive mode)"
            elif $DRY_RUN; then
                log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would restart $DBUS_SERVICE (detached) to heal oddjob D-Bus registration"
            else
                # Run detached restart to survive D-Bus drop when executing over SSH
                nohup setsid bash -c "systemctl restart '$DBUS_SERVICE' >/dev/null 2>&1 < /dev/null" >/dev/null 2>&1 &
                disown || true
                sleep 3
            fi

            # After D-Bus restart, re-test
            if dbus-send --system --dest=com.redhat.oddjob_mkhomedir --print-reply / com.redhat.oddjob_mkhomedir.Hello &>/dev/null; then
                log_info "✅ oddjob mkhomedir D-Bus service operational after D-Bus restart"
            else
                log_info "⚠️ D-Bus Hello still denied - common on RHEL/OL 7 (AccessDenied not fatal)"
            fi
        fi
    fi

    # Final health validation summary
    svc_state="inactive"
    systemctl is-active "$ODDJOB_SERVICE" &>/dev/null && svc_state="active"

    if [[ -f "$DBUS_SVC" && -f "$ODDJOB_XML" && "$svc_state" == "active" ]]; then
        log_info "✅ oddjob mkhomedir registration healthy (files present; service active)"
    else
        log_info "⚠️ oddjob mkhomedir registration may be incomplete (svc=$svc_state, dbus_svc: $( [[ -f $DBUS_SVC ]] && echo ok || echo missing ), xml: $( [[ -f $ODDJOB_XML ]] && echo ok || echo missing ))"
    fi
fi

# -------------------------------------------------------------------------
# Defensive PAM verification (cross-distro, non-intrusive)
# -------------------------------------------------------------------------
log_info "🧩 Verifying PAM stack consistency (non-intrusive check)"

# Detect primary PAM layout
case "$OS_FAMILY" in
	rhel)
		PAM_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
		;;
	debian|suse)
		PAM_FILES=("/etc/pam.d/common-auth" "/etc/pam.d/common-account" "/etc/pam.d/common-session" "/etc/pam.d/common-password")
		;;
	*)
		log_info "ℹ Unknown PAM layout for $OS_FAMILY - skipping PAM consistency check"
		PAM_FILES=()
		;;
esac

for file in "${PAM_FILES[@]}"; do
	if [[ ! -f "$file" ]]; then
		log_info "ℹ Skipping non-existent PAM file: $file"
		continue
	fi

    # Backup before modification
    backup_file "$file"

	# Disable legacy PAM modules (safe-comment)
	if grep -Eq 'pam_(ldap|winbind|nis)\.so' "$file"; then
        cmd_must sed -i '/pam_ldap\.so/s/^/# disabled legacy -> /' "$file"
        cmd_must sed -i '/pam_winbind\.so/s/^/# disabled legacy -> /' "$file"
        cmd_must sed -i '/pam_nis\.so/s/^/# disabled legacy -> /' "$file"
	fi

	# Guarantee pam_sss.so presence per section (DRY-RUN aware)
    for context in auth account password session; do
        if ! grep -Eq "^[[:space:]]*${context}[[:space:]].*pam_sss\\.so" "$file"; then
            case "$context" in
                auth)
                    append_line "$file" "auth        sufficient    pam_sss.so forward_pass"
                    ;;
                account)
                    append_line "$file" "account     [default=bad success=ok user_unknown=ignore] pam_sss.so"
                    ;;
                password)
                    append_line "$file" "password    sufficient    pam_sss.so use_authtok"
                    ;;
                session)
                    append_line "$file" "session     optional      pam_sss.so"
                    ;;
            esac
            log_info "🧩 Added missing pam_sss.so for $context -> $(basename "$file")"
        fi
    done
done

# Re-run consistency for RHEL-like systems
if [[ "$OS_FAMILY" =~ ^(rhel)$ ]]; then
	if command -v authconfig >/dev/null 2>&1; then
		cmd_must env LANG=C LC_ALL=C authconfig --update
	fi
fi

# -------------------------------------------------------------------------
# Final PAM validation (cross-distro, symlink-aware, fallback-safe)
# -------------------------------------------------------------------------
log_info "🔍 Performing PAM validation with symbolic link awareness"

PAM_VALIDATE_FILES=()
case "$OS_FAMILY" in
	rhel)
		for f in /etc/pam.d/system-auth /etc/pam.d/system-auth-ac /etc/pam.d/password-auth /etc/pam.d/password-auth-ac; do
			[[ -e "$f" ]] && PAM_VALIDATE_FILES+=("$f")
		done
		;;
	debian)
		for f in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session; do
			[[ -e "$f" ]] && PAM_VALIDATE_FILES+=("$f")
		done
		;;
	suse)
		for f in /etc/pam.d/common-auth-pc /etc/pam.d/common-account-pc /etc/pam.d/common-password-pc /etc/pam.d/common-session-pc; do
			[[ -e "$f" ]] && PAM_VALIDATE_FILES+=("$f")
		done
		;;
esac

if grep -E "pam_sss\.so" "${PAM_VALIDATE_FILES[@]}" 2>/dev/null | grep -qv '^[[:space:]]*#'; then
	log_info "✅ PAM integration validated - pam_sss.so is active and correctly configured"
else
	log_info "⚠️ PAM validation ambiguous - no active pam_sss.so lines detected"
	log_info "ℹ This may occur on OL7/RHEL7 due to symlinked .ac templates"
	log_info "ℹ If authentication via SSSD works, this warning can be ignored"
fi

# -------------------------------------------------------------------------
# Ensure NSS configuration uses SSSD (cross-distro, legacy-friendly)
# -------------------------------------------------------------------------
log_info "🔧 Validating /etc/nsswitch.conf for SSSD integration"

# Resolve the canonical nsswitch path (SUSE may ship defaults under /usr/etc)
NSS_FILE="/etc/nsswitch.conf"
[[ ! -f "$NSS_FILE" && -f /usr/etc/nsswitch.conf ]] && NSS_FILE="/usr/etc/nsswitch.conf"

# If the file does not exist, create a minimal, sane default first (0644)
if [[ ! -f "$NSS_FILE" ]]; then
    log_info "⚙ Creating minimal $NSS_FILE"

    old_umask="$(umask)"              # Save current umask
    umask 022                         # Ensure default readable system file permissions

    write_file 0644 "$NSS_FILE" <<'EOF'
passwd:		files
shadow:		files
group:		files
hosts:		files dns
services:	files
netgroup:	files
EOF

    if ! $DRY_RUN && ! $VALIDATE_ONLY; then
        chown root:root "$NSS_FILE" 2>/dev/null || true
    fi
    umask "$old_umask"
fi

# Basic access checks (after creation above to avoid false negatives)
[[ -r "$NSS_FILE" ]] || log_error "Cannot read $NSS_FILE - verify overlay/permissions." 1
[[ -w "$(dirname "$NSS_FILE")" ]] || log_error "NSS path $(dirname "$NSS_FILE") is not writable (read-only filesystem)." 1

# Ensure nsswitch.conf is mutable before editing (auto-restores via cleanup trap)
_file_ensure_mutable "$NSS_FILE"

# Normalize line endings (CRLF-safe) before backup
if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would normalize CRLF in $NSS_FILE"
elif $VALIDATE_ONLY; then
    log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Skipping CRLF normalization in $NSS_FILE"
else
    cmd_must sed -i 's/\r$//' "$NSS_FILE"
fi

# Backup prior to modifications
backup_file "$NSS_FILE"

# -------------------------------------------------------------------------
# NSS/SSSD line normalization (deduplicated, legacy-safe, idempotent)
# -------------------------------------------------------------------------
# Work file (real or temp)
NSS_EDIT="$NSS_FILE"
NSS_EDIT_TMP=""

# VALIDATE_ONLY and DRY_RUN both work on a temp copy to avoid modifying the real file
if $DRY_RUN || $VALIDATE_ONLY; then
    NSS_EDIT_TMP="$(safe_mktemp "/tmp/nsswitch.conf.XXXXXX")"
    if [[ -f "$NSS_FILE" ]]; then
        cp -p -- "$NSS_FILE" "$NSS_EDIT_TMP"
    else
        : >"$NSS_EDIT_TMP"
    fi
    NSS_EDIT="$NSS_EDIT_TMP"
fi

# All edits below operate on $NSS_EDIT (temp file in DRY_RUN/VALIDATE_ONLY, real file otherwise).
# Direct sed/awk is used intentionally to bypass cmd_must suppression on temp files.
for key in passwd shadow group services netgroup; do
    pattern="^[[:space:]]*${key}:"

    [ -f "$NSS_EDIT" ] || : >"$NSS_EDIT"

    # Normalize whitespace (work file) — use cmd_must only on the real file
    if [[ "$NSS_EDIT" == "$NSS_FILE" ]]; then
        cmd_must sed -i 's/[[:space:]]\{2,\}/ /g; s/[[:space:]]\+$//' "$NSS_EDIT"
    else
        sed -i 's/[[:space:]]\{2,\}/ /g; s/[[:space:]]\+$//' "$NSS_EDIT"
    fi

    # Remove duplicate entries (preserve first non-commented)
    if grep -Eq "${pattern}" "$NSS_EDIT"; then
        awk -v key="${key}" '
            BEGIN {found=0}
            /^[[:space:]]*#/ {print; next}
            tolower($0) ~ "^[[:space:]]*"key":" {
                if (found==0) {found=1; print}
                next
            }
            {print}
        ' "$NSS_EDIT" > "${NSS_EDIT}.tmp" && mv "${NSS_EDIT}.tmp" "$NSS_EDIT"
    fi

    # Skip if entry already includes 'sss'
    if grep -Eq "${pattern}[^#]*[[:space:]]sss([[:space:]]|\$)" "$NSS_EDIT"; then
        $VERBOSE && log_info "ℹ️ '${key}' already includes sss"
        continue
    fi

    # If entry exists but lacks 'sss', patch it
    if grep -qE "${pattern}[^#]*" "$NSS_EDIT"; then
        log_info "🧩 Updating existing '${key}' entry to include sss"
        if [[ "$NSS_EDIT" == "$NSS_FILE" ]]; then
            # shellcheck disable=SC2086
            cmd_must sed $SED_EXT -i "s/[[:space:]]+(ldap|nis|yp)//g; s/[[:space:]]{2,}/ /g" "$NSS_EDIT"
            cmd_must sed -i \
                -e "s/^\([[:space:]]*${key}:[^#]*\)\(#.*\)$/\1 sss \2/" \
                -e "s/^\([[:space:]]*${key}:[^#]*\)$/\1 sss/" "$NSS_EDIT"
            cmd_must sed -i 's/sss[[:space:]]\+sss/sss/g; s/[[:space:]]\{2,\}/ /g' "$NSS_EDIT"
        else
            # shellcheck disable=SC2086
            sed $SED_EXT -i "s/[[:space:]]+(ldap|nis|yp)//g; s/[[:space:]]{2,}/ /g" "$NSS_EDIT"
            sed -i \
                -e "s/^\([[:space:]]*${key}:[^#]*\)\(#.*\)$/\1 sss \2/" \
                -e "s/^\([[:space:]]*${key}:[^#]*\)$/\1 sss/" "$NSS_EDIT"
            sed -i 's/sss[[:space:]]\+sss/sss/g; s/[[:space:]]\{2,\}/ /g' "$NSS_EDIT"
        fi
        log_info "✅ '${key}' updated"
    else
        printf '%s\n' "${key}: files sss" >>"$NSS_EDIT"
        log_info "➕ Created missing '${key}' entry"
    fi
done

# Final whitespace normalization (collapse multiple spaces, trim ends)
awk '{$1=$1}1' "$NSS_EDIT" > "${NSS_EDIT}.tmp" && mv "${NSS_EDIT}.tmp" "$NSS_EDIT"

# -------------------------------------------------------------------------
# Validation (validate the WORK file, not the real file in DRY-RUN)
# -------------------------------------------------------------------------
if ! grep -qE '^passwd:[^#]*sss' "$NSS_EDIT" || ! grep -qE '^group:[^#]*sss' "$NSS_EDIT"; then
    log_error "Failed to configure NSS/SSSD for passwd/group lookups." 1
fi

# -------------------------------------------------------------------------
# Commit (only when not DRY-RUN and not VALIDATE_ONLY)
# -------------------------------------------------------------------------
if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would update $NSS_FILE with NSS/SSSD mappings (preview):"
    while IFS= read -r l || [[ -n "$l" ]]; do
        [[ -n "$l" ]] && log_info "   $l"
    done < <(grep -E '^(passwd|shadow|group|services|netgroup):' "$NSS_EDIT" 2>/dev/null || true)
elif $VALIDATE_ONLY; then
    log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} NSS/SSSD mappings validated (no changes applied to $NSS_FILE)"
else
    # Real mode: commit temp work to actual file
    if [[ "$NSS_EDIT" != "$NSS_FILE" ]]; then
        backup_file "$NSS_FILE"
        cp -p -- "$NSS_EDIT" "$NSS_FILE"
    fi
    command -v restorecon >/dev/null 2>&1 && cmd_try restorecon -F "$NSS_FILE" || true
fi

# Restore immutable bit if it was originally set
_file_restore_attr "$NSS_FILE"

# Optional runtime sanity checks (non-blocking)
if ! timeout 5 getent passwd root >/dev/null 2>&1; then
    log_info "⚠ NSS passwd lookup failed or timed out - verify SSSD/NSCD/network"
fi
if ! timeout 5 getent group root >/dev/null 2>&1; then
    log_info "⚠ NSS group lookup failed or timed out - verify SSSD/NSCD/network"
fi

# -------------------------------------------------------------------------
# Cache refresh (skip entirely in DRY-RUN)
# -------------------------------------------------------------------------
if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would stop nslcd (if present), restart sssd/nscd, and flush sss_cache"
else
    # If legacy nslcd is present, stop it to avoid conflicts with SSSD
    if command -v systemctl &>/dev/null; then
        systemctl list-units --type=service 2>/dev/null | grep -q '^nslcd\.service' && cmd_try systemctl stop nslcd || true
    fi

    # Restart order: SSSD first (reads nsswitch/sssd.conf), then NSCD to clear caches
    if command -v systemctl &>/dev/null; then
        # 1. SSSD
        if systemctl list-unit-files 2>/dev/null | grep -q '^sssd' || systemctl is-active sssd &>/dev/null; then
            log_info "🔄 Restarting SSSD"
            cmd_try systemctl restart sssd || true
        fi
        # 2. NSCD
        if systemctl list-unit-files 2>/dev/null | grep -q '^nscd' || systemctl is-active nscd &>/dev/null; then
            log_info "🔄 Restarting NSCD"
            cmd_try systemctl restart nscd || true
        fi
    else
        # Non-systemd fallback
        pgrep sssd &>/dev/null && { pkill -HUP sssd; log_info "🔄 Reloaded sssd"; }
        pgrep nscd &>/dev/null && { pkill -HUP nscd; log_info "🔄 Reloaded nscd"; }
    fi

    # Explicit SSSD cache flush when available
    if command -v sss_cache >/dev/null 2>&1; then
        sss_cache -E || true
    fi
fi

log_info "🌟 NSS/SSSD integration completed successfully"

# Cleanup temp work file (DRY-RUN only)
[[ -n "$NSS_EDIT_TMP" ]] && rm -f "$NSS_EDIT_TMP" || true

# -------------------------------------------------------------------------
# Disable legacy pam_ldap if SSSD is active (RHEL-like systems)
# -------------------------------------------------------------------------
if [[ "$OS_FAMILY" == "rhel" ]]; then
	log_info "🧩 Checking for legacy pam_ldap entries (system-auth, password-auth)"

	for pamfile in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
		[[ -f "$pamfile" ]] || continue

		# Backup PAM file before modification
        backup_file "$pamfile"

		# Detect presence of pam_ldap.so
		if grep -q "pam_ldap.so" "$pamfile"; then
			cmd_must sed -i \
            -e 's/^[[:space:]]*auth.*pam_ldap\.so/# &/' \
            -e 's/^[[:space:]]*account.*pam_ldap\.so/# &/' \
            -e 's/^[[:space:]]*password.*pam_ldap\.so/# &/' \
            -e 's/^[[:space:]]*session.*pam_ldap\.so/# &/' \
            "$pamfile"
		else
			[[ $VERBOSE == true ]] && log_info "ℹ No pam_ldap.so entries in $(basename "$pamfile")"
		fi
	done
fi

# -------------------------------------------------------------------------
# NTP (Chrony) - ROBUST (legacy + modern), non-destructive when possible
# -------------------------------------------------------------------------
log_info "⏰ Configuring NTP (Chrony) to use: ${NTP_SERVER}"

# Basic validation of NTP_SERVER (hostname/IP, no spaces) ----
if [[ -z "${NTP_SERVER:-}" ]]; then
    log_error "NTP_SERVER is empty - cannot configure time sync" 1
fi
if [[ "$NTP_SERVER" =~ [[:space:]] ]]; then
    log_error "NTP_SERVER contains whitespace: '$NTP_SERVER' (invalid)" 1
fi
if [[ ! "$NTP_SERVER" =~ ^[A-Za-z0-9._-]+$ ]]; then
    log_error "NTP_SERVER has invalid characters: '$NTP_SERVER' (allowed: A-Z a-z 0-9 . _ -)" 1
fi

# Optional preflight: reachability (UDP/123 is hard to probe without extra tools)
# We at least validate DNS resolution when it's a hostname.
if [[ ! "$NTP_SERVER" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    if ! getent hosts "$NTP_SERVER" >/dev/null 2>&1; then
        log_info "⚠️ NTP_SERVER hostname not resolvable right now: $NTP_SERVER (chrony may still work later)"
    fi
fi

# Detect chrony config main path (distro differences) ----
chrony_conf=""
if [[ -f /etc/chrony.conf ]]; then
    chrony_conf="/etc/chrony.conf"              # RHEL-like
elif [[ -f /etc/chrony/chrony.conf ]]; then
    chrony_conf="/etc/chrony/chrony.conf"       # Debian-like
else
    # Fallback: pick a sane default based on existing directory
    if [[ -d /etc/chrony ]]; then
        chrony_conf="/etc/chrony/chrony.conf"
    else
        chrony_conf="/etc/chrony.conf"
    fi
fi

# Ensure parent dirs exist (legacy safe)
cmd_try mkdir -p "$(dirname "$chrony_conf")" || true

# Backup if exists
if [[ -f "$chrony_conf" ]]; then
    backup_file "$chrony_conf"
else
    log_info "⚠️ Chrony main config not found at $chrony_conf - will create minimal base"
fi

# Decide strategy: drop-in (preferred) vs managed block inside main ----
# We prefer drop-in if main config has confdir/include pointing to a directory we can use.
chrony_dropin_dir=""
chrony_dropin_file=""
use_dropin=false

# Load existing content (if file exists) for detection (safe on empty)
chrony_main_content=""
if [[ -f "$chrony_conf" ]]; then
    chrony_main_content="$(cat "$chrony_conf" 2>/dev/null || true)"
fi

# Detect common chrony include mechanisms:
#   - RHEL:  confdir /etc/chrony.d
#   - Debian: confdir /etc/chrony/conf.d
#   - Debian: include /etc/chrony/conf.d/*.conf
#   - Some:   include /etc/chrony.d/*.conf
if echo "$chrony_main_content" | grep -qiE '^[[:space:]]*confdir[[:space:]]+/etc/chrony(\.d|/conf\.d)([[:space:]]|$)'; then
    chrony_dropin_dir="$(echo "$chrony_main_content" | awk '
        {
          l = tolower($0)
          if (l ~ /^[[:space:]]*confdir[[:space:]]+\/etc\/chrony(\.d|\/conf\.d)([[:space:]]|$)/) {
            print $2; exit
          }
        }
      '
    )"
elif echo "$chrony_main_content" | grep -qiE '^[[:space:]]*include[[:space:]]+/etc/chrony(\.d|/conf\.d)/.*\.conf([[:space:]]|$)'; then
    chrony_dropin_dir="$(echo "$chrony_main_content" | awk '
        {
          l = tolower($0)
          if (l ~ /^[[:space:]]*include[[:space:]]+\/etc\/chrony(\.d|\/conf\.d)\/.*\.conf([[:space:]]|$)/) {
            path = $2
            # strip glob/file -> keep dir
            gsub(/\*.*$/, "", path)
            sub(/\/[^\/]+\.conf$/, "/", path)
            sub(/\/$/, "", path)
            print path; exit
          }
        }
      '
    )"
fi

if [[ -n "$chrony_dropin_dir" ]]; then
    use_dropin=true
    cmd_try mkdir -p "$chrony_dropin_dir" || true
    chrony_dropin_file="${chrony_dropin_dir}/99-linux-ad-domain-join.conf"
fi

# Render Chrony configuration payload (portable + conservative) ----
# Notes:
# - We purposely avoid distro-specific directives unless harmless.
# - We set makestep to fix initial skew for Kerberos quickly.
# - driftfile path differs; we pick a safe default but also ensure dir exists.
# - logdir is optional; some minimal images don’t have it; harmless if absent.
chrony_drift_dir="/var/lib/chrony"
chrony_drift_file="/var/lib/chrony/drift"
if [[ -d /var/lib/chrony-drift && ! -d /var/lib/chrony ]]; then
    chrony_drift_dir="/var/lib/chrony-drift"
    chrony_drift_file="/var/lib/chrony-drift/drift"
fi
cmd_try mkdir -p "$chrony_drift_dir" || true
cmd_try mkdir -p /var/log/chrony 2>/dev/null || true

chrony_payload="$(cat <<EOF
# ======================================================================
# Managed by linux-ad-domain-join.sh
# Purpose: enforce domain NTP source for Kerberos stability
# DO NOT EDIT: changes may be overwritten
# Generated: $(date '+%F %T')
# ======================================================================

# Preferred domain NTP source
server ${NTP_SERVER} iburst

# Clock discipline basics
driftfile ${chrony_drift_file}
makestep 1.0 3
rtcsync

# Optional logging (best-effort)
logdir /var/log/chrony
EOF
)"

# Apply configuration (drop-in preferred; else managed block in main) ----
if $use_dropin; then
    log_info "🧩 Chrony include detected -> using drop-in: ${chrony_dropin_file}"
    write_file 0644 "$chrony_dropin_file" <<<"$chrony_payload"
else
    # Ensure base config exists; if missing, create minimal that is acceptable everywhere.
    if [[ ! -f "$chrony_conf" ]]; then
        log_info "🧩 Creating minimal Chrony base config at $chrony_conf"
        write_file 0644 "$chrony_conf" <<'EOF'
# Minimal chrony configuration created by linux-ad-domain-join.sh
# (No confdir/include detected; settings will be embedded below)
EOF
    fi

    # Replace an existing managed block, or append a new one.
    log_info "🧩 No include/confdir detected -> embedding managed block into $chrony_conf"

    tmp_chrony="$(safe_mktemp)"
    : >"$tmp_chrony"

    in_managed=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip CR safely
        line="${line%$'\r'}"

        if [[ "$line" == "# BEGIN linux-ad-domain-join chrony" ]]; then
            in_managed=1
            continue
        fi
        if [[ "$line" == "# END linux-ad-domain-join chrony" ]]; then
            in_managed=0
            continue
        fi

        # Preserve everything outside our managed block, but disable conflicting directives
        if (( in_managed == 0 )); then
            # Do not touch comments or blank lines
            if [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "$line" ]]; then
                echo "$line" >>"$tmp_chrony"
                continue
            fi

            # Do not disable include/confdir statements (drop-in support)
            if [[ "$line" =~ ^[[:space:]]*(include|confdir)[[:space:]]+ ]]; then
                echo "$line" >>"$tmp_chrony"
                continue
            fi

            # Comment out existing time-sync directives that we are about to enforce
            # to prevent duplication and configuration ambiguity.
            if [[ "$line" =~ ^[[:space:]]*(server|pool|driftfile|makestep|rtcsync|logdir)([[:space:]]+|$) ]]; then
                if [[ "$line" =~ disabled-by-linux-ad-domain-join: ]]; then
                    echo "$line" >>"$tmp_chrony"
                else
                    echo "# disabled-by-linux-ad-domain-join: $line" >>"$tmp_chrony"
                fi
            else
                echo "$line" >>"$tmp_chrony"
            fi
        fi
    done <"$chrony_conf"

    # Ensure a single blank line before our managed block (visual hygiene)
    tail -n 1 "$tmp_chrony" 2>/dev/null | grep -q '^[[:space:]]*$' || echo "" >>"$tmp_chrony"

    {
        echo "# BEGIN linux-ad-domain-join chrony"
        echo "$chrony_payload"
        echo "# END linux-ad-domain-join chrony"
        echo ""
    } >>"$tmp_chrony"


    # Normalize excessive blank lines to keep config visually clean.
    # Rule: collapse 2+ consecutive blank lines into a single blank line.
    tmp_chrony_norm="$(safe_mktemp)"
    awk '
        BEGIN { blank=0 }
        /^[[:space:]]*$/ {
            blank++
            if (blank <= 1) print ""
            next
        }
        { blank=0; print }
    ' "$tmp_chrony" >"$tmp_chrony_norm"

    mv -f "$tmp_chrony_norm" "$tmp_chrony"

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would update $chrony_conf with embedded managed block (preview suppressed)"
        rm -f "$tmp_chrony"
    else
        chown root:root "$tmp_chrony" 2>/dev/null || true
        chmod 644 "$tmp_chrony" 2>/dev/null || true
        mv -f "$tmp_chrony" "$chrony_conf" || log_error "Failed to install chrony config: $chrony_conf" 1
    fi
fi

# Detect chrony service name across systemd + sysvinit ----
chrony_service=""
chrony_unit=""

if command -v systemctl >/dev/null 2>&1; then
    chrony_unit="$(detect_service_unit "chrony.service" "chronyd.service")"
    if [[ -n "$chrony_unit" ]]; then
        chrony_service="${chrony_unit%.service}"
    fi
fi

# SysV fallback detection if systemd unit not found (or no systemd at all)
if [[ -z "$chrony_service" ]]; then
    if [[ -x /etc/init.d/chronyd ]]; then
        chrony_service="chronyd"
    elif [[ -x /etc/init.d/chrony ]]; then
        chrony_service="chrony"
    else
        # Last resort: common binary name; service wrapper may still work
        chrony_service="chronyd"
    fi
fi

# Disable conflicting time services (best-effort, non-fatal) ----
# systemd-timesyncd
if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-timesyncd\.service'; then
        if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
            log_info "🛑 Stopping systemd-timesyncd (conflicts with chrony)"
            cmd_try systemctl stop systemd-timesyncd || true
            cmd_try systemctl disable systemd-timesyncd || true
        fi
    fi
fi

# ntpd/ntp (very common in legacy)
if command -v systemctl >/dev/null 2>&1; then
    for u in ntpd.service ntp.service; do
        if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
            if systemctl is-active --quiet "${u%.service}" 2>/dev/null; then
                log_info "🛑 Stopping ${u%.service} (conflicts with chrony)"
                cmd_try systemctl stop "${u%.service}" || true
                cmd_try systemctl disable "${u%.service}" || true
            fi
        fi
    done
else
    # SysV best-effort
    if command -v service >/dev/null 2>&1; then
        service ntpd stop >/dev/null 2>&1 || true
        service ntp stop  >/dev/null 2>&1 || true
    fi
fi

# Enable + restart chrony (systemd/sysvinit) ----
log_info "🔧 Enabling and restarting Chrony service (${chrony_service})"

if $VALIDATE_ONLY; then
    log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Suppressing service enable/restart for chrony"
else
    if command -v systemctl >/dev/null 2>&1; then
        cmd_try systemctl enable "$chrony_service" || true
        cmd_try systemctl restart "$chrony_service" || cmd_try systemctl start "$chrony_service" || true
    elif command -v chkconfig >/dev/null 2>&1; then
        cmd_try chkconfig "$chrony_service" on || true
        cmd_try service "$chrony_service" restart || cmd_try service "$chrony_service" start || true
    elif command -v update-rc.d >/dev/null 2>&1; then
        cmd_try update-rc.d "$chrony_service" defaults || true
        cmd_try service "$chrony_service" restart || cmd_try service "$chrony_service" start || true
    elif command -v service >/dev/null 2>&1; then
        cmd_try service "$chrony_service" restart || cmd_try service "$chrony_service" start || true
    else
        log_info "⚠️ No service manager found to restart chrony; skipping restart"
    fi
fi

# Wait for synchronization (chronyc compatibility aware) ----
# We do NOT hard-require systemctl, and we don’t hard-require "Leap status".
# Success criteria (portable):
#   - chronyc sources shows a selected source (*), OR
#   - chronyc tracking shows Reference ID != 00000000 and Stratum is a number.
log_info "🕒 Waiting for NTP synchronization (up to 45s)"

synced=false
start_time="$(date +%s)"

# If chronyc has 'waitsync', prefer it (cleaner on newer chrony).
has_waitsync=false
if chronyc -h 2>/dev/null | grep -qi 'waitsync'; then
    has_waitsync=true
elif chronyc help 2>/dev/null | grep -qi 'waitsync'; then
    has_waitsync=true
fi

if $VALIDATE_ONLY; then
    log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Skipping active sync wait"
else
    if $has_waitsync; then
        # Use timeout with SIGKILL fallback for stubborn processes
        if timeout --signal=KILL 0 true >/dev/null 2>&1; then
            cmd_try timeout --signal=KILL 50 timeout 45 chronyc -a waitsync 45 0.5 >/dev/null 2>&1 || true
        else
            cmd_try timeout 45 chronyc -a waitsync 45 0.5 >/dev/null 2>&1 || true
        fi
    fi

    # Manual polling (works everywhere)
    for i in $(seq 1 45); do
        # 1) sources selected marker (*)
        if chronyc sources -n 2>/dev/null | grep -qE '^[\^\=\#\?][[:space:]]*\*'; then
            synced=true
        fi

        # 2) tracking fallback check
        if [[ "$synced" != true ]]; then
            refid="$(chronyc tracking 2>/dev/null | awk -F': *' 'tolower($1)=="reference id" {print $2; exit}' | awk '{print $1}' || true)"
            stratum="$(chronyc tracking 2>/dev/null | awk -F': *' 'tolower($1)=="stratum" {print $2; exit}' | awk '{print $1}' || true)"
            if [[ -n "$refid" && "$refid" != "00000000" && "$refid" != "0.0.0.0" && "$stratum" =~ ^[0-9]+$ ]]; then
                synced=true
            fi
        fi

        if [[ "$synced" == true ]]; then
            # Try to print what we are synced to (varies)
            synced_server="$(chronyc tracking 2>/dev/null | awk -F':' 'tolower($0) ~ /^reference id/ {print $2; exit}' | trim_line 2>/dev/null || true)"
            log_info "✅ NTP synchronized (Reference: ${synced_server:-unknown})"
            break
        fi

        # Progress line (stderr, sanitized)
        printf "\r${C_DIM}[%s]${C_RESET} ${C_BLUE}[i]${C_RESET} Waiting for NTP sync... ${C_CYAN}(%2ds/%2ds)${C_RESET}" "$(date '+%F %T')" "$i" "45" >&2
        sleep 1
    done
    printf "\r\033[K" >&2
fi

if [[ "$synced" != true ]]; then
    log_info "⚠️ NTP not synchronized yet after 45s (server: $NTP_SERVER)."
    log_info "ℹ Debug hints:"
    log_info "   - Check: chronyc sources -v"
    log_info "   - Check: chronyc tracking"
    log_info "   - Check logs: journalctl -u ${chrony_service} (systemd) OR /var/log/chrony/*"
else
    end_time="$(date +%s)"
    elapsed=$(( end_time - start_time ))
    log_info "ℹ Time sync confirmed in ${elapsed}s - proceeding with Kerberos operations"
fi

# -------------------------------------------------------------------------
# Obtain Kerberos ticket for domain operations
# -------------------------------------------------------------------------
log_info "🔑 Getting Kerberos ticket for user ${DOMAIN_USER}@${REALM}"
kdestroy -q 2>/dev/null || true

kinit "${DOMAIN_USER}@${REALM}" <"$PASS_FILE" >/dev/null 2>&1 || {
    log_error "Failed to obtain Kerberos ticket for ${DOMAIN_USER}@${REALM}" 2
}

# -------------------------------------------------------------------------
# Optional: Verbose LDAP debugging
# -------------------------------------------------------------------------
if $VERBOSE; then
    log_info "🧪 DEBUG: Testing LDAP search for computer object..."
    echo "🔸 HOST_SHORT_U: $HOST_SHORT_U"
    echo "🔸 OU: $OU"
    echo "🔸 BASE_DN: $BASE_DN"

    LDAP_RAW="$(
        set +e +o pipefail
        timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no -H "ldap://${LDAP_SERVER}" \
          -b "$BASE_DN" "(sAMAccountName=${HOST_SHORT_U_ESCAPED}\$)" distinguishedName 2>&1
    )" && LDAP_CODE=0 || LDAP_CODE=$?

    echo "🔹 Exit Code: $LDAP_CODE"
    echo "🔹 LDAP Output:"
    echo "$LDAP_RAW"
fi

# -------------------------------------------------------------------------
# Check computer object existence and OU alignment
# -------------------------------------------------------------------------
log_info "🔍 Checking if computer object exists in AD"

# Perform search allowing non-fatal exit codes (e.g. not found)
LDAP_OUT="$(
    set +e +o pipefail
    timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no -H "ldap://${LDAP_SERVER}" \
      -b "$BASE_DN" "(sAMAccountName=${HOST_SHORT_U_ESCAPED}\$)" distinguishedName 2>/dev/null
)" && LDAP_CODE=0 || LDAP_CODE=$?

# Extract DN using grep/PCRE
CURRENT_DN="$(printf '%s\n' "$LDAP_OUT" | sed -n 's/^distinguishedName:[[:space:]]*//p' | head -n1)"
$VERBOSE && echo "$LDAP_OUT"

if [[ -n "$CURRENT_DN" ]]; then
    EXPECTED_DN="CN=${HOST_SHORT_U},${OU}"

    if [[ "$CURRENT_DN" == "$EXPECTED_DN" ]]; then
        $VERBOSE && log_info "ℹ️ Computer object is already in the correct OU"
    else
        log_info "♻️ Computer object is currently in OU: $CURRENT_DN"
        log_info "🚚 Attempting to move object to target OU: $OU"

        # Prepare LDIF for move operation
        TMP_LDIF=$(safe_mktemp)
        write_file 0600 "$TMP_LDIF" <<EOF
dn: $CURRENT_DN
changetype: modrdn
newrdn: CN=${HOST_SHORT_U}
deleteoldrdn: 1
newsuperior: $OU
EOF

        # -------------------------------------------------------------------------
        # SAFETY ZONE: OU Move Operation (Handle Permission Denied Gracefully)
        # -------------------------------------------------------------------------
        LDAP_MOVE_CODE=0
        if $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would move computer object via ldapmodify"
        else
            # Save/restore ERR trap (consistent with trust validation block pattern)
            _saved_move_trap="$(trap -p ERR)" || true
            trap - ERR
            set +e
            if $VERBOSE; then
                ldapmodify -Y GSSAPI -H "ldap://${LDAP_SERVER}" -f "$TMP_LDIF"
                LDAP_MOVE_CODE=$?
            else
                ldapmodify -Y GSSAPI -H "ldap://${LDAP_SERVER}" -f "$TMP_LDIF" >/dev/null 2>&1
                LDAP_MOVE_CODE=$?
            fi
            set -e
            if [[ -n "$_saved_move_trap" ]]; then
                eval "$_saved_move_trap"
            fi
        fi

        rm -f "$TMP_LDIF"

        # Analyze result
        if [[ "$LDAP_MOVE_CODE" -eq 0 ]]; then
            log_info "✅ Computer object moved successfully to target OU."
        elif [[ "$LDAP_MOVE_CODE" -eq 50 ]]; then
            # LDAP Error 50: Insufficient Access Rights
            # Common scenario: User can join, but cannot move objects created by others
            log_info "ℹ️ Access denied moving computer object (AD restriction). Keeping current location."
            log_info "↪ Continuing with object in: $CURRENT_DN"
            
            # Update OU variable to point to the current location so join/update succeeds
            OU="${CURRENT_DN#*,}"
        else
            # Handle other LDAP errors gracefully
            log_info "⚠️ Unable to move object (LDAP Code $LDAP_MOVE_CODE). Proceeding in current location."
            OU="${CURRENT_DN#*,}"
        fi
    fi
else
    log_info "📛 Computer object not found in AD. Proceeding with domain join."
fi

# Validation-only mode: exit here
if $VALIDATE_ONLY; then
    log_info "✅ VALIDATE-ONLY: pre-checks completed successfully. Skipping domain join and all configuration writes."
    exit 0
fi

# -------------------------------------------------------------------------
# DOMAIN JOIN PHASE (adcli only + IP description)
# -------------------------------------------------------------------------
log_info "🔗 Joining domain $DOMAIN via adcli (direct mode, no realm)"

# Resolve DC IP for logging
DC_IP="$(getent hosts "$DC_SERVER" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
[[ -z "$DC_IP" ]] && DC_IP=$(dig +short "$DC_SERVER" | head -n1)
log_info "🔍 Target DC for join: $DC_SERVER (${DC_IP:-unresolved})"

# Clean previous Kerberos tickets and renew authentication
kdestroy -q 2>/dev/null || true
kinit "${DOMAIN_USER}@${REALM}" <"$PASS_FILE" >/dev/null 2>&1 || {
    log_error "Failed to obtain Kerberos ticket for $DOMAIN_USER@$REALM" 2
}

# Safely capture Kerberos principal (ignore klist exit errors)
KLIST_PRINCIPAL="$(
    set +e +o pipefail
    klist 2>/dev/null | awk '/Default principal/ {print $3; exit}'
)" || true
[[ -z "$KLIST_PRINCIPAL" ]] && KLIST_PRINCIPAL="(no active ticket)"

JOIN_LOG=$(safe_mktemp)

# Execute adcli join deterministically
if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would join domain via adcli (execution suppressed)."
    true
elif timeout 90s adcli join \
    --verbose \
    --domain="$DOMAIN" \
    --domain-realm="$REALM" \
    --domain-controller="$DC_SERVER" \
    --domain-ou="$OU" \
    --login-user="$DOMAIN_USER" \
    --stdin-password \
    --host-fqdn="$HOST_FQDN" \
    --computer-name="$HOST_SHORT_U" \
    --host-keytab="$KRB5_KEYTAB" \
    --os-name="$OS_NAME" \
    --os-version="$OS_VERSION" \
    --trusted-for-delegation=no \
    --add-service-principal="RestrictedKrbHost/${HOST_SHORT_U}" \
    --add-service-principal="RestrictedKrbHost/${HOST_FQDN}" \
    --add-service-principal="host/${HOST_SHORT_U}" \
    --add-service-principal="host/${HOST_FQDN}" \
    --show-details <"$PASS_FILE" >"$JOIN_LOG" 2>&1; then

    log_info "✅ Joined domain successfully via adcli (DC: $DC_SERVER, IP: ${DC_IP:-unknown})"

    # adcli testjoin (non-fatal)
    if command -v adcli >/dev/null 2>&1; then
        if adcli testjoin --domain="$DOMAIN" >/dev/null 2>&1; then
            log_info "✅ adcli testjoin: OK"
        else
            log_info "⚠️ adcli testjoin failed (non-fatal). Keytab trust check will be authoritative."
        fi
    fi

    # Ensure keytab has correct permissions (security hardening)
    if [[ -f "$KRB5_KEYTAB" ]]; then
        cmd_must chmod 600 "$KRB5_KEYTAB"
        cmd_must chown root:root "$KRB5_KEYTAB"
        log_info "🔒 Keytab permissions hardened (600, root:root)"
    fi

else
    log_info "❌ Domain join failed. Last output lines:"
    tail -n 5 "$JOIN_LOG" | sed -E 's/^[[:space:]]+//'
    log_error "Domain join failed via adcli" 3
fi

kdestroy -q 2>/dev/null || true
rm -f "$JOIN_LOG"

# -------------------------------------------------------------------------
# Update AD Description with IP after successful join
# -------------------------------------------------------------------------
HOST_IP="${PRIMARY_IP:-}"
if [[ -n "$HOST_IP" ]]; then
    log_info "🧩 Updating AD description with IP: $HOST_IP"
    kinit "${DOMAIN_USER}@${REALM}" <"$PASS_FILE" >/dev/null 2>&1 || \
        log_info "⚠️ Failed to refresh Kerberos ticket for description update"

    TMP_LDIF=$(safe_mktemp)
	timestamp=$(date '+%Y-%m-%dT%H:%M:%S%z')
    write_file 0600 "$TMP_LDIF" <<EOF
dn: CN=${HOST_SHORT_U},${OU}
changetype: modify
replace: description
description: [${HOST_IP}] - Joined with adcli by ${DOMAIN_USER} on ${timestamp}
EOF
    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would update AD description via ldapmodify (execution suppressed)."
    else
        # Retry with backoff to tolerate AD replication delay
        _desc_ok=false
        for _desc_attempt in 1 2 3; do
            if ldapmodify -Y GSSAPI -H "ldap://${LDAP_SERVER}" -f "$TMP_LDIF" >/dev/null 2>&1; then
                log_info "✅ Description updated successfully in AD"
                _desc_ok=true
                break
            fi
            if (( _desc_attempt < 3 )); then
                log_info "⚠ AD description update failed (attempt ${_desc_attempt}/3, retrying in 5s)"
                sleep 5
            fi
        done
        $_desc_ok || log_info "⚠️ Unable to update AD description after 3 attempts (check permissions or ticket validity)"
    fi
    rm -f "$TMP_LDIF"
else
    log_info "⚠️ Unable to detect host IP for AD description update"
fi

# Read the current msDS-KeyVersionNumber with retry (tolerates AD replication delay)
MSDS_KVNO=""
for _kvno_attempt in 1 2 3; do
    # Subshell isolates set +e +o pipefail from parent
    MSDS_KVNO="$(
        set +e +o pipefail
        timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no \
            -H "ldap://${LDAP_SERVER}" \
            -b "CN=${HOST_SHORT_U},${OU}" msDS-KeyVersionNumber 2>/dev/null | \
            awk '/^msDS-KeyVersionNumber:/ {print $2}' | head -n1
    )" || true

    if [[ -n "$MSDS_KVNO" ]]; then
        log_info "ℹ️ msDS-KeyVersionNumber in AD: ${MSDS_KVNO}"
        break
    fi
    if (( _kvno_attempt < 3 )); then
        log_info "⚠ msDS-KeyVersionNumber not available yet (attempt ${_kvno_attempt}/3, retrying in 5s)"
        sleep 5
    fi
done
[[ -z "$MSDS_KVNO" ]] && { MSDS_KVNO="Unknown"; log_info "⚠️ Unable to read msDS-KeyVersionNumber from AD after 3 attempts"; }

# Clean up temporary Kerberos ticket
kdestroy -q 2>/dev/null || true

# -------------------------------------------------------------------------
# Authenticate administrative user (Kerberos TGT acquisition)
# -------------------------------------------------------------------------
log_info "🔐 Authenticating domain user for administrative operations"

# Obtain a valid user TGT for administrative operations.
# NOTE: The password is provided securely via stdin and never exposed in process arguments or shell history.
log_info "ℹ Obtaining Kerberos ticket for synchronization"
kinit "${DOMAIN_USER}@${REALM}" <"$PASS_FILE" >/dev/null 2>&1 || \
    log_error "Failed to obtain Kerberos ticket for ${DOMAIN_USER}@${REALM}" 2

# Save current trap/shell state before trust validation block
_saved_err_trap="$(trap -p ERR)" || true
_had_errexit=false; [[ $- == *e* ]] && _had_errexit=true
_had_pipefail=false; [[ :$SHELLOPTS: == *:pipefail:* ]] && _had_pipefail=true

trap - ERR
set +e +o pipefail

# -------------------------------------------------------------------------
# Validate machine Kerberos keytab (domain trust check)
# -------------------------------------------------------------------------
TRUST_STATUS="⚠️ Trust check failed"
PRINCIPAL="$(hostname -s | tr '[:lower:]' '[:upper:]')\$@${REALM_UPPER}"
KRB_LOG=$(safe_mktemp)
START_MS="$(now_ms)"

KRB5_TRACE=$KRB_LOG kinit -kt "$KRB5_KEYTAB" "$PRINCIPAL" >/dev/null 2>&1
EXIT_CODE=$?
END_MS="$(now_ms)"
ELAPSED=$((END_MS - START_MS))

# Resolve DC name dynamically
DC_USED="$(grep -Eo 'to (dgram|stream) ([0-9.]+|[A-Za-z0-9._-]+)' "$KRB_LOG" 2>/dev/null | awk '{print $3}' | tail -n1 || true)"
[[ -z "$DC_USED" ]] && DC_USED=$(grep -Eo '([A-Za-z0-9._-]+\.[A-Za-z]{2,})' "$KRB_LOG" | grep -vi "$REALM" | tail -n1)
[[ -z "$DC_USED" ]] && DC_USED="(unknown DC)"

# Optional reverse DNS
if [[ "$DC_USED" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if command -v host >/dev/null 2>&1; then
        DC_NAME=$(host "$DC_USED" 2>/dev/null | awk '/pointer/ {print $5}' | sed 's/\.$//')
    elif command -v dig >/dev/null 2>&1; then
        DC_NAME=$(dig +short -x "$DC_USED" 2>/dev/null | sed 's/\.$//')
    fi
else
    DC_NAME="$DC_USED"
fi
[[ -z "$DC_NAME" ]] && DC_NAME="$DC_USED"

# Ping RTT
PING_RTT="$(ping -c 1 -W 1 "$DC_NAME" 2>/dev/null | awk -F'=' '/time=/{print $NF}' | tr -d ' ' || echo 'n/a')"

# Determine trust status
if [[ $EXIT_CODE -eq 0 ]]; then
    TRUST_STATUS="✅ Kerberos trust OK"
else
    TRUST_STATUS="⚠️ Kerberos trust failed"
    log_info "⚠️ Kerberos trust check failed - review trace: $KRB_LOG"
fi

# Save for summary
DC_TRUST_SERVER="$DC_NAME"
TRUST_ELAPSED="$ELAPSED"
TRUST_RTT="$PING_RTT"

# Verbose trace
if [[ "${VERBOSE:-false}" == "true" ]]; then
    echo "--------------------------------------------------------------------------"
    echo "[*] Kerberos trace summary:"
    grep -E "Sending initial|Response was from|error from KDC" "$KRB_LOG" | sed 's/^/   /'
    echo "--------------------------------------------------------------------------"
fi

# Cleanup
kdestroy -q 2>/dev/null || true
rm -f "$KRB_LOG" 2>/dev/null || true

# Restore shell state after trust validation block
$_had_errexit && set -e
$_had_pipefail && set -o pipefail
if [[ -n "$_saved_err_trap" ]]; then
    eval "$_saved_err_trap"
fi
unset _saved_err_trap _had_errexit _had_pipefail

# -------------------------------------------------------------------------
# Validate and re-enable computer object if disabled in AD
# -------------------------------------------------------------------------
log_info "🔧 Checking if computer object is disabled in AD..."

# Query userAccountControl via GSSAPI (machine trust)
UAC_RAW=$(timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no -H "ldap://${LDAP_SERVER}" \
    -b "CN=${HOST_SHORT_U},${OU}" userAccountControl \
    2>$($VERBOSE && echo /dev/stderr || echo /dev/null) | \
    awk '/^userAccountControl:/ {print $2}' || true)

if [[ -z "$UAC_RAW" ]]; then
    $VERBOSE && log_info "ℹ userAccountControl attribute not returned for CN=${HOST_SHORT_U},${OU} (skipping auto re-enable step)"
else
    # Normalize userAccountControl to a decimal integer
    if [[ "$UAC_RAW" =~ ^0x[0-9A-Fa-f]+$ ]]; then
        UAC=$((UAC_RAW))
    elif [[ "$UAC_RAW" =~ ^[0-9]+$ ]]; then
        UAC="$UAC_RAW"
    else
        log_info "⚠ Unexpected userAccountControl format '$UAC_RAW' for CN=${HOST_SHORT_U},${OU} (skipping auto re-enable)"
        UAC=""
    fi

    if [[ -n "${UAC:-}" ]]; then
        # Check ACCOUNTDISABLE bit (0x2)
        if (( (UAC & 2) != 0 )); then
            log_info "♻️ Computer object is disabled (userAccountControl=$UAC). Re-enabling..."

            NEW_UAC=$((UAC & ~2))  # Clear only the disable bit, preserve other flags

            if $DRY_RUN; then
                log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would re-enable computer object via ldapmodify (execution suppressed)."
            else
                _reenable_rc=0
                if $VERBOSE; then
                    ldapmodify -Y GSSAPI -H "ldap://${LDAP_SERVER}" <<EOF || _reenable_rc=$?
dn: CN=${HOST_SHORT_U},${OU}
changetype: modify
replace: userAccountControl
userAccountControl: $NEW_UAC
EOF
                else
                    ldapmodify -Y GSSAPI -H "ldap://${LDAP_SERVER}" >/dev/null 2>&1 <<EOF || _reenable_rc=$?
dn: CN=${HOST_SHORT_U},${OU}
changetype: modify
replace: userAccountControl
userAccountControl: $NEW_UAC
EOF
                fi

                if (( _reenable_rc == 0 )); then
                    log_info "✅ Computer object re-enabled successfully (userAccountControl=$NEW_UAC)"
                else
                    log_info "⚠️ Failed to re-enable computer object (LDAP rc=$_reenable_rc, UAC target=$NEW_UAC)"
                fi
            fi
        else
            $VERBOSE && log_info "ℹ userAccountControl=$UAC (object is already enabled or no action required)"
        fi
    fi
fi

# -------------------------------------------------------------------------
# Kerberos trust checking
# -------------------------------------------------------------------------
log_info "🔑 Rechecking Kerberos trust after re-enabling computer object"
kdestroy -q 2>/dev/null || true
kinit -kt "$KRB5_KEYTAB" "${HOST_SHORT_U}\$@${REALM}" >/dev/null 2>&1 \
    && log_info "✅ Trust OK after re-enable" \
    || log_info "⚠️ Trust still not valid after re-enable (replication delay?)"

# -------------------------------------------------------------------------
# Configure SSSD
# -------------------------------------------------------------------------
SSSD_CONF=/etc/sssd/sssd.conf
if [[ -f $SSSD_CONF ]]; then
    backup_file "$SSSD_CONF"
fi

# Write SSSD configuration (auto-discovery mode for DNS updates)
log_info "🛠️ Writing SSSD configuration (auto-discovery mode for DNS updates)"

# Determine debug level
SSSD_DEBUG_LEVEL=0
$VERBOSE && SSSD_DEBUG_LEVEL=9

# Determine dyndns_iface if PRIMARY_IFACE is set (rendered conditionally to avoid blank lines)
DYNDNS_IFACE_LINE=""
if [[ -n "${PRIMARY_IFACE:-}" && "${PRIMARY_IFACE:-}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    DYNDNS_IFACE_LINE="dyndns_iface = ${PRIMARY_IFACE}"
fi

# Render SSSD configuration
write_file 0600 "$SSSD_CONF" <<EOF
# ============================================================================
# File:        /etc/sssd/sssd.conf
# Description: SSSD configuration generated automatically by linux-ad-domain-join.sh
# Author:      Lucas Bonfim de Oliveira Lima (soulucasbonfim)
# Domain:      $REALM
# Hostname:    $HOST_FQDN
# Generated:   $(date '+%Y-%m-%d %H:%M:%S')
# ---------------------------------------------------------------------------
# Notes:
#   • DO NOT EDIT MANUALLY - changes may be overwritten by automation.
#   • Ensure permissions are strict: chmod 600 /etc/sssd/sssd.conf
# ============================================================================
[sssd]
config_file_version = 2
services = nss,pam
domains = $REALM


# -------------------------------------------------------------------------
# Core identity & authentication providers
# -------------------------------------------------------------------------
[domain/$REALM]
id_provider = ad
auth_provider = ad
access_provider = simple
chpass_provider = ad


# -------------------------------------------------------------------------
# Active Directory and Kerberos parameters
# -------------------------------------------------------------------------
ad_domain = $DOMAIN_LOWER
ad_hostname = $HOST_FQDN
krb5_realm = $REALM_UPPER
krb5_keytab = $KRB5_KEYTAB
realmd_tags = manages-system joined-with-adcli


# -------------------------------------------------------------------------
# General settings
# -------------------------------------------------------------------------
debug_level = $SSSD_DEBUG_LEVEL
cache_credentials = True
enumerate = False
ldap_id_mapping = True
krb5_store_password_if_offline = True


# -------------------------------------------------------------------------
# Identity and login behavior
# -------------------------------------------------------------------------
default_shell = /bin/bash
fallback_homedir = /home/%u@%d
use_fully_qualified_names = False


# -------------------------------------------------------------------------
# Dynamic DNS update (Secure Update)
# -------------------------------------------------------------------------
${DYNDNS_IFACE_LINE:+${DYNDNS_IFACE_LINE}}
dyndns_update = True
dyndns_refresh_interval = 43200
dyndns_ttl = 3600
dyndns_update_ptr = True
EOF

# Ownership is enforced by write_file (install -o/-g), but keep a safety check
cmd_try chown root:root "$SSSD_CONF" || true
cmd_try chmod 600 "$SSSD_CONF" || true

# -------------------------------------------------------------------------
# Optional: flush old caches before restart
# -------------------------------------------------------------------------
if command -v sss_cache >/dev/null 2>&1; then
    if [[ "${NONINTERACTIVE:-false}" == "true" ]]; then
        log_info "ℹ️ NONINTERACTIVE mode detected - skipping SSSD cache flush to preserve UID mapping"
    else
        log_info "🔁 Flushing old SSSD caches"
        sss_cache -E >/dev/null 2>&1 || log_info "⚠️ Failed to flush SSSD cache (non-critical)"
    fi
else
    log_info "ℹ️ sss_cache not found - skipping cache flush"
fi

# -------------------------------------------------------------------------
# Validate SSSD configuration syntax
# -------------------------------------------------------------------------
if command -v sssctl >/dev/null 2>&1; then
    log_info "🔍 Validating SSSD configuration syntax"
    mapfile -t _lines < <(sssctl config-check 2>&1)
    for l in "${_lines[@]}"; do
        [[ -n "$l" ]] && log_info "ℹ️ $l"
    done
else
    log_info "ℹ️ sssctl not available, skipping validation"
fi

# -------------------------------------------------------------------------
# Non-destructive su PAM integration (ensure pam_sss without overwriting file)
# -------------------------------------------------------------------------
PAM_SU_FILE="/etc/pam.d/su"
log_info "🔐 Validating /etc/pam.d/su for SSSD integration (non-destructive)"

if [[ -f "$PAM_SU_FILE" ]]; then
    
    # Backup existing PAM su file
    backup_file "$PAM_SU_FILE" su_backup

    # If pam_sss is already referenced in auth stack, do not touch the file
	if grep -Eq '^[[:space:]]*auth[[:space:]]+(required|requisite|sufficient|include)[[:space:]].*pam_sss\.so' "$PAM_SU_FILE"; then
        log_info "ℹ pam_sss already present in $PAM_SU_FILE (no changes applied)"
    else
        # Inject pam_sss.so right after pam_unix.so in the auth stack
        tmp_su="$(safe_mktemp)"
        awk '
          BEGIN { inserted=0 }
          /^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_unix\.so/ && !inserted {
              print $0
              print "auth   sufficient pam_sss.so use_first_pass"
              inserted=1
              next
          }
          { print $0 }
          END {
              if (inserted == 0) {
                  print ""
                  print "auth   sufficient pam_sss.so use_first_pass"
              }
          }
        ' "$PAM_SU_FILE" >"$tmp_su"

        if $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would update $PAM_SU_FILE to include pam_sss.so (non-destructive)"
            rm -f "$tmp_su"
        else
            cmd_must mv -f "$tmp_su" "$PAM_SU_FILE"
            cmd_must chmod 644 "$PAM_SU_FILE"
        fi
        log_info "✅ pam_sss binding injected into $PAM_SU_FILE (original preserved in ${su_backup:-unknown})"
    fi
else
    log_info "⚠ $PAM_SU_FILE not found - creating minimal SSSD-aware su configuration"

    case "$OS_FAMILY" in
      debian)
        write_file 0644 "$PAM_SU_FILE" <<'EOF'
# PAM configuration for the su command - generated by linux-ad-domain-join.sh
auth   [success=1 default=ignore] pam_succeed_if.so quiet uid = 0
auth   [success=done default=ignore] pam_localuser.so
auth   sufficient pam_unix.so try_first_pass nullok
auth   sufficient pam_sss.so use_first_pass
auth   required   pam_deny.so

@include common-account
@include common-session
EOF
        ;;
      rhel|suse)
        write_file 0644 "$PAM_SU_FILE" <<'EOF'
# PAM configuration for the su command - generated by linux-ad-domain-join.sh
auth   [success=1 default=ignore] pam_succeed_if.so quiet uid = 0
auth   [success=done default=ignore] pam_localuser.so
auth   sufficient pam_unix.so try_first_pass nullok
auth   sufficient pam_sss.so use_first_pass
auth   required   pam_deny.so

account include system-auth
session include system-auth
EOF
        ;;
      *)
        # Fallback: very conservative minimal config
        write_file 0644 "$PAM_SU_FILE" <<'EOF'
# PAM configuration for the su command - generated by linux-ad-domain-join.sh
auth   sufficient pam_unix.so try_first_pass nullok
auth   sufficient pam_sss.so use_first_pass
auth   required   pam_deny.so
EOF
        ;;
    esac

    cmd_must chmod 644 "$PAM_SU_FILE"
    log_info "✅ PAM su file created with SSSD integration for OS family '$OS_FAMILY'"
fi

log_info "🔧 Enabling SSSD"
cmd_must systemctl enable sssd

log_info "🔄 Restarting SSSD"
cmd_must systemctl restart sssd

# -------------------------------------------------------------------------
# Restarts systemd-logind to refresh PAM and D-Bus session handling
# -------------------------------------------------------------------------
log_info "🔄 Starting direct execution block for systemd-logind restart"

LOGIND_UNIT="systemd-logind.service"

# 1. Check for systemctl presence (Systemd environments)
if command -v systemctl &>/dev/null; then
    
    # Check if the logind unit file exists
    if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${LOGIND_UNIT}"; then
        
        log_info "✅ Systemd detected. Attempting restart of ${LOGIND_UNIT} to refresh PAM/D-Bus"

        cmd_try systemctl restart "$LOGIND_UNIT"
        if (( CMD_LAST_RC == 0 )); then
            log_info "🚀 ${LOGIND_UNIT} restarted successfully."
        else
            log_info "⚠️ Failed to restart ${LOGIND_UNIT}. Attempting safe reload instead."
            cmd_try systemctl reload "$LOGIND_UNIT" >/dev/null 2>&1
            if (( CMD_LAST_RC == 0 )); then
                log_info "🚀 ${LOGIND_UNIT} reloaded successfully."
            else
                log_info "🛑 Failed to restart or reload ${LOGIND_UNIT}. Continuing script execution."
            fi
        fi
        
    else
        log_info "ℹ️ Systemd found, but ${LOGIND_UNIT} unit file is missing. Skipping restart."
    fi
    
elif command -v service &>/dev/null; then
    # 2. SysVinit/Upstart environments (Using 'service' command)
    
    # systemd-logind is not a SysV service; skip action gracefully.
    log_info "ℹ️ SysVinit/Upstart detected. systemd-logind is not applicable; skipping restart."
    
else
    # 3. No known service manager
    log_info "ℹ️ Neither systemctl nor service command found. Skipping systemd-logind action."
fi

unset DOMAIN_PASS

# -------------------------------------------------------------------------
# Session timeout hardening (SSH keepalive + shell TMOUT)
# -------------------------------------------------------------------------
log_info "⏳ Applying session timeout settings (SSH + shell)"
require_uint_range "SESSION_TIMEOUT_SECONDS" "$SESSION_TIMEOUT_SECONDS" 30 86400

# 1) Disable any existing TMOUT in /etc/profile.d to prevent duplicates
disable_tmout_in_profile_d

# 2) Enforce TMOUT via a single canonical drop-in
apply_tmout_profile "$SESSION_TIMEOUT_SECONDS"

# -------------------------------------------------------------------------
# Configure SSH AllowGroups
# -------------------------------------------------------------------------
log_info "🔒 Configuring SSH"
SSH_CFG="/etc/ssh/sshd_config"

# Backup before changes
if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would backup $SSH_CFG"
else
    backup_file "$SSH_CFG"
fi

# Build AllowGroups safely (skip empty or '(none)')
ALLOW_GROUPS="$GRP_SSH $GRP_SSH_ALL $SSH_G root"
if [[ -n "$GLOBAL_ADMIN_GROUPS" && "$GLOBAL_ADMIN_GROUPS" != "(none)" ]]; then
    ALLOW_GROUPS="$ALLOW_GROUPS $GLOBAL_ADMIN_GROUPS"
fi

# Normalize multiple spaces and trim ends
ALLOW_GROUPS="$(trim_ws "$ALLOW_GROUPS")"

# Apply AllowGroups directive
sshd_set_directive_dedup "AllowGroups" "$ALLOW_GROUPS" "$SSH_CFG"
log_info "🧩 AllowGroups updated -> AllowGroups $ALLOW_GROUPS"

# Configure SSH PasswordAuthentication
sshd_set_directive_dedup "PasswordAuthentication" "$PASSWORD_AUTHENTICATION" "$SSH_CFG"

# -------------------------------------------------------------------------
# SSH session keepalive timeout (simple: user enters seconds; CountMax fixed)
# -------------------------------------------------------------------------
log_info "🧩 Configuring SSH keepalive timeout"

# Normalize PermitRootLogin value again (safety)
PERMIT_ROOT_LOGIN="$(normalize_yes_no "$PERMIT_ROOT_LOGIN")"
[[ -n "$PERMIT_ROOT_LOGIN" ]] || log_error "PermitRootLogin invalid (expected yes/no)" 1

# Deduplicated directives
sshd_set_directive_dedup "ClientAliveInterval" "$SESSION_TIMEOUT_SECONDS" "$SSH_CFG"
sshd_set_directive_dedup "ClientAliveCountMax" "1" "$SSH_CFG"
sshd_set_directive_dedup "PermitRootLogin" "$PERMIT_ROOT_LOGIN" "$SSH_CFG"

# Validate config BEFORE restarting sshd (avoids lockout)
validate_sshd_config_or_die "$SSH_CFG"

# Restart SSH safely (service name differs by distro)
ssh_unit="$(detect_service_unit "ssh.service" "sshd.service")"
if [[ -n "$ssh_unit" ]]; then
    cmd_try systemctl restart "$ssh_unit" || true
else
    log_info "⚠️ SSH service unit not found (ssh/sshd). Skipping restart."
fi

# -------------------------------------------------------------------------
# AD admin sudoers drop-in + base variables
# -------------------------------------------------------------------------
SUDOERS_MAIN="/etc/sudoers"
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_AD="${SUDOERS_DIR}/10-ad-linux-privilege-model"
BLOCK_FILE="${SUDOERS_DIR}/00-block-root-shell"

# Ensure target directory exists
log_info "🛡️ Configuring sudoers directory: $SUDOERS_DIR"
cmd_try mkdir -p "$SUDOERS_DIR"

# -------------------------------------------------------------------------
# Create ROOT_SHELLS command alias (centralized restriction control)
# -------------------------------------------------------------------------
log_info "🛠️ Installing ROOT_SHELLS alias at $BLOCK_FILE"

write_file 0440 "$BLOCK_FILE" <<'EOF'
# ========================================================================
# FILE: 00-block-root-shell
#
# Global security baseline for all Linux servers joined to Active Directory.
# This file defines command aliases and security controls that enforce
# privilege containment and prevent root shell escalation by operational
# administrators.
#
# IMPORTANT:
# - This file contains global rules only. No AD groups are configured here.
# - Do NOT place operational or security group privileges in this file.
# - All AD group privileges are defined in: 10-ad-linux-privilege-model
# ========================================================================


# ------------------------------------------------------------------------
# ROOT_SHELLS
# Command Alias: Denies any attempt to spawn an interactive root shell.
# This includes direct shells (bash, sh, dash, zsh) and indirect shells
# via /usr/bin/env or similar environment tricks.
#
# This alias is used with:
#       !ROOT_SHELLS
# in the AD group privilege definitions.
# ------------------------------------------------------------------------
Cmnd_Alias ROOT_SHELLS = \
    /bin/su, /usr/bin/su, \
    /bin/bash, /usr/bin/bash, \
    /bin/sh, /usr/bin/sh, \
    /bin/dash, /usr/bin/dash, \
    /bin/zsh, /usr/bin/zsh, \
    /usr/bin/env bash, \
    /usr/bin/env bash -i, \
    /usr/bin/env -i bash, \
    /usr/bin/env bash -c *, \
    /usr/bin/env -i bash -c *, \
    /usr/bin/env sh, \
    /usr/bin/env -i sh, \
    /usr/bin/env -i bash -i, \
    /usr/bin/env dash, \
    /usr/bin/env -i dash, \
    /usr/bin/env zsh, \
    /usr/bin/env -i zsh

# ------------------------------------------------------------------------
# Optional Alias (not active by default)
# Used for blocking common privilege-escalation capable interpreters.
# Uncomment and enforce in 10-ad-linux-privilege-model if required.
#
# Cmnd_Alias PRIV_ESC = /usr/bin/python*, /usr/bin/perl*, /usr/bin/lua*, /usr/bin/ruby*
# ------------------------------------------------------------------------
EOF

if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would validate sudoers syntax: visudo -cf $BLOCK_FILE"
else
    cmd_must visudo -cf "$BLOCK_FILE"
fi

log_info "🔒 ROOT_SHELLS alias applied"

# -------------------------------------------------------------------------
# AD admin sudoers drop-in
# -------------------------------------------------------------------------
log_info "🛡️ Configuring sudoers file: $SUDOERS_AD"

# Create or refresh AD admin sudoers definition
write_file 0440 "$SUDOERS_AD" <<EOF
# ========================================================================
# FILE: 10-ad-linux-privilege-model
#
# PURPOSE
# -------
# Centralized privilege and security governance model for Linux hosts
# integrated with Active Directory.
#
# This file defines a strict separation between:
#
#   - SECURITY administrators (SEC):
#       * Govern authentication, authorization, identity and credentials
#       * Execute only explicitly approved security commands
#       * Cannot obtain interactive root shell
#
#   - OPERATIONAL administrators (ADM):
#       * Operate the system and applications
#       * Can manage services and software
#       * Cannot alter security posture
#       * Cannot obtain interactive root shell
#
#
# SCOPE CONTROL
# -------------
# Group scope (global vs host-level) is handled in Active Directory:
#
#   - %SEC_ALL / %ADM_ALL  -> global authority
#   - %SEC     / %ADM      -> host-level authority
# ========================================================================


# ------------------------------------------------------------------------
# SUDOERS security management
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SUDOERS = \\
    /usr/sbin/visudo, \\
    /usr/bin/vim /etc/sudoers*, \\
    /usr/bin/nano /etc/sudoers*, \\
    /bin/cp /etc/sudoers*, \\
    /bin/mv /etc/sudoers*, \\
    /usr/bin/chmod /etc/sudoers*, \\
    /usr/bin/chown /etc/sudoers*


# ------------------------------------------------------------------------
# Security-critical authentication services
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SECURITY_SERVICES = \\
    /usr/bin/systemctl restart sshd, \\
    /usr/bin/systemctl reload sshd, \\
    /usr/bin/systemctl restart systemd-logind, \\
    /usr/bin/systemctl daemon-reload


# ------------------------------------------------------------------------
# Credential management (root authority)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_CREDENTIALS = \\
    /usr/bin/passwd root


# ------------------------------------------------------------------------
# Block inline editors on security files (sed -i)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_INLINE_EDIT = \\
    /bin/sed -i* /etc/sudoers*, \\
    /bin/sed -i* /etc/ssh/*


# ------------------------------------------------------------------------
# Block overwrite via tee on security files
# ------------------------------------------------------------------------
Cmnd_Alias SEC_TEE = \\
    /usr/bin/tee /etc/sudoers*, \\
    /usr/bin/tee /etc/ssh/*


# ------------------------------------------------------------------------
# PAM authentication stack
# ------------------------------------------------------------------------
Cmnd_Alias SEC_PAM = \\
    /usr/bin/vim /etc/pam.d/*, \\
    /usr/bin/nano /etc/pam.d/*, \\
    /bin/cp /etc/pam.d/*, \\
    /bin/mv /etc/pam.d/*, \\
    /usr/bin/chmod /etc/pam.d/*, \\
    /usr/bin/chown /etc/pam.d/*


# ------------------------------------------------------------------------
# Identity and NSS (local users, groups, resolution)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_IDENTITY = \\
    /usr/bin/vim /etc/nsswitch.conf, \\
    /usr/bin/nano /etc/nsswitch.conf, \\
    /usr/bin/vim /etc/passwd, \\
    /usr/bin/vim /etc/shadow, \\
    /usr/bin/vim /etc/group, \\
    /usr/bin/vim /etc/gshadow, \\
    /bin/cp /etc/passwd /etc/shadow /etc/group /etc/gshadow, \\
    /bin/mv /etc/passwd /etc/shadow /etc/group /etc/gshadow, \\
    /usr/bin/chmod /etc/passwd /etc/shadow /etc/group /etc/gshadow, \\
    /usr/bin/chown /etc/passwd /etc/shadow /etc/group /etc/gshadow


# ------------------------------------------------------------------------
# SSSD / Active Directory integration
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SSSD = \\
    /usr/bin/vim /etc/sssd/sssd.conf, \\
    /usr/bin/nano /etc/sssd/sssd.conf, \\
    /bin/cp /etc/sssd/sssd.conf, \\
    /bin/mv /etc/sssd/sssd.conf, \\
    /usr/bin/chmod /etc/sssd/sssd.conf, \\
    /usr/bin/chown /etc/sssd/sssd.conf


# ------------------------------------------------------------------------
# Polkit privilege rules (modern privilege escalation layer)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_POLKIT = \\
    /usr/bin/vim /etc/polkit-1/*, \\
    /usr/bin/nano /etc/polkit-1/*, \\
    /bin/cp /etc/polkit-1/*, \\
    /bin/mv /etc/polkit-1/*, \\
    /usr/bin/chmod /etc/polkit-1/*, \\
    /usr/bin/chown /etc/polkit-1/*


# ------------------------------------------------------------------------
# systemd overrides for security services
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SYSTEMD_OVERRIDES = \\
    /usr/bin/vim /etc/systemd/system/sshd.service*, \\
    /usr/bin/nano /etc/systemd/system/sshd.service*, \\
    /bin/cp /etc/systemd/system/sshd.service*, \\
    /bin/mv /etc/systemd/system/sshd.service*


# ------------------------------------------------------------------------
# Optional: advanced PAM / security tuning
# (Enable only if these controls are actively used)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SECURITY_MISC = \\
    /usr/bin/vim /etc/security/*, \\
    /usr/bin/nano /etc/security/*, \\
    /bin/cp /etc/security/*, \\
    /bin/mv /etc/security/*


# ------------------------------------------------------------------------
# Central Security Authority (single source of truth)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_ALL_CMDS = \\
    SEC_SUDOERS, \\
    SEC_SECURITY_SERVICES, \\
    SEC_CREDENTIALS, \\
    SEC_INLINE_EDIT, \\
    SEC_TEE, \\
    SEC_PAM, \\
    SEC_IDENTITY, \\
    SEC_SSSD, \\
    SEC_POLKIT, \\
    SEC_SYSTEMD_OVERRIDES, \\
    SEC_SECURITY_MISC


# ========================================================================
# SECURITY ADMINISTRATORS (SEC)
# ========================================================================
# Scope:
# - Security configuration only
# - Authentication, authorization, identity and credentials
# - No operational administration
# - No interactive root shell
# ========================================================================
%$SEC_ALL ALL=(root) NOPASSWD: SEC_ALL_CMDS, !ROOT_SHELLS
%$SEC     ALL=(root) NOPASSWD: SEC_ALL_CMDS, !ROOT_SHELLS


# ========================================================================
# OPERATIONAL ADMINISTRATORS (ADM)
# ========================================================================
# Scope:
# - Full operational administration
# - Explicitly excluded from security posture changes
# - No interactive root shell
# ========================================================================
%$ADM_ALL ALL=(root) NOPASSWD: ALL, !SEC_ALL_CMDS, !ROOT_SHELLS
%$ADM     ALL=(root) NOPASSWD: ALL, !SEC_ALL_CMDS, !ROOT_SHELLS


# ========================================================================
# FULL ADMINISTRATORS (SUPER)
# ========================================================================
# Scope:
# - Full operational administration
# - Full security administration
# - Union of ADM and SEC privileges
# - No interactive root shell
#
# NOTE:
# - Membership in SUPER replaces ADM and SEC
# - Users must NOT be assigned to ADM and SEC simultaneously
# ========================================================================
%$SUPER_ALL ALL=(root) NOPASSWD: ALL, !ROOT_SHELLS
%$SUPER     ALL=(root) NOPASSWD: ALL, !ROOT_SHELLS
EOF

# -------------------------------------------------------------------------
# Normalize /etc/sudoers includes (use includedir, drop explicit includes)
# -------------------------------------------------------------------------
log_info "🔧 Normalizing sudoers includes in $SUDOERS_MAIN"

# Backup main sudoers file before changes
backup_file "$SUDOERS_MAIN" SUDO_BAK

tmp_sudo="$(safe_mktemp)"
includedir_present=false

while IFS= read -r line || [[ -n "$line" ]]; do
    # Remove any explicit "#include /etc/sudoers.d/..." lines (per-file includes)
    if [[ "$line" =~ ^[[:space:]]*[#@]include[[:space:]]+/etc/sudoers\.d/ ]]; then
        continue
    fi

    # Detect active "#includedir /etc/sudoers.d" or "@includedir /etc/sudoers.d"
    if [[ "$line" =~ ^[[:space:]]*[@#]includedir[[:space:]]+/etc/sudoers\.d ]]; then
        includedir_present=true
    fi

    # Fix incorrectly commented includedir (e.g. "# #includedir" or "## #includedir")
    if [[ "$line" =~ ^[[:space:]]*#+[[:space:]]*[#@]includedir[[:space:]]+/etc/sudoers\.d ]]; then
        line="#includedir /etc/sudoers.d"
        includedir_present=true
    fi

    echo "$line" >>"$tmp_sudo"
done <"$SUDOERS_MAIN"

# If no includedir was found, append it
if [[ "$includedir_present" == false ]]; then
    echo "" >>"$tmp_sudo"
    echo "#includedir /etc/sudoers.d" >>"$tmp_sudo"
fi

# Align temporary sudoers file permissions (required for visudo validation)
chown root:root "$tmp_sudo" 2>/dev/null || true
chmod 440 "$tmp_sudo" || log_error "Failed to set permissions on temporary sudoers file" 1

# Validate new sudoers before committing (Capture output for detailed error logging)
log_info "🔍 Validating temporary sudoers configuration..."

# Execute visudo using a temp file for log capture
VISUDO_OUTPUT="$(visudo -cf "$tmp_sudo" 2>&1)" && VISUDO_RC=0 || VISUDO_RC=$?

if [[ $VISUDO_RC -eq 0 ]]; then
    # SUCCESS: Log the detailed output (including warnings and 'parsed OK' messages)
    if [[ -n "$VISUDO_OUTPUT" ]]; then
        echo "$VISUDO_OUTPUT" | while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -n "$line" ]] && log_info "ℹ️ $line"
        done
    fi
    
    # Commit the changes
    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would replace $SUDOERS_MAIN with validated sudoers content"
        rm -f "$tmp_sudo"
    else
        cmd_must mv -f "$tmp_sudo" "$SUDOERS_MAIN"
        cmd_must chmod 440 "$SUDOERS_MAIN"
    fi
    log_info "✅ Sudoers includes normalized successfully"
else
    # FAILURE: Syntax Error Detected
    log_info "❌ visudo syntax check failed. Details:"
    
    # Log the detailed error from visudo
    echo "$VISUDO_OUTPUT" | while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -n "$line" ]] && log_info "   visudo: $line"
    done
    
    # Clean up temp file (always clean the temp file)
    rm -f "$tmp_sudo"
    
    # Decision to continue based on mode
    if $NONINTERACTIVE; then
        # NON-INTERACTIVE MODE: Must rollback and abort
        if $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would restore sudoers backup: $SUDO_BAK -> $SUDOERS_MAIN"
        else
            cmd_must cp -p -- "$SUDO_BAK" "$SUDOERS_MAIN"
        fi
        log_info "💾 Restored backup: $SUDO_BAK"
        log_error "visudo syntax check failed during normalization (restored $SUDO_BAK)" 1
    else
        # INTERACTIVE MODE: Ask user to continue or abort
        read_sanitized "⚠️ Sudoers check failed. Continue script execution anyway? [y/N]: " REPLY
        
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            log_info "ℹ️ Ignoring visudo error (manual correction required). Proceeding with original $SUDOERS_MAIN."
        else
            # User chooses to abort: Must rollback and abort
            if $DRY_RUN; then
                log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would restore sudoers backup: $SUDO_BAK -> $SUDOERS_MAIN"
            else
                cmd_must cp -p -- "$SUDO_BAK" "$SUDOERS_MAIN"
            fi
            log_info "💾 Restored backup: $SUDO_BAK"
            log_error "visudo syntax check failed during normalization (abort requested)" 1
        fi
    fi
fi

# -------------------------------------------------------------------------
# Enumerate sudoers files (main file + drop-in directory)
# -------------------------------------------------------------------------
log_info "🗂️ Enumerating sudoers configuration files"

FILES=("$SUDOERS_MAIN")

# Bash 4.4+ required for mapfile -d ''
if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) )); then
    mapfile -t -d '' _DROPIN_FILES < <(find "$SUDOERS_DIR" -maxdepth 1 -type f -print0)
    FILES+=("${_DROPIN_FILES[@]}")
    unset _DROPIN_FILES
else
    while IFS= read -r -d '' f || [[ -n "$f" ]]; do
        FILES+=("$f")
    done < <(find "$SUDOERS_DIR" -maxdepth 1 -type f -print0)
fi

# -------------------------------------------------------------------------
# Extract administrative groups from all sudoers files
# -------------------------------------------------------------------------
log_info "🔎 Enumerating administrative groups"

declare -a RAW_GROUPS=()
for f in "${FILES[@]}"; do
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^%([A-Za-z0-9._-]+)[[:space:]] ]]; then
            RAW_GROUPS+=("${BASH_REMATCH[1]}")
        fi
    done <"$f"
done

declare -A _SEEN_GROUPS=()
declare -a TARGET_GROUPS=()
for g in "${RAW_GROUPS[@]+"${RAW_GROUPS[@]}"}"; do
    if [[ -z "${_SEEN_GROUPS[$g]+set}" ]]; then
        _SEEN_GROUPS["$g"]=1
        TARGET_GROUPS+=("$g")
    fi
done
unset _SEEN_GROUPS

if [[ ${#TARGET_GROUPS[@]} -eq 0 ]]; then
    log_info "📌 No sudo groups detected for hardening (nothing to patch)."
else
	# -------------------------------------------------------------------------
	# Patch sudo rules to enforce !ROOT_SHELLS restriction
	# -------------------------------------------------------------------------
    log_info "📌 Sudo groups detected (${#TARGET_GROUPS[@]} total):"
    for grp in "${TARGET_GROUPS[@]}"; do
        log_info "   • $grp"
    done

	log_info "⚙️ Updating rules"

    for f in "${FILES[@]}"; do
		declare -a patched=()
		declare -a compliant=()

		tmp="$(safe_mktemp "/tmp/$(basename "$f").XXXXXX")"
        : >"$tmp"

		while IFS= read -r line || [[ -n "$line" ]]; do
			original="$line"
			handled=false

			for grp in "${TARGET_GROUPS[@]:-}"; do
				good_all="%${grp} ALL=(ALL:ALL) ALL, !ROOT_SHELLS"
				good_npw="%${grp} ALL=(ALL) NOPASSWD: ALL, !ROOT_SHELLS"

				# Escape regex metacharacters in group name for safe pattern matching
				grp_escaped="$(regex_escape_ere "$grp")"

				pat_all="^%${grp_escaped}[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+ALL$"
				pat_npw="^%${grp_escaped}[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+NOPASSWD:[[:space:]]+ALL$"

				# Already compliant
				if [[ "$line" == "$good_all" || "$line" == "$good_npw" ]]; then
					compliant+=("$grp")
					echo "$line" >>"$tmp"
					handled=true
					break
				fi

				# Needs patching: ALL=(ALL:ALL) ALL
				if [[ "$line" =~ $pat_all ]]; then
					echo "# ORIGINAL (disabled by hardening $(date +%F))" >>"$tmp"
					echo "# $original" >>"$tmp"
					echo "$good_all" >>"$tmp"
					echo "" >>"$tmp"
					patched+=("$grp")
					handled=true
					break
				fi

				# Needs patching: ALL with NOPASSWD
				if [[ "$line" =~ $pat_npw ]]; then
					echo "# ORIGINAL (disabled by hardening $(date +%F))" >>"$tmp"
					echo "# $original" >>"$tmp"
					echo "$good_npw" >>"$tmp"
					echo "" >>"$tmp"
					patched+=("$grp")
					handled=true
					break
				fi
			done

			[[ "$handled" == false ]] && echo "$line" >>"$tmp"

		done <"$f"

		# Align temporary drop-in file permissions (required for visudo)
		chown root:root "$tmp" 2>/dev/null || true
		chmod 440 "$tmp" || { rm -f "$tmp"; log_error "Failed to set permissions on $tmp" 1; }

		# Validate syntax before committing changes
		# Temporarily disable 'set -e' so a syntax error doesn't crash the script immediately
		VISUDO_OUTPUT="$(visudo -cf "$tmp" 2>&1)" && VISUDO_RC=0 || VISUDO_RC=$?

		if [[ $VISUDO_RC -ne 0 ]]; then
			log_info "❌ Sudoers drop-in check failed for $f. Details:"
			# Log the detailed error from visudo
			echo "$VISUDO_OUTPUT" | while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -n "$line" ]] && log_info "   visudo: $line"
            done

			rm -f "$tmp"
			# The 'continue' statement prevents committing the bad file, relying on the backup.
			log_info "⚠️ Invalid syntax after modifying $f (changes discarded, original file preserved). Skipping."
			continue
		fi

		if $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would replace $f with patched version (validated)"
            rm -f "$tmp"
        else
            cmd_must mv -f "$tmp" "$f"
            cmd_must chmod 440 "$f"
        fi

		# Standardized log output format
		if [[ ${#patched[@]} -gt 0 ]]; then
			log_info "📄 $f → patched: ${patched[*]}"
		elif [[ ${#compliant[@]} -gt 0 ]]; then
			log_info "📄 $f → unchanged: ${compliant[*]}"
		fi
	done
fi

log_info "🚀 Completed domain join for $DOMAIN"

# -------------------------------------------------------------------------
# POST-VALIDATION SUMMARY (Domain Join Verification)
# -------------------------------------------------------------------------
log_info "💡 Performing post-validation summary checks"

REALM_JOINED=$(safe_realm_list | awk '/^[^ ]/ {print $1}' | head -n1)

if command -v systemctl >/dev/null 2>&1; then
    # ---------------------------------------------------------------
    # SSSD service status (systemd)
    # ---------------------------------------------------------------
    if systemctl list-unit-files "sssd.service" 2>/dev/null | grep -q 'sssd\.service'; then
        SSSD_STATUS=$(systemctl is-active sssd 2>/dev/null || echo "inactive")
    else
        pgrep sssd >/dev/null 2>&1 && SSSD_STATUS="active" || SSSD_STATUS="inactive"
    fi
    [[ -z "$SSSD_STATUS" ]] && SSSD_STATUS="inactive"

    # ---------------------------------------------------------------
    # SSH service status (handle ssh vs sshd naming)
    # ---------------------------------------------------------------
    if systemctl list-unit-files "ssh.service" 2>/dev/null | grep -q 'ssh\.service'; then
        SSH_STATUS=$(systemctl is-active ssh 2>/dev/null || echo "inactive")
    elif systemctl list-unit-files "sshd.service" 2>/dev/null | grep -q 'sshd\.service'; then
        SSH_STATUS=$(systemctl is-active sshd 2>/dev/null || echo "inactive")
    else
        # fallback for systems without standard ssh unit
        pgrep sshd >/dev/null 2>&1 && SSH_STATUS="active" || SSH_STATUS="inactive"
    fi
    [[ -z "$SSH_STATUS" ]] && SSH_STATUS="inactive"
else
    # ---------------------------------------------------------------
    # Fallback for distros without systemd
    # ---------------------------------------------------------------
    pgrep sssd >/dev/null 2>&1 && SSSD_STATUS="active" || SSSD_STATUS="inactive"
    pgrep sshd >/dev/null 2>&1 && SSH_STATUS="active"  || SSH_STATUS="inactive"
fi

# Normalize empty or unexpected values
[[ -z "$TRUST_STATUS" ]] && TRUST_STATUS="⚠️ Unknown"
[[ -z "$REALM_JOINED" ]] && REALM_JOINED="⚠️ Not detected"

# Summary output
print_divider
log_info "🌟 DOMAIN JOIN VALIDATION SUMMARY"
print_divider

# Colorize status values
REALM_COLOR="${C_GREEN}"
[[ "$REALM_JOINED" == "⚠️ Not detected" ]] && REALM_COLOR="${C_YELLOW}"

TRUST_COLOR="${C_GREEN}"
[[ "$TRUST_STATUS" =~ "failed" ]] && TRUST_COLOR="${C_RED}"

SSSD_COLOR="${C_GREEN}"
[[ "$SSSD_STATUS" == "inactive" ]] && SSSD_COLOR="${C_RED}"

SSH_COLOR="${C_GREEN}"
[[ "$SSH_STATUS" == "inactive" ]] && SSH_COLOR="${C_RED}"

printf "${C_CYAN}%-25s${C_RESET} %s\n" "Realm:" "${REALM_COLOR}${REALM_JOINED}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "DC Server (input):" "${C_DIM}${DC_SERVER_INPUT}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "KDC used (trust):" "${C_DIM}${DC_TRUST_SERVER:-n/a}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "Computer Name:" "${C_BOLD}${HOST_SHORT_U}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "Kerberos Principal:" "${C_DIM}${KLIST_PRINCIPAL:-⚠️ None active}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "Key Version (KVNO):" "${C_DIM}${MSDS_KVNO}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "Domain Trust:" "${TRUST_COLOR}${TRUST_STATUS}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "Handshake (ms):" "${C_DIM}${TRUST_ELAPSED:-n/a}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "Network RTT:" "${C_DIM}${TRUST_RTT:-n/a}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "SSSD Service:" "${SSSD_COLOR}${SSSD_STATUS}${C_RESET}"
printf "${C_CYAN}%-25s${C_RESET} %s\n" "SSH Service:" "${SSH_COLOR}${SSH_STATUS}${C_RESET}"
print_divider

# Insert short pause and newline without spawning a subshell
sleep 0.05
echo

# Force sync and restore terminal
sync
stty sane 2>/dev/null || true

exit 0