#!/bin/bash
# -------------------------------------------------------------------------------------------------
# Script Name:        linux-ad-domain-join.sh
# -------------------------------------------------------------------------------------------------
# Author:      Lucas Bonfim de Oliveira Lima
# LinkedIn:    https://www.linkedin.com/in/soulucasbonfim
# GitHub:      https://github.com/soulucasbonfim
# Created:     2025-04-27
# Version:     3.4.1
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
#                     DOMAIN_USER, DOMAIN_PASS (or DOMAIN_PASS_FILE),
#                     SESSION_TIMEOUT_SECONDS, PERMIT_ROOT_LOGIN as env vars)
#                     Optional env vars: PASSWORD_AUTHENTICATION (default: yes),
#                     NTP_SERVER (default: ntp.<domain>),
#                     ADM_GROUP, ADM_GROUP_ALL, SSH_GROUP, SSH_GROUP_ALL,
#                     SEC_GROUP, SEC_GROUP_ALL, SUPER_GROUP, SUPER_GROUP_ALL
#   --verbose, -v     Enable full command output and debugging traces
#   --validate-only   Validate configuration and prerequisites without making changes
#
#   Security note (non-interactive mode):
#     DOMAIN_PASS passed via env persists in /proc/<pid>/environ for the
#     script lifetime (Linux kernel limitation). For hardened environments,
#     prefer DOMAIN_PASS_FILE pointing to a root-only file (0400/0600):
#       DOMAIN_PASS_FILE=/run/secrets/ad-pass ./linux-ad-domain-join.sh -y
#     Legacy method (still supported):
#       DOMAIN_PASS="$(< /run/secrets/ad-pass)" ./linux-ad-domain-join.sh -y
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
#  101 - Unsupported distribution / package manager
#  127 - Command not found
#
# -------------------------------------------------------------------------------------------------

# Define script version
scriptVersion="$(grep -m1 "^# Version:" "${BASH_SOURCE[0]:-$0}" 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "unknown")"

# Strict mode: fail fast, track errors, prevent unset vars, propagate pipe failures
set -Eeuo pipefail

# Ignore SIGPIPE (broken pipe) - prevents silent death when output is piped
trap '' PIPE 2>/dev/null || true

# Safe IFS: use standard whitespace splitting (space/tab/newline) to avoid surprises
IFS=$' \t\n'

# Require Bash 4.0+ (associative arrays, mapfile, printf -v).
# NOTE: Bash 4.0 is the minimum. Features from newer versions are intentionally
# avoided: no 'local -n' (nameref, 4.3+), no 'exec {var}>' (dynamic FD, 4.1+).
# Lock uses a fixed FD (exec 9>) for Bash 4.0 compatibility (no dynamic FD syntax).
if [[ -z "${BASH_VERSINFO[0]:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo "[$(date '+%F %T')] [ERROR] Bash 4.0+ required. Current: ${BASH_VERSION:-unknown}" >&2
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
# Portable timeout wrapper (detect once, use everywhere)
# -------------------------------------------------------------------------
# On minimal/container images, coreutils 'timeout' may be absent.
# This wrapper runs the command with timeout protection when available,
# or falls back to direct execution (best-effort, no hang protection).
# Same pattern as $SED_EXT: detect at startup, use everywhere.
# Usage: safe_timeout <duration> <cmd> [args...]
#   safe_timeout 5 kinit user@REALM
#   safe_timeout "${KINIT_TIMEOUT}s" kinit user@REALM
# -------------------------------------------------------------------------
HAS_TIMEOUT=false
command -v timeout >/dev/null 2>&1 && HAS_TIMEOUT=true

safe_timeout() {
    # Usage: safe_timeout <duration> <command> [args...]
    # Return 125 on invocation errors (mirrors coreutils timeout behavior).
    if (( $# < 2 )) || [[ -z "${1:-}" ]]; then
        return 125
    fi

    if $HAS_TIMEOUT; then
        timeout "$@"
    else
        # Strip timeout-specific flags and duration to reach the actual command.
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --signal=*|--kill-after=*)
                    shift ;;
                -k|-s|--signal|--kill-after)
                    (( $# >= 2 )) || return 125
                    shift 2 ;;
                -k*|-s*)
                    shift ;;
                --foreground|--preserve-status)
                    shift ;;
                --)
                    shift; break ;;
                -*)
                    shift ;;
                *)
                    # First positional arg is the duration — skip it
                    shift; break ;;
            esac
        done

        (( $# > 0 )) || return 125
        "$@"
    fi
}

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
_locale_list="$(locale -a 2>/dev/null || true)"
if printf '%s\n' "$_locale_list" | grep -qiE '^(C\.UTF-8|en_US\.UTF-8|pt_BR\.UTF-8)$'; then
    if printf '%s\n' "$_locale_list" | grep -qi '^C\.UTF-8$'; then
        _CACHED_SED_LOCALE="C.UTF-8"
    elif printf '%s\n' "$_locale_list" | grep -qi '^en_US\.UTF-8$'; then
        _CACHED_SED_LOCALE="en_US.UTF-8"
    else
        _CACHED_SED_LOCALE="pt_BR.UTF-8"
    fi
fi

# -------------------------------------------------------------------------
# Terminal Initialization & Screen Clear (MAXIMUM COMPATIBILITY)
# -------------------------------------------------------------------------
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
# NOTE: Uses 'printf -v' (Bash 4.0+) instead of 'local -n' / nameref (Bash 4.3+)
# to maintain compatibility with Bash 4.0-4.2 (e.g., RHEL 7.0-7.3).
# This is an intentional design choice - do not refactor to use 'local -n'.
# -------------------------------------------------------------------------
read_sanitized() {
    local prompt sanitized var_name ts _rs_input
    prompt="${1:-}"
    var_name="${2:-}"

    [[ -z "$var_name" ]] && log_error "read_sanitized: missing var_name" 1

    # Validate variable name to prevent injection via printf -v
    # (only alphanumeric and underscore, must start with letter or underscore)
    [[ "$var_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || \
        log_error "read_sanitized: invalid variable name '$var_name'" 1

    ts="${C_DIM}[$(date '+%F %T')]${C_RESET}"
    sanitized="$(sanitize_log_msg <<< "$prompt")"
    sanitized="$(colorize_tag "$sanitized")"

    # Read into local, then assign to caller's variable via printf -v (Bash 4.0+ safe)
    read -rp "${ts} ${sanitized}" _rs_input
    printf -v "$var_name" '%s' "$_rs_input"
}

# -------------------------------------------------------------------------
# Utility: Print a safe divider, resistant to SSH/tmux/resize mismatches.
# -------------------------------------------------------------------------
print_divider() {
    local cols
    cols=$(tput cols 2>/dev/null) || \
    cols=$(stty size 2>/dev/null | awk '{print $2}') || \
    cols=""
    [[ "$cols" =~ ^[0-9]+$ && "$cols" -ge 20 ]] || cols=80
    sync
    local line
    line=$(printf '%*s' "$cols" '' | tr ' ' '-')
    printf '%s%s%s\n' "$C_DIM" "$line" "$C_RESET" >&2
}

# -------------------------------------------------------------------------
# Validate AD group name (policy-driven, sAMAccountName-friendly subset)
# -------------------------------------------------------------------------
validate_ad_group_name() {
    local name="$1"
    local context="${2:-group}"

    # Empty is valid (will use default)
    [[ -z "$name" ]] && return 0

    # Reject control characters to prevent config-file injection via env vars.
    # (Space is allowed; other whitespace is not.)
    if [[ "$name" == *$'\n'* || "$name" == *$'\r'* || "$name" == *$'\t'* ]]; then
        log_info "⚠️ ${context} contains control characters (newline/tab) - rejected"
        return 1
    fi

    # Length policy:
    # - AD schema limits and effective constraints can vary by object class and tooling.
    # - This script enforces an internal safety/policy cap of 64 characters for group identifiers.
    if [[ ${#name} -gt 64 ]]; then
        log_info "⚠️ ${context} name too long (policy max 64 chars): $name"
        return 1
    fi

    # Character policy:
    # - We intentionally restrict to a safe subset to avoid escaping issues across sudoers/SSH/PAM tooling.
    # - Space is allowed explicitly; other whitespace is rejected above.
    if [[ ! "$name" =~ ^[A-Za-z0-9._\ -]+$ ]]; then
        log_info "⚠️ ${context} contains invalid characters: $name"
        log_info "   Allowed: letters, digits, dot (.), underscore (_), hyphen (-), space"
        return 1
    fi

    # Reserved prefixes check
    if [[ "$name" =~ ^(CN|OU|DC)= ]]; then
        log_info "⚠️ ${context} starts with LDAP DN prefix: $name"
        return 1
    fi

    # Cannot start or end with hyphen or dot (safety restriction)
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

    # Use variables for braces to avoid bash parameter-expansion delimiter ambiguity with '}'.
    local esc_lbrace='\\{'
    local esc_rbrace='\\}'

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
    s="${s//\{/$esc_lbrace}"
    s="${s//\}/$esc_rbrace}"
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
# Validate host or IPv4/IPv6 endpoint (used for DC_SERVER, NTP_SERVER).
# -------------------------------------------------------------------------
# Accepts: FQDN, short hostname, IPv4, and basic IPv6.
# Rejects: control characters, newlines, whitespace, shell metacharacters.
# This is an intentional security gate for non-interactive inputs.
# -------------------------------------------------------------------------
validate_host_or_ip() {
    local value="${1:-}"
    [[ -n "$value" ]] || return 1

    # Reject any whitespace/control characters early.
    [[ "$value" =~ [[:space:]] ]] && return 1

    # IPv4 format check (strict octet range 0-255)
    if [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local o1 o2 o3 o4
        IFS='.' read -r o1 o2 o3 o4 <<< "$value"
        local o o10
        for o in "$o1" "$o2" "$o3" "$o4"; do
            o10=$((10#$o))
            (( o10 >= 0 && o10 <= 255 )) || return 1
        done
        return 0
    fi

    # Basic IPv6 check (hex groups separated by colons, optional :: compression)
    if [[ "$value" =~ ^[0-9a-fA-F:]+$ && "$value" == *:* ]]; then
        return 0
    fi

    # DNS hostname/FQDN check (RFC 1123: labels, alphanumeric+hyphen, max 253 chars)
    (( ${#value} > 253 )) && return 1
    [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]] || return 1
    return 0
}

# -------------------------------------------------------------------------
# Validate LDAP Distinguished Name shape (used for OU parameter).
# -------------------------------------------------------------------------
# Checks: non-empty, no newlines/CR (LDIF injection), max 1024 chars,
# at least 2 RDN components, each matching KEY=VALUE format.
# NOTE:
# - Supports escaped commas (e.g., CN=User\, Name) for safe splitting.
# - Does not attempt full RFC 4514 semantics validation (e.g., hex escapes);
#   this is sufficient for the OU DN usage in this script.
# -------------------------------------------------------------------------
validate_ldap_dn() {
    local dn="${1:-}"
    [[ -n "$dn" ]] || return 1
    [[ "$dn" == *$'\n'* || "$dn" == *$'\r'* ]] && return 1
    (( ${#dn} <= 1024 )) || return 1

    # Split on unescaped commas (supports escaped commas like '\,').
    local -a _rdns=()
    local _cur="" _esc=false ch
    local i

    for (( i=0; i<${#dn}; i++ )); do
        ch="${dn:$i:1}"

        if $_esc; then
            _cur+="$ch"
            _esc=false
            continue
        fi

        if [[ "$ch" == "\\" ]]; then
            _cur+="$ch"
            _esc=true
            continue
        fi

        if [[ "$ch" == "," ]]; then
            _rdns+=( "$_cur" )
            _cur=""
            continue
        fi

        _cur+="$ch"
    done

    # Trailing backslash indicates invalid DN escaping.
    $_esc && return 1

    _rdns+=( "$_cur" )
    (( ${#_rdns[@]} >= 2 )) || return 1

    local rdn
    for rdn in "${_rdns[@]}"; do
        # Allow optional whitespace around separators.
        rdn="${rdn#"${rdn%%[![:space:]]*}"}"
        rdn="${rdn%"${rdn##*[![:space:]]}"}"
        # Accept RDNs like CN=..., OU=..., DC=...
        [[ "$rdn" =~ ^[A-Za-z][A-Za-z0-9-]*=.+$ ]] || return 1
    done

    return 0
}

# -------------------------------------------------------------------------
# Global error trap - catches any unexpected command failure.
# Uses BASH_LINENO[0] and FUNCNAME[1] for accurate callsite reporting
# inside nested functions (more reliable than $LINENO in string traps).
# -------------------------------------------------------------------------
_err_trap() {
    local rc=$?
    local line="${BASH_LINENO[0]:-$LINENO}"
    local src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]:-$0}}"
    local func="${FUNCNAME[1]:-MAIN}"
    log_error "Unexpected error (rc=${rc}) at ${src}:${line} in ${func}(): ${BASH_COMMAND}" "${rc}"
}

# Define the trap command string for restoration after temporarily disabling ERR trap.
# Referenced by cmd_try(), cmd_try_in(), and other helpers that need to restore the trap.
readonly ERROR_TRAP_CMD="_err_trap"
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

# -------------------------------------------------------------------------
# Default values for optional flags (env may preseed; CLI overrides)
# -------------------------------------------------------------------------
: "${YES:=false}"
: "${FORCE:=false}"
: "${DRY_RUN:=false}"
: "${NONINTERACTIVE:=false}"
: "${VERBOSE:=false}"
: "${VALIDATE_ONLY:=false}"

# Parse flags (CLI wins over env)
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)       DRY_RUN=true ;;
        --yes|-y)        NONINTERACTIVE=true ;;
        --verbose|-v)    VERBOSE=true ;;
        --validate-only) VALIDATE_ONLY=true ;;
        *)
            log_error "Unknown option: $1" 1
            ;;
    esac
    shift
done

# Normalize boolean-like environment inputs to strict true/false.
# Prevents accidental command execution when flags are used as shell predicates.
_normalize_bool_var() {
    local var="$1"
    local val

    # Validate variable name to prevent unexpected printf -v assignment.
    if [[ -z "$var" || ! "$var" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        log_error "_normalize_bool_var: invalid variable name '$var'" 1
    fi

    val="${!var:-false}"
    val="${val,,}"  # Bash 4+: lowercase

    case "$val" in
        true|1|yes|y|on)     val=true  ;;
        false|0|no|n|off|"") val=false ;;
        *)
            log_info "⚠ ${var}='${!var}' is not a valid boolean (expected true/false) - defaulting to false"
            val=false
            ;;
    esac

    printf -v "$var" '%s' "$val"
}

for _b in YES FORCE DRY_RUN NONINTERACTIVE VERBOSE VALIDATE_ONLY; do
    _normalize_bool_var "$_b"
done
unset _b

LDAP_TIMEOUT="${LDAP_TIMEOUT:-30}"
# Validate LDAP_TIMEOUT is a positive integer (reject suffixes, floats, negatives)
if ! [[ "$LDAP_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    log_info "⚠ LDAP_TIMEOUT='$LDAP_TIMEOUT' is not a valid positive integer - defaulting to 30"
    LDAP_TIMEOUT=30
fi

JOIN_TIMEOUT="${JOIN_TIMEOUT:-120}"
if ! [[ "$JOIN_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    log_info "⚠ JOIN_TIMEOUT='$JOIN_TIMEOUT' is not a valid positive integer - defaulting to 120"
    JOIN_TIMEOUT=120
fi

KINIT_TIMEOUT="${KINIT_TIMEOUT:-20}"
if ! [[ "$KINIT_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    log_info "⚠ KINIT_TIMEOUT='$KINIT_TIMEOUT' is not a valid positive integer - defaulting to 20"
    KINIT_TIMEOUT=20
fi

TRUST_TIMEOUT="${TRUST_TIMEOUT:-15}"
if ! [[ "$TRUST_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    log_info "⚠ TRUST_TIMEOUT='$TRUST_TIMEOUT' is not a valid positive integer - defaulting to 15"
    TRUST_TIMEOUT=15
fi

KRB5_KEYTAB="${KRB5_KEYTAB:-/etc/krb5.keytab}"

# -------------------------------------------------------------------------
# Logging + Backup roots (after flags/defaults)
# - Logs go to /var/log/linux-ad-domain-join/ with timestamped filenames
# - VALIDATE_ONLY uses /tmp to keep the run non-invasive
# -------------------------------------------------------------------------
LOG_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_HOSTNAME="${HOSTNAME_SHORT:-localhost}"

if $VALIDATE_ONLY || $DRY_RUN; then
    LOG_DIR="${LOG_DIR:-/tmp/linux-ad-domain-join}"
    BACKUP_ROOT="${BACKUP_ROOT:-/tmp/linux-ad-domain-join-backups}"
else
    LOG_DIR="${LOG_DIR:-/var/log/linux-ad-domain-join}"
    BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/linux-ad-domain-join}"
fi

# Build timestamped log filename (PID suffix prevents collision on same-second double-run)
LOG_FILE="${LOG_DIR}/${LOG_TIMESTAMP}_${LOG_HOSTNAME}_$$.log"

# Ensure roots are absolute (defense-in-depth).
[[ "$LOG_DIR" == /* ]] || log_error "LOG_DIR must be an absolute path: $LOG_DIR" 1
[[ "$BACKUP_ROOT" == /* ]] || log_error "BACKUP_ROOT must be an absolute path: $BACKUP_ROOT" 1

# Ensure BACKUP_ROOT is safe (defense-in-depth for pruning logic).
# Reject empty, root, and overly generic system directories.
[[ "$BACKUP_ROOT" =~ ^/[^/]+/[^/]+ ]] || log_error "BACKUP_ROOT is too generic/short: $BACKUP_ROOT" 1

case "$BACKUP_ROOT" in
    "/"|"/etc"|"/bin"|"/sbin"|"/usr"|"/var"|"/var/log"|"/home"|"/root")
        log_error "BACKUP_ROOT points to a critical system directory: $BACKUP_ROOT" 1
        ;;
esac

# -------------------------------------------------------------------------
# Hardening: refuse unsafe LOG_DIR/BACKUP_ROOT when not in read-only modes
# -------------------------------------------------------------------------
_assert_secure_dir() {
    # Usage: _assert_secure_dir <dir> <label>
    # Enforces: not symlink, owned by root (best-effort), not group/other-writable.
    # Comments in en-US per project convention.
    local d="$1"
    local label="${2:-DIR}"

    [[ -n "$d" ]] || return 0
    [[ -d "$d" ]] || return 0

    [[ -L "$d" ]] && log_error "$label is a symlink (refusing): $d" 1

    if command -v stat >/dev/null 2>&1; then
        local mode uid
        mode="$(stat -c '%a' "$d" 2>/dev/null || true)"
        uid="$(stat -c '%u' "$d" 2>/dev/null || true)"

        if [[ "$uid" =~ ^[0-9]+$ ]] && (( uid != 0 )); then
            log_error "$label must be owned by root (uid 0). Found uid=$uid for $d" 1
        fi

        if [[ "$mode" =~ ^[0-9]{3,4}$ ]]; then
            # Refuse group/other-writable directories (prevents symlink/file clobber attacks).
            (( (8#$mode & 8#022) == 0 )) || log_error "$label is writable by group/others (mode $mode) - refusing: $d" 1
        fi
    fi
}

if ! $VALIDATE_ONLY && ! $DRY_RUN; then
    # Refuse world-writable trees in production mode (untrusted path risk).
    case "$LOG_DIR" in
        /tmp/*|/var/tmp/*|/dev/shm/*)
            log_error "LOG_DIR must not be under a world-writable tree in production mode: $LOG_DIR" 1
            ;;
    esac

    case "$BACKUP_ROOT" in
        /tmp/*|/var/tmp/*|/dev/shm/*)
            log_error "BACKUP_ROOT must not be under a world-writable tree in production mode: $BACKUP_ROOT" 1
            ;;
    esac
fi

# Refuse symlinked backup roots under world-writable trees (legacy guard).
if [[ "$BACKUP_ROOT" == /tmp/* || "$BACKUP_ROOT" == /var/tmp/* || "$BACKUP_ROOT" == /dev/shm/* ]]; then
    [[ -L "$BACKUP_ROOT" ]] && log_error "BACKUP_ROOT is a symlink (refusing): $BACKUP_ROOT" 1
fi

# Extra protection for LOG_DIR under /tmp and /var/tmp (legacy guard + TOCTOU recheck).
if [[ "$LOG_DIR" == /tmp/* || "$LOG_DIR" == /var/tmp/* ]]; then
    if [[ -L "$LOG_DIR" ]]; then
        log_info "⚠ LOG_DIR is a symlink ($LOG_DIR) - refusing to use it"
        rm -f -- "$LOG_DIR" 2>/dev/null || true
    fi
    # Re-check after removal to close TOCTOU window (symlink could be recreated)
    if [[ -L "$LOG_DIR" ]]; then
        log_error "LOG_DIR is still a symlink after removal (possible race condition): $LOG_DIR" 1
    fi
fi

_log_dir_created=false
if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p -- "$LOG_DIR" 2>/dev/null || true
    _log_dir_created=true
fi
if $_log_dir_created; then
    chmod 750 -- "$LOG_DIR" 2>/dev/null || true
fi

# If LOG_DIR already existed, enforce safety in production mode (best-effort).
if ! $VALIDATE_ONLY && ! $DRY_RUN; then
    _assert_secure_dir "$LOG_DIR" "LOG_DIR"
    # BACKUP_ROOT may not exist yet; validate only if present.
    _assert_secure_dir "$BACKUP_ROOT" "BACKUP_ROOT"
fi

# Create the log file under a restrictive umask so it is safe even if chmod fails.
__prev_umask="$(umask)"
umask 027

# Refuse symlinked log files before opening (prevents clobber via attacker-controlled paths).
[[ -L "$LOG_FILE" ]] && log_error "LOG_FILE is a symlink (refusing): $LOG_FILE" 1

if ! : >>"$LOG_FILE" 2>/dev/null; then
    # Fallback if /var/log is not writable
    LOG_DIR="/tmp/linux-ad-domain-join"
    LOG_FILE="${LOG_DIR}/${LOG_TIMESTAMP}_${LOG_HOSTNAME}.log"

    _log_dir_created=false
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p -- "$LOG_DIR" 2>/dev/null || true
        _log_dir_created=true
    fi
    if $_log_dir_created; then
        chmod 750 -- "$LOG_DIR" 2>/dev/null || true
    fi

    # Always enforce safety on the fallback directory (it lives under /tmp).
    if ! $VALIDATE_ONLY && ! $DRY_RUN; then
        _assert_secure_dir "$LOG_DIR" "LOG_DIR (fallback)"
    fi

    [[ -L "$LOG_FILE" ]] && { echo "[$(date '+%F %T')] [ERROR] LOG_FILE is a symlink: $LOG_FILE" >&2; exit 1; }

    : >>"$LOG_FILE" 2>/dev/null || { echo "[$(date '+%F %T')] [ERROR] Cannot write LOG_FILE=$LOG_FILE" >&2; exit 1; }
fi

umask "$__prev_umask"
unset __prev_umask

# Restrict log file permissions (contains AD topology metadata)
chmod 640 "$LOG_FILE" 2>/dev/null || log_info "⚠ Unable to chmod 640 on LOG_FILE=$LOG_FILE (check filesystem/ACLs)"

# Prune old log files (keep last 30 logs)
LOG_RETENTION="${LOG_RETENTION:-30}"
# Validate LOG_RETENTION is a positive integer (prevent arithmetic errors on bad env input)
if ! [[ "$LOG_RETENTION" =~ ^[1-9][0-9]*$ ]]; then
    log_info "⚠ LOG_RETENTION='$LOG_RETENTION' is not a valid positive integer - defaulting to 30"
    LOG_RETENTION=30
fi
_prune_old_logs() {
    local log_dir="$1" keep="$2"
    [[ -d "$log_dir" ]] || return 0

    local count
    # Best-effort: never abort the whole run if log pruning hits filesystem edge-cases.
    count="$(find "$log_dir" -maxdepth 1 -type f -name '*.log' 2>/dev/null | wc -l || true)"
    [[ "$count" =~ ^[0-9]+$ ]] || count=0
    (( count > keep )) || return 0

    # Preferred path: GNU find supports -printf (common on enterprise distros).
    # Fallback path exists below for minimal/BusyBox find implementations.
    if find "$log_dir" -maxdepth 1 -type f -name '*.log' -printf '%T@\t%p\n' >/dev/null 2>&1; then
        # Log filenames are script-generated (timestamp_hostname_pid.log) and never
        # contain whitespace or newlines. Use newline-delimited pipeline for
        # compatibility with coreutils < 8.25 (no head -z; e.g. RHEL 7).
        find "$log_dir" -maxdepth 1 -type f -name '*.log' -printf '%T@\t%p\n' 2>/dev/null \
            | sort -t$'\t' -k1,1n \
            | head -n "$(( count - keep ))" \
            | while IFS=$'\t' read -r _ts old_log; do
                  rm -f -- "$old_log" 2>/dev/null || true
              done || true
        return 0
    fi

    # Fallback: no -printf support. Use ls -1t (newest first) and delete beyond keep.
    # NOTE: This is best-effort; never fail the run if pruning cannot be completed.
    local -a files=()
    local f

    local _prev_nullglob=false
    shopt -q nullglob && _prev_nullglob=true
    shopt -s nullglob
    for f in "$log_dir"/*.log; do
        files+=( "$f" )
    done
    $_prev_nullglob || shopt -u nullglob

    (( ${#files[@]} > keep )) || return 0

    # Delete from (keep+1) to end (oldest tail).
    ls -1t -- "$log_dir"/*.log 2>/dev/null \
        | awk -v keep="$keep" 'NR>keep {print}' \
        | while IFS= read -r old_log; do
              [[ -n "$old_log" ]] && rm -f -- "$old_log" 2>/dev/null || true
          done || true
}
# NOTE: Log pruning moved to after lock acquisition (see below)

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

# Fixed FD number for flock. FD 9 is the conventional choice for script locks.
# We use a fixed FD (exec N>) instead of dynamic allocation (exec {var}>) to
# maintain compatibility with Bash 4.0 (dynamic FD syntax requires Bash 4.1+).
readonly _LOCK_FD_FIXED=9

if command -v flock >/dev/null 2>&1; then
    # Use an fd-based lock (auto-released on process exit).
    # NOTE: exec FD>> does NOT set O_CLOEXEC. Child processes inherit this FD
    # unless explicitly closed. The detached D-Bus remediation in cleanup_secrets
    # closes FD 9 via redirection (9>&-) to avoid keeping the lock alive.
    # Open without truncating before the lock is acquired (avoids clobbering
    # the lock file contents when another run is active).
    exec 9>>"$LOCK_FILE"
    if ! flock -n "$_LOCK_FD_FIXED"; then
        echo "[$(date '+%F %T')] [ERROR] Another instance is already running (lock: $LOCK_FILE)" >&2
        exit 16
    fi
    # Store PID for troubleshooting (best-effort). We hold the lock now, so overwrite is safe.
    printf '%s\n' "$$" >"$LOCK_FILE" 2>/dev/null || true
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
        rm -rf -- "${LOCK_DIR_FALLBACK:?}" 2>/dev/null || true
        # Atomic re-acquisition; sleep+retry reduces TOCTOU window
        if ! mkdir "$LOCK_DIR_FALLBACK" 2>/dev/null; then
            sleep 0.2
            if ! mkdir "$LOCK_DIR_FALLBACK" 2>/dev/null; then
                echo "[$(date '+%F %T')] [ERROR] Failed to acquire lock after stale cleanup (lock: $LOCK_DIR_FALLBACK)" >&2
                exit 16
            fi
        fi
    fi
    printf '%s\n' "$$" >"${LOCK_DIR_FALLBACK}/pid" 2>/dev/null || true
    LOCK_MODE="mkdir"
fi

# Prune old logs (safe: runs after lock acquisition to prevent concurrent prune)
_prune_old_logs "$LOG_DIR" "$LOG_RETENTION"

# -------------------------------------------------------------------------
# Redirect stdout/stderr to log file while mirroring to console via tee.
# -------------------------------------------------------------------------
if command -v tee >/dev/null 2>&1; then
    : >"$LOG_FILE" 2>/dev/null || true

    # Prefer line-buffered tee to prevent interleaved writes from dual process substitutions
    if command -v stdbuf >/dev/null 2>&1; then
        exec > >(stdbuf -oL tee -a "$LOG_FILE") 2> >(stdbuf -oL tee -a "$LOG_FILE" >&2)
    else
        exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)
    fi

    # Brief pause to let tee process substitutions initialize.
    # On heavily loaded systems (CI/CD, cloud VMs with I/O throttling),
    # the subprocesses may take longer to start - 0.2s covers most cases.
    sleep 0.2

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
BACKUP_RUN_ID="$(date +%Y%m%d_%H%M%S)_${HOSTNAME_SHORT}_$$"
BACKUP_DIR="${BACKUP_ROOT}/${BACKUP_RUN_ID}"

# -------------------------------------------------------------------------
# Utility: Convert string to lowercase (for case-insensitive comparisons)
# -------------------------------------------------------------------------
to_lower() { printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]'; }

# -------------------------------------------------------------------------
# Trim leading/trailing whitespace and common list markers from command output lines.
# -------------------------------------------------------------------------
trim_ws() {
    local v="$1"
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    printf '%s' "$v"
}

# -------------------------------------------------------------------------
# Safe mktemp wrapper with enhanced error handling and logging context.
# -------------------------------------------------------------------------
safe_mktemp() {
    local tmpfile template

    # BusyBox mktemp (and some minimal images) require an explicit template.
    # When no args are provided, force a portable /tmp template.
    if (( $# == 0 )); then
        template="/tmp/linux-ad-domain-join.XXXXXX"
        if ! tmpfile="$(mktemp "$template" 2>/dev/null)"; then
            log_error "mktemp failed (template: $template)" 1
        fi
    else
        template="${*}"
        # Redirect stderr to /dev/null to prevent contaminating the path with warnings.
        # On failure, log_error provides adequate context (template name + exit code).
        if ! tmpfile="$(mktemp "$@" 2>/dev/null)"; then
            log_error "mktemp failed (template: $template)" 1
        fi
    fi

    [[ -z "$tmpfile" ]] && log_error "mktemp returned empty path" 1
    printf '%s' "$tmpfile"
}

# -------------------------------------------------------------------------
# Secure file deletion (best-effort: shred > srm > rm)
# -------------------------------------------------------------------------
# Overwrites file content before unlinking to reduce recovery risk on
# non-SSD/non-TRIM storage. Falls back to plain rm when neither shred
# nor srm is available (common in minimal/container images).
# -------------------------------------------------------------------------
secure_delete() {
    local f="$1"
    [[ -n "$f" && -f "$f" ]] || return 0

    # Hardening: always terminate option parsing to avoid paths starting with '-'
    # from being treated as flags by rm/shred/srm.
    if command -v shred >/dev/null 2>&1; then
        shred -u -z -n 3 -- "$f" 2>/dev/null || rm -f -- "$f"
    elif command -v srm >/dev/null 2>&1; then
        srm -f -- "$f" 2>/dev/null || rm -f -- "$f"
    else
        rm -f -- "$f"
    fi
}

# Restore SELinux security context after file creation/move.
# No-op on systems without SELinux. Accepts same args as restorecon.
# Ephemeral paths (/tmp, /var/tmp, /dev/shm, /run) are silently skipped
# because they inherit correct context from their parent directory and
# have no matching policy rule in the system file_contexts database.
selinux_restore() {
    # Skip in read-only modes (restorecon modifies xattrs)
    if $DRY_RUN || $VALIDATE_ONLY; then return 0; fi

    local -a filtered=()
    local arg

    for arg in "$@"; do
        if [[ "$arg" == -* ]]; then
            filtered+=("$arg")
            continue
        fi
        [[ "$arg" == /tmp/* || "$arg" == /var/tmp/* || "$arg" == /dev/shm/* || "$arg" == /run/* ]] && continue
        filtered+=("$arg")
    done

    (( ${#filtered[@]} == 0 )) && return 0

    command -v restorecon >/dev/null 2>&1 && restorecon "${filtered[@]}" 2>/dev/null || true
}

# -------------------------------------------------------------------------
# Trim leading/trailing whitespace and common list markers (e.g., '-', '*', '•')
# from command output lines. Also strips trailing "[...]" from "curl error" lines.
# -------------------------------------------------------------------------
trim_line() {
    # shellcheck disable=SC2086  # SED_EXT must be expanded as a flag (-E/-r)
    sed $SED_EXT \
        -e 's/^[[:space:]]+//' \
        -e 's/^[[:space:]]*[-*•][[:space:]]+//' \
        -e 's/[[:space:]]+$//' \
        -e '/[Cc]url error/ s/[[:space:]]\[[^]]*][[:space:]]*$//'
}

# -------------------------------------------------------------------------
# Unified service control function: abstracts over systemctl, service/chkconfig, and direct init.d scripts.
# -------------------------------------------------------------------------
service_control() {
    local svc_name="$1"
    local action="$2"
    local rc=0

    # Defense-in-depth: ensure direct calls respect read-only simulation modes.
    if $VALIDATE_ONLY; then
        case "$action" in
            start|stop|restart|reload|enable|disable|mask|unmask|enable-now)
                log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Suppressed service action: $svc_name $action"
                return 0
                ;;
        esac
    fi

    if $DRY_RUN; then
        case "$action" in
            start|stop|restart|reload|enable|disable|mask|unmask|enable-now)
                log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would run service action: $svc_name $action"
                return 0
                ;;
        esac
    fi

    # Modern systemd-based systems (RHEL 7+, Ubuntu 16.04+, Debian 8+)
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        case "$action" in
            start)      systemctl start "$svc_name" || rc=$? ;;
            stop)       systemctl stop "$svc_name" || rc=$? ;;
            restart)    systemctl restart "$svc_name" || rc=$? ;;
            reload)     systemctl reload "$svc_name" || rc=$? ;;
            enable)     systemctl enable "$svc_name" || rc=$? ;;
            disable)    systemctl disable "$svc_name" || rc=$? ;;
            mask)       systemctl mask "$svc_name" || rc=$? ;;
            unmask)     systemctl unmask "$svc_name" || rc=$? ;;
            status)     systemctl status "$svc_name" || rc=$? ;;
            enable-now) systemctl enable --now "$svc_name" || rc=$? ;;
            *)          log_error "Unknown service action: $action" 1 ;;
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
                # Enable and start in two steps. Track both exit codes independently.
                local rc_en=0 rc_st=0
                service_control "$svc_name" enable || rc_en=$?
                service_control "$svc_name" start  || rc_st=$?
                # Propagate failure if either step failed
                (( rc_en != 0 || rc_st != 0 )) && rc=1 || rc=0
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

# -------------------------------------------------------------------------
# Initialize backup directory for the current run. Respects VALIDATE_ONLY and DRY_RUN modes with appropriate logging.
# -------------------------------------------------------------------------
init_backup_dir() {
    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Backup directory creation suppressed: $BACKUP_DIR"
        return 0
    fi

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would create backup directory: $BACKUP_DIR"
        return 0
    fi

    # Ensure backups are private: they may include sensitive configuration snapshots.
    install -d -m 700 -- "$BACKUP_DIR" || log_error "Failed to create secure backup directory: $BACKUP_DIR" 30

    log_info "💾 Backup directory: $BACKUP_DIR"
}

# -------------------------------------------------------------------------
# Backup pruning: keep only the last N backup runs (directories) in BACKUP_ROOT, sorted by modification time (newest first).
# -------------------------------------------------------------------------
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

    # Newline-delimited list: safe with spaces; paths containing newlines are out-of-scope for backup dirs here.
    find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@\t%p\n' 2>/dev/null \
        | sort -t$'\t' -k1,1rn >"$tmp_list" || true

    local total
    total="$(wc -l <"$tmp_list" 2>/dev/null || echo 0)"
    [[ "$total" =~ ^[0-9]+$ ]] || total=0

    if (( total > keep )); then
        local _skip=0 _ts d
        while IFS=$'\t' read -r _ts d; do
            (( ++_skip <= keep )) && continue
            [[ -n "$d" ]] && rm -rf -- "$d" 2>/dev/null || true
        done < "$tmp_list"
    fi

    rm -f "$tmp_list"
}

# -------------------------------------------------------------------------
# Backup a file with a unique name in the current run's backup directory, preserving permissions and SELinux context.
# -------------------------------------------------------------------------
init_backup_dir

# -------------------------------------------------------------------------
# Prune old backup runs (keep last 20 by default) - best-effort, safe under set -eEuo
# -------------------------------------------------------------------------
backup_prune_old_runs 20

# -------------------------------------------------------------------------
# Validate that a value is an unsigned integer (no suffixes, decimals, negatives)
# -------------------------------------------------------------------------
is_uint() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

# -------------------------------------------------------------------------
# Validate that a value is an unsigned integer within a specified range (inclusive).
# -------------------------------------------------------------------------
require_uint_range() {
    local name="$1" val="$2" min="$3" max="$4"
    is_uint "$val" || log_error "$name must be an integer (seconds). Got: '$val'" 1

    # Force base-10 to avoid octal interpretation (e.g., "0900") in bash arithmetic.
    local val10 min10 max10
    val10=$((10#$val))
    min10=$((10#$min))
    max10=$((10#$max))

    (( val10 >= min10 && val10 <= max10 )) || log_error "$name must be between $min and $max seconds. Got: $val" 1
}

# -------------------------------------------------------------------------
# Normalize various yes/no inputs to "yes" or "no" (case-insensitive, supports multiple languages and common variants)
# -------------------------------------------------------------------------
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

# -------------------------------------------------------------------------
# TMOUT management: disable existing TMOUT lines in /etc/profile.d/*.sh and apply new profile with specified timeout.
# -------------------------------------------------------------------------
disable_tmout_in_profile_d() {
    local f bk

    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Suppressed TMOUT cleanup in /etc/profile.d (non-invasive mode)"
        return 0
    fi

    local _prev_nullglob=false
    shopt -q nullglob && _prev_nullglob=true
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

        # Restore SELinux context after in-place edits (sed -i may replace the inode).
        selinux_restore "$f"

        log_info "🧹 Disabled existing TMOUT lines in $f"
    done

    $_prev_nullglob || shopt -u nullglob
}

# -------------------------------------------------------------------------
# Apply TMOUT profile with the specified timeout value, ensuring idempotency and SELinux context restoration.
# -------------------------------------------------------------------------
apply_tmout_profile() {
    local timeout="$1"
    local target="/etc/profile.d/99-session-timeout.sh"
    local tmp payload

    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would ensure $target enforces TMOUT=$timeout"
        return 0
    fi

    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would ensure $target enforces TMOUT=$timeout"
        return 0
    fi

    payload="$(cat <<EOF
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
)"

    tmp="$(safe_mktemp "/tmp/99-session-timeout.sh.XXXXXX")"
    printf '%s\n' "$payload" >"$tmp"

    if [[ -f "$target" ]] && cmp -s "$tmp" "$target"; then
        rm -f "$tmp"
        selinux_restore "$target"
        log_info "✅ TMOUT already enforced via $target (TMOUT=$timeout seconds)"
        return 0
    fi

    [[ -f "$target" ]] && backup_file "$target"
    printf '%s\n' "$payload" | write_file 0644 "$target"

    rm -f "$tmp"
    selinux_restore "$target"

    log_info "✅ TMOUT enforced via $target (TMOUT=$timeout seconds)"
}

# -------------------------------------------------------------------------
# SSHD config management: set directive with deduplication (preserve Match blocks)
# -------------------------------------------------------------------------
sshd_set_directive_dedup() {
    # Ensures the directive is set once in the global section (before any Match blocks),
    # while preserving any Match-specific overrides. Preserves perms/owner.
    local key="$1" value="$2" file="$3"
    local tmp

    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would set global '$key $value' in $file (deduplicated, preserving Match blocks)"
        return 0
    fi

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
    selinux_restore "$file"
}

# -------------------------------------------------------------------------
# Validates the given sshd_config file using `sshd -t -f <file>`.
# If validation fails, attempts to restore from backup and exits with an error. 
# In DRY_RUN mode, only logs the intended validation command without executing it.
# -------------------------------------------------------------------------
validate_sshd_config_or_die() {
    local file="$1"
    local _sshd_line

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

    trap - ERR
    set +e
    sshd_check_output="$("$sshd_bin" -t -f "$file" 2>&1)"
    sshd_rc=$?
    $had_errexit && set -e
    trap "$ERROR_TRAP_CMD" ERR

    if (( sshd_rc != 0 )); then
        log_info "❌ sshd config validation failed for: $file"
        if [[ -n "$sshd_check_output" ]]; then
            while IFS= read -r _sshd_line; do
                [[ -n "$_sshd_line" ]] && log_info "   sshd -t: $_sshd_line"
            done <<< "$sshd_check_output"
        fi

        # VALIDATE_ONLY must never mutate the system. Report and abort only.
        if $VALIDATE_ONLY; then
            log_error "sshd config validation failed in VALIDATE_ONLY mode (no rollback attempted)." 1
        fi

        # Restore latest backup and refuse to proceed
        local rel="${file#/}"
        local backup_path="${BACKUP_DIR}/${rel}"

        if [[ -f "$backup_path" ]]; then
            log_info "Restoring backup: $backup_path -> $file"
            cp -pf -- "$backup_path" "$file" || log_error "Failed to restore backup from $backup_path" 1
            selinux_restore "$file"
            log_error "sshd_config restored from backup. Refusing to proceed." 1
        else
            log_error "No backup found at $backup_path. Refusing to proceed with broken config." 1
        fi

    fi
}

# -------------------------------------------------------------------------
# Detects if any of the given service unit names exist on the system (systemd), returning the first match. Checks both systemctl and direct file existence to cover masked/static units.
# -------------------------------------------------------------------------
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

# -------------------------------------------------------------------------
# Extracts the first non-wrapper binary from a command line, ignoring common wrappers (env, sudo, timeout, etc.) and their options.
# -------------------------------------------------------------------------
first_bin_from_cmd() {
    local arg
    local timeout_skip_next_nonflag=false

    for arg in "$@"; do
        # Common wrappers (skip)
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

# -------------------------------------------------------------------------
# Parses common package manager error messages from a log file and provides user-friendly explanations and troubleshooting tips.
# -------------------------------------------------------------------------
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

# -------------------------------------------------------------------------
# Utility to print commands with proper quoting for readability in logs and dry-run output.
# -------------------------------------------------------------------------
print_cmd_quoted() {
    local a out=()
    for a in "$@"; do
        out+=( "$(printf '%q' "$a")" )
    done
    printf '%s' "${out[*]}"
}

# -------------------------------------------------------------------------
# Check if a command exists in PATH or at a given path. Used for validating commands before execution.
# -------------------------------------------------------------------------
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

# -------------------------------------------------------------------------
# Extract target files from sed -i arguments for immutable attribute handling.
# -------------------------------------------------------------------------
_cmd_run_capture() {
    # Internal: runs a command (array), captures stdout+stderr into tmpfile, returns RC.
    # Usage: _cmd_run_capture <tmp_out_path> <cmd...>
    local tmp_out="$1"; shift
    local -a cmd=( "$@" )

    # Force C locale for predictable parsing
    LC_ALL=C LANG=C "${cmd[@]}" >"$tmp_out" 2>&1
    return $?
}

# -------------------------------------------------------------------------
# Command classification for VALIDATE_ONLY mode (non-invasive dry-run)
# -------------------------------------------------------------------------
is_mutating_cmd() {
    # Determines if a command can modify the system. If yes, it will be suppressed in VALIDATE_ONLY mode.
    local first_bin="$1"; shift
    local -a args=( "$@" )
    local a

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
        service_control)
            # Internal wrapper that delegates to systemctl/service/init.d.
            # Treat state-changing actions as mutating in VALIDATE_ONLY mode.
            for a in "${args[@]}"; do
                case "$a" in
                    start|stop|restart|reload|enable|disable|mask|unmask|enable-now)
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
        apt|apt-get|aptitude)
            return 0
            ;;
        dnf|yum)
            return 0
            ;;
        zypper)
            return 0
            ;;
        dpkg)
            for a in "${args[@]}"; do
                case "$a" in
                    -i|--install|-r|--remove|-P|--purge|--configure|--unpack) return 0 ;;
                esac
            done
            ;;
        rpm)
            for a in "${args[@]}"; do
                case "$a" in
                    -i|-U|-F|-e|--install|--upgrade|--freshen|--erase) return 0 ;;
                esac
            done
            ;;
    esac

    return 1
}

# -------------------------------------------------------------------------
# Command execution wrapper with validation, dry-run, and classified error logging
# -------------------------------------------------------------------------
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
            # Restore SELinux contexts after in-place edits that may replace files on disk.
            if [[ "$first_bin" == "sed" ]]; then
                local _imf2
                while IFS= read -r _imf2; do
                    [[ -n "$_imf2" ]] && selinux_restore "$_imf2"
                done < <(_extract_sed_target_files "${cmd[@]}" 2>/dev/null || true)
            fi
            return 0
        else
            rc=$?
            log_info "❗ Command failed (exit $rc): $(print_cmd_quoted "${cmd[@]}")"
            return "$rc"
        fi
    fi

    tmp_out="$(safe_mktemp)" || { log_info "❗ mktemp failed (cannot capture command output)"; return 1; }
    if _cmd_run_capture "$tmp_out" "${cmd[@]}"; then
        # Restore SELinux contexts after in-place edits that may replace files on disk.
        if [[ "$first_bin" == "sed" ]]; then
            local _imf2
            while IFS= read -r _imf2; do
                [[ -n "$_imf2" ]] && selinux_restore "$_imf2"
            done < <(_extract_sed_target_files "${cmd[@]}" 2>/dev/null || true)
        fi
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
# - cmd_run/cmd_run_in: raw execution, returns actual RC
# - cmd_try:    returns actual RC; caller decides fate:
#                 cmd_try <cmd> || true  → tolerate failure
#                 cmd_try <cmd>          → fatal under set -e (ERR trap fires)
# - cmd_try_in: returns actual RC (same semantics as cmd_try, with stdin redirection)
# - cmd_must/cmd_must_in: fatal wrappers; capture RC first, then exit with
#                         descriptive message (avoids ERR trap preempting log output)
# -------------------------------------------------------------------------

# Global variable to hold last command RC for cmd_try/cmd_try_in (since cmd_must/cmd_must_in need to capture it before exiting)
CMD_LAST_RC=0

# -------------------------------------------------------------------------
# Strict-mode safe execution layer with context-aware error logging
# -------------------------------------------------------------------------
cmd_try() {
    local rc=0
    local had_errexit=false

    [[ $- == *e* ]] && had_errexit=true

    trap - ERR
    set +e

    cmd_run "$@"
    rc=$?

    $had_errexit && set -e

    # Restore the global ERR trap (always ERROR_TRAP_CMD in this script)
    trap "$ERROR_TRAP_CMD" ERR

    CMD_LAST_RC=$rc
    return "$rc"
}

# -------------------------------------------------------------------------
# Fatal wrapper for cmd_try: logs error with context and exits if command failed
# -------------------------------------------------------------------------
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

# -------------------------------------------------------------------------
# Strict-mode safe execution with stdin redirection (designed for use in cmd_must_in)
# -------------------------------------------------------------------------
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

    tmp_out="$(safe_mktemp)" || { log_info "❗ mktemp failed (cannot capture command output)"; return 1; }
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

# -------------------------------------------------------------------------
# Strict-mode safe execution layer with context-aware error logging (designed for use in cmd_must_in)
# -------------------------------------------------------------------------
cmd_try_in() {
    # Usage: cmd_try_in <stdin_file> <cmd> [args...]
    local rc=0
    local had_errexit=false

    [[ $- == *e* ]] && had_errexit=true

    trap - ERR
    set +e

    cmd_run_in "$@"
    rc=$?

    $had_errexit && set -e

    # Restore ERR trap by re-declaring directly (avoids eval)
    trap "$ERROR_TRAP_CMD" ERR

    CMD_LAST_RC=$rc
    return "$rc"
}

# -------------------------------------------------------------------------
# Fatal wrapper for cmd_try_in: logs error with context and exits if command failed
# -------------------------------------------------------------------------
cmd_must_in() {
    # Usage: cmd_must_in <stdin_file> <cmd> [args...]
    cmd_try_in "$@" || true
    (( CMD_LAST_RC == 0 )) || log_error "Command failed: $(print_cmd_quoted "${@:2}") < ${1} (exit $CMD_LAST_RC)" "$CMD_LAST_RC"
    return 0
}

# -------------------------------------------------------------------------
# Utility: check if required command exists, else log error and exit
# -------------------------------------------------------------------------
check_cmd() {
    command -v "$1" >/dev/null 2>&1 || log_error "Required command '$1' not found" 1
}

# -------------------------------------------------------------------------
# Safe wrapper for realm list (handles systems without realmd or with DBus timeout)
# -------------------------------------------------------------------------
safe_realm_list() {
    local timeout_s=5
    local tmp_out=""
    local code=0

    # Non-fatal temp file creation (this is a "safe" helper; do not abort the script here)
    tmp_out="$(safe_mktemp)" || {
        log_info "ℹ mktemp failed in safe_realm_list(); returning empty realm list"
        echo ""
        return 0
    }

    # Ensure temp file is removed even if a command fails under errexit
    trap 'rm -f "$tmp_out" 2>/dev/null || true; trap - RETURN' RETURN

    if ! command -v realm >/dev/null 2>&1; then
        # Older systems: emulate empty result
        : >"$tmp_out"
        log_info "ℹ realmd not installed; skipping realm enumeration"
    else
        safe_timeout "$timeout_s" realm list >"$tmp_out" 2>/dev/null || code=$?

        if (( code != 0 )); then
            log_info "ℹ realm list timed out or failed (code $code)"
            : >"$tmp_out"
        fi
    fi

    # Output contents (may be empty) without risking errexit
    cat "$tmp_out" 2>/dev/null || true
}

# -------------------------------------------------------------------------
# Idempotent file backup with path traversal protection and flexible output
# -------------------------------------------------------------------------
backup_file() {
    # Usage:
    #   backup_file /path/file            -> performs backup (silent)
    #   backup_file /path/file outvar     -> performs backup + sets variable 'outvar' with backup path
    #
    # Behavior: idempotent per run (one backup per file path).
    # All log output goes to stderr. No stdout emission.
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

    # Prefer --preserve=all (ACL, xattr, SELinux context); fall back to -p for non-GNU cp.
    if ! cp --preserve=all -- "$path" "$bak" 2>/dev/null; then
        cp -p -- "$path" "$bak" || log_error "Failed to backup '$path' to '$bak'" 32
    fi

    if [[ -n "$__outvar" ]]; then
        printf -v "$__outvar" '%s' "$bak"
    fi
}

# -------------------------------------------------------------------------
# Writes content from stdin to a file with specified mode, creating parent dirs as needed (idempotent if content/mode unchanged)
# -------------------------------------------------------------------------
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

    # Atomic write: stage to temp file, then rename into place
    # (rename(2) is atomic on POSIX filesystems, preventing truncated configs)
    local _wf_tmp
    _wf_tmp="$(safe_mktemp "${path}.XXXXXX")"
    install -m "$mode" -o root -g root /dev/stdin "$_wf_tmp" || {
        rm -f "$_wf_tmp"
        log_error "write_file: install failed for $path" 1
    }
    mv -f "$_wf_tmp" "$path" || {
        rm -f "$_wf_tmp"
        log_error "write_file: mv failed for $path" 1
    }

    _file_restore_attr "$path"

    # Restore SELinux context if applicable (install via /dev/stdin
    # inherits caller's context instead of the policy-defined context)
    selinux_restore "$path"
}

# -------------------------------------------------------------------------
# Append a line to a file (non-idempotent, may create duplicates if run multiple times)
# -------------------------------------------------------------------------
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

# -------------------------------------------------------------------------
# Writes a single line to a file, replacing existing content (idempotent if line is unchanged)
# -------------------------------------------------------------------------
write_line_file() {
    # Usage: write_line_file <mode> <path> <single_line>
    local mode="$1" path="$2" line="$3"
    printf '%s\n' "$line" | write_file "$mode" "$path"
}

# -------------------------------------------------------------------------
# Append a line to a file only if an exact match doesn't already exist (idempotent)
# -------------------------------------------------------------------------
append_line_unique() {
    # Usage: append_line_unique <path> <exact_line>
    local path="$1" line="$2"
    grep -Fxq -- "$line" "$path" 2>/dev/null && return 0
    append_line "$path" "$line"
}

# -------------------------------------------------------------------------
# Check if chattr/lsattr are available (returns 0 if both are present, 1 if either is missing)
# -------------------------------------------------------------------------
_chattr_available() { command -v lsattr >/dev/null 2>&1 && command -v chattr >/dev/null 2>&1; }

# -------------------------------------------------------------------------
# Check if a file has the immutable bit set (returns 0 if immutable, 1 if not or on error)
# -------------------------------------------------------------------------
_file_has_immutable() {
    local f="$1"
    _chattr_available || return 1
    [[ -e "$f" ]] || return 1
    local flags
    flags="$(lsattr -d -- "$f" 2>/dev/null | awk '{print $1}' || true)"
    # Check for the immutable flag ('i') anywhere in the lsattr attribute string
    [[ -n "$flags" && "$flags" == *i* ]] && return 0
    return 1
}

# -------------------------------------------------------------------------
# Ensure a file is mutable by temporarily removing the immutable bit if set (idempotent)
# -------------------------------------------------------------------------
declare -A _IMMUTABLE_TRACKER=()

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

# -------------------------------------------------------------------------
# Restore immutable bit after file operation if we had removed it (idempotent)
# -------------------------------------------------------------------------
_file_restore_attr() {
    local f="$1"
    [[ "${_IMMUTABLE_TRACKER[$f]:-}" == "1" ]] || return 0
    if [[ -e "$f" ]]; then
        chattr +i -- "$f" 2>/dev/null || true
        $VERBOSE && log_info "🔒 Restored immutable bit on $f"
    fi
    # Double quotes required: single quotes prevent $f expansion,
    # leaving the tracker entry orphaned (Bash quoting rule for unset).
    unset "_IMMUTABLE_TRACKER[$f]"
}

# -------------------------------------------------------------------------
# Restore immutable bits for all tracked files (called on exit)
# -------------------------------------------------------------------------
_file_restore_all_attrs() {
    (( ${#_IMMUTABLE_TRACKER[@]} == 0 )) && return 0
    local f
    for f in "${!_IMMUTABLE_TRACKER[@]}"; do
        _file_restore_attr "$f"
    done
}

# -------------------------------------------------------------------------
# Sed target file extractor (handles -i with/without suffix, multiple files, and mixed options)
# -------------------------------------------------------------------------
_extract_sed_target_files() {
    local -a args=("$@")
    local -a files=()
    local skip_next=false has_inplace=false arg

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

    (( ${#files[@]} > 0 )) && printf '%s\n' "${files[@]}"
}

# Milliseconds timestamp with fallback
now_ms() {
    date +%s%3N 2>/dev/null || echo "$(( $(date +%s) * 1000 ))"
}

# -------------------------------------------------------------------------
# Netcat compatibility layer (nc vs ncat) — cached detection
# -------------------------------------------------------------------------
_CACHED_NETCAT_BIN=""
_NETCAT_DETECTED=false

detect_netcat_bin() {
    if $_NETCAT_DETECTED; then
        printf '%s' "$_CACHED_NETCAT_BIN"
        return
    fi
    _NETCAT_DETECTED=true
    if command -v nc >/dev/null 2>&1; then
        _CACHED_NETCAT_BIN="nc"
    elif command -v ncat >/dev/null 2>&1; then
        _CACHED_NETCAT_BIN="ncat"
    fi
    printf '%s' "$_CACHED_NETCAT_BIN"
}

# -------------------------------------------------------------------------
# Checks if a TCP port is open on a given host within a timeout, using netcat if available, else bash /dev/tcp
# -------------------------------------------------------------------------
tcp_port_open() {
    # Usage: tcp_port_open <host> <port> <timeout_seconds>
    local host="$1" port="$2" t="${3:-3}"
    local ncbin

    # Input validation (defense-in-depth against injection in /dev/tcp fallback).
    # Accept FQDN, short hostname, IPv4, and bare/bracketed IPv6.
    # This is an intentional security gate - do not remove.
    [[ -n "$host" ]] || return 1
    [[ "$host" =~ ^\[[0-9a-fA-F:.]+\]$ || "$host" =~ ^[A-Za-z0-9._:-]+$ ]] || return 1
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
    (( 10#$port >= 1 && 10#$port <= 65535 )) || return 1

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

    # Fallback: bash /dev/tcp. Variables passed as positional args (not interpolated
    # in command string) to prevent injection. Same pattern as flock in DC discovery.
    safe_timeout "$t" bash -c 'echo > "/dev/tcp/$1/$2"' _ "$host" "$port" >/dev/null 2>&1
}

# -------------------------------------------------------------------------
# OS metadata loader (os-release with legacy fallbacks)
# - Prefers /etc/os-release, then /usr/lib/os-release
# - Falls back to common legacy release files if os-release is missing
# -------------------------------------------------------------------------
load_os_release() {
    local f pretty ver _k _v

    for f in /etc/os-release /usr/lib/os-release; do
        [[ -r "$f" ]] || continue

        # Parse only well-formed KEY=VALUE lines (no code execution via source).
        # This is a defense-in-depth measure against a compromised os-release file.
        while IFS='=' read -r _k _v; do
            # Accept only uppercase alphanumeric keys (standard os-release keys)
            [[ "$_k" =~ ^[A-Z0-9_]+$ ]] || continue
            # Reject keys that could overwrite critical shell/env variables
            # (defense-in-depth: os-release is root-owned, but protects against
            # corrupted images or supply-chain tampering)
            case "$_k" in
                PATH|HOME|SHELL|TERM|LANG|IFS|PWD|OLDPWD|RANDOM|SECONDS|\
                LINENO|EUID|UID|PPID|HOSTNAME|HOSTTYPE|MACHTYPE|OSTYPE|\
                SHELLOPTS|BASHOPTS|BASH|FUNCNAME|GROUPS|DIRSTACK)
                    continue ;;
                LC_*|BASH_*) continue ;;
            esac
            # Strip trailing CR (Windows line endings on some cloud images)
            _v="${_v%$'\r'}"
            # Strip surrounding quotes (single or double)
            _v="${_v#\"}"; _v="${_v%\"}"
            _v="${_v#\'}"; _v="${_v%\'}"
            printf -v "$_k" '%s' "$_v"
        done < <(grep -E '^[A-Z0-9_]+=.' "$f" 2>/dev/null || true)

        [[ -n "${ID:-}" ]] || log_error "OS release file loaded but ID is empty: $f" 1
        return 0
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
# Auto-discover the nearest Domain Controller via DNS SRV + ping latency
# -------------------------------------------------------------------------
# Uses the standard AD SRV record: _ldap._tcp.dc._msdcs.<domain>
# (same mechanism Windows uses for DC Locator).
# Discovery chain: dig → host → nslookup → adcli (fallback).
# When multiple DCs are found, pings all in parallel and picks the fastest.
# Prints the chosen DC FQDN to stdout. Returns 1 if discovery fails.
# -------------------------------------------------------------------------
discover_nearest_dc() {
    local domain="${1:?Usage: discover_nearest_dc <domain>}"
    local srv_record="_ldap._tcp.dc._msdcs.${domain,,}"
    local candidates="" dc_arr=() best=""

    # ── Discover candidates from DNS SRV ──
    if [[ -z "$candidates" ]] && command -v dig >/dev/null 2>&1; then
        candidates="$(dig +short +tcp SRV "$srv_record" 2>/dev/null \
            | awk '{gsub(/\.$/,"",$4); print $4}' \
            | awk '!seen[tolower($0)]++ {print}' \
            | tr '\n' ' ')" || true
    fi
    if [[ -z "$candidates" ]] && command -v host >/dev/null 2>&1; then
        candidates="$(host -t SRV "$srv_record" 2>/dev/null \
            | awk '/SRV/ {gsub(/\.$/,"",$NF); print $NF}' \
            | awk '!seen[tolower($0)]++ {print}' \
            | tr '\n' ' ')" || true
    fi
    if [[ -z "$candidates" ]] && command -v nslookup >/dev/null 2>&1; then
        candidates="$(nslookup -type=SRV "$srv_record" 2>/dev/null \
            | awk '/service =/ {gsub(/\.$/,"",$NF); print $NF}' \
            | awk '!seen[tolower($0)]++ {print}' \
            | tr '\n' ' ')" || true
    fi
    if [[ -z "$candidates" ]] && command -v adcli >/dev/null 2>&1; then
        candidates="$(adcli info "${domain,,}" 2>/dev/null \
            | awk -F' = ' '/^domain-controllers/ {print $2}')" || true
    fi

    candidates="$(trim_ws "${candidates:-}")"
    [[ -z "$candidates" ]] && return 1

    read -ra dc_arr <<< "$candidates"

    # ── Single DC - no ping needed ──
    if (( ${#dc_arr[@]} == 1 )); then
        echo "${dc_arr[0]}"
        return 0
    fi

    # ── Multiple DCs - parallel ping, pick lowest latency ──
    local ping_tmp _dc _dc_l _dc_ip _dc_avg _running=0
    ping_tmp="$(mktemp /tmp/.dc-ping.XXXXXX 2>/dev/null)" || {
        # mktemp failed - fall back to first candidate
        echo "${dc_arr[0]}"
        return 0
    }

    for _dc in "${dc_arr[@]}"; do
        (
            _dc_l="${_dc,,}"

            # Resolve: getent → host → dig
            _dc_ip=""
            if command -v getent >/dev/null 2>&1; then
                _dc_ip="$(getent hosts "$_dc" 2>/dev/null | awk '{print $1; exit}')" || true
            fi
            if [[ -z "$_dc_ip" ]] && command -v host >/dev/null 2>&1; then
                _dc_ip="$(host -t A "$_dc" 2>/dev/null | awk '/has address/ {print $4; exit}')" || true
            fi
            if [[ -z "$_dc_ip" ]] && command -v dig >/dev/null 2>&1; then
                _dc_ip="$(dig +short A "$_dc" 2>/dev/null | head -1)" || true
            fi
            [[ -z "$_dc_ip" ]] && return

            _dc_avg="$(ping -c 1 -W 1 -q "$_dc_ip" 2>/dev/null \
                | awk -F'/' '/^(rtt|round-trip)/ {printf "%.3f", $5}')" || true
            if [[ -n "$_dc_avg" && "$_dc_avg" != "0.000" ]]; then
                # Use flock for atomic append (prevents interleaved writes from parallel subshells).
                # Variables are passed as positional args to bash -c (not interpolated in the
                # command string) to prevent injection from crafted DNS hostnames.
                # This is an intentional security pattern - do not refactor to use inline expansion.
                if command -v flock >/dev/null 2>&1; then
                    flock "$ping_tmp" bash -c 'printf "%s\n" "$1" >> "$2"' _ "${_dc_avg}|${_dc_l}" "$ping_tmp"
                else
                    printf '%s\n' "${_dc_avg}|${_dc_l}" >> "$ping_tmp"
                fi
            fi
        ) &

        _running=$(( _running + 1 ))
        if (( _running >= 15 )); then
            wait
            _running=0
        fi
    done
    wait

    if [[ -s "$ping_tmp" ]]; then
        best="$(sort -t'|' -k1,1 -g "$ping_tmp" | head -1 | cut -d'|' -f2)"
    fi
    rm -f "$ping_tmp"

    if [[ -n "$best" ]]; then
        echo "$best"
        return 0
    fi

    # All pings failed - return first candidate
    echo "${dc_arr[0]}"
    return 0
}

# -------------------------------------------------------------------------
# OS detection
# -------------------------------------------------------------------------
load_os_release
case "$ID" in
    ubuntu|debian) OS_FAMILY=debian; PKG=apt; SSH_G=sudo; [[ "$ID" == "ubuntu" ]] && UBUNTU_MAJOR="$(get_major_version_id)" ;;
    rhel|rocky|almalinux|centos) OS_FAMILY=rhel; RHEL_MAJOR="$(get_major_version_id)"; PKG=$([[ "$RHEL_MAJOR" -lt 8 ]] && echo yum || echo dnf); SSH_G=wheel ;;
    oracle|ol) OS_FAMILY=rhel; RHEL_MAJOR="$(get_major_version_id)"; [[ "$RHEL_MAJOR" -eq 0 ]] && RHEL_MAJOR="$(grep -Eo '[0-9]+' /etc/oracle-release 2>/dev/null | head -n1 || echo 0)"; PKG=$([[ "$RHEL_MAJOR" -lt 8 ]] && echo yum || echo dnf); SSH_G=wheel ;;
    sles|suse|opensuse-leap|opensuse|opensuse-tumbleweed) OS_FAMILY=suse; PKG=zypper; SSH_G=wheel ;;
    fedora) OS_FAMILY=rhel; PKG=dnf; SSH_G=wheel ;;
    amzn) OS_FAMILY=rhel; PKG=dnf; SSH_G=wheel ;;
    *) log_error "Unsupported distro: $ID. You may need to extend the detection logic." 101 ;;
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
            cmd_must "$PKG" install ${extra_flags[@]+"${extra_flags[@]}"} -y "${to_install[@]}"
            ;;
        zypper)
            cmd_must "$PKG" install -n "${to_install[@]}"
            ;;
        *)
            log_error "Unsupported package manager: $PKG" 101
            ;;
    esac
}

# Best-effort: detect current computer OU/container in AD.
# - First tries existing user Kerberos cache (GSSAPI).
# - If running as root, falls back to machine keytab (COMPUTER$@REALM).
# Outputs: OU DN on stdout; returns 0 on success, 1 on failure.
detect_current_computer_ou() {
    local dc host_u host_u_esc realm filter out ou ccache princ

    # Need ldapsearch + a DC + base DN
    command -v ldapsearch >/dev/null 2>&1 || return 1
    [[ -n "${DC_SERVER:-}" && -n "${DOMAIN_DN:-}" && -n "${DOMAIN:-}" ]] || return 1

    dc="$DC_SERVER"

    # GSSAPI with LDAP over IP is unreliable (SPN). If DC is an IP, resolve to a hostname.
    if [[ "$dc" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        dc="$(getent hosts "$dc" 2>/dev/null | awk '{print $2; exit}')"
        [[ -n "$dc" ]] || return 1
    fi

    host_u="$(hostname -s 2>/dev/null | tr '[:lower:]' '[:upper:]')"
    [[ -n "$host_u" ]] || return 1
    filter="(sAMAccountName=${host_u}\$)"

    # 1) Try with existing Kerberos creds (user cache)
    out="$(
        set +e +o pipefail
        safe_timeout "$LDAP_TIMEOUT" ldapsearch -LLL -Y GSSAPI -o ldif-wrap=no \
            -H "ldap://${dc}" -b "$DOMAIN_DN" "$filter" distinguishedName 2>/dev/null
    )" || true

    ou="$(printf '%s\n' "$out" | sed -n 's/^distinguishedName: CN=[^,]*,//p' | head -n1)"
    if [[ -n "$ou" ]] && validate_ldap_dn "$ou"; then
        printf '%s\n' "$ou"
        return 0
    fi

    # 2) Root fallback: use machine keytab (prefer COMPUTER$@REALM)
    [[ $EUID -eq 0 && -r /etc/krb5.keytab ]] || return 1
    command -v kinit >/dev/null 2>&1 || return 1
    command -v klist >/dev/null 2>&1 || return 1

    realm="$(printf '%s' "$DOMAIN" | tr '[:lower:]' '[:upper:]')"
    princ="$(klist -k /etc/krb5.keytab 2>/dev/null | awk 'NR>3{print $2}' | sort -u | grep -F "${host_u}\$@${realm}" | head -n1)"
    [[ -n "$princ" ]] || princ="$(klist -k /etc/krb5.keytab 2>/dev/null | awk 'NR>3{print $2}' | sort -u | grep -F "\$@${realm}" | head -n1)"
    [[ -n "$princ" ]] || return 1

    ccache="/tmp/krb5cc_ou_detect.$$"
    if ! KRB5CCNAME="$ccache" safe_timeout "${TRUST_TIMEOUT:-15}s" kinit -k -t /etc/krb5.keytab "$princ" >/dev/null 2>&1; then
        rm -f "$ccache" 2>/dev/null || true
        return 1
    fi

    out="$(
        set +e +o pipefail
        KRB5CCNAME="$ccache" safe_timeout "$LDAP_TIMEOUT" ldapsearch -LLL -Y GSSAPI -o ldif-wrap=no \
            -H "ldap://${dc}" -b "$DOMAIN_DN" "$filter" distinguishedName 2>/dev/null
    )" || true

    KRB5CCNAME="$ccache" kdestroy -q >/dev/null 2>&1 || true
    rm -f "$ccache" 2>/dev/null || true

    ou="$(printf '%s\n' "$out" | sed -n 's/^distinguishedName: CN=[^,]*,//p' | head -n1)"
    if [[ -n "$ou" ]] && validate_ldap_dn "$ou"; then
        printf '%s\n' "$ou"
        return 0
    fi

    return 1
}

# -------------------------------------------------------------------------
# List required tools
# -------------------------------------------------------------------------
tools=( realm adcli kinit kdestroy systemctl sed grep tput hostname cp chmod tee ldapsearch ldapmodify chronyc host dig ip pgrep install )

# timedatectl is optional - script has chrony config fallback for NTP setup
command -v timedatectl >/dev/null 2>&1 && tools+=( timedatectl )

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

HAS_INTERNET=false
if (( ${#missing_pkgs[@]} > 0 )); then
    [[ ${#missing_cmds[@]} -gt 0 ]] && log_info "⚠ Missing tools (pre-install): ${missing_cmds[*]}"
    log_info "🧩 Missing packages: ${missing_pkgs[*]}"

    # -------------------------------------------------------------------------
    # [Self-Healing] Detect and repair RPM database corruption
    # (RHEL-like only - must run before attempting package install)
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
                    # (backup_file does not support directories - use cp -a directly)
                    if [[ -d /var/lib/rpm ]]; then
                        backup_path="/var/lib/rpm.bak.$(date +%F_%H-%M)"
                        cp -a /var/lib/rpm "$backup_path" 2>/dev/null || true
                        log_info "💾 Backup created at: $backup_path"
                    fi

                    # Ensure no package manager process is running before touching rpmdb locks
                    if pgrep -x yum >/dev/null 2>&1 || pgrep -x dnf >/dev/null 2>&1 || pgrep -x rpm >/dev/null 2>&1 || pgrep -x packagekitd >/dev/null 2>&1; then
                        log_error "RPM database repair aborted: a package manager process is running (yum/dnf/rpm/packagekitd). Stop it and retry." 1
                    fi

                    # Remove potential stale locks (Berkeley DB and stale rpm lock file).
                    # On RHEL 9+ (SQLite backend), __db.* files do not exist and this glob
                    # is a harmless no-op. No conditional logic needed - rm -f handles it.
                    rm -f /var/lib/rpm/__db.* 2>/dev/null
                    rm -f /var/lib/rpm/.rpm.lock 2>/dev/null

                    # Attempt rebuild
                    if safe_timeout 300 rpm --rebuilddb &>/dev/null; then
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
    # Internet connectivity check (only needed for package install)
    # -------------------------------------------------------------------------
    log_info "🌐 Checking Internet connectivity for package installation"
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
        if safe_timeout 3 getent hosts example.com >/dev/null 2>&1; then
            CONNECT_DETAILS+=( "✅ DNS resolution working (resolver: $DNS_SERVER)" )
        else
            CONNECT_DETAILS+=( "⚠️ DNS resolution failed using $DNS_SERVER" )
        fi
    fi

    # Test outbound reachability (generic TCP probe)
    # Variables passed as positional args to prevent injection if NET_TEST_HOSTS
    # is ever made configurable. Same pattern as tcp_port_open().
    NET_TEST_HOSTS=( "1.1.1.1" "8.8.8.8" "9.9.9.9" )
    NET_OK=false
    for H in "${NET_TEST_HOSTS[@]}"; do
        if safe_timeout 2 bash -c 'echo > "/dev/tcp/$1/443"' _ "$H" 2>/dev/null; then
            CONNECT_DETAILS+=( "✅ TCP/443 reachable (host $H)" )
            NET_OK=true
            break
        elif safe_timeout 2 bash -c 'echo > "/dev/tcp/$1/80"' _ "$H" 2>/dev/null; then
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
        line_sanitized="$(sanitize_log_msg <<< "$line")"
        line_colored="$(colorize_tag "$line_sanitized")"
        log_info "   ${line_colored}"
    done

    # Fail fast with documented exit code when offline and packages are needed.
    # NOTE: In VALIDATE_ONLY mode we must not fail with "cannot install" semantics,
    # because installation is intentionally suppressed.
    if [[ "$HAS_INTERNET" == "false" && "$NET_OK" == "false" ]]; then
        if $VALIDATE_ONLY; then
            log_info "⚠ VALIDATE-ONLY: system appears offline; package installation is suppressed. Missing packages: ${missing_pkgs[*]}"
        else
            log_error "Missing packages (${missing_pkgs[*]}) and system is offline - cannot install" 100
        fi
    fi

    # -------------------------------------------------------------------------
    # Install missing packages
    # -------------------------------------------------------------------------
    install_missing_deps "${missing_pkgs[@]}"

    # -------------------------------------------------------------------------
    # Post-install: validate that required commands are now available
    # -------------------------------------------------------------------------
    for cmd in realm adcli kinit kdestroy systemctl \
               sed grep tput hostname cp chmod tee \
               ldapsearch ldapmodify chronyc; do
        check_cmd "$cmd"
    done

    $HAS_TIMEOUT || log_info "ℹ timeout not available - commands will run without hang protection"

    # timedatectl: optional post-install (chrony config fallback exists for NTP setup)
    command -v timedatectl >/dev/null 2>&1 || log_info "ℹ timedatectl not found - NTP will be configured via chrony config only"

    case "$OS_FAMILY" in
        debian) check_cmd pam-auth-update ;;
        rhel)
            if (( RHEL_MAJOR < 8 )); then
                check_cmd authconfig
            else
                check_cmd authselect
            fi
            ;;
        suse) check_cmd pam-config ;;
    esac
else
    log_info "✅ All required packages and tools are present - skipping connectivity check"
fi

# -------------------------------------------------------------------------
# Collect domain join inputs
# -------------------------------------------------------------------------
if $NONINTERACTIVE; then
    : "${DOMAIN:?DOMAIN required}"
    : "${OU:?OU required}"

    # Validate core identity inputs early (fail fast before network operations).
    # These checks mirror the interactive flow validations.
    validate_domain_name "$DOMAIN" || log_error "Invalid DOMAIN format: $DOMAIN" 1
    validate_ldap_dn "$OU"         || log_error "Invalid OU DN format: $OU" 1

    # DC_SERVER: auto-discover nearest if not provided
    if [[ -z "${DC_SERVER:-}" ]]; then
        log_info "🔍 DC_SERVER not set - running auto-discovery..."
        DC_SERVER="$(discover_nearest_dc "$DOMAIN")" || true
        if [[ -n "$DC_SERVER" ]]; then
            log_info "✅ DC auto-discovered: ${DC_SERVER}"
        else
            log_error "DC_SERVER required (auto-discovery failed - pass DC_SERVER explicitly)" 1
        fi
    fi
    : "${NTP_SERVER:=ntp.${DOMAIN,,}}"
    : "${DOMAIN_USER:?DOMAIN_USER required}"

    # Credential resolution: DOMAIN_PASS_FILE takes precedence over DOMAIN_PASS
    # when both are set (file-based is safer; env-based persists in /proc/<pid>/environ).
    if [[ -z "${DOMAIN_PASS:-}" && -n "${DOMAIN_PASS_FILE:-}" ]]; then
        [[ -f "$DOMAIN_PASS_FILE" ]] || log_error "DOMAIN_PASS_FILE not found: $DOMAIN_PASS_FILE" 1
        [[ -r "$DOMAIN_PASS_FILE" ]] || log_error "DOMAIN_PASS_FILE not readable: $DOMAIN_PASS_FILE" 1

        # Reject group/other-readable files (defense-in-depth)
        if command -v stat >/dev/null 2>&1; then
            _pass_perms="$(stat -c '%a' "$DOMAIN_PASS_FILE" 2>/dev/null || true)"
            if [[ "$_pass_perms" =~ ^[0-9]{3,4}$ ]]; then
                if (( (8#${_pass_perms} & 8#077) != 0 )); then
                    log_error "DOMAIN_PASS_FILE permissions too open (${_pass_perms}, expected 0400/0600): $DOMAIN_PASS_FILE" 1
                fi
            fi
        fi

        # Read only the first line; secrets managers (Vault, K8s) almost always append a trailing newline.
        # Using 'read -r' strips it naturally without a subshell.
        IFS= read -r DOMAIN_PASS < "$DOMAIN_PASS_FILE" \
            || log_error "DOMAIN_PASS_FILE is empty or unreadable: $DOMAIN_PASS_FILE" 1

        # Strip trailing CR (Windows line endings).
        DOMAIN_PASS="${DOMAIN_PASS%$'\r'}"

        [[ -n "$DOMAIN_PASS" ]] || log_error "DOMAIN_PASS_FILE resolved to empty string: $DOMAIN_PASS_FILE" 1

        log_info "🔐 Password loaded from file: $DOMAIN_PASS_FILE"
    fi
    : "${DOMAIN_PASS:?DOMAIN_PASS or DOMAIN_PASS_FILE required}"

    : "${SESSION_TIMEOUT_SECONDS:?SESSION_TIMEOUT_SECONDS required (seconds)}"
    : "${PERMIT_ROOT_LOGIN:?PERMIT_ROOT_LOGIN required (yes|no)}"

    # Validate endpoint and user inputs (prevents late failures in kinit/ldapmodify)
    validate_host_or_ip "$DC_SERVER"  || log_error "Invalid DC_SERVER value: $DC_SERVER" 1
    validate_host_or_ip "$NTP_SERVER" || log_error "Invalid NTP_SERVER value: $NTP_SERVER" 1
    validate_username "$DOMAIN_USER"  || log_error "Invalid DOMAIN_USER format: $DOMAIN_USER" 1

    # Administrative groups (optional with smart defaults)
    HOST_L="${HOSTNAME_SHORT,,}"
    ADM="${ADM_GROUP:-grp-adm-$HOST_L}"
    ADM_ALL="${ADM_GROUP_ALL:-grp-adm-all-linux-servers}"
    GRP_SSH="${SSH_GROUP:-grp-ssh-$HOST_L}"
    GRP_SSH_ALL="${SSH_GROUP_ALL:-grp-ssh-all-linux-servers}"
    SEC="${SEC_GROUP:-grp-sec-$HOST_L}"
    SEC_ALL="${SEC_GROUP_ALL:-grp-sec-all-linux-servers}"
    SUPER="${SUPER_GROUP:-grp-super-$HOST_L}"
    SUPER_ALL="${SUPER_GROUP_ALL:-grp-super-all-linux-servers}"

    # Normalize and validate inputs
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

    # DC Server - auto-discover nearest via DNS SRV + ping latency
    log_info "🔍 Discovering nearest Domain Controller..."
    default_DC_SERVER="$(discover_nearest_dc "$DOMAIN")" || true

    if [[ -n "$default_DC_SERVER" ]]; then
        log_info "✅ Auto-detected Nearest DC"
    else
        # Fallback: static pattern if discovery failed
        default_DC_SERVER="${DOMAIN_SHORT,,}-ad01.${DOMAIN,,}"
        log_info "ℹ DNS SRV discovery unavailable - using fallback: ${default_DC_SERVER}"
    fi

    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} DC server ${C_DIM}[default: ${default_DC_SERVER}]${C_RESET}: " "$(date '+%F %T')"
        read -r DC_SERVER
        DC_SERVER="$(trim_ws "${DC_SERVER:-}")"
        DC_SERVER="${DC_SERVER:-$default_DC_SERVER}"
        if validate_host_or_ip "$DC_SERVER" && [[ "$DC_SERVER" == *.* ]]; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid DC server. Use FQDN (e.g., dc01.domain.com) or IP.\n" "$(date '+%F %T')"
    done

    # OU (optional, default filled)
    DOMAIN_DN=$(awk -F'.' '{
		for (i = 1; i <= NF; i++) printf "%sDC=%s", (i>1?",":""), toupper($i)
	}' <<< "$DOMAIN")

    default_OU="CN=Computers,${DOMAIN_DN}"

    # Best-effort: auto-detect existing computer OU/container (rejoin UX).
    # Uses current user Kerberos cache first; if running as root, falls back to machine keytab.
    if detected_ou="$(detect_current_computer_ou)"; then
        default_OU="$detected_ou"
        log_info "✅ Auto-detected current computer OU/container"
    fi
    unset detected_ou

    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} OU ${C_DIM}[default: ${default_OU}]${C_RESET}: " "$(date '+%F %T')"
        read -r OU
        OU="$(trim_ws "${OU:-}")"
        OU="${OU:-$default_OU}"
        if validate_ldap_dn "$OU"; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid OU format. Expected: OU=Name,DC=domain,DC=tld\n" "$(date '+%F %T')"
    done

	# NTP Server (optional, default filled)
    default_NTP_SERVER="ntp.${DOMAIN,,}"
    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} NTP server ${C_DIM}[default: ${default_NTP_SERVER}]${C_RESET}: " "$(date '+%F %T')"
        read -r NTP_SERVER
        NTP_SERVER="$(trim_ws "${NTP_SERVER:-}")"
        NTP_SERVER="${NTP_SERVER:-$default_NTP_SERVER}"
        # Require FQDN or IP (short hostnames may not resolve without search domain)
        if validate_host_or_ip "$NTP_SERVER" && [[ "$NTP_SERVER" == *.* ]]; then
            break
        fi
        printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid NTP server. Use FQDN (e.g., ntp.domain.com) or IP.\n" "$(date '+%F %T')"
    done

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

    # Session timeout (SSH + Shell) in seconds
    default_SESSION_TIMEOUT_SECONDS=900
    while true; do
        printf "${C_DIM}[%s]${C_RESET} ${C_YELLOW}[?]${C_RESET} Session timeout in seconds (SSH + shell) ${C_DIM}[default: ${default_SESSION_TIMEOUT_SECONDS}]${C_RESET}: " "$(date '+%F %T')"
        read -r SESSION_TIMEOUT_SECONDS
        SESSION_TIMEOUT_SECONDS="$(trim_ws "${SESSION_TIMEOUT_SECONDS:-$default_SESSION_TIMEOUT_SECONDS}")"

        if is_uint "$SESSION_TIMEOUT_SECONDS" && (( 10#$SESSION_TIMEOUT_SECONDS >= 30 && 10#$SESSION_TIMEOUT_SECONDS <= 86400 )); then
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
    HOST_L="${HOSTNAME_SHORT,,}"

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

# Prepare environment
DOMAIN_LOWER="${DOMAIN,,}"
DOMAIN_UPPER="${DOMAIN^^}"
REALM=${DOMAIN^^}
HOST_FQDN="${HOSTNAME_SHORT}.${DOMAIN_LOWER}"
DC_SERVER_INPUT="$DC_SERVER"
LDAP_SERVER="$DC_SERVER_INPUT"

# Hostname format for Kerberos (uppercase short name)
HOST_SHORT="$HOSTNAME_SHORT"
HOST_SHORT_U=$(echo "$HOST_SHORT" | tr '[:lower:]' '[:upper:]')

# Escaped version for LDAP filter injection protection (RFC 4515)
HOST_SHORT_U_ESCAPED=$(ldap_escape_filter "$HOST_SHORT_U")

MACHINE_PRINCIPAL="${HOST_SHORT_U}\$@${REALM}"

# All LDAP operations in this script use GSSAPI authentication (-Y GSSAPI).
# GSSAPI provides its own encryption layer (Sign&Seal, SSF:256), making LDAPS
# redundant and potentially incompatible (known channel binding conflicts with
# GSSAPI over LDAPS on many AD/OpenLDAP configurations).
#
# Transport selection:
#   1. Always use ldap:// (TCP/389) for GSSAPI operations
#   2. GSSAPI Sign&Seal provides encryption + integrity (equivalent to TLS)
#   3. Optionally layer STARTTLS for defense-in-depth (if available)
LDAP_URI="ldap://${LDAP_SERVER}"
LDAP_TLS_FLAG=""

# Check LDAPS availability (informational - not used with GSSAPI)
if tcp_port_open "$LDAP_SERVER" 636 3; then
    log_info "ℹ LDAPS (TCP/636) available but not used - GSSAPI Sign&Seal provides encryption (SSF:256)"
fi

# Attempt STARTTLS as optional defense-in-depth layer on top of GSSAPI
if safe_timeout 5 ldapsearch -x -H "$LDAP_URI" -ZZ -b "" -s base namingContexts >/dev/null 2>&1; then
    LDAP_TLS_FLAG="-ZZ"
    log_info "✅ LDAP STARTTLS available - layered on top of GSSAPI for defense-in-depth"
else
    log_info "✅ Using GSSAPI Sign&Seal encryption (SSF:256) - transport is secure"
fi

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
# Resolve DC to IPv4 for source-IP detection. May fail if DC has no A record
# or if getent is unavailable - handled by fallback strategies below.
DC_V4="$(getent ahostsv4 "$DC_SERVER" 2>/dev/null | awk 'NR==1{print $1; exit}')" || true

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
        PRIMARY_IFACE="$(ip -o -4 addr show scope global 2>/dev/null | awk -v skip="$SKIP_IFACES" '$2 !~ skip {print $2; exit}')"
        PRIMARY_IP="$(ip -o -4 addr show scope global 2>/dev/null | awk -v skip="$SKIP_IFACES" '$2 !~ skip {print $4; exit}' | cut -d/ -f1)"
    fi
fi

# Strategy 3: ifconfig fallback (legacy systems: RHEL 6, Ubuntu 14.04, Debian 7)
if [[ -z "$PRIMARY_IP" ]] && command -v ifconfig >/dev/null 2>&1; then
    PRIMARY_IP="$(ifconfig 2>/dev/null | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | awk '{print $2}' | sed 's/addr://g' | head -n1 || true)"
fi

[[ -z "$PRIMARY_IP" ]] && log_error "Unable to detect primary IP address (no active NIC found)" 15

# Escape PRIMARY_IP for regex-safe matching (consistent with HOST_FQDN_RE pattern)
PRIMARY_IP_RE="$(regex_escape_ere "$PRIMARY_IP")"

$VERBOSE && log_info "ℹ Primary IP selected: ${PRIMARY_IP} (iface: ${PRIMARY_IFACE:-unknown})"

# Detect socket listing tool (array to avoid word-splitting, consistent with script patterns)
NETSTAT_CMD=()
if command -v ss >/dev/null 2>&1; then
    NETSTAT_CMD=( ss -tulpen )
elif command -v netstat >/dev/null 2>&1; then
    NETSTAT_CMD=( netstat -tulpen )
fi

# Check for active web services (port 80 or 443)
if (( ${#NETSTAT_CMD[@]} > 0 )) && "${NETSTAT_CMD[@]}" 2>/dev/null | grep -qE ':(80|443)\b'; then
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
if ! grep -qE '^[[:space:]]*::1[[:space:]]+localhost' "$HOSTS_FILE"; then
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

# Restore SELinux context after sed -i modifications (sed creates new inode)
selinux_restore "$HOSTS_FILE"

# Final validation (HOST_FQDN_RE: dots and other ERE metachars escaped for exact match)
HOST_FQDN_RE="$(regex_escape_ere "$HOST_FQDN")"
if $DRY_RUN || $VALIDATE_ONLY; then
    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Skipping /etc/hosts validation because no changes were applied."
    else
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Skipping /etc/hosts validation because no changes were applied."
    fi
elif ! grep -qE "^[[:space:]]*${PRIMARY_IP_RE}[[:space:]]+${HOST_FQDN_RE}" "$HOSTS_FILE"; then
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
if [[ -z "$DC_DNS_IP" ]]; then
    DC_DNS_IP="$(getent ahostsv4 "$DC_SERVER" 2>/dev/null | awk 'NR==1{print $1; exit}')" || true
fi

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
                _nm_ok=true

                # Get current DNS to prepend DC (avoid overwriting all DNS)
                _current_dns="$(nmcli -g ipv4.dns con show "$_nm_conn" 2>/dev/null | tr ',' ' ')"
                _current_dns="$(trim_ws "$_current_dns")"
                if [[ "$_current_dns" != *"$DC_DNS_IP"* ]]; then
                    _new_dns="$DC_DNS_IP"
                    [[ -n "$_current_dns" ]] && _new_dns="$DC_DNS_IP $_current_dns"
                    nmcli con mod "$_nm_conn" ipv4.dns "$_new_dns" 2>/dev/null || _nm_ok=false
                fi
                # Add search domain
                _current_search="$(nmcli -g ipv4.dns-search con show "$_nm_conn" 2>/dev/null | tr ',' ' ')"
                _current_search="$(trim_ws "$_current_search")"
                if [[ "$_current_search" != *"$DOMAIN"* ]]; then
                    _new_search="$DOMAIN"
                    [[ -n "$_current_search" ]] && _new_search="$DOMAIN $_current_search"
                    nmcli con mod "$_nm_conn" ipv4.dns-search "$_new_search" 2>/dev/null || _nm_ok=false
                fi
                # Prevent DHCP from overwriting AD DNS (required for stable Kerberos/LDAP resolution).
                # If DC IP changes (DR scenario), re-run this script or update via nmcli manually.
                # NOTE: This is intentional for domain-joined servers. Laptops or dynamic
                # environments should use a separate enrollment workflow.
                nmcli con mod "$_nm_conn" ipv4.ignore-auto-dns yes 2>/dev/null || _nm_ok=false
                log_info "ℹ DHCP DNS disabled on '$_nm_conn' to enforce AD DNS consistency"
                # Apply changes (suppress stdout to keep log clean)
                nmcli con up "$_nm_conn" >/dev/null 2>&1 || _nm_ok=false

                _applied_dns="$(nmcli -g ipv4.dns con show "$_nm_conn" 2>/dev/null | tr ',' ' ')"
                _applied_dns="$(trim_ws "$_applied_dns")"
                _applied_search="$(nmcli -g ipv4.dns-search con show "$_nm_conn" 2>/dev/null | tr ',' ' ')"
                _applied_search="$(trim_ws "$_applied_search")"

                if $_nm_ok && [[ " $_applied_dns " == *" $DC_DNS_IP "* ]] && [[ " $_applied_search " == *" $DOMAIN "* ]]; then
                    log_info "✅ DNS configured via NetworkManager (connection: $_nm_conn)"
                    _dns_configured=true
                else
                    log_info "⚠ NetworkManager DNS configuration could not be verified; will try next method"
                fi
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
                _res_ok=true
                resolvectl dns "$_resolve_iface" "$DC_DNS_IP" 2>/dev/null || _res_ok=false
                resolvectl domain "$_resolve_iface" "$DOMAIN" 2>/dev/null || _res_ok=false

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
                    if systemctl restart systemd-resolved 2>/dev/null; then
                        log_info "✅ DNS persisted via ${_resolved_dropin}/99-ad-domain.conf"
                    else
                        log_info "⚠ Failed to restart systemd-resolved after writing ${_resolved_dropin}/99-ad-domain.conf"
                    fi
                fi

                _applied_dns="$(resolvectl dns "$_resolve_iface" 2>/dev/null || true)"
                _applied_domain="$(resolvectl domain "$_resolve_iface" 2>/dev/null || true)"

                if $_res_ok && [[ "$_applied_dns" == *"$DC_DNS_IP"* ]] && [[ "$_applied_domain" == *"$DOMAIN"* ]]; then
                    log_info "✅ DNS configured via systemd-resolved (interface: $_resolve_iface)"
                    _dns_configured=true
                else
                    log_info "⚠ systemd-resolved DNS configuration could not be verified; will try next method"
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
            if netplan apply 2>/dev/null; then
                log_info "✅ DNS configured via Netplan ($_netplan_dropin)"
                _dns_configured=true
            else
                log_info "⚠ netplan apply failed - manual review recommended"
                log_info "⚠ Netplan DNS configuration not applied; will try next method"
            fi
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
            # Refuse to replace symlinked resolv.conf (systemd-resolved, NetworkManager, netplan).
            # In these cases, persistence must be configured via the owning subsystem.
            if [[ -L "$RESOLV_CONF" ]]; then
                log_info "⚠ $RESOLV_CONF is a symlink; refusing fallback replacement. Configure DNS via resolved/NM/netplan/dhclient."
                _dns_configured=false
            else
                _file_ensure_mutable "$RESOLV_CONF"

                # Backup current resolv.conf
                backup_file "$RESOLV_CONF"

                # Check if already configured
                if grep -qE "^nameserver[[:space:]]+${DC_DNS_IP//./\\.}([[:space:]]|$)" "$RESOLV_CONF" 2>/dev/null; then
                    log_info "✅ DNS already configured in $RESOLV_CONF"
                else
                    # Build a new resolv.conf preserving key directives (options/search) and existing resolvers.
                    _tmp_resolv="$(safe_mktemp)"

                    {
                        echo "# Managed by linux-ad-domain-join.sh"

                        # Preserve resolver directives that impact behavior (best-effort).
                        grep -E '^(options|sortlist|rotate)[[:space:]]' "$RESOLV_CONF" 2>/dev/null || true

                        # Preserve existing search/domain tokens, but ensure $DOMAIN is present first.
                        _search_line="$(grep -E '^(search|domain)[[:space:]]+' "$RESOLV_CONF" 2>/dev/null | head -n1 || true)"
                        _search_domains=""
                        if [[ -n "$_search_line" ]]; then
                            _search_domains="$(printf '%s\n' "$_search_line" | awk '{$1=""; sub(/^[[:space:]]+/, ""); print}')"
                        fi

                        _final_search="$DOMAIN"
                        for _d in $_search_domains; do
                            [[ "$_d" == "$DOMAIN" ]] && continue
                            _final_search+=" $_d"
                        done
                        echo "search $_final_search"

                        # Nameservers: put AD DNS first, then keep up to 2 additional distinct resolvers.
                        echo "nameserver $DC_DNS_IP"
                        _ns_kept=1
                        while read -r _ns; do
                            [[ -n "$_ns" ]] || continue
                            [[ "$_ns" == "$DC_DNS_IP" ]] && continue
                            echo "nameserver $_ns"
                            _ns_kept=$(( _ns_kept + 1 ))
                            (( _ns_kept >= 3 )) && break
                        done < <(grep -E '^nameserver[[:space:]]+' "$RESOLV_CONF" 2>/dev/null | awk '{print $2}' | awk '!seen[$0]++ {print}')
                    } >"$_tmp_resolv"

                    # Atomic rename preferred; fall back to copy for cross-filesystem targets
                    if ! mv -f "$_tmp_resolv" "$RESOLV_CONF" 2>/dev/null; then
                        cp -f "$_tmp_resolv" "$RESOLV_CONF" || log_error "Failed to update $RESOLV_CONF" 1
                        rm -f "$_tmp_resolv"
                    fi

                    selinux_restore "$RESOLV_CONF"
                    log_info "✅ DNS configured in $RESOLV_CONF (preserved options/search/nameservers)"
                fi

                _file_restore_attr "$RESOLV_CONF"
                _dns_configured=true
            fi
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

# Test DNS resolution (fallback chain: getent > host > nslookup)
# getent uses NSS (always available), host/nslookup need bind-utils/dnsutils
if command -v getent >/dev/null 2>&1; then
    getent ahosts "$DC_SERVER" >/dev/null 2>&1 || \
        log_error "Unable to resolve domain controller: $DC_SERVER (check DNS configuration)" 10
elif command -v host >/dev/null 2>&1; then
    host "$DC_SERVER" >/dev/null 2>&1 || \
        log_error "Unable to resolve domain controller: $DC_SERVER (check DNS configuration)" 10
elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$DC_SERVER" >/dev/null 2>&1 || \
        log_error "Unable to resolve domain controller: $DC_SERVER (check DNS configuration)" 10
else
    log_info "⚠ No DNS resolver tool available (getent/host/nslookup) - skipping DNS pre-check"
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
    _ntp_out="$(safe_timeout 10 ntpdate -q "$NTP_SERVER" 2>/dev/null || true)"
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
    # Protect pipeline with || true to handle empty/missing Date header
    _http_date="$(safe_timeout 5 curl -sI "http://${DC_SERVER}/" 2>/dev/null | awk -F': ' '/^[Dd]ate:/{print $2}' | tr -d '\r' || true)"
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
    if $VALIDATE_ONLY; then
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Password file creation suppressed (credential validation skipped)"
        return 0
    fi

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
        log_info "⚠️ WARNING: Password file will be created in /tmp (potentially disk-backed). Consider mounting tmpfs."
    fi

    # Create temp file with secure permissions (0600) atomically via umask
    # No separate chmod needed - umask 077 ensures correct permissions at creation
    # Use safe_mktemp for consistent error handling and logging
    PASS_FILE="$(safe_mktemp "${base}/.adjoin.pass.XXXXXX")" || log_error "Failed to create temporary password file" 1

    if [[ -z "${DOMAIN_PASS:-}" ]]; then
        log_error "DOMAIN_PASS is empty; cannot proceed with credential-based operations." 1
    fi

    # Store password WITHOUT trailing newline (printf '%s', not echo).
    #
    # Why no newline:
    #   - Some consumers interpret the trailing newline differently; keep the secret unambiguous.
    if [[ "${DOMAIN_PASS:-}" == *$'\n'* || "${DOMAIN_PASS:-}" == *$'\r'* ]]; then
        log_error "DOMAIN_PASS contains newline/CR characters; refusing to avoid ambiguous stdin/file parsing." 1
    fi

    printf '%s' "$DOMAIN_PASS" > "$PASS_FILE" || log_error "Failed to write temporary password file" 1

    # Remove from memory ASAP
    unset DOMAIN_PASS

    if $DRY_RUN; then
        # In DRY_RUN, we still materialize PASS_FILE so read-only auth checks (e.g., kinit) can run deterministically.
        # The file must be removed by the script's global cleanup/EXIT trap.
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Password file materialized for deterministic read-only checks (will be deleted by cleanup)"
    fi
}

cleanup_secrets() {
    # Accept an explicit exit code when called outside the EXIT trap.
    # If not provided, fall back to the caller's $? (works for EXIT trap usage).
    local _exit_code="${1:-$?}"

    # Defensive: ensure numeric exit code.
    if [[ ! "$_exit_code" =~ ^[0-9]+$ ]]; then
        _exit_code=1
    fi

    # -------------------------------------------------------------------------
    # Deferred D-Bus restart (only on successful exit)
    # -------------------------------------------------------------------------
    # Dispatched FIRST in the EXIT trap, before file cleanup, because:
    #   1. All configs (sudoers, SSH, SSSD, PAM) are already committed at this point
    #   2. The detached process (nohup+setsid) survives the script exit
    #   3. Prevents session sluggishness observed on some distros when D-Bus
    #      is not restarted after oddjob registration changes
    #   4. Running in EXIT trap guarantees execution regardless of script flow
    #
    # Variables are passed via environment export (not interpolated in bash -c)
    # to prevent shell injection. This is an intentional security pattern.
    # -------------------------------------------------------------------------
    if (( _exit_code == 0 )) && \
       [[ "${_DBUS_RESTART_DEFERRED:-false}" == "true" && -n "${_DBUS_RESTART_UNIT:-}" ]]; then
        log_info "🔄 Executing deferred D-Bus remediation ($_DBUS_RESTART_UNIT)" 2>/dev/null || true

        # Determine if we're running over SSH (affects restart strategy).
        # Full D-Bus restart terminates systemd-logind, which drops SSH sessions.
        local _is_ssh=false
        [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_TTY:-}" ]] && _is_ssh=true

        # Export vars for the detached subshell. Single-quoted bash -c prevents
        # shell expansion (security: no interpolation of user-controlled data).
        #
        # Close the inherited lock FD (9) via redirection so the detached process
        # cannot keep the flock alive after the main script exits.
        _DBUS_UNIT_EXPORT="$_DBUS_RESTART_UNIT" \
        _IS_SSH="$_is_ssh" \
        nohup setsid bash -c '
            sleep 1

            # Restart helper with systemd + sysvinit fallbacks
            _restart_unit() {
                local unit="$1"
                local svc="${unit%.service}"

                if command -v systemctl >/dev/null 2>&1; then
                    systemctl restart "$unit" >/dev/null 2>&1 || true
                    return 0
                fi

                if command -v service >/dev/null 2>&1; then
                    service "$svc" restart >/dev/null 2>&1 || true
                    return 0
                fi

                if [[ -x "/etc/init.d/$svc" ]]; then
                    "/etc/init.d/$svc" restart >/dev/null 2>&1 || true
                fi
            }

            # --- Escalating D-Bus remediation strategy ---
            # Step 1: Try lightweight config reload (no process restart, no session impact)
            if command -v busctl >/dev/null 2>&1; then
                busctl call org.freedesktop.DBus / org.freedesktop.DBus ReloadConfig >/dev/null 2>&1 || true
            elif command -v dbus-send >/dev/null 2>&1; then
                dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
                    / org.freedesktop.DBus.ReloadConfig >/dev/null 2>&1 || true
            fi

            # Step 2: Restart oddjobd (safe, does not affect SSH sessions)
            _restart_unit "oddjobd"
            sleep 1

            # Step 3: Test if oddjobd is now responsive via D-Bus
            if dbus-send --system --dest=com.redhat.oddjob_mkhomedir --print-reply \
                / com.redhat.oddjob_mkhomedir.Hello >/dev/null 2>&1; then
                # Success - oddjobd operational, no full D-Bus restart needed
                exit 0
            fi

            # Step 4: Full D-Bus restart as last resort (only if NOT over SSH)
            if [[ "$_IS_SSH" == "true" ]]; then
                # Over SSH: full D-Bus restart would kill this session and all others.
                # Log recommendation and exit; admin should reboot at a planned window.
                logger -t linux-ad-domain-join \
                    "WARNING: oddjobd not responding after D-Bus reload. Running over SSH - skipping full D-Bus restart to preserve sessions. A planned reboot is recommended." \
                    2>/dev/null || true
                exit 0
            fi

            # Not SSH: safe to perform full restart (console/BMC/local session)
            _restart_unit "$_DBUS_UNIT_EXPORT"
            _restart_unit "oddjobd"
        ' 9>&- </dev/null >/dev/null 2>&1 &
        disown 2>/dev/null || true

        if $_is_ssh; then
            log_info "⚠️  D-Bus remediation dispatched (reload + oddjobd restart only - SSH session protected)" 2>/dev/null || true
            log_info "ℹ️  If oddjob issues persist, a planned reboot is recommended." 2>/dev/null || true
        else
            log_info "✅ D-Bus remediation dispatched (full restart if needed, will complete after script exit)" 2>/dev/null || true
        fi
    fi

    # Restore immutable bits on any files we unlocked
    _file_restore_all_attrs 2>/dev/null || true

    # Best-effort secure delete of password file
    secure_delete "${PASS_FILE:-}"

    # Cleanup intermediate temp files (best-effort, non-sensitive)
    for _tf in "${KRB_TRACE:-}" "${KRB_LOG:-}" "${JOIN_LOG:-}" "${TMP_LDIF:-}"; do
        [[ -n "$_tf" && -f "$_tf" ]] && rm -f "$_tf" 2>/dev/null || true
    done

    # Release mkdir-based lock (if flock is unavailable).
    # :? expansion is defense-in-depth - prevents rm -rf on empty string even if
    # the -n guard above is accidentally removed in future maintenance.
    if [[ "${LOCK_MODE:-}" == "mkdir" && -n "${LOCK_DIR_FALLBACK:-}" ]]; then
        rm -rf "${LOCK_DIR_FALLBACK:?}" 2>/dev/null || true
    fi

    unset PASS_FILE

    # Just in case someone reintroduced it
    unset DOMAIN_PASS
}

# Pre-declare temp file variables referenced by cleanup_secrets trap.
# Actual values are assigned later when the files are created.
KRB_TRACE="" KRB_LOG="" JOIN_LOG="" TMP_LDIF=""

# Deferred D-Bus restart flag (set during oddjob remediation, executed in cleanup_secrets EXIT trap)
_DBUS_RESTART_DEFERRED=false
_DBUS_RESTART_UNIT=""

# Deterministic signal handler: cleanup + exit with signal-appropriate code.
# Separating signal traps from EXIT ensures the script cannot continue
# execution after Ctrl+C or SIGTERM, regardless of where the signal lands.
terminate_on_signal() {
    local sig="${1:-TERM}"
    local rc=1

    case "$sig" in
        HUP)  rc=129 ;;
        INT)  rc=130 ;;
        TERM) rc=143 ;;
        *)    rc=1   ;;
    esac

    # Prevent recursive trap invocation
    trap - EXIT HUP INT TERM

    # Pass the intended exit code so cleanup logic can reliably detect abort vs success.
    cleanup_secrets "$rc"

    exit "$rc"
}

# Ensure cleanup_secrets can see the real exit status on normal script termination.
trap 'cleanup_secrets "$?"' EXIT
trap 'terminate_on_signal HUP'  HUP
trap 'terminate_on_signal INT'  INT
trap 'terminate_on_signal TERM' TERM

# Create secret file now (DOMAIN_PASS must exist at this moment)
create_secret_passfile

# -------------------------------------------------------------------------
# Kerberos credential validation (controlled error handling block)
# -------------------------------------------------------------------------
log_info "🔐 Verifying credentials for $DOMAIN_USER@$REALM"
KRB_TRACE=$(safe_mktemp)

if $VALIDATE_ONLY; then
    log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Kerberos credential validation suppressed (non-invasive mode)"
    log_info "✅ VALIDATE-ONLY: pre-checks completed successfully. Skipping domain join and all configuration writes."
    exit 0
fi

# Temporarily relax -e and disable ERR trap to classify kinit failures
trap - ERR
set +e

KRB5_TRACE="$KRB_TRACE" safe_timeout "${KINIT_TIMEOUT:-20}s" kinit "$DOMAIN_USER@$REALM" <"$PASS_FILE" >/dev/null 2>&1
KINIT_CODE=$?


# Restore strict mode (symmetric with set -Eeuo pipefail at script initialization)
set -Eeuo pipefail

# Restore ERR trap safely
trap "$ERROR_TRAP_CMD" ERR

# analyze both return code AND trace contents
if (( KINIT_CODE == 0 )) && ! grep -qiE 'CLIENT_LOCKED_OUT|revoked|disabled|locked out|denied|expired' "$KRB_TRACE"; then
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
        # Best-effort: do not let grep/sed failures abort the script in strict mode.
        _krb_last_msg="$(grep -E 'krb5|KRB5|error|revoked|denied' "$KRB_TRACE" 2>/dev/null \
            | tail -n 1 | sed $SED_EXT 's/[[:space:]]+/ /g' || true)"
        [[ -n "$_krb_last_msg" ]] && log_info "ℹ Last trace line: $_krb_last_msg"
        log_error "Kerberos authentication failed with unknown reason (exit $KINIT_CODE)" 14
    fi
fi
rm -f "$KRB_TRACE"

# -------------------------------------------------------------------------
# Convert DNS domain to LDAP DN: "example.com" -> "DC=EXAMPLE,DC=COM"
# NOTE: DOMAIN_DN may already be set from the interactive flow (line ~3043).
# Re-derive unconditionally to guarantee correctness in both code paths.
: "${DOMAIN_DN:=$(awk -F'.' '{
    for (i = 1; i <= NF; i++) printf "%sDC=%s", (i>1?",":""), toupper($i)
}' <<< "$DOMAIN")}"

BASE_DN="$DOMAIN_DN"

# Normalize and validate OU DN early (non-interactive path).
# This prevents confusing "OU not found" when the DN format is invalid.
OU="$(trim_ws "${OU:-}")"
if [[ -z "$OU" ]]; then
    log_info "⚠ OU not provided - using default Computers container"
    OU="CN=Computers,${DOMAIN_DN}"
elif ! validate_ldap_dn "$OU"; then
    log_info "⚠ Invalid OU DN format - using default Computers container"
    OU="CN=Computers,${DOMAIN_DN}"
elif [[ ! "$OU" =~ [Dd][Cc]= ]]; then
    log_info "⚠ OU missing DC= - using default Computers container"
    OU="CN=Computers,${DOMAIN_DN}"
fi

# -------------------------------------------------------------------------
# Validate OU existence (with fallback, simple bind)
# -------------------------------------------------------------------------
log_info "🔍 Checking OU: $OU"

LDAP_OUT="$(
    set +e +o pipefail
    safe_timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no \
        $LDAP_TLS_FLAG -H "$LDAP_URI" \
        -b "$OU" "(|(objectClass=organizationalUnit)(objectClass=container))" 2>&1
)" && LDAP_CODE=0 || LDAP_CODE=$?

if [[ $LDAP_CODE -ne 0 || -z "$LDAP_OUT" ]]; then
    log_info "⚠ OU not found - applying fallback"
    OU="CN=Computers,${DOMAIN_DN}"
    log_info "↪ Using fallback: $OU"

    # Test fallback OU also under safe mode
    LDAP_OUT="$(
        set +e +o pipefail
        safe_timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no \
            $LDAP_TLS_FLAG -H "$LDAP_URI" \
            -b "$OU" "(|(objectClass=organizationalUnit)(objectClass=container))" 2>&1
    )" && LDAP_CODE=0 || LDAP_CODE=$?

    [[ $LDAP_CODE -ne 0 || -z "$LDAP_OUT" ]] && log_error "Invalid OU and fallback missing - aborting" 4
fi

# checking existing realm
log_info "🧭 Verifying local realm join state"

# Snapshot once to avoid inconsistent DBus/realmd results across multiple calls
realm_list="$(safe_realm_list)"
domain_lc="${DOMAIN,,}"

# Exact-match realm detection (avoid regex false-positives; dots must be literal)
REALM_JOINED="$(
    printf '%s\n' "$realm_list" \
        | awk '/^[^ ]/ {print tolower($1)}' \
        | grep -Fx -- "$domain_lc" || true
)"

# -------------------------------------------------------------------------
# DOMAIN VALIDATION & REJOIN DECISION
# -------------------------------------------------------------------------
if [[ -n "$REALM_JOINED" ]]; then
    log_info "🔎 Realm configuration found for $DOMAIN (local state)"

    _kinit_ok=false
    safe_timeout "${TRUST_TIMEOUT:-15}s" kinit -kt "$KRB5_KEYTAB" "$MACHINE_PRINCIPAL" >/dev/null 2>&1 && _kinit_ok=true

    if $_kinit_ok; then
        kdestroy -q 2>/dev/null || true
        log_info "✅ Kerberos trust is intact (keytab is valid)"
        if ! $NONINTERACTIVE; then
            while true; do
                read_sanitized "⚠️ Joined locally with valid trust. Rejoin anyway? [y/N]: " REPLY
                case "${REPLY,,}" in
                    y|yes) break ;;
                    n|no|"") log_info "🚪 Exiting without rejoin"; exit 0 ;;
                    *) printf "${C_DIM}[%s]${C_RESET} ${C_RED}[!]${C_RESET} Invalid option. Type 'y' or 'n'.\n" "$(date '+%F %T')" ;;
                esac
            done
        else
            log_info "ℹ Non-interactive: proceeding with forced rejoin"
        fi
    else
        log_info "⚠️ Kerberos trust is broken (keytab test failed or timed out). Proceeding with rejoin and cleanup."
    fi

    # ---------------------------------------------------------------------
    # DOMAIN LEAVE & CLEANUP PHASE
    # ---------------------------------------------------------------------
    log_info "🚪 Preparing to leave existing domain configuration..."

    # Use fixed-string match for the domain name (avoid regex behavior)
    if printf '%s\n' "$realm_list" | grep -qiF -- "$DOMAIN"; then
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

    # Always perform residual cleanup, but preserve rollback material first.
    # If the subsequent join fails, the operator can restore from these backups.
    for _cleanup_rf in "$KRB5_KEYTAB" /etc/sssd/sssd.conf /etc/realmd.conf; do
        [[ -f "$_cleanup_rf" ]] && backup_file "$_cleanup_rf"
    done
    unset _cleanup_rf

    cmd_try rm -f "$KRB5_KEYTAB" /etc/sssd/sssd.conf /etc/realmd.conf
    log_info "🧹 Residual realm configuration cleaned."


else
    log_info "📛 Realm configuration not found. Host is not joined to $DOMAIN"
fi

unset realm_list domain_lc _kinit_ok

# -------------------------------------------------------------------------
# Ensure /etc/krb5.conf consistency with current domain parameters
# -------------------------------------------------------------------------
log_info "🔧 Ensuring /etc/krb5.conf consistency for realm $REALM"

KRB_CONF="/etc/krb5.conf"

# Backup existing krb5.conf if present
if [[ -f "$KRB_CONF" ]]; then
    backup_file "$KRB_CONF"
fi

# If DC_SERVER is not set, attempt SRV autodiscovery
if [[ -z "$DC_SERVER" ]]; then
    log_info "ℹ DC_SERVER variable empty - attempting autodiscovery via SRV records"
    DC_SERVER="$(discover_nearest_dc "$DOMAIN")" || true
    [[ -z "$DC_SERVER" ]] && log_error "Unable to autodiscover domain controller for $DOMAIN" 11
fi

# -------------------------------------------------------------------------
# Dynamic Kerberos configuration (krb5.conf) generation
# -------------------------------------------------------------------------
# Check for Kerberos SRV records using available DNS tools (dig > host > nslookup)
_krb_srv_found=false
if command -v dig >/dev/null 2>&1; then
    dig +short _kerberos._tcp."$DOMAIN" SRV 2>/dev/null | grep -qE '^[0-9]' && _krb_srv_found=true
elif command -v host >/dev/null 2>&1; then
    host -t SRV _kerberos._tcp."$DOMAIN" 2>/dev/null | grep -q 'SRV' && _krb_srv_found=true
elif command -v nslookup >/dev/null 2>&1; then
    nslookup -type=SRV _kerberos._tcp."$DOMAIN" 2>/dev/null | grep -q 'service' && _krb_srv_found=true
fi
if $_krb_srv_found; then
    log_info "🌐 SRV records found for $DOMAIN - enabling DNS-based KDC discovery"
    write_file 0644 "$KRB_CONF" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true
    rdns = false

[realms]
    $REALM = {
        default_domain = ${DOMAIN_LOWER}
    }

[domain_realm]
    .${DOMAIN_LOWER} = ${REALM}
    ${DOMAIN_LOWER} = ${REALM}
EOF
else
    log_info "⚠️ No SRV records found for $DOMAIN - using static KDC configuration ($DC_SERVER)"
    write_file 0644 "$KRB_CONF" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true
    rdns = false

[realms]
    $REALM = {
        kdc = $DC_SERVER
        admin_server = $DC_SERVER
        default_domain = ${DOMAIN_LOWER}
    }

[domain_realm]
    .${DOMAIN_LOWER} = ${REALM}
    ${DOMAIN_LOWER} = ${REALM}
EOF
fi

# Apply standard permissions
cmd_must chmod 644 "$KRB_CONF"
log_info "✅ /etc/krb5.conf regenerated for realm $REALM"

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
			cmd_must service_control oddjobd enable-now
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

    # Create or repair the D-Bus service activation file.
    # NOTE: This writes to /usr/share/dbus-1/ which is vendor-managed territory.
    # This is an intentional last-resort fallback - the file is only created when
    # missing (package corruption, minimal install). Future 'yum update oddjob' will
    # overwrite this with the official vendor version, which is the desired outcome.
    # Do not replace this with package reinstall logic - DNS/repos may be unavailable
    # at this point in the domain join process.
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
        # Detect the correct helper binary path (varies by RHEL version):
        #   RHEL 7:   /usr/sbin/oddjob-mkhomedir
        #   RHEL 8+:  /usr/libexec/oddjob/mkhomedir
        _oddjob_helper="/usr/sbin/oddjob-mkhomedir"
        if [[ -x /usr/libexec/oddjob/mkhomedir ]]; then
            _oddjob_helper="/usr/libexec/oddjob/mkhomedir"
        fi

        log_info "🔧 Restoring oddjob mkhomedir XML: $ODDJOB_XML (helper: $_oddjob_helper)"
        write_file 0644 "$ODDJOB_XML" <<EOF
<oddjobconfig version="1.0">
<service name="com.redhat.oddjob_mkhomedir">
    <object name="/">
    <interface name="com.redhat.oddjob_mkhomedir">
        <method name="CreateHome">
        <arg type="string" name="username"/>
        <arg type="string" name="homedir"/>
        <arg type="boolean" name="create_dir"/>
        <execute helper="$_oddjob_helper" user="root"/>
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
        selinux_restore -F "$DBUS_SVC" "$ODDJOB_XML"

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
    while [[ "$retry_count" -lt "$max_retries" ]]; do
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
            # Defer D-Bus restart to end of script (after all critical config is committed).
            # Restarting D-Bus mid-execution risks SSH session disruption on some distros,
            # and can cause latency/degradation if NOT restarted at all.
            # The deferred approach ensures the system is fully configured before any
            # session-impacting restart occurs.
            log_info "ℹ D-Bus restart required for oddjob - deferring to end of script"
            log_info "ℹ oddjob mkhomedir may not be fully operational until D-Bus is restarted"
            _DBUS_RESTART_DEFERRED=true
            _DBUS_RESTART_UNIT="$DBUS_SERVICE"

            if $VALIDATE_ONLY; then
                log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would defer restart of $DBUS_SERVICE to end of script"
                _DBUS_RESTART_DEFERRED=false
            elif $DRY_RUN; then
                log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would defer restart of $DBUS_SERVICE to end of script"
                _DBUS_RESTART_DEFERRED=false
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
# Defensive PAM check + minimal remediation (cross-distro)
# Notes:
# - This block MAY modify PAM files (with backup) to ensure pam_sss is active.
# - When inserting pam_sss lines, we place them BEFORE pam_deny/pam_permit to
#   avoid adding them after terminal rules where they become ineffective.
# -------------------------------------------------------------------------
log_info "🧩 Verifying PAM stack consistency (may apply minimal remediation)"

# Insert a PAM line before the first "terminal" rule for that context.
# This avoids appending after pam_deny/pam_permit where the line can be ineffective.
_pam_insert_before_terminal_rule() {
    local file="$1"
    local match_re="$2"
    local insert_line="$3"

    # DRY_RUN / VALIDATE_ONLY: report only
    if $DRY_RUN || $VALIDATE_ONLY; then
        log_info "🟡 Would insert into $(basename "$file") before terminal rule: $insert_line"
        return 0
    fi

    local tmp mode uid gid
    mode="$(stat -c '%a' "$file" 2>/dev/null || echo 644)"
    uid="$(stat -c '%u' "$file" 2>/dev/null || echo 0)"
    gid="$(stat -c '%g' "$file" 2>/dev/null || echo 0)"

    tmp="$(safe_mktemp "${file}.XXXXXX")" || log_error "Failed to create temp file for PAM edit: $file" 1

    awk -v re="$match_re" -v ins="$insert_line" '
        BEGIN { added=0 }
        {
            if (!added && $0 ~ re) {
                print ins
                added=1
            }
            print
        }
        END {
            if (!added) print ins
        }
    ' "$file" >"$tmp" || { rm -f "$tmp"; log_error "Failed to render updated PAM file: $file" 1; }

    chown "$uid:$gid" "$tmp" 2>/dev/null || true
    chmod "$mode" "$tmp" 2>/dev/null || true

    mv -f "$tmp" "$file" || { rm -f "$tmp"; log_error "Failed to update PAM file atomically: $file" 1; }
    selinux_restore "$file"
}

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
    if grep -Eq '^[^#]*pam_(ldap|winbind|nis)\.so' "$file"; then
        cmd_must sed -i \
            -e '/^[[:space:]]*#/!{/pam_ldap\.so/s/^/# disabled legacy -> /}' \
            -e '/^[[:space:]]*#/!{/pam_winbind\.so/s/^/# disabled legacy -> /}' \
            -e '/^[[:space:]]*#/!{/pam_nis\.so/s/^/# disabled legacy -> /}' \
            "$file"
    fi

    # Ensure pam_sss.so is present per PAM context.
    # Insert before terminal rules (pam_deny/pam_permit) for correctness.
    for context in auth account password session; do
        if ! grep -Eq "^[[:space:]]*${context}[[:space:]].*pam_sss\\.so" "$file"; then
            desired=""
            case "$context" in
                auth)     desired="auth        sufficient    pam_sss.so forward_pass" ;;
                account)  desired="account     [default=bad success=ok user_unknown=ignore] pam_sss.so" ;;
                password) desired="password    sufficient    pam_sss.so use_authtok" ;;
                session)  desired="session     optional      pam_sss.so" ;;
            esac

            # Match terminal rule for this context; if none exists, we append at EOF.
            _pam_insert_before_terminal_rule \
                "$file" \
                "^[[:space:]]*${context}[[:space:]].*pam_(deny|permit)\\.so" \
                "$desired"

            log_info "🧩 Ensured pam_sss.so for $context -> $(basename "$file")"
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

if (( ${#PAM_VALIDATE_FILES[@]} > 0 )) && grep -E "pam_sss\.so" "${PAM_VALIDATE_FILES[@]}" 2>/dev/null | grep -qv '^[[:space:]]*#'; then
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

    # Normalize whitespace (work file) - use cmd_must only on the real file
    if [[ "$NSS_EDIT" == "$NSS_FILE" ]]; then
        cmd_must sed -i 's/[[:space:]]\{2,\}/ /g; s/[[:space:]]\+$//' "$NSS_EDIT"
    else
        sed -i 's/[[:space:]]\{2,\}/ /g; s/[[:space:]]\+$//' "$NSS_EDIT" || { $VERBOSE && log_info "⚠ sed whitespace normalization failed on temp NSS file: $NSS_EDIT"; true; }
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
            sed $SED_EXT -i "s/[[:space:]]+(ldap|nis|yp)//g; s/[[:space:]]{2,}/ /g" "$NSS_EDIT" || { $VERBOSE && log_info "⚠ sed legacy NSS sources (ldap|nis|yp) cleanup failed on temp file: $NSS_EDIT"; true; }
            sed -i \
                -e "s/^\([[:space:]]*${key}:[^#]*\)\(#.*\)$/\1 sss \2/" \
                -e "s/^\([[:space:]]*${key}:[^#]*\)$/\1 sss/" "$NSS_EDIT" || { $VERBOSE && log_info "⚠ sed sss injection failed on temp NSS file: $NSS_EDIT"; true; }
            sed -i 's/sss[[:space:]]\+sss/sss/g; s/[[:space:]]\{2,\}/ /g' "$NSS_EDIT" || { $VERBOSE && log_info "⚠ sed deduplication failed on temp NSS file: $NSS_EDIT"; true; }
        fi
        log_info "✅ '${key}' updated"
    else
        printf '%s\n' "${key}: files sss" >>"$NSS_EDIT"
        log_info "➕ Created missing '${key}' entry"
    fi
done

# Final whitespace normalization (collapse multiple spaces, trim ends)
awk '{gsub(/[[:space:]]+/, " "); sub(/^ /, ""); sub(/ $/, "")}1' "$NSS_EDIT" > "${NSS_EDIT}.tmp" && mv "${NSS_EDIT}.tmp" "$NSS_EDIT"

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
    selinux_restore -F "$NSS_FILE"
fi

# Restore immutable bit if it was originally set
_file_restore_attr "$NSS_FILE"

# Optional runtime sanity checks (non-blocking)
if ! safe_timeout 5 getent passwd root >/dev/null 2>&1; then
    log_info "⚠ NSS passwd lookup failed or timed out - verify SSSD/NSCD/network"
fi
if ! safe_timeout 5 getent group root >/dev/null 2>&1; then
    log_info "⚠ NSS group lookup failed or timed out - verify SSSD/NSCD/network"
fi

# -------------------------------------------------------------------------
# Cache refresh (skip entirely in DRY-RUN)
# -------------------------------------------------------------------------
if $DRY_RUN || $VALIDATE_ONLY; then
    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would stop nslcd (if present), restart sssd/nscd, and flush sss_cache"
    else
        log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would stop nslcd (if present), restart sssd/nscd, and flush sss_cache"
    fi
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

# Cleanup temp work file (DRY-RUN / VALIDATE-ONLY)
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
            selinux_restore "$pamfile"
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

    # Keep temp files in the same filesystem as target to preserve atomic rename semantics.
    tmp_chrony="$(safe_mktemp "${chrony_conf}.XXXXXX")"
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
            if [[ "$line" =~ ^[[:space:]]*(server|pool|driftfile|makestep|rtcsync|logdir|sourcedir)([[:space:]]+|$) ]]; then
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
    tmp_chrony_norm="$(safe_mktemp "${chrony_conf}.norm.XXXXXX")"
    awk '
        BEGIN { blank=0 }
        /^[[:space:]]*$/ {
            blank++
            if (blank <= 1) print ""
            next
        }
        { blank=0; print }
    ' "$tmp_chrony" >"$tmp_chrony_norm"

    mv -f "$tmp_chrony_norm" "$tmp_chrony" || {
        rm -f "$tmp_chrony_norm" "$tmp_chrony"
        log_error "Failed to normalize temporary chrony configuration" 1
    }

    if $DRY_RUN || $VALIDATE_ONLY; then
        $DRY_RUN && log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would update $chrony_conf with embedded managed block (preview suppressed)"
        $VALIDATE_ONLY && log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would update $chrony_conf with embedded managed block (suppressed)"
        rm -f "$tmp_chrony"
    else
        chown root:root "$tmp_chrony" 2>/dev/null || true
        chmod 644 "$tmp_chrony" 2>/dev/null || true
        cmd_must mv -f "$tmp_chrony" "$chrony_conf"
        selinux_restore "$chrony_conf"
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
if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would stop/disable conflicting time services (systemd-timesyncd, ntpd, ntp)"
else
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
            cmd_try service ntpd stop || true
            cmd_try service ntp stop  || true
        fi
    fi
fi

# Enable + restart chrony (systemd/sysvinit) ----
log_info "🔧 Enabling and restarting Chrony service (${chrony_service})"

_chrony_running=false
if $VALIDATE_ONLY; then
    log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Suppressing service enable/restart for chrony"
elif $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would enable and restart ${chrony_service}"
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

    # Verify chrony is actually running before entering wait loop
    sleep 1
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$chrony_service" 2>/dev/null && _chrony_running=true
    elif pidof chronyd >/dev/null 2>&1 || pidof chrony >/dev/null 2>&1; then
        _chrony_running=true
    fi

    if ! $_chrony_running; then
        log_info "⚠️ Chrony service failed to start - skipping NTP sync wait"
        log_info "ℹ Debug: systemctl status ${chrony_service} / journalctl -xeu ${chrony_service}"
    fi
fi

# -------------------------------------------------------------------------
# Wait for NTP synchronization (time-jump aware)
# -------------------------------------------------------------------------
# Uses /proc/uptime (monotonic) instead of date +%s (wall clock) to avoid
# incorrect elapsed time when chrony steps the system clock during sync.
# Budget is shared between waitsync (if available) and manual polling.
# -------------------------------------------------------------------------
synced=false
_ntp_budget=45

# Monotonic clock reader: /proc/uptime is immune to wall-clock jumps
_uptime_secs() { awk '{printf "%d\n",$1}' /proc/uptime 2>/dev/null || echo "${SECONDS:-0}"; }

_mono_start="$(_uptime_secs)"
_mono_deadline=$(( _mono_start + _ntp_budget ))

if $VALIDATE_ONLY; then
    log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Skipping active sync wait"
elif $_chrony_running; then
    log_info "🕒 Waiting for NTP synchronization (up to ${_ntp_budget}s)"

    # Prefer chronyc waitsync if available (cleaner on newer chrony)
    has_waitsync=false
    if chronyc waitsync 0 0 0 0 >/dev/null 2>&1; then
        has_waitsync=true
    elif chronyc -h 2>&1 | grep -qi 'waitsync'; then
        has_waitsync=true
    elif chronyc help 2>&1 | grep -qi 'waitsync'; then
        has_waitsync=true
    fi

    if $has_waitsync; then
        _remaining=$(( _mono_deadline - $(_uptime_secs) ))
        if (( _remaining > 0 )); then
            if $HAS_TIMEOUT && timeout --signal=KILL 0 true >/dev/null 2>&1; then
                cmd_try timeout --signal=KILL $((_remaining + 5)) timeout "$_remaining" \
                    chronyc -a waitsync "$_remaining" 0.5 >/dev/null 2>&1 || true
            else
                cmd_try safe_timeout "$_remaining" \
                    chronyc -a waitsync "$_remaining" 0.5 >/dev/null 2>&1 || true
            fi
        fi
    fi

    # Manual polling for remaining budget (works on all chrony versions)
    while :; do
        _mono_now="$(_uptime_secs)"
        _elapsed=$(( _mono_now - _mono_start ))
        (( _mono_now >= _mono_deadline )) && break

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
            synced_server="$(chronyc tracking 2>/dev/null | awk -F':' 'tolower($0) ~ /^reference id/ {print $2; exit}' | trim_line 2>/dev/null || true)"
            log_info "✅ NTP synchronized (Reference: ${synced_server:-unknown})"
            break
        fi

        if [[ -t 2 ]]; then
            printf "\r${C_DIM}[%s]${C_RESET} ${C_BLUE}[i]${C_RESET} Waiting for NTP sync... ${C_CYAN}(%2ds/%2ds)${C_RESET}" \
                "$(date '+%F %T')" "$_elapsed" "$_ntp_budget" >&2
        fi
        sleep 1
    done
    [[ -t 2 ]] && printf "\r\033[K" >&2
fi

if [[ "$synced" != true && "$_chrony_running" == true ]]; then
    log_info "⚠️ NTP not synchronized yet after ${_ntp_budget}s (server: $NTP_SERVER)."
    log_info "ℹ Debug hints:"
    log_info "   - Check: chronyc sources -v"
    log_info "   - Check: chronyc tracking"
    log_info "   - Check logs: journalctl -u ${chrony_service} (systemd) OR /var/log/chrony/*"
elif [[ "$synced" == true ]]; then
    _mono_end="$(_uptime_secs)"
    _elapsed=$(( _mono_end - _mono_start ))
    log_info "ℹ Time sync confirmed in ${_elapsed}s - proceeding with Kerberos operations"
fi

unset _chrony_running _ntp_budget _mono_start _mono_deadline _mono_now _mono_end _elapsed _remaining

# -------------------------------------------------------------------------
# Obtain Kerberos ticket for domain operations
# -------------------------------------------------------------------------
log_info "🔑 Getting Kerberos ticket for user ${DOMAIN_USER}@${REALM}"
kdestroy -q 2>/dev/null || true

safe_timeout "${KINIT_TIMEOUT:-20}s" kinit "${DOMAIN_USER}@${REALM}" <"$PASS_FILE" >/dev/null 2>&1 || {
    log_error "Failed to obtain Kerberos ticket for ${DOMAIN_USER}@${REALM}" 2
}

# -------------------------------------------------------------------------
# Optional: Verbose LDAP debugging
# -------------------------------------------------------------------------
if $VERBOSE; then
    log_info "🧪 DEBUG: Testing LDAP search for computer object..."
    log_info "🔸 HOST_SHORT_U: $HOST_SHORT_U"
    log_info "🔸 OU: $OU"
    log_info "🔸 BASE_DN: $BASE_DN"

    LDAP_RAW="$(
        set +e +o pipefail
        safe_timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no $LDAP_TLS_FLAG -H "$LDAP_URI" \
          -b "$BASE_DN" "(sAMAccountName=${HOST_SHORT_U_ESCAPED}\$)" distinguishedName 2>&1
    )" && LDAP_CODE=0 || LDAP_CODE=$?

    log_info "🔹 Exit Code: $LDAP_CODE"
    log_info "🔹 LDAP Output:"
    log_info "$LDAP_RAW"
fi

# -------------------------------------------------------------------------
# Check computer object existence and OU alignment
# -------------------------------------------------------------------------
log_info "🔍 Checking if computer object exists in AD"

# Perform search allowing non-fatal exit codes (e.g. not found)
LDAP_OUT="$(
    set +e +o pipefail
    safe_timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no $LDAP_TLS_FLAG -H "$LDAP_URI" \
      -b "$BASE_DN" "(sAMAccountName=${HOST_SHORT_U_ESCAPED}\$)" distinguishedName 2>/dev/null
)" && LDAP_CODE=0 || LDAP_CODE=$?

# Extract DN from LDAP output
CURRENT_DN="$(printf '%s\n' "$LDAP_OUT" | sed -n 's/^distinguishedName:[[:space:]]*//p' | head -n1)"
$VERBOSE && log_info "$LDAP_OUT"

if [[ -n "$CURRENT_DN" ]]; then
    EXPECTED_DN="CN=${HOST_SHORT_U},${OU}"

    # Normalize DNs for idempotent comparison (LDAP DNs are case-insensitive per RFC 4514).
    # Strips whitespace around '=' and ',' and lowercases both strings.
    # This prevents unnecessary ldapmodify modrdn when the AD returns a DN that
    # differs only in casing or spacing (e.g., "OU=Servers" vs "OU=servers").
    _current_dn_norm="$(
        printf '%s' "$CURRENT_DN" \
            | sed 's/[[:space:]]*,[[:space:]]*/,/g; s/[[:space:]]*=[[:space:]]*/=/g' \
            | tr '[:upper:]' '[:lower:]'
    )"
    _expected_dn_norm="$(
        printf '%s' "$EXPECTED_DN" \
            | sed 's/[[:space:]]*,[[:space:]]*/,/g; s/[[:space:]]*=[[:space:]]*/=/g' \
            | tr '[:upper:]' '[:lower:]'
    )"

    if [[ "$_current_dn_norm" == "$_expected_dn_norm" ]]; then
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
        _did_attempt_move=false

        if $DRY_RUN || $VALIDATE_ONLY; then
            if $VALIDATE_ONLY; then
                log_info "${C_MAGENTA}[VALIDATE-ONLY]${C_RESET} Would move computer object via ldapmodify"
            else
                log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would move computer object via ldapmodify"
            fi
        else
            _did_attempt_move=true

            # Temporarily relax strict mode for LDAP move (may fail with permission denied)
            trap - ERR
            set +e

            if $VERBOSE; then
                safe_timeout "$LDAP_TIMEOUT" ldapmodify -Y GSSAPI $LDAP_TLS_FLAG -H "$LDAP_URI" -f "$TMP_LDIF"
                LDAP_MOVE_CODE=$?
            else
                safe_timeout "$LDAP_TIMEOUT" ldapmodify -Y GSSAPI $LDAP_TLS_FLAG -H "$LDAP_URI" -f "$TMP_LDIF" >/dev/null 2>&1
                LDAP_MOVE_CODE=$?
            fi

            # Restore strict mode
            set -Eeuo pipefail
            trap "$ERROR_TRAP_CMD" ERR
        fi

        rm -f "$TMP_LDIF"

        # Analyze result only when the move was actually attempted.
        if [[ "$_did_attempt_move" == true ]]; then
            if [[ "$LDAP_MOVE_CODE" -eq 0 ]]; then
                log_info "✅ Computer object moved successfully to target OU."
            elif [[ "$LDAP_MOVE_CODE" -eq 50 ]]; then
                # LDAP Error 50: Insufficient Access Rights
                log_info "ℹ️ Access denied moving computer object (AD restriction). Keeping current location."
                log_info "↪ Continuing with object in: $CURRENT_DN"
                OU="${CURRENT_DN#*,}"
            else
                log_info "⚠️ Unable to move object (LDAP Code $LDAP_MOVE_CODE). Proceeding in current location."
                OU="${CURRENT_DN#*,}"
            fi
        fi
        unset _did_attempt_move
    fi
else
    log_info "📛 Computer object not found in AD. Proceeding with domain join."
fi

# -------------------------------------------------------------------------
# DOMAIN JOIN PHASE (adcli only + IP description)
# -------------------------------------------------------------------------
log_info "🔗 Joining domain $DOMAIN via adcli (direct mode, no realm)"

# Resolve DC IP for logging
DC_IP="$(getent hosts "$DC_SERVER" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
if [[ -z "$DC_IP" ]] && command -v dig >/dev/null 2>&1; then
    # Best-effort fallback (logging only): never fail the run due to missing dig/DNS response.
    DC_IP="$(dig +short "$DC_SERVER" 2>/dev/null | head -n1 || true)"
fi
log_info "🔍 Target DC for join: $DC_SERVER (${DC_IP:-unresolved})"

# Clean previous Kerberos tickets and renew authentication
kdestroy -q 2>/dev/null || true

safe_timeout "${KINIT_TIMEOUT:-20}s" kinit "${DOMAIN_USER}@${REALM}" <"$PASS_FILE" >/dev/null 2>&1 || {
    log_error "Failed to obtain Kerberos ticket for $DOMAIN_USER@$REALM (failed or timed out)" 2
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
elif safe_timeout "${JOIN_TIMEOUT}s" adcli join \
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
        selinux_restore "$KRB5_KEYTAB"
        log_info "🔒 Keytab permissions hardened (600, root:root)"
    fi

else
    log_info "❌ Domain join failed. Last output lines:"
    tail -n 5 "$JOIN_LOG" | sed 's/^[[:space:]][[:space:]]*//'
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
    safe_timeout "${KINIT_TIMEOUT:-20}s" kinit "${DOMAIN_USER}@${REALM}" <"$PASS_FILE" >/dev/null 2>&1 || \
        log_info "⚠️ Failed to refresh Kerberos ticket for description update"

    TMP_LDIF=$(safe_mktemp)
    _ad_desc_timestamp=$(date '+%Y-%m-%dT%H:%M:%S%z')
    write_file 0600 "$TMP_LDIF" <<EOF
dn: CN=${HOST_SHORT_U},${OU}
changetype: modify
replace: description
description: [${HOST_IP}] - Joined with adcli by ${DOMAIN_USER} on ${_ad_desc_timestamp}
EOF
    if $DRY_RUN; then
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would update AD description via ldapmodify (execution suppressed)."
    else
        # Retry with backoff to tolerate AD replication delay
        _desc_ok=false
        for _desc_attempt in 1 2 3; do
            if safe_timeout "$LDAP_TIMEOUT" ldapmodify -Y GSSAPI $LDAP_TLS_FLAG -H "$LDAP_URI" -f "$TMP_LDIF" >/dev/null 2>&1; then
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
        safe_timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no \
            $LDAP_TLS_FLAG -H "$LDAP_URI" \
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
safe_timeout "${KINIT_TIMEOUT:-20}s" kinit "${DOMAIN_USER}@${REALM}" <"$PASS_FILE" >/dev/null 2>&1 || \
    log_error "Failed to obtain Kerberos ticket for ${DOMAIN_USER}@${REALM}" 2

# Reduce credential exposure window: password file is no longer needed after this point.
secure_delete "${PASS_FILE:-}"
unset PASS_FILE

# Temporarily relax strict mode for trust validation block
trap - ERR
set +e +o pipefail

# -------------------------------------------------------------------------
# Validate machine Kerberos keytab (domain trust check)
# -------------------------------------------------------------------------
TRUST_STATUS="⚠️ Trust check failed"
PRINCIPAL="${HOST_SHORT_U}\$@${REALM}"
KRB_LOG=$(safe_mktemp)
START_MS="$(now_ms)"

KRB5_TRACE="$KRB_LOG" safe_timeout "${TRUST_TIMEOUT:-15}s" kinit -kt "$KRB5_KEYTAB" "$PRINCIPAL" >/dev/null 2>&1
EXIT_CODE=$?
END_MS="$(now_ms)"
ELAPSED=$((END_MS - START_MS))

# Resolve DC name dynamically
DC_USED="$(grep -Eo 'to (dgram|stream) ([0-9.]+|[A-Za-z0-9._-]+)' "$KRB_LOG" 2>/dev/null | awk '{print $3}' | tail -n1 || true)"
[[ -z "$DC_USED" ]] && DC_USED=$(grep -Eo '([A-Za-z0-9._-]+\.[A-Za-z]{2,})' "$KRB_LOG" | grep -viF "$REALM" | tail -n1)
[[ -z "$DC_USED" ]] && DC_USED="(unknown DC)"

# Optional reverse DNS
DC_NAME=""
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
PING_RTT="$(ping -c 1 -W 1 "$DC_NAME" 2>/dev/null | awk -F'=' '/time=/{print $NF}' | tr -d ' ')" || true
[[ -z "$PING_RTT" ]] && PING_RTT="n/a"

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
    print_divider
    log_info "[*] Kerberos trace summary:"
    while IFS= read -r _ktrace_line; do
        [[ -n "$_ktrace_line" ]] && log_info "   $_ktrace_line"
    done < <(grep -E "Sending initial|Response was from|error from KDC" "$KRB_LOG" 2>/dev/null || true)
    print_divider
fi

# Cleanup
rm -f "$KRB_LOG" 2>/dev/null || true

# Restore strict mode after trust validation block.
# Symmetric with 'set -Eeuo pipefail' at script initialization.
# -E (errtrace) and -u (nounset) are never disabled, but are included here
# for explicit symmetry and to prevent accidental omission in future edits.
set -Eeuo pipefail
trap "$ERROR_TRAP_CMD" ERR

# -------------------------------------------------------------------------
# Validate and re-enable computer object if disabled in AD
# -------------------------------------------------------------------------
log_info "🔧 Checking if computer object is disabled in AD..."

# Query userAccountControl via GSSAPI (machine trust)
# Avoid /dev/stderr dependency: in minimal/rescue environments /proc may not be mounted.
if $VERBOSE; then
    UAC_RAW=$(safe_timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no $LDAP_TLS_FLAG -H "$LDAP_URI" \
        -b "CN=${HOST_SHORT_U},${OU}" userAccountControl \
        | awk '/^userAccountControl:/ {print $2}' || true)
else
    UAC_RAW=$(safe_timeout "$LDAP_TIMEOUT" ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no $LDAP_TLS_FLAG -H "$LDAP_URI" \
        -b "CN=${HOST_SHORT_U},${OU}" userAccountControl \
        2>/dev/null | \
        awk '/^userAccountControl:/ {print $2}' || true)
fi

if [[ -z "$UAC_RAW" ]]; then
    $VERBOSE && log_info "ℹ userAccountControl attribute not returned for CN=${HOST_SHORT_U},${OU} (skipping auto re-enable step)"
else
    # Normalize userAccountControl to a decimal integer
    if [[ "$UAC_RAW" =~ ^0x[0-9A-Fa-f]+$ ]]; then
        UAC=$((UAC_RAW))
    elif [[ "$UAC_RAW" =~ ^[0-9]+$ ]]; then
        # Force base-10 to avoid octal interpretation on leading zeros.
        UAC=$((10#$UAC_RAW))
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
                    safe_timeout "$LDAP_TIMEOUT" ldapmodify -Y GSSAPI $LDAP_TLS_FLAG -H "$LDAP_URI" <<EOF || _reenable_rc=$?
dn: CN=${HOST_SHORT_U},${OU}
changetype: modify
replace: userAccountControl
userAccountControl: $NEW_UAC
EOF
                else
                    safe_timeout "$LDAP_TIMEOUT" ldapmodify -Y GSSAPI $LDAP_TLS_FLAG -H "$LDAP_URI" >/dev/null 2>&1 <<EOF || _reenable_rc=$?
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
safe_timeout "${KINIT_TIMEOUT:-20}s" kinit -kt "$KRB5_KEYTAB" "${HOST_SHORT_U}\$@${REALM}" >/dev/null 2>&1 \
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

# Restrict local login to authorized AD groups only
simple_allow_groups = $ADM, $ADM_ALL, $SEC, $SEC_ALL, $SUPER, $SUPER_ALL, $GRP_SSH, $GRP_SSH_ALL

# -------------------------------------------------------------------------
# Active Directory and Kerberos parameters
# -------------------------------------------------------------------------
ad_domain = $DOMAIN_LOWER
ad_hostname = $HOST_FQDN
krb5_realm = $REALM
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

# Defense-in-depth: re-enforce strict ownership/permissions
# (write_file already sets these via install -m/-o/-g, but SSSD
# refuses to start if permissions are not exactly 0600 root:root)
cmd_try chown root:root "$SSSD_CONF" || true
cmd_try chmod 600 "$SSSD_CONF" || true

# -------------------------------------------------------------------------
# Optional: flush old caches before restart
# -------------------------------------------------------------------------
if command -v sss_cache >/dev/null 2>&1; then
    if [[ "${NONINTERACTIVE:-false}" == "true" ]]; then
        log_info "ℹ️ NONINTERACTIVE mode detected - skipping SSSD cache flush to preserve UID mapping"
    else
        if $DRY_RUN; then
            log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would flush SSSD caches (sss_cache -E)"
        else
            log_info "🔁 Flushing old SSSD caches"
            sss_cache -E >/dev/null 2>&1 || log_info "⚠️ Failed to flush SSSD cache (non-critical)"
        fi
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
    for l in "${_lines[@]+"${_lines[@]}"}"; do
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
            selinux_restore "$PAM_SU_FILE"
            log_info "✅ pam_sss binding injected into $PAM_SU_FILE (original preserved in ${su_backup:-unknown})"
        fi
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

if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would enable and restart SSSD"
else
    log_info "🔧 Enabling SSSD"
    cmd_must service_control sssd enable

    log_info "🔄 Restarting SSSD"
    cmd_must service_control sssd restart
fi

# -------------------------------------------------------------------------
# Restarts systemd-logind to refresh PAM and D-Bus session handling
# -------------------------------------------------------------------------
log_info "🔄 Starting direct execution block for systemd-logind restart"

LOGIND_UNIT="systemd-logind.service"

# 1. Check for systemctl presence (Systemd environments)
if $DRY_RUN; then
    log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Would restart ${LOGIND_UNIT} to refresh PAM/D-Bus"
elif command -v systemctl &>/dev/null; then
    
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

# Defense-in-depth: ensure DOMAIN_PASS is not lingering in memory
# (already unset in create_secret_passfile, but may be reintroduced by future edits)
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

# Build AllowGroups (AD groups + system defaults)
# NOTE: SSH AllowGroups uses space as delimiter between group names.
# OpenSSH has no escaping mechanism for spaces in group names.
# When any SSH group contains spaces, AllowGroups is omitted entirely
# and access control is enforced exclusively by SSSD (simple_allow_groups).
if [[ "$GRP_SSH" == *" "* || "$GRP_SSH_ALL" == *" "* ]]; then
    log_info "⚠ SSH group names contain spaces - AllowGroups directive will be omitted"
    [[ "$GRP_SSH" == *" "* ]]     && log_info "   ↪ '$GRP_SSH' contains spaces"
    [[ "$GRP_SSH_ALL" == *" "* ]] && log_info "   ↪ '$GRP_SSH_ALL' contains spaces"
    log_info "ℹ SSH access control enforced exclusively by SSSD simple_allow_groups"

    # Remove any pre-existing AllowGroups from global section (stale from previous run)
    if grep -qiE '^[[:space:]]*AllowGroups[[:space:]]' "$SSH_CFG" 2>/dev/null; then
        cmd_must sed -i '/^[[:space:]]*AllowGroups[[:space:]]/d' "$SSH_CFG"
        if ! $DRY_RUN && ! $VALIDATE_ONLY; then
            log_info "🧹 Removed pre-existing AllowGroups directive from $SSH_CFG"
        fi
    fi
else
    ALLOW_GROUPS="$GRP_SSH $GRP_SSH_ALL $SSH_G root"

    # Normalize multiple spaces and trim ends
    ALLOW_GROUPS="$(trim_ws "$ALLOW_GROUPS")"

    # Apply AllowGroups directive
    sshd_set_directive_dedup "AllowGroups" "$ALLOW_GROUPS" "$SSH_CFG"
    log_info "🧩 AllowGroups updated -> AllowGroups $ALLOW_GROUPS"
fi

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
BLOCK_FILE="${SUDOERS_DIR}/00-block-root-shell"
SUDOERS_AD="${SUDOERS_DIR}/10-ad-linux-privilege-model"

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
# - This file contains global DENY aliases only.
# - No AD groups are configured here.
# - All AD group privileges are defined in: 10-ad-linux-privilege-model
#
# DENY ALIASES DEFINED HERE:
#   ROOT_SHELLS        - Direct shell spawning (bash, sh, dash, zsh, su, env)
#   PRIV_ESC           - Interpreters that can exec shell (python, perl, etc.)
#   SEC_SUDOERS_WRITE  - Direct writes to sudoers (sed -i, tee)
#   SEC_CREDENTIALS    - Root password management (passwd root)
# ========================================================================


# ------------------------------------------------------------------------
# ROOT_SHELLS - Block direct root shell access
#
# Denies any attempt to spawn an interactive root shell.
# This includes direct shells (bash, sh, dash, zsh), indirect shells
# via /usr/bin/env (including -S and -- variants), custom-built shells
# in /usr/local/bin/, and util-linux 'script' (which spawns root shells).
#
# Usage in privilege rules:
#       !ROOT_SHELLS
#
# NOTE: This blocks 'sudo bash' and 'sudo su', but does NOT prevent
# shell escape from within privileged editors (vim :!bash, nano Ctrl+T).
# Editor-based escapes are mitigated by using sudoedit (see privilege model).
# ------------------------------------------------------------------------
Cmnd_Alias ROOT_SHELLS = \
    /bin/su, /usr/bin/su, /usr/local/bin/su, \
    /bin/bash, /usr/bin/bash, /usr/local/bin/bash, \
    /bin/sh, /usr/bin/sh, /usr/local/bin/sh, \
    /bin/dash, /usr/bin/dash, /usr/local/bin/dash, \
    /bin/zsh, /usr/bin/zsh, /usr/local/bin/zsh, \
    /usr/bin/env bash, \
    /usr/bin/env bash -i, \
    /usr/bin/env -i bash, \
    /usr/bin/env -S bash, \
    /usr/bin/env -- bash, \
    /usr/bin/env bash -c *, \
    /usr/bin/env -i bash -c *, \
    /usr/bin/env sh, \
    /usr/bin/env -i sh, \
    /usr/bin/env -S sh, \
    /usr/bin/env -- sh, \
    /usr/bin/env -i bash -i, \
    /usr/bin/env dash, \
    /usr/bin/env -i dash, \
    /usr/bin/env -- dash, \
    /usr/bin/env zsh, \
    /usr/bin/env -i zsh, \
    /usr/bin/env -- zsh, \
    /usr/bin/script, /bin/script, /usr/local/bin/script


# ------------------------------------------------------------------------
# PRIV_ESC - Block privilege-escalation capable interpreters
#
# These interpreters can execute arbitrary system commands:
#   sudo python3 -c 'import os; os.system("/bin/bash")'
#   sudo perl -e 'exec "/bin/bash"'
#   sudo ruby -e 'exec "/bin/bash"'
#
# Blocking these prevents indirect root shell access via interpreters.
# Scripts using these languages should be executed as scripts
# (sudo ./script.py), not via direct interpreter invocation.
# The shebang is resolved by the kernel (execve), not by sudo.
#
# NOTE: Operational tools like find, awk, tar, less, man are intentionally
# NOT blocked here - they are required for system administration.
# The residual risk from these tools is accepted and compensated with
# audit logging (auditd).
#
# Usage in privilege rules:
#       !PRIV_ESC
# ------------------------------------------------------------------------
Cmnd_Alias PRIV_ESC = \
    /usr/bin/python*, /bin/python*, \
    /usr/bin/perl*, /bin/perl*, \
    /usr/bin/ruby*, /bin/ruby*, \
    /usr/bin/lua*, /bin/lua*, \
    /usr/bin/expect, /bin/expect, \
    /usr/bin/gdb, /bin/gdb, \
    /usr/bin/strace, /bin/strace, \
    /usr/bin/ltrace, /bin/ltrace


# ------------------------------------------------------------------------
# SEC_SUDOERS_WRITE - Block direct writes to sudoers files
#
# Prevents modification of sudoers files via sed -i or tee.
# These tools can silently alter privilege rules:
#
#   sed -i 's/!ROOT_SHELLS//' /etc/sudoers.d/10-ad-linux-privilege-model
#   echo 'user ALL=(ALL) NOPASSWD: ALL' | tee /etc/sudoers.d/backdoor
#
# Safe alternative: use visudo (validates syntax before committing).
#
# This alias is applied as a DENY to ALL roles (SEC, ADM, SUPER).
# It is NOT included in any allow list - it is only used with !
#
# Usage in privilege rules:
#       !SEC_SUDOERS_WRITE
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SUDOERS_WRITE = \
    /bin/sed -i* /etc/sudoers*, \
    /usr/bin/sed -i* /etc/sudoers*, \
    /bin/sed --in-place* /etc/sudoers*, \
    /usr/bin/sed --in-place* /etc/sudoers*, \
    /usr/bin/tee /etc/sudoers*, \
    /usr/bin/tee -a /etc/sudoers*


# ------------------------------------------------------------------------
# SEC_CREDENTIALS - Root password management
#
# Only SUPER administrators may reset the root password.
# This alias is used as a DENY for SEC and ADM roles.
# SUPER inherits access via ALL without this deny.
#
# Usage in privilege rules:
#       !SEC_CREDENTIALS    (applied to SEC and ADM)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_CREDENTIALS = \
    /usr/bin/passwd root
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
#       * File editing via sudoedit (editor runs unprivileged)
#       * Cannot obtain interactive root shell
#       * Cannot reset root password
#
#   - OPERATIONAL administrators (ADM):
#       * Operate the system and applications
#       * Can manage services and software
#       * Cannot alter security posture
#       * Cannot obtain interactive root shell
#       * Cannot reset root password
#
#   - FULL administrators (SUPER):
#       * Union of ADM and SEC privileges
#       * File editing via sudoedit (editor runs unprivileged)
#       * Cannot obtain interactive root shell
#       * CAN reset root password (only role with this privilege)
#
#
# SCOPE CONTROL
# -------------
# Group scope (global vs host-level) is handled in Active Directory:
#
#   - %SEC_ALL / %ADM_ALL / %SUPER_ALL  -> global authority
#   - %SEC     / %ADM     / %SUPER      -> host-level authority
#
#
# EDITOR SECURITY MODEL (sudoedit)
# ---------------------------------
# File editing uses 'sudoedit' (sudo -e) instead of 'sudo vim/nano'.
#
# Why: 'sudo vim /etc/file' runs the editor AS ROOT. The user can escape
# to a root shell via :!bash (vim), Ctrl+T (nano), or similar features.
# The !ROOT_SHELLS restriction does NOT prevent this because the shell
# is spawned by the editor process (already running as root), not by sudo.
#
# How sudoedit works:
#   1. sudo copies the target file to a temp file owned by the calling user
#   2. Opens the user's editor WITHOUT root privileges (\$SUDO_EDITOR/\$EDITOR)
#   3. After the editor exits, sudo copies the temp back as root
#
# Result: :!bash or Ctrl+T opens a shell as the USER, not root.
#
# Usage for SEC/SUPER administrators:
#   sudoedit /etc/pam.d/sshd          (safe - editor is unprivileged)
#   sudoedit /etc/sssd/sssd.conf      (safe - editor is unprivileged)
#   sudoedit /etc/ssh/sshd_config     (safe - editor is unprivileged)
#
# The following are NOT available via sudo (shell escape vectors):
#   sudo vim /etc/pam.d/sshd          (NOT PERMITTED - :!bash = root shell)
#   sudo nano /etc/sssd/sssd.conf     (NOT PERMITTED - Ctrl+T = root shell)
#
# NOTE: vim and nano remain available for non-privileged file editing.
# Only 'sudo vim/nano' on security files is restricted in this model.
# Regular users editing their own files (without sudo) are not affected.
#
# To configure your preferred editor for sudoedit:
#   export SUDO_EDITOR=vim    (in ~/.bashrc or /etc/profile.d/)
#   export SUDO_EDITOR=nano   (if you prefer nano)
#
#
# SUDOERS WRITE PROTECTION
# -------------------------
# Direct writes to /etc/sudoers* via sed -i and tee are BLOCKED for
# all roles (SEC, ADM, SUPER) via !SEC_SUDOERS_WRITE.
# This prevents:
#   - Removal of !ROOT_SHELLS restrictions
#   - Injection of backdoor sudoers rules
# Use 'visudo' for sudoers editing (validates syntax before committing).
#
#
# INTERPRETER RESTRICTION
# ------------------------
# Interpreters that can exec arbitrary commands (python, perl, ruby, lua,
# expect, gdb, strace, ltrace) are blocked via !PRIV_ESC for all roles.
# Scripts using these languages should be executed as scripts:
#   sudo ./myscript.py       (OK - shebang resolved by kernel, not sudo)
#   sudo python3 myscript.py (BLOCKED - direct interpreter invocation)
#
#
# ROOT PASSWORD MANAGEMENT
# -------------------------
# Only SUPER can reset the root password (passwd root).
# SEC and ADM are explicitly denied via !SEC_CREDENTIALS.
#
#
# DENY ALIASES (defined in 00-block-root-shell)
# -----------------------------------------------
# The following deny aliases are applied per role:
#
#   ALL ROLES:
#     !ROOT_SHELLS       - Direct shell access (bash, sh, su, env tricks)
#     !PRIV_ESC          - Interpreters (python, perl, ruby, lua, etc.)
#     !SEC_SUDOERS_WRITE - Direct writes to sudoers (sed -i, tee)
#
#   SEC and ADM only:
#     !SEC_CREDENTIALS   - Root password management (passwd root)
# ========================================================================


# ------------------------------------------------------------------------
# SUDOERS management
# Only visudo is permitted (syntax-validated editing).
# NOTE: vim/nano removed - they run as root and allow shell escape.
# Use visudo for sudoers, sudoedit for other security files.
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SUDOERS = \\
    /usr/sbin/visudo, \\
    /bin/cp /etc/sudoers*, \\
    /bin/mv /etc/sudoers*, \\
    /usr/bin/chmod /etc/sudoers*, \\
    /usr/bin/chown /etc/sudoers*


# ------------------------------------------------------------------------
# Security-critical authentication services
# Includes both 'sshd' (RHEL/SUSE) and 'ssh' (Debian/Ubuntu) unit names
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SECURITY_SERVICES = \\
    /usr/bin/systemctl restart sshd, \\
    /usr/bin/systemctl reload sshd, \\
    /usr/bin/systemctl restart ssh, \\
    /usr/bin/systemctl reload ssh, \\
    /usr/bin/systemctl restart systemd-logind, \\
    /usr/bin/systemctl daemon-reload


# ------------------------------------------------------------------------
# Inline editing on SSH configuration (permitted for SEC automation)
# sed -i is a legitimate operational tool for adjusting SSH directives
# in automation scripts and quick one-liner fixes.
#
# NOTE: sed -i on /etc/sudoers* is BLOCKED separately via
# !SEC_SUDOERS_WRITE (defined in 00-block-root-shell).
# Only SSH targets are permitted here.
# ------------------------------------------------------------------------
Cmnd_Alias SEC_INLINE_EDIT_SSH = \\
    /bin/sed -i* /etc/ssh/*, \\
    /usr/bin/sed -i* /etc/ssh/*


# ------------------------------------------------------------------------
# Pipe overwrite on SSH configuration (permitted for SEC automation)
# tee is commonly used in automation to write config fragments.
#
# NOTE: tee on /etc/sudoers* is BLOCKED separately via
# !SEC_SUDOERS_WRITE (defined in 00-block-root-shell).
# Only SSH targets are permitted here.
# ------------------------------------------------------------------------
Cmnd_Alias SEC_TEE_SSH = \\
    /usr/bin/tee /etc/ssh/*


# ------------------------------------------------------------------------
# PAM authentication stack
# Editing via sudoedit (editor runs unprivileged - no root shell escape)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_PAM = \\
    sudoedit /etc/pam.d/*, \\
    /bin/cp /etc/pam.d/*, \\
    /bin/mv /etc/pam.d/*, \\
    /usr/bin/chmod /etc/pam.d/*, \\
    /usr/bin/chown /etc/pam.d/*


# ------------------------------------------------------------------------
# Identity and NSS (local users, groups, resolution)
# Editing via sudoedit (editor runs unprivileged - no root shell escape)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_IDENTITY = \\
    sudoedit /etc/nsswitch.conf, \\
    sudoedit /etc/passwd, \\
    sudoedit /etc/shadow, \\
    sudoedit /etc/group, \\
    sudoedit /etc/gshadow, \\
    /bin/cp /etc/passwd*, \\
    /bin/cp /etc/shadow*, \\
    /bin/cp /etc/group*, \\
    /bin/cp /etc/gshadow*, \\
    /bin/mv /etc/passwd*, \\
    /bin/mv /etc/shadow*, \\
    /bin/mv /etc/group*, \\
    /bin/mv /etc/gshadow*, \\
    /usr/bin/chmod /etc/passwd*, \\
    /usr/bin/chmod /etc/shadow*, \\
    /usr/bin/chmod /etc/group*, \\
    /usr/bin/chmod /etc/gshadow*, \\
    /usr/bin/chown /etc/passwd*, \\
    /usr/bin/chown /etc/shadow*, \\
    /usr/bin/chown /etc/group*, \\
    /usr/bin/chown /etc/gshadow*


# ------------------------------------------------------------------------
# SSSD / Active Directory integration
# Editing via sudoedit (editor runs unprivileged - no root shell escape)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SSSD = \\
    sudoedit /etc/sssd/sssd.conf, \\
    /bin/cp /etc/sssd/sssd.conf, \\
    /bin/mv /etc/sssd/sssd.conf, \\
    /usr/bin/chmod /etc/sssd/sssd.conf, \\
    /usr/bin/chown /etc/sssd/sssd.conf


# ------------------------------------------------------------------------
# Polkit privilege rules (modern privilege escalation layer)
# Editing via sudoedit (editor runs unprivileged - no root shell escape)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_POLKIT = \\
    sudoedit /etc/polkit-1/*, \\
    /bin/cp /etc/polkit-1/*, \\
    /bin/mv /etc/polkit-1/*, \\
    /usr/bin/chmod /etc/polkit-1/*, \\
    /usr/bin/chown /etc/polkit-1/*


# ------------------------------------------------------------------------
# SSH configuration
# Editing via sudoedit (editor runs unprivileged - no root shell escape)
# cp/mv/chmod/chown for file management operations
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SSH_CONFIG = \\
    sudoedit /etc/ssh/sshd_config, \\
    sudoedit /etc/ssh/sshd_config.d/*, \\
    sudoedit /etc/ssh/ssh_config, \\
    /bin/cp /etc/ssh/*, \\
    /bin/mv /etc/ssh/*, \\
    /usr/bin/chmod /etc/ssh/*, \\
    /usr/bin/chown /etc/ssh/*


# ------------------------------------------------------------------------
# systemd overrides for security services
# Editing via sudoedit (editor runs unprivileged - no root shell escape)
# Includes both sshd (RHEL/SUSE) and ssh (Debian/Ubuntu) unit names
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SYSTEMD_OVERRIDES = \\
    sudoedit /etc/systemd/system/sshd.service*, \\
    sudoedit /etc/systemd/system/ssh.service*, \\
    /bin/cp /etc/systemd/system/sshd.service*, \\
    /bin/cp /etc/systemd/system/ssh.service*, \\
    /bin/mv /etc/systemd/system/sshd.service*, \\
    /bin/mv /etc/systemd/system/ssh.service*


# ------------------------------------------------------------------------
# Optional: advanced PAM / security tuning
# Editing via sudoedit (editor runs unprivileged - no root shell escape)
# (Enable only if these controls are actively used)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_SECURITY_MISC = \\
    sudoedit /etc/security/*, \\
    /bin/cp /etc/security/*, \\
    /bin/mv /etc/security/*


# ------------------------------------------------------------------------
# Central Security Authority - allowed operations (whitelist)
# All permitted commands for the SEC role.
#
# NOTE: The following aliases are NOT here (they are DENY-only):
#   - SEC_CREDENTIALS    (passwd root - SUPER only)
#   - SEC_SUDOERS_WRITE  (sed -i / tee on sudoers)
#   - ROOT_SHELLS        (direct shell access)
#   - PRIV_ESC           (interpreters)
# ------------------------------------------------------------------------
Cmnd_Alias SEC_ALL_CMDS = \\
    SEC_SUDOERS, \\
    SEC_SECURITY_SERVICES, \\
    SEC_INLINE_EDIT_SSH, \\
    SEC_TEE_SSH, \\
    SEC_PAM, \\
    SEC_IDENTITY, \\
    SEC_SSSD, \\
    SEC_POLKIT, \\
    SEC_SSH_CONFIG, \\
    SEC_SYSTEMD_OVERRIDES, \\
    SEC_SECURITY_MISC


# ========================================================================
# SECURITY ADMINISTRATORS (SEC)
# ========================================================================
# Scope:
# - Security configuration only (auth, authz, identity, credentials)
# - File editing via sudoedit (editor runs unprivileged - no root escape)
# - No operational administration
# - Cannot obtain interactive root shell
# - Cannot invoke interpreters (python, perl, ruby, etc.)
# - Cannot write directly to sudoers (use visudo)
# - Cannot reset root password (SUPER only)
#
# NOTE: Spaces in group names are backslash-escaped inline (sudoers requirement).
# ========================================================================
%${SEC_ALL// /\\ } ALL=(root) NOPASSWD: SEC_ALL_CMDS, !ROOT_SHELLS, !PRIV_ESC, !SEC_SUDOERS_WRITE, !SEC_CREDENTIALS
%${SEC// /\\ }     ALL=(root) NOPASSWD: SEC_ALL_CMDS, !ROOT_SHELLS, !PRIV_ESC, !SEC_SUDOERS_WRITE, !SEC_CREDENTIALS


# ========================================================================
# OPERATIONAL ADMINISTRATORS (ADM)
# ========================================================================
# Scope:
# - Full operational administration
# - Explicitly excluded from security posture changes (!SEC_ALL_CMDS)
# - Cannot obtain interactive root shell
# - Cannot invoke interpreters (python, perl, ruby, etc.)
# - Cannot write directly to sudoers (use visudo)
# - Cannot reset root password (SUPER only)
#
# NOTE: Spaces in group names are backslash-escaped inline (sudoers requirement).
# ========================================================================
%${ADM_ALL// /\\ } ALL=(root) NOPASSWD: ALL, !SEC_ALL_CMDS, !ROOT_SHELLS, !PRIV_ESC, !SEC_SUDOERS_WRITE, !SEC_CREDENTIALS
%${ADM// /\\ }     ALL=(root) NOPASSWD: ALL, !SEC_ALL_CMDS, !ROOT_SHELLS, !PRIV_ESC, !SEC_SUDOERS_WRITE, !SEC_CREDENTIALS


# ========================================================================
# FULL ADMINISTRATORS (SUPER)
# ========================================================================
# Scope:
# - Full operational + security administration
# - Union of ADM and SEC privileges
# - File editing via sudoedit (editor runs unprivileged - no root escape)
# - Cannot obtain interactive root shell
# - Cannot invoke interpreters (python, perl, ruby, etc.)
# - Cannot write directly to sudoers (defense-in-depth; use visudo)
# - CAN reset root password (only role with this privilege)
#
# NOTE:
# - Membership in SUPER replaces ADM and SEC
# - Users must NOT be assigned to ADM and SEC simultaneously
# - Spaces in group names are backslash-escaped inline (sudoers requirement).
# ========================================================================
%${SUPER_ALL// /\\ } ALL=(root) NOPASSWD: ALL, !ROOT_SHELLS, !PRIV_ESC, !SEC_SUDOERS_WRITE
%${SUPER// /\\ }     ALL=(root) NOPASSWD: ALL, !ROOT_SHELLS, !PRIV_ESC, !SEC_SUDOERS_WRITE
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

        # NOTE: Validation succeeded, but no changes were committed in DRY-RUN mode.
        log_info "${C_YELLOW}[DRY-RUN]${C_RESET} Sudoers normalization validated (not committed)"
    else
        cmd_must mv -f "$tmp_sudo" "$SUDOERS_MAIN"
        cmd_must chmod 440 "$SUDOERS_MAIN"
        selinux_restore "$SUDOERS_MAIN"

        log_info "✅ Sudoers includes normalized successfully"
    fi
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
        # Match group names including backslash-escaped spaces (sudoers format: %Domain\ Admins)
        # Captures everything after '%' up to the first unescaped whitespace followed by ALL=
        if [[ "$line" =~ ^%(([A-Za-z0-9._-]|\\.)+)[[:space:]] ]]; then
            _grp="${BASH_REMATCH[1]}"
            # Unescape backslash-space sequences to get the logical group name
            _grp="${_grp//\\ / }"
            RAW_GROUPS+=("$_grp")
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
		patched=()
		compliant=()

		tmp="$(safe_mktemp "/tmp/$(basename "$f").XXXXXX")"
        : >"$tmp"

		while IFS= read -r line || [[ -n "$line" ]]; do
			original="$line"
			handled=false

			for grp in "${TARGET_GROUPS[@]}"; do
				# Render group token exactly as sudoers expects (spaces must be backslash-escaped).
				# Example: "Domain Admins" -> "Domain\ Admins"
				grp_sudo="${grp// /\\ }"

				good_all="%${grp_sudo} ALL=(ALL:ALL) ALL, !ROOT_SHELLS"
				good_npw="%${grp_sudo} ALL=(ALL) NOPASSWD: ALL, !ROOT_SHELLS"

				# Escape regex metacharacters in the sudoers token for safe pattern matching.
				# NOTE: grp_sudo may contain backslashes (escaped spaces); regex_escape_ere handles this.
				grp_token_escaped="$(regex_escape_ere "$grp_sudo")"

				# Allow optional spaces around '=' as sudoers syntax permits (e.g., ALL = (ALL))
				# Trailing whitespace tolerance: editors may leave invisible spaces at end of line
				pat_all="^%${grp_token_escaped}[[:space:]]+ALL[[:space:]]*=[[:space:]]*\\(ALL(:ALL)?\\)[[:space:]]+ALL[[:space:]]*$"
				pat_npw="^%${grp_token_escaped}[[:space:]]+ALL[[:space:]]*=[[:space:]]*\\(ALL(:ALL)?\\)[[:space:]]+NOPASSWD:[[:space:]]+ALL[[:space:]]*$"

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
		# Capture visudo RC without tripping errexit via explicit &&/|| assignment
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
            selinux_restore "$f"
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
    # -------------------------------------------------------------------------
    # SSSD service status (systemd)
    # -------------------------------------------------------------------------
    if systemctl list-unit-files "sssd.service" 2>/dev/null | grep -q 'sssd\.service'; then
        SSSD_STATUS=$(systemctl is-active sssd 2>/dev/null || echo "inactive")
    else
        pgrep sssd >/dev/null 2>&1 && SSSD_STATUS="active" || SSSD_STATUS="inactive"
    fi
    [[ -z "$SSSD_STATUS" ]] && SSSD_STATUS="inactive"

    # -------------------------------------------------------------------------
    # SSH service status (handle ssh vs sshd naming)
    # -------------------------------------------------------------------------
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
    # -------------------------------------------------------------------------
    # Fallback for distros without systemd
    # -------------------------------------------------------------------------
    pgrep sssd >/dev/null 2>&1 && SSSD_STATUS="active" || SSSD_STATUS="inactive"
    pgrep sshd >/dev/null 2>&1 && SSH_STATUS="active"  || SSH_STATUS="inactive"
fi

# Normalize empty or unexpected values (safe under set -u)
: "${TRUST_STATUS:=⚠️ Unknown}"
: "${DC_TRUST_SERVER:=n/a}"
: "${TRUST_ELAPSED:=n/a}"
: "${TRUST_RTT:=n/a}"
: "${REALM_JOINED:=⚠️ Not detected}"

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

# Flush tee pipelines: close stdout to signal EOF to tee, wait for completion.
# Keep stderr open for cleanup trap errors (cleanup_secrets may log warnings).
exec 1>&-
wait 2>/dev/null || true

# NOTE: stderr is intentionally left open until after exit 0
# so the EXIT trap (cleanup_secrets) can still log to the console.
# The kernel closes fd 2 automatically on process termination.

exit 0