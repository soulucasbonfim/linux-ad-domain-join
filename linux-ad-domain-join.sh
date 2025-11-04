#!/bin/bash
# =================================================================================================
# Script Name:        linux-ad-domain-join.sh
# -------------------------------------------------------------------------------------------------
# Description:
#   Automates the process of joining a Linux host to an Active Directory (AD) domain.
#   Provides full multi-distro compatibility (RHEL-like, Debian-like, SUSE), with support for:
#     • Realmd/adcli/SSSD integration
#     • Dynamic DNS updates (secure GSS-TSIG)
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
#
# -------------------------------------------------------------------------------------------------
# Usage:
#   ./linux-ad-domain-join.sh [--dry-run] [--yes|-y] [--verbose|-v]
#
# Options:
#   --dry-run         Simulate all actions without applying changes
#   --yes, -y         Non-interactive mode (requires DOMAIN, OU, DC_SERVER,
#                     DOMAIN_USER, DOMAIN_PASS, GLOBAL_ADMIN_GROUPS as env vars)
#   --verbose, -v     Enable full command output and debugging traces
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
# Compatibility Matrix:
#   • Ubuntu 18.04 / 20.04 / 22.04 / 24.04 (APT)
#   • Debian 10+ (APT)
#   • Oracle Linux 7.x / 8.x / 9.x (YUM/DNF)
#   • RHEL / Rocky / AlmaLinux 7.x–9.x (YUM/DNF)
#   • SUSE Linux Enterprise 12 / 15 (Zypper)
#
# -------------------------------------------------------------------------------------------------
# Author:      Lucas Bonfim de Oliveira Lima
# LinkedIn:    https://www.linkedin.com/in/soulucasbonfim
# Created:     2025-04-27
# Updated:     2025-10-31
# Version:     1.8.1
# License:     MIT
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
#  100 - Missing packages and system offline (no installation possible)
#
# -------------------------------------------------------------------------------------------------

set -euo pipefail

# -------------------------------------------------------------------------
# Logging functions (ASCII-safe for non-Unicode terminals)
# -------------------------------------------------------------------------
sanitize_log_msg() {
    LC_ALL=C sed -E '
        # Warnings / Alerts
        s/⚠|⚠️|❗|❕|🚨|📛|🧯|🔥|💣|🧨/[!]/g;
        # Informational / Neutral
        s/ℹ|ℹ️|🧵|🕒|📡|🌐|💡|🧬|🧭|⏰|🧾|🪪|🧠|🪶|🔢|💬|📘|🔋|🧮/[i]/g;
        # Operational / Progress / Configuration
        s/🔁|🔧|🛠|🛠️|🧩|🏷|💾|♻|🚚|⚙️|⚙|🏷️|🧹|🔗|🔌|🔄|↪|🛡️|🧱|🗂|🗂️|🧰|🛡|📦|📎|🪄/[>]/g;
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

log_info() {
    local msg="$1"
    msg="$(sanitize_log_msg <<< "$msg")"
    echo "[$(date '+%F %T')] $msg"
}

log_error() {
    local msg="$1"; local code="${2:-1}"
    local ts="[$(date '+%F %T')]"
    trap - ERR
    local line1="$ts ❌ [ERROR] $msg"
    local line2="$ts ℹ Exiting with code $code"
    echo "$(sanitize_log_msg <<< "$line1")" >&2
    echo "$(sanitize_log_msg <<< "$line2")" >&2
    sync; sleep 0.05
    exit "$code"
}

# -------------------------------------------------------------------------
# Read wrapper with safe emoji sanitization
# -------------------------------------------------------------------------
read_sanitized() {
    local prompt sanitized var_name
    prompt="$1"
    var_name="$2"
    sanitized="$(sanitize_log_msg <<< "$prompt")"
    read -rp "[$(date '+%F %T')] $sanitized" "$var_name"
}

# -------------------------------------------------------------------------
# Global error trap - catches any unexpected command failure
# -------------------------------------------------------------------------
trap 'log_error "Unexpected error at line $LINENO in \"$BASH_COMMAND\"" $?' ERR

# -------------------------------------------------------------------------
# Privilege check
# -------------------------------------------------------------------------
if (( EUID != 0 )); then
    log_error "Must run as root"
fi

# -------------------------------------------------------------------------
# Validate hostname length (AD supports up to 15 characters for NetBIOS)
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

# -------------------------------------------------------------------------
# Setup logging
# -------------------------------------------------------------------------
LOG_FILE="/var/log/linux-ad-domain-join.log"
mkdir -p "$(dirname "$LOG_FILE")"
: > "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)

DRY_RUN=false
NONINTERACTIVE=false
VERBOSE=false

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)    DRY_RUN=true ;;
        --yes|-y)     NONINTERACTIVE=true ;;
        --verbose|-v) VERBOSE=true ;;
        *)
            log_error "Unknown option: $1" 1
            ;;
    esac
    shift
done

to_lower(){ echo "$1" | tr '[:upper:]' '[:lower:]'; }

trim_line(){ sed -e 's/^[[:space:]]\+//' -e 's/^[[:space:]]*[-*•][[:space:]]\+//' -e 's/[[:space:]]\+$//' -e '/[Cc]url error/ s/[[:space:]]\[[^]]*\][[:space:]]*$//'; }

# Extract the first real command (ignores VAR=VAL)
first_bin_from_cmd() {
    awk '{
        for (i=1; i<=NF; i++) {
            if ($i ~ /^[A-Za-z_][A-Za-z0-9_]*=/) continue;
            print $i; exit
        }
    }' <<< "$*"
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
        pk_apt=$(grep -m1 -oE 'NO_PUBKEY[[:space:]]+[0-9A-F]+' "$log" | trim_line)
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

run_cmd(){
    if $DRY_RUN; then echo "[DRY-RUN] $*"; else eval "$@"; fi
}

run_cmd_logged() {
    if $VERBOSE; then
        set +e
        LC_ALL=C LANG=C eval "$@"
        local ret=$?
        set -e
        (( ret == 0 )) || log_error "Command failed: $* (exit $ret)" "$ret"
        return
    fi

    $DRY_RUN && { echo "[DRY-RUN] $*"; return; }

    # identify the real binary (ignores VAR=VAL)
    local bin; bin="$(first_bin_from_cmd "$*")"
    [[ -n "$bin" ]] || bin="${1%% *}"
    command -v "$bin" &>/dev/null || log_error "Command not found: $bin" 127

    local tmp_out ret; tmp_out="$(mktemp)"
    set +e
    LC_ALL=C LANG=C eval "$@" >"$tmp_out" 2>&1
    ret=$?
    set -e

    if (( ret != 0 )); then
        # try to parse friendly output; if no match, show the last useful line
        if ! parse_pkg_error "$tmp_out" "$bin"; then
            local last; last=$(sed -n '/./p' "$tmp_out" | tail -n1 | trim_line)
            [[ -n "$last" ]] && log_info "❗ $last"
        fi
        rm -f "$tmp_out"
        log_error "Command failed: $* (exit code $ret)" "$ret"
    else
        local last; last=$(sed -n '/./p' "$tmp_out" | tail -n1 | trim_line)
        rm -f "$tmp_out"
    fi
}

check_cmd(){
    command -v "$1" >/dev/null || log_error "Required command '$1' not found" 1
}

# -------------------------------------------------------------------------
# Safe wrapper for realm list (handles systems without realmd or with DBus timeout)
# -------------------------------------------------------------------------
safe_realm_list() {
    local timeout_s=5
    local tmp_out; tmp_out="$(mktemp)"

    if ! command -v realm >/dev/null 2>&1; then
        # Older systems: emulate empty result
        echo "" > "$tmp_out"
        log_info "ℹ realmd not installed; skipping realm enumeration" >&2
    else
        # Execute with timeout; suppress DBus activation logs
        timeout "$timeout_s" realm list >"$tmp_out" 2>/dev/null
        local code=$?
        if (( code != 0 )); then
            log_info "ℹ realm list timed out or failed (code $code)" >&2
            echo "" > "$tmp_out"
        fi
    fi

    # Output contents (may be empty)
    cat "$tmp_out"
    rm -f "$tmp_out"
}

# distro detection
. /etc/os-release
case "$ID" in
    ubuntu|debian) OS_FAMILY=debian; PKG=apt; SSH_G=sudo ;;
	rhel|rocky|almalinux) OS_FAMILY=rhel; PKG=dnf; SSH_G=wheel ;;
	centos) OS_FAMILY=rhel; PKG=$([[ ${VERSION_ID%%.*} -lt 8 ]] && echo yum || echo dnf); SSH_G=wheel ;;
    oracle|ol) OS_FAMILY=rhel; VER_NUM=$(grep -Eo '[0-9]+' /etc/oracle-release | head -1); PKG=$([[ ${VER_NUM:-0} -lt 8 ]] && echo yum || echo dnf); SSH_G=wheel ;;
    sles|suse) OS_FAMILY=suse; PKG=zypper; SSH_G=wheel ;;
    fedora) OS_FAMILY=rhel; PKG=dnf; SSH_G=wheel ;;
    amzn) OS_FAMILY=rhel; PKG=dnf; SSH_G=wheel ;;
    *) log_error "Unsupported distro: $ID. You may need to extend the detection logic." ;;
esac
OS_NAME=${PRETTY_NAME:-$ID}
OS_VERSION=${VERSION_ID:-$(uname -r)}
OS_ARCH=$(uname -m)
KERNEL_VER=$(uname -r)

log_info "🌐 Hostname: $(hostname) / IP(s): $(hostname -I | awk '{print $1}')"
log_info "🧬 OS detected: $OS_NAME ($ID $OS_VERSION, kernel $KERNEL_VER, arch $OS_ARCH)"
log_info "🧬 OS family: $OS_FAMILY, Package Manager: $PKG, SSH group: $SSH_G"

# -------------------------------------------------------------------------
# Smart Internet Connectivity Detection (dynamic and autonomous)
# -------------------------------------------------------------------------
log_info "🌐 Detecting Internet connectivity intelligently"
HAS_INTERNET=false
CONNECT_DETAILS=()

# Detect default route / gateway
DEFAULT_ROUTE=$(ip route get 1.1.1.1 2>/dev/null | awk '/via/ {print $3; exit}')
if [[ -n "$DEFAULT_ROUTE" ]]; then
    CONNECT_DETAILS+=( "✅ Default route detected via gateway $DEFAULT_ROUTE" )
else
    CONNECT_DETAILS+=( "🛑 No default route - host likely isolated or LAN-only" )
fi

# Check DNS functionality (without relying on specific domains)
DNS_SERVER=$(grep -m1 '^nameserver' /etc/resolv.conf | awk '{print $2}')
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
    log_info "   $line"
done

# -------------------------------------------------------------------------
# [Self-Healing] Detect and repair RPM database corruption (RHEL-like only)
# -------------------------------------------------------------------------
if [[ -f /etc/redhat-release || -f /etc/centos-release || -f /etc/oracle-release || -f /etc/rocky-release || -f /etc/almalinux-release ]]; then
    log_info "🧩 Checking RPM database integrity"

    # Test basic query (lightweight check)
    if ! rpm -qf /etc/redhat-release &>/dev/null; then
        log_info "⚙ RPM database appears corrupted - initiating recovery"

        # Backup existing RPM database
        if [[ -d /var/lib/rpm ]]; then
            backup_path="/var/lib/rpm.bak.$(date +%F_%H-%M)"
            cp -a /var/lib/rpm "$backup_path" 2>/dev/null || true
            log_info "💾 Backup created at: $backup_path"
        fi

        # Remove potential stale locks
        rm -f /var/lib/rpm/__db.* 2>/dev/null

        # Attempt rebuild
        if rpm --rebuilddb &>/dev/null; then
            log_info "✅ RPM database rebuilt successfully"
        else
            log_error "Failed to rebuild RPM database. Please investigate manually at $backup_path" 8
        fi

        # Re-test after rebuild
        if ! rpm -qf /etc/redhat-release &>/dev/null; then
            log_error "RPM database still corrupted after rebuild. Aborting execution." 9
        fi
    else
        log_info "✅ RPM database integrity verified"
    fi
fi

# -------------------------------------------------------------------------
# Auto-install missing dependencies (connectivity-aware)
# -------------------------------------------------------------------------
install_missing_deps() {
    # Define the list of packages to install from the function arguments first
    local to_install=( "$@" )
	
	# ---------------------------------------------------------------------
    # Enforce connectivity check result before installation
    # ---------------------------------------------------------------------
    if [[ "$HAS_INTERNET" == "false" ]]; then
        log_error "System is offline and missing required packages: ${to_install[*]}" 100
    fi
	
    log_info "🔌 Installing missing packages: ${to_install[*]}"
    $VERBOSE && log_info "🧬 install_missing_deps() entered with args: $*"
	
    # Proceed directly with the installation command.
	# 'dnf/yum install' is more resilient than 'repolist' and can handle partial repo outages.
	# Includes protections identified during field debugging.
    case "$PKG" in
        apt)
            run_cmd_logged "DEBIAN_FRONTEND=noninteractive apt-get update -qq"
            run_cmd_logged "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${to_install[*]}"
            ;;
        yum|dnf)
            # Start with flags common to both yum and dnf
            local extra_flags="--noplugins"
			
            # Add dnf-only flags
            if [[ "$PKG" == "dnf" ]]; then
                extra_flags+=" -4"
            fi
            run_cmd_logged "$PKG install $extra_flags -y ${to_install[*]}"
			;;
        zypper)
            run_cmd_logged "zypper install -n ${to_install[*]}"
            ;;
		*)
            log_error "Unsupported package manager: $PKG" 101
            ;;
    esac
}

# -------------------------------------------------------------------------
# List required tools
# -------------------------------------------------------------------------
tools=( realm adcli kinit kdestroy timedatectl systemctl sed grep tput timeout hostname cp chmod tee ldapsearch ldapmodify chronyc nc )

# Add PAM config tool based on OS family
case "$OS_FAMILY" in
    debian)
		tools+=( pam-auth-update )
		;;
    rhel)
		RHEL_MAJOR=$(rpm -q --qf '%{VERSION}' $(rpm -qf /etc/redhat-release) | cut -d. -f1)
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
               ldap-utils chrony dialog )
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
		RHEL_MAJOR=$(rpm -q --qf '%{VERSION}' "$(rpm -qf /etc/redhat-release)" | cut -d. -f1)
		pkgs=( realmd sssd sssd-tools adcli oddjob oddjob-mkhomedir \
			   krb5-workstation chrony openldap-clients nmap-ncat )
		if (( RHEL_MAJOR < 8 )); then
			pkgs+=( authconfig )
		else
			# RHEL 8 - authselect, package renamed
			pkgs+=( authselect )
		fi
		;;
    suse)
		pkgs=( realmd sssd adcli oddjob oddjob-mkhomedir \
			   krb5-client pam-config chrony )
		# Prefer openldap2-client (SLES 12) or openldap-clients (Leap 15/SLES 15)
		if zypper se -x openldap-clients >/dev/null 2>&1; then
			pkgs+=( openldap-clients )
		else
			pkgs+=( openldap2-client )
		fi

		# Prefer netcat-openbsd or nmap-ncat if available
		if zypper se -x netcat-openbsd >/dev/null 2>&1; then
			pkgs+=( netcat-openbsd )
		elif zypper se -x nmap-ncat >/dev/null 2>&1; then
			pkgs+=( nmap-ncat )
		else
			pkgs+=( netcat )
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
		RHEL_MAJOR=$(rpm -q --qf '%{VERSION}' $(rpm -qf /etc/redhat-release) | cut -d. -f1)
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

# gather inputs
if $NONINTERACTIVE; then
    : "${DOMAIN:?DOMAIN required}"
    : "${OU:?OU required}"
    : "${DC_SERVER:?DC_SERVER required}"
    : "${DOMAIN_USER:?DOMAIN_USER required}"
    : "${DOMAIN_PASS:?DOMAIN_PASS required}"
else
    log_info "🧪 Collecting inputs"
    DIVIDER=$(printf '%*s\n' "$(tput cols)" '' | tr ' ' '-')
    echo "$DIVIDER"
	
    read -rp "Domain (e.g., acme.net): " DOMAIN
	DOMAIN_UPPER=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
	DOMAIN_SHORT=$(echo "$DOMAIN" | cut -d'.' -f1 | tr '[:lower:]' '[:upper:]')
	
	default_OU="OU=Servers,OU=DC_ORACLE,OU=SITES,OU=OPERATIONS,OU=${DOMAIN_SHORT},OU=COMPANIES,DC=${DOMAIN_SHORT},DC=$(echo "$DOMAIN" | cut -d'.' -f2 | tr '[:lower:]' '[:upper:]')"
	read -rp "OU [default: ${default_OU}]: " OU
	OU=${OU:-$default_OU}
	
	default_DC_SERVER="${DOMAIN_SHORT,,}-sp-ad01.${DOMAIN,,}"
	read -rp "DC server [default: ${default_DC_SERVER}]: " DC_SERVER
	DC_SERVER=${DC_SERVER:-$default_DC_SERVER}
	
    read -rp "Join user (e.g., adm-l.lima): " DOMAIN_USER
    read -rsp "Password for $DOMAIN_USER: " DOMAIN_PASS; printf '%*s\n' 16 '' | tr ' ' '*'
fi

for var in DOMAIN OU DC_SERVER DOMAIN_USER DOMAIN_PASS; do
    [[ -n "${!var}" ]] || log_error "$var is required" 1
done

# -------------------------------------------------------------------------
# Global admin group(s) for SSH AllowGroups
# -------------------------------------------------------------------------
if $NONINTERACTIVE; then
    : "${GLOBAL_ADMIN_GROUPS:?GLOBAL_ADMIN_GROUPS required in non-interactive mode}"
else
    echo "Define the global admin group(s) allowed SSH access (space-separated):"
    read -rp "Global admin group(s): " GLOBAL_ADMIN_GROUPS
    while [[ -z "$GLOBAL_ADMIN_GROUPS" ]]; do
        echo "⚠️ You must specify at least one group."
        read -rp "Global admin group(s): " GLOBAL_ADMIN_GROUPS
    done
fi

log_info "🔐 Using global admin group(s) for SSH access: $GLOBAL_ADMIN_GROUPS"

# prepare environment
REALM=${DOMAIN^^}
OS_NAME=$PRETTY_NAME
OS_VERSION=$(uname -r)
HOST_FQDN="$(hostname -s).$(to_lower "$DOMAIN")"

# Hostname format for Kerberos (uppercase short name)
HOST_SHORT=$(hostname -s)
HOST_SHORT_U=$(echo "$HOST_SHORT" | tr '[:lower:]' '[:upper:]')
MACHINE_PRINCIPAL="${HOST_SHORT_U}\$@${REALM}"

# -------------------------------------------------------------------------
# Hostname and FQDN Consistency Validation (/etc/hostname, /etc/hosts)
# -------------------------------------------------------------------------
log_info "🔍 Validating hostname and FQDN consistency"

HOSTS_FILE="/etc/hosts"

# Detect primary IPv4 address (excluding loopback interfaces)
PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i!~/^127\./){print $i; exit}}')
if [[ -z "$PRIMARY_IP" ]]; then
    PRIMARY_IP=$(ip -4 addr show scope global | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
fi
[[ -z "$PRIMARY_IP" ]] && log_error "Unable to detect primary IP address (no active NIC found)" 15

# Ensure /etc/hostname contains the correct short hostname
if [[ -f /etc/hostname ]]; then
    CURRENT_HOSTNAME_FILE=$(< /etc/hostname)
    if [[ "$CURRENT_HOSTNAME_FILE" != "$HOST_SHORT" ]]; then
        echo "$HOST_SHORT" > /etc/hostname
        log_info "🧩 Updated /etc/hostname to '$HOST_SHORT'"
    fi
else
    echo "$HOST_SHORT" > /etc/hostname
    log_info "🧩 Created /etc/hostname with '$HOST_SHORT'"
fi

# /etc/hosts:
#    - DO NOT delete existing content
#    - Only fix/create the local hostname entry
#    - Preserve IPv6, comments, static entries for other hosts, etc.
#    - Backup before making changes

if [[ ! -f "$HOSTS_FILE" ]]; then
    log_info "⚙️ Creating new $HOSTS_FILE"
    echo "127.0.0.1   localhost" > "$HOSTS_FILE"
else
    # Ensure a basic IPv4 localhost line exists
    if ! grep -qE '^[[:space:]]*127\.0\.0\.1[[:space:]]+.*\blocalhost\b' "$HOSTS_FILE"; then
        echo "127.0.0.1   localhost" >> "$HOSTS_FILE"
    fi
fi

# Perform safe backup before modification
cp -p "$HOSTS_FILE" "${HOSTS_FILE}.bak.$(date +%s)"
log_info "💾 Backup saved as ${HOSTS_FILE}.bak.$(date +%s)"

# Now we will generate a new in-memory version that:
# - Updates the line mentioning this host (shortname or FQDN) to reflect the correct IP
# - If no line for this host exists, adds a clean one at the end

if grep -qE "^[[:space:]]*[^#]*\b(${HOST_FQDN}|${HOST_SHORT})\b" "$HOSTS_FILE"; then
    log_info "🧩 Found existing /etc/hosts entry for this host - checking for drift"

    # Execute the AWK block in a temporary file, capturing stderr
	awk -v ip="$PRIMARY_IP" -v fqdn="$HOST_FQDN" -v short="$HOST_SHORT" '
		BEGIN { updated=0 }
		{
			# Preserve comments as-is
			if ($0 ~ /^[[:space:]]*#/) { print; next }

			# Line references this machine? (either FQDN or shortname as hostname token)
			match_self = 0
			if ($0 ~ ("[[:space:]]"fqdn"([[:space:]]|$)")) match_self=1
			if ($0 ~ ("[[:space:]]"short"([[:space:]]|$)")) match_self=1

			if (match_self) {
				# Rewrite canonical line: "<IP>\t<FQDN> <SHORT>"
				printf "%s\t%s %s\n", ip, fqdn, short
				updated=1
			} else {
				print
			}
		}
		END {
			if (updated==1) {
				printf "[i] Host mapping updated to %s -> %s %s\n", ip, fqdn, short > "/dev/stderr"
			}
		}
	' "$HOSTS_FILE" > "${HOSTS_FILE}.tmp" 2> "${HOSTS_FILE}.awklog"

	# If there are messages in the awk log, send them to log_info
	if [[ -s "${HOSTS_FILE}.awklog" ]]; then
		while IFS= read -r line; do
			log_info "$line"
		done < "${HOSTS_FILE}.awklog"
	fi

	# Apply safe substitution
	mv -f "${HOSTS_FILE}.tmp" "$HOSTS_FILE"
	rm -f "${HOSTS_FILE}.awklog"
else
    # No entry for the current host → add a clean new line at the end
    log_info "➕ Adding local host mapping to /etc/hosts: ${PRIMARY_IP} ${HOST_FQDN} ${HOST_SHORT}"
    printf "%s\t%s %s\n" "$PRIMARY_IP" "$HOST_FQDN" "$HOST_SHORT" >> "$HOSTS_FILE"
fi

# Remove Ubuntu-style 127.0.1.1 entries (can break Kerberos reverse lookups)
if grep -qE '^[[:space:]]*127\.0\.1\.1[[:space:]]+' "$HOSTS_FILE"; then
    log_info "⚙️ Removing obsolete 127.0.1.1 hostname entries (Ubuntu/Debian compatibility fix)"
    sed -i '/^[[:space:]]*127\.0\.1\.1[[:space:]]\+/d' "$HOSTS_FILE"
fi

# Adjust default permissions
chmod 644 "$HOSTS_FILE"

if ! grep -qE "^[[:space:]]*${PRIMARY_IP}[[:space:]]+${HOST_FQDN}" "$HOSTS_FILE"; then
    log_error "Host mapping not applied correctly in /etc/hosts"
else
    log_info "✅ Host mapping verified for ${HOST_FQDN} (${PRIMARY_IP})"
fi

# Ensure that the runtime hostname resolves correctly (hostname -f)
if [[ "$(hostname -f 2>/dev/null)" != "$HOST_FQDN" ]]; then
    hostnamectl set-hostname "$HOST_SHORT" 2>/dev/null || hostname "$HOST_SHORT"
    log_info "⚙️ Adjusted runtime hostname for FQDN resolution"
fi

log_info "✅ Hostname/FQDN consistency validation complete"

# Pre-check: verify DNS and KDC connectivity
log_info "🔎 Performing pre-check for DNS and KDC reachability"

# Test DNS resolution
if ! host "$DC_SERVER" &>/dev/null; then
    log_error "Unable to resolve domain controller: $DC_SERVER (check DNS configuration)" 10
fi

# Test Kerberos (TCP/88)
if nc -z -w3 "$DC_SERVER" 88 &>/dev/null 2>&1; then
    :  # ok
elif nc -w3 "$DC_SERVER" 88 </dev/null &>/dev/null 2>&1; then
    :  # fallback for old Ncat (no -z)
elif timeout 3 bash -c "echo > /dev/tcp/$DC_SERVER/88" 2>/dev/null; then
    :  # fallback for systems without working nc
else
    log_error "Cannot reach Kerberos port 88 on $DC_SERVER (network/firewall issue)" 11
fi

# Test LDAP (TCP/389)
if nc -z -w3 "$DC_SERVER" 389 &>/dev/null 2>&1; then
    :  # ok
elif nc -w3 "$DC_SERVER" 389 </dev/null &>/dev/null 2>&1; then
    :  # fallback for old Ncat
elif timeout 3 bash -c "echo > /dev/tcp/$DC_SERVER/389" 2>/dev/null; then
    :  # fallback
else
    log_error "Cannot reach LDAP port 389 on $DC_SERVER (network/firewall issue)" 12
fi

# Optional: SRV record check
if ! dig +short _kerberos._tcp."$DOMAIN" &>/dev/null; then
    log_info "⚠️ No _kerberos._tcp SRV records found for $DOMAIN (realm discovery may fail)"
fi

log_info "✅ DNS and KDC reachability OK"

# verify credentials
log_info "🔐 Verifying credentials for $DOMAIN_USER@$REALM"
KRB_TRACE=$(mktemp)

trap - ERR
set +e
echo "$DOMAIN_PASS" | KRB5_TRACE="$KRB_TRACE" kinit "$DOMAIN_USER@$REALM" >/dev/null 2>&1
KINIT_CODE=$?
set -e

# Restore global trap after controlled block
trap 'log_error "Unexpected error at line $LINENO in \"$BASH_COMMAND\"" $?' ERR

# analyze both return code AND trace contents
if (( KINIT_CODE == 0 )) && ! grep -qiE 'CLIENT_LOCKED_OUT|revoked|disabled|locked out|denied|expired' "$KRB_TRACE"; then
    kdestroy -q
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
    else
        last_msg=$(grep -E 'krb5|KRB5|error|revoked|denied' "$KRB_TRACE" | tail -n 1 | sed -E 's/\s+/ /g')
        [[ -n "$last_msg" ]] && log_info "ℹ Last trace line: $last_msg"
        log_error "Kerberos authentication failed with unknown reason (exit $KINIT_CODE)" 14
    fi
fi
rm -f "$KRB_TRACE"

# -------------------------------------------------------------------------
# Self-Destruction Mechanism (Local Execution Safety Guard)
# -------------------------------------------------------------------------
if [[ -f "$0" && -w "$0" ]]; then
    exec 3< "$0"             # Keep script loaded in memory
    rm -f -- "$0"            # Delete file from disk (cleanup)
else
    log_info "ℹ Skipping self-removal (script not a regular file: $0)"
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
    if kinit -kt /etc/krb5.keytab "$MACHINE_PRINCIPAL" >/dev/null 2>&1; then
        kdestroy -q
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
            REALM_LEAVE_CMD="realm leave --force"
        else
            REALM_LEAVE_CMD="realm leave --unattended"
        fi

        if [[ "$VERBOSE" == "true" ]]; then
            $REALM_LEAVE_CMD || REALMLEAVE_RC=$?
        else
            $REALM_LEAVE_CMD >/dev/null 2>&1 || REALMLEAVE_RC=$?
        fi

        REALMLEAVE_RC=${REALMLEAVE_RC:-0}
        if [[ $REALMLEAVE_RC -eq 0 ]]; then
            log_info "✅ Successfully left current realm."
        else
            log_info "⚠️ Leave operation returned non-zero code ($REALMLEAVE_RC) - continuing with cleanup."
        fi
    else
        log_info "ℹ️ No active realm detected - performing residual cleanup to ensure a fresh join."
    fi

    # Always perform residual cleanup
    rm -f /etc/krb5.keytab /etc/sssd/sssd.conf /etc/realmd.conf
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
DOMAIN_LOWER="${DOMAIN,,}"

# Backup existing krb5.conf if present
if [[ -f "$KRB_CONF" ]]; then
    KRB_BAK="${KRB_CONF}.bak.$(date +%s)"
    cp -p "$KRB_CONF" "$KRB_BAK"
    log_info "💾 Backup created: $KRB_BAK"
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
    cat >"$KRB_CONF" <<EOF
[libdefaults]
    default_realm = $REALM_UPPER
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true
    rdns = false
    allow_weak_crypto = false

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
    cat >"$KRB_CONF" <<EOF
[libdefaults]
    default_realm = $REALM_UPPER
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true
    rdns = false
    allow_weak_crypto = false

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
chmod 644 "$KRB_CONF"
log_info "✅ /etc/krb5.conf regenerated for realm $REALM_UPPER"

# -------------------------------------------------------------------------
# Enable SSSD and PAM mkhomedir (per-distro native)
# -------------------------------------------------------------------------
log_info "🔑 Configuring PAM for SSSD login and mkhomedir"

case $OS_FAMILY in
	debian)
		run_cmd_logged "pam-auth-update --enable sss mkhomedir --force"
	;;
	rhel|ol|rocky|almalinux|centos)
		RHEL_MAJOR=$(rpm -q --qf '%{VERSION}' $(rpm -qf /etc/redhat-release) | cut -d. -f1)
		if (( RHEL_MAJOR < 8 )); then
			# RHEL/CentOS/OL 6–7 → authconfig
			run_cmd_logged "LANG=C LC_ALL=C authconfig --enablesssd --enablesssdauth --enablemkhomedir --update"
		else
			# RHEL/OL 8+ → authselect
			run_cmd_logged "authselect select sssd with-mkhomedir --force"
			run_cmd_logged "systemctl enable --now oddjobd"
		fi
	;;
	suse)
		run_cmd_logged "pam-config -a --sss --mkhomedir"
	;;
	*)
		log_info "⚠ Unsupported OS_FAMILY for PAM automation: $OS_FAMILY"
	;;
esac

# -------------------------------------------------------------------------
# Ensure oddjob mkhomedir D-Bus registration (RHEL/OL fix, NO installs here)
# Place this block right AFTER enabling mkhomedir (authconfig/authselect)
# -------------------------------------------------------------------------

# Only for RHEL-like families
if [[ "$OS_FAMILY" =~ ^(rhel|ol|centos|rocky|almalinux)$ ]]; then
    log_info "🧩 Verifying oddjob mkhomedir D-Bus registration (no package installs)"

    DBUS_SVC="/usr/share/dbus-1/system-services/com.redhat.oddjob.service"
    ODDJOB_XML="/etc/oddjobd.conf.d/mkhomedir.conf"
    ODDJOB_SERVICE="oddjobd.service"
    ODDJOB_CHANGED=0

    mkdir -p "$(dirname "$DBUS_SVC")" "$(dirname "$ODDJOB_XML")"

    # Create/repair the D-Bus service auto-activation file (idempotent)
    if [[ ! -f "$DBUS_SVC" ]]; then
        log_info "[>] Restoring D-Bus service file: $DBUS_SVC"
        install -m 0644 -D /dev/stdin "$DBUS_SVC" <<'EOF'
[D-BUS Service]
Name=com.redhat.oddjob
Exec=/usr/sbin/oddjobd -n
User=root
SystemdService=oddjobd.service
EOF
        ODDJOB_CHANGED=1
    fi

    # Create/repair the oddjob XML interface for mkhomedir (idempotent)
    if [[ ! -f "$ODDJOB_XML" ]]; then
        log_info "[>] Restoring oddjob mkhomedir XML: $ODDJOB_XML"
        install -m 0644 -D /dev/stdin "$ODDJOB_XML" <<'EOF'
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

    # Apply SELinux contexts (if available) and reload managers when files change
    if (( ODDJOB_CHANGED == 1 )); then
        command -v restorecon >/dev/null 2>&1 && restorecon -F "$DBUS_SVC" "$ODDJOB_XML" 2>/dev/null || true
        run_cmd_logged "systemctl daemon-reload"
        if command -v busctl >/dev/null 2>&1; then
            busctl call org.freedesktop.DBus / org.freedesktop.DBus ReloadConfig 2>/dev/null || true
        else
            dbus-send --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig >/dev/null 2>&1 || true
        fi
    fi

    # Ensure service is enabled/active
    if ! systemctl is-enabled "$ODDJOB_SERVICE" &>/dev/null; then
        log_info "[>] Enabling $ODDJOB_SERVICE"
        run_cmd_logged "systemctl enable $ODDJOB_SERVICE"
    fi
    if ! systemctl is-active --quiet "$ODDJOB_SERVICE"; then
        log_info "[>] Starting $ODDJOB_SERVICE"
        run_cmd_logged "systemctl start $ODDJOB_SERVICE"
    fi

    # Tolerant D-Bus probe (AccessDenied is common on OL7 and not fatal)
    if dbus-send --system --dest=com.redhat.oddjob_mkhomedir --print-reply / com.redhat.oddjob_mkhomedir.Hello &>/dev/null; then
        log_info "✅ oddjob mkhomedir D-Bus service operational"
    else
        log_info "ℹ️ D-Bus Hello denied or unavailable — common on OL7; PAM auto-activation may still work"
    fi

    # Final health validation (files + service)
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
	rhel|rocky|almalinux|centos|ol)
		PAM_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
		;;
	debian|ubuntu|suse)
		PAM_FILES=("/etc/pam.d/common-auth" "/etc/pam.d/common-account" "/etc/pam.d/common-session" "/etc/pam.d/common-password")
		;;
	*)
		log_info "ℹ Unknown PAM layout for $OS_FAMILY — skipping PAM consistency check"
		PAM_FILES=()
		;;
esac

for file in "${PAM_FILES[@]}"; do
	if [[ ! -f "$file" ]]; then
		log_info "ℹ Skipping non-existent PAM file: $file"
		continue
	fi

	PAM_BACKUP="${file}.bak.$(date +%Y%m%d%H%M%S)"
	run_cmd "cp -p \"$file\" \"$PAM_BACKUP\"" && log_info "💾 Backup saved: $PAM_BACKUP"

	# Disable legacy PAM modules (safe-comment)
	if grep -Eq 'pam_(ldap|winbind|nis)\.so' "$file"; then
		run_cmd_logged "sed -i '/pam_ldap\\.so/s/^/# disabled legacy -> /' \"$file\""
		run_cmd_logged "sed -i '/pam_winbind\\.so/s/^/# disabled legacy -> /' \"$file\""
		run_cmd_logged "sed -i '/pam_nis\\.so/s/^/# disabled legacy -> /' \"$file\""
	fi

	# Guarantee pam_sss.so presence per section
	for context in auth account password session; do
		if ! grep -Eq "^[[:space:]]*${context}[[:space:]].*pam_sss\\.so" "$file"; then
			case "$context" in
				auth)
					echo "auth        sufficient    pam_sss.so forward_pass" >>"$file"
					;;
				account)
					echo "account     [default=bad success=ok user_unknown=ignore] pam_sss.so" >>"$file"
					;;
				password)
					echo "password    sufficient    pam_sss.so use_authtok" >>"$file"
					;;
				session)
					echo "session     optional      pam_sss.so" >>"$file"
					;;
			esac
			log_info "🧩 Added missing pam_sss.so for $context → $(basename "$file")"
		fi
	done
done

# Re-run consistency for RHEL-like systems
if [[ "$OS_FAMILY" =~ ^(rhel|ol|rocky|almalinux|centos)$ ]]; then
	if command -v authconfig >/dev/null 2>&1; then
		run_cmd_logged "LANG=C LC_ALL=C authconfig --update"
	fi
fi

# -------------------------------------------------------------------------
# Final PAM validation (cross-distro, symlink-aware, fallback-safe)
# -------------------------------------------------------------------------
log_info "🔍 Performing PAM validation with symbolic link awareness"

PAM_VALIDATE_FILES=()
case "$OS_FAMILY" in
	rhel|ol|centos|rocky|almalinux)
		for f in /etc/pam.d/system-auth /etc/pam.d/system-auth-ac /etc/pam.d/password-auth /etc/pam.d/password-auth-ac; do
			[[ -e "$f" ]] && PAM_VALIDATE_FILES+=("$f")
		done
		;;
	debian|ubuntu)
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
	log_info "✅ PAM integration validated — pam_sss.so is active and correctly configured"
else
	log_info "⚠️ PAM validation ambiguous — no active pam_sss.so lines detected"
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
	umask 022
	cat >"$NSS_FILE" <<'EOF'
passwd:		files
shadow:		files
group:		files
hosts:		files dns
services:	files
netgroup:	files
EOF
	chmod 0644 "$NSS_FILE"
fi

# Basic access checks (after creation above to avoid false negatives)
[[ -r "$NSS_FILE" ]] || log_error "Cannot read $NSS_FILE — verify overlay/permissions." 1
[[ -w "$(dirname "$NSS_FILE")" ]] || log_error "NSS path $(dirname "$NSS_FILE") is not writable (read-only filesystem)." 1

# -------------------------------------------------------------------------
# ROBUST IMMUTABILITY DETECTION (lsattr/chattr)
# -------------------------------------------------------------------------
if command -v lsattr >/dev/null 2>&1; then
    # Temporarily disable -e to tolerate unsupported filesystems (e.g., XFS, Btrfs)
    set +e
    LSATTR_SUPPORTED=false

    # Test whether lsattr can actually operate on the target file
    if lsattr -d -- "$NSS_FILE" >/dev/null 2>&1; then
        LSATTR_SUPPORTED=true
    fi

    # Re-enable strict error mode
    set -e

    if $LSATTR_SUPPORTED; then
        log_info "🧩 Filesystem supports lsattr — checking for immutable attribute"

        # Extract flags safely; tolerate legacy lsattr output or missing fields
        LSATTR_FLAGS="$(lsattr -d -- "$NSS_FILE" 2>/dev/null | awk '{print $1}' || true)"

        if [[ -n "$LSATTR_FLAGS" ]] && echo "$LSATTR_FLAGS" | grep -q 'i'; then
            log_error "$NSS_FILE is immutable (chattr +i). Remove the immutable bit to proceed." 1
        fi
    else
        log_info "ℹ lsattr operation not supported by the underlying filesystem — skipping immutability check"
    fi
else
    log_info "ℹ lsattr not available on this system — skipping immutability check"
fi

# Normalize line endings (CRLF-safe) before backup
sed -i 's/\r$//' "$NSS_FILE"

# Choose a portable sed extended-regex flag (-E preferred, fallback to -r)
if echo | sed -E 's/(.*)//' >/dev/null 2>&1; then
	SED_EXT='-E'
elif echo | sed -r 's/(.*)//' >/dev/null 2>&1; then
	SED_EXT='-r'
else
	log_error "sed without extended regex support (-E/-r) — install a compatible sed." 1
fi

# Backup prior to modifications
NSS_BACKUP="${NSS_FILE}.bak.$(date +%Y%m%d%H%M%S)"
run_cmd "cp -p \"$NSS_FILE\" \"$NSS_BACKUP\""
log_info "💾 Backup saved as $NSS_BACKUP"

# -------------------------------------------------------------------------
# Helper: safely ensure `key:` line contains `sss` (cross-distro & legacy-safe)
# -------------------------------------------------------------------------
add_sss_if_missing() {
	local key="$1"
	local pattern="^[[:space:]]*${key}:"
	# Ensure counters exist (even if running under set -u or subshell)
	: "${NSS_ADDED:=0}"
	: "${NSS_CREATED:=0}"

	# 1. Does a non-commented line exist for this key?
	if grep -qE "${pattern}[^#]*" "$NSS_FILE"; then
		# 2. If it exists but lacks 'sss', patch it
		if ! grep -qE "${pattern}[^#]*sss" "$NSS_FILE"; then

			# 3. Remove conflicting legacy sources (ldap, nis, yp) and normalize whitespace
			run_cmd_logged "sed -i 's/[[:space:]]\\+(ldap|nis|yp)//g; s/[[:space:]]\\{2,\\}/ /g' \"$NSS_FILE\""

			# 4. UNIVERSAL INSERTION — works from sed 4.1.5 (2006) → 4.9 (2025)
			#    Using basic regex grouping (\(...\)) avoids unsupported -E/-r flags.
			run_cmd_logged "sed -i \
				-e 's/^\([[:space:]]*${key}:[^#]*\)\(#.*\)$/\1 sss \2/' \
				-e 's/^\([[:space:]]*${key}:[^#]*\)$/\1 sss/' \"$NSS_FILE\""

			# 5. Final dedupe/normalize (avoid 'sss sss' and extra spaces)
			run_cmd_logged "sed -i 's/sss[[:space:]]\\+sss/sss/g; s/[[:space:]]\\{2,\\}/ /g' \"$NSS_FILE\""

			log_info "✅ '${key}' updated"
			((NSS_ADDED++))
		fi
	else
		# 6. Create a new line when the key is missing entirely
		echo "${key}: files sss" >>"$NSS_FILE"
		log_info "➕ Created missing '${key}' entry"
		((NSS_CREATED++))
	fi
}

# -------------------------------------------------------------------------
# Apply to the core maps
# -------------------------------------------------------------------------
#for section in passwd shadow group services netgroup; do
#	add_sss_if_missing "$section"
#done

# Add sudoers on RHEL/SUSE (Debian/Ubuntu usually manage sudoers via PAM/files, not NSS)
if [[ "$OS_FAMILY" =~ ^(rhel|suse)$ ]]; then
	add_sss_if_missing "sudoers"
fi

# Final whitespace normalization (collapse multiple spaces, trim ends)
awk '{$1=$1}1' "$NSS_FILE" > "${NSS_FILE}.tmp" && mv "${NSS_FILE}.tmp" "$NSS_FILE"

# Restore SELinux context if applicable
command -v restorecon >/dev/null 2>&1 && restorecon -F "$NSS_FILE" || true

# -------------------------------------------------------------------------
# Validation and cache refresh
# -------------------------------------------------------------------------
if ! grep -qE '^passwd:[^#]*sss' "$NSS_FILE" || ! grep -qE '^group:[^#]*sss' "$NSS_FILE"; then
	log_error "Failed to configure NSS/SSSD for passwd/group lookups." 1
fi

# Optional runtime sanity checks (non-blocking)
getent passwd root >/dev/null || log_info "⚠ NSS runtime check (passwd) inconclusive — verify SSSD/NSCD"
getent group root >/dev/null || log_info "⚠ NSS runtime check (group) inconclusive — verify SSSD/NSCD"

# If legacy nslcd is present, stop it to avoid conflicts with SSSD
if command -v systemctl &>/dev/null; then
	systemctl list-units --type=service 2>/dev/null | grep -q '^nslcd\.service' && run_cmd_logged "systemctl stop nslcd || true"
fi

# Restart order: SSSD first (reads nsswitch/sssd.conf), then NSCD to clear caches
if command -v systemctl &>/dev/null; then
	# 1. SSSD
	if systemctl list-unit-files 2>/dev/null | grep -q '^sssd' || systemctl is-active sssd &>/dev/null; then
		log_info "🔄 Restarting SSSD"
		run_cmd_logged "systemctl restart sssd || true"
	fi
	# 2. NSCD
	if systemctl list-unit-files 2>/dev/null | grep -q '^nscd' || systemctl is-active nscd &>/dev/null; then
		log_info "🔄 Restarting NSCD"
		run_cmd_logged "systemctl restart nscd || true"
	fi
else
	# Non-systemd fallback
	pgrep sssd &>/dev/null && { pkill -HUP sssd; log_info "🔄 Reloaded sssd"; }
	pgrep nscd &>/dev/null && { pkill -HUP nscd; log_info "🔄 Reloaded nscd"; }
fi

# Explicit SSSD cache flush when available
if command -v sss_cache >/dev/null 2>&1; then
	# This only fails if SSSD is not running, which is fine.
	sss_cache -E || true
fi

log_info "🌟 NSS/SSSD integration completed successfully"

# -------------------------------------------------------------------------
# Disable legacy pam_ldap if SSSD is active (RHEL-like systems)
# -------------------------------------------------------------------------
if [[ "$OS_FAMILY" == "rhel" || "$OS_FAMILY" == "ol" || "$OS_FAMILY" == "rocky" || "$OS_FAMILY" == "almalinux" ]]; then
	log_info "🧩 Checking for legacy pam_ldap entries (system-auth, password-auth)"

	for pamfile in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
		[[ -f "$pamfile" ]] || continue

		# Backup
		cp -p "$pamfile" "${pamfile}.bak.$(date +%Y%m%d%H%M%S)"
		[[ $VERBOSE == true ]] && log_info "💾 Backup saved: ${pamfile}.bak.$(date +%Y%m%d%H%M%S)"

		# Detect presence of pam_ldap.so
		if grep -q "pam_ldap.so" "$pamfile"; then
			run_cmd_logged "sed -i 's/^[[:space:]]*auth.*pam_ldap\\.so/# &/; \
			                s/^[[:space:]]*account.*pam_ldap\\.so/# &/; \
			                s/^[[:space:]]*password.*pam_ldap\\.so/# &/; \
			                s/^[[:space:]]*session.*pam_ldap\\.so/# &/' \"$pamfile\""
		else
			[[ $VERBOSE == true ]] && log_info "ℹ No pam_ldap.so entries in $(basename "$pamfile")"
		fi
	done
fi

# configure NTP with domain
log_info "⏰ Configuring NTP to use domain ($DOMAIN)"

# Detect chrony configuration file path
if [[ -f /etc/chrony.conf ]]; then
    chrony_conf="/etc/chrony.conf"  # RHEL-like
elif [[ -f /etc/chrony/chrony.conf ]]; then
    chrony_conf="/etc/chrony/chrony.conf"  # Debian-like
else
    # Default fallback path (based on existing directory)
    if [[ -d /etc/chrony ]]; then
        chrony_conf="/etc/chrony/chrony.conf"
    else
        chrony_conf="/etc/chrony.conf"
    fi
fi

# Backup or initialize chrony.conf
if [[ -f "$chrony_conf" ]]; then
    cp "$chrony_conf" "${chrony_conf}.bak"
    log_info "💾 Backup of chrony.conf saved as ${chrony_conf}.bak"
else
    log_info "⚠️ File $chrony_conf not found. Creating a new one from scratch"
    mkdir -p "$(dirname "$chrony_conf")"
    touch "$chrony_conf"
fi

# Write new configuration (universal minimal config)
cat <<EOF > "$chrony_conf"
server $DOMAIN iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
EOF

# -------------------------------------------------------------------------
# Detect chrony service name safely (OL7 / RHEL7 compatible)
# -------------------------------------------------------------------------
chrony_service=""

# Prefer modern detection
if systemctl list-unit-files 2>/dev/null | grep -q '^chrony\.service'; then
    chrony_service="chrony"
elif systemctl list-unit-files 2>/dev/null | grep -q '^chronyd\.service'; then
    chrony_service="chronyd"
# Fallback for very old systemd (no list-unit-files)
elif [[ -f /usr/lib/systemd/system/chronyd.service ]]; then
    chrony_service="chronyd"
elif [[ -f /usr/lib/systemd/system/chrony.service ]]; then
    chrony_service="chrony"
fi

# Validation
if [[ -z "$chrony_service" ]]; then
    log_error "Unable to detect chrony service name - please ensure it is installed." 1
fi

# If detected unit is an alias, normalize to chrony.service
if [[ "$chrony_service" == "chronyd" && "$(readlink -f /etc/systemd/system/chronyd.service 2>/dev/null)" == *"chrony.service" ]]; then
    log_info "  Detected alias 'chronyd.service' → using real unit 'chrony.service'"
    chrony_service="chrony"
fi

# Enable and restart safely
run_cmd_logged "systemctl enable --now $chrony_service"
run_cmd "systemctl restart $chrony_service"

# -------------------------------------------------------------------------
# Wait for NTP synchronization (Chrony only, Debian/RHEL compatible)
# -------------------------------------------------------------------------
synced=false
start_time=$(date +%s)

for i in {1..30}; do
    if systemctl is-active "$chrony_service" &>/dev/null && \
       chronyc sources | grep -q '^\^\*' && \
       [[ "$(chronyc tracking | awk -F': *' '/Leap status/ {print $2}')" == "Normal" ]]; then
        synced_server=$(chronyc tracking | awk -F'[()]' '/Reference ID/ {print $2}')
        # clear previous line before printing success
        printf "\r\033[K" >&2
        log_info "✅ NTP synchronized successfully with: ${synced_server:-chrony}"
        synced=true
        break
    fi

    # real-time progress line
    printf "\r[%s] ℹ Waiting for NTP synchronization... (elapsed: %2ds / max: 30s)" \
		"$(date '+%F %T')" "$i" | sanitize_log_msg >&2
    sleep 1
done

# final line cleanup to prevent log breaking
printf "\r\033[K" >&2

if [[ "$synced" != true ]]; then
    log_info "⚠️ NTP is not yet synchronized with $DOMAIN after 30s; please verify chronyd logs"
else
    end_time=$(date +%s)
    elapsed=$(( end_time - start_time ))
    log_info "ℹ Time synchronization confirmed in ${elapsed}s - proceeding with Kerberos setup"
fi

log_info "🔑 Getting Kerberos ticket for user $DOMAIN_USER"
echo "$DOMAIN_PASS" | kinit "${DOMAIN_USER}@${REALM}" >/dev/null || {
    log_error "Failed to obtain Kerberos ticket for $DOMAIN_USER"
}

BASE_DN=$(awk -F, '{for (i=1; i<=NF; i++) if ($i ~ /^DC=/) print $i}' <<< "$OU" | paste -sd, -)

if $VERBOSE; then
    log_info "🧪 DEBUG: Testing LDAP search for computer object..."
    echo "🔸 HOST_SHORT_U: $HOST_SHORT_U"
    echo "🔸 OU: $OU"
    echo "🔸 BASE_DN: $BASE_DN"

    set +e
    LDAP_RAW=$(ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no \
      -H "ldap://${DC_SERVER}" \
      -b "$BASE_DN" "(sAMAccountName=${HOST_SHORT_U}\$)" distinguishedName 2>&1)
    LDAP_CODE=$?
    set -e

    echo "🔹 Exit Code: $LDAP_CODE"
    echo "🔹 LDAP Output:"
    echo "$LDAP_RAW"
fi

# ensure computer object is in correct OU (if exists)
log_info "🔍 Checking if computer object exists in AD"

set +e
LDAP_OUT=$(ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no -H "ldap://${DC_SERVER}" \
  -b "$BASE_DN" "(sAMAccountName=${HOST_SHORT_U}\$)" distinguishedName 2>/dev/null)
LDAP_CODE=$?
set -e

CURRENT_DN=$(echo "$LDAP_OUT" | grep -oP '^distinguishedName: \K.+' || true)
$VERBOSE && echo "$LDAP_OUT"

if [[ -n "$CURRENT_DN" ]]; then
    EXPECTED_DN="CN=${HOST_SHORT_U},${OU}"
    if [[ "$CURRENT_DN" == "$EXPECTED_DN" ]]; then
        $VERBOSE && log_info "ℹ️ Computer object is already in the correct OU"
    else
        log_info "♻️ Computer object is currently in OU: $CURRENT_DN"
        log_info "🚚 Moving object to target OU: $OU"

        if $VERBOSE; then
            ldapmodify -Y GSSAPI -H "ldap://${DC_SERVER}" <<EOF
dn: $CURRENT_DN
changetype: modrdn
newrdn: CN=${HOST_SHORT_U}
deleteoldrdn: 1
newsuperior: $OU
EOF
            LDAP_MOVE_CODE=$?
        else
            TMP_LDIF=$(mktemp)
            cat <<EOF > "$TMP_LDIF"
dn: $CURRENT_DN
changetype: modrdn
newrdn: CN=${HOST_SHORT_U}
deleteoldrdn: 1
newsuperior: $OU
EOF
            ldapmodify -Y GSSAPI -H "ldap://${DC_SERVER}" -f "$TMP_LDIF" >/dev/null 2>&1
            LDAP_MOVE_CODE=$?
            rm -f "$TMP_LDIF"
        fi

        if [[ "$LDAP_MOVE_CODE" -ne 0 ]]; then
            log_error "Failed to move computer object in AD (code $LDAP_MOVE_CODE)" 4
        fi
    fi
else
    log_info "📛 Computer object not found in AD. Proceeding with domain join."
fi

# -------------------------------------------------------------------------
# DOMAIN JOIN PHASE (adcli only + IP description)
# -------------------------------------------------------------------------
log_info "🔗 Joining domain $DOMAIN via adcli (direct mode, no realm)"

# Resolve DC IP for logging
DC_IP=$(getent hosts "$DC_SERVER" | awk '{print $1}' | head -n1)
[[ -z "$DC_IP" ]] && DC_IP=$(dig +short "$DC_SERVER" | head -n1)
log_info "🔍 Target DC for join: $DC_SERVER (${DC_IP:-unresolved})"

# Clean previous Kerberos tickets and renew authentication
kdestroy -q 2>/dev/null || true
echo "$DOMAIN_PASS" | kinit "${DOMAIN_USER}@${REALM}" >/dev/null 2>&1 || {
    log_error "Failed to obtain Kerberos ticket for $DOMAIN_USER@$REALM" 2
}

# Safely capture Kerberos principal (ignore klist exit errors)
set +e +o pipefail
KLIST_PRINCIPAL=$(klist 2>/dev/null | awk '/Default principal/ {print $3; exit}')
KLIST_RC=$?
set -e -o pipefail
[[ $KLIST_RC -ne 0 || -z "$KLIST_PRINCIPAL" ]] && KLIST_PRINCIPAL="(no active ticket)"

JOIN_LOG=$(mktemp)

# Execute adcli join deterministically
if echo "$DOMAIN_PASS" | timeout 90s adcli join \
    --verbose \
    --domain="$DOMAIN" \
    --domain-realm="$REALM" \
    --domain-controller="$DC_SERVER" \
    --domain-ou="$OU" \
    --login-user="$DOMAIN_USER" \
    --stdin-password \
    --host-fqdn="$HOST_FQDN" \
    --computer-name="$HOST_SHORT_U" \
    --host-keytab="/etc/krb5.keytab" \
    --os-name="$OS_NAME" \
    --os-version="$OS_VERSION" \
    --trusted-for-delegation=no \
    --add-service-principal="RestrictedKrbHost/${HOST_SHORT_U}" \
    --add-service-principal="RestrictedKrbHost/${HOST_FQDN}" \
    --add-service-principal="host/${HOST_SHORT_U}" \
    --add-service-principal="host/${HOST_FQDN}" \
    --show-details >"$JOIN_LOG" 2>&1; then
    log_info "✅ Joined domain successfully via adcli (DC: $DC_SERVER, IP: ${DC_IP:-unknown})"
else
    log_info "❌ Domain join failed. Last output lines:"
    tail -n 5 "$JOIN_LOG" | sed -E 's/^[[:space:]]+//'
    log_error "Domain join failed via adcli" 3
fi

kdestroy -q
rm -f "$JOIN_LOG"

# -------------------------------------------------------------------------
# Update AD Description with IP after successful join
# -------------------------------------------------------------------------
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [[ -n "$HOST_IP" ]]; then
    log_info "🧩 Updating AD description with IP: $HOST_IP"
    echo "$DOMAIN_PASS" | kinit "${DOMAIN_USER}@${REALM}" >/dev/null 2>&1 || \
        log_info "⚠️ Failed to refresh Kerberos ticket for description update"

    TMP_LDIF=$(mktemp)
	timestamp=$(date '+%Y-%m-%dT%H:%M:%S%z')
    cat <<EOF > "$TMP_LDIF"
dn: CN=${HOST_SHORT_U},${OU}
changetype: modify
replace: description
description: [${HOST_IP}] - Joined with adcli by ${DOMAIN_USER} on ${timestamp}
EOF
    if ldapmodify -Y GSSAPI -H "ldap://${DC_SERVER}" -f "$TMP_LDIF" >/dev/null 2>&1; then
        log_info "✅ Description updated successfully in AD"
    else
        log_info "⚠️ Unable to update AD description (check permissions or ticket validity)"
    fi
    rm -f "$TMP_LDIF"
else
    log_info "⚠️ Unable to detect host IP for AD description update"
fi

# Read the current msDS-KeyVersionNumber (to validate keytab update)
set +e +o pipefail
MSDS_KVNO=$(ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no \
    -H "ldap://${DC_SERVER}" \
    -b "CN=${HOST_SHORT_U},${OU}" msDS-KeyVersionNumber 2>/dev/null | \
    awk '/^msDS-KeyVersionNumber:/ {print $2}' | head -n1)
LDAP_RC=$?
set -e -o pipefail

if [[ $LDAP_RC -ne 0 || -z "$MSDS_KVNO" ]]; then
    log_info "⚠️ Unable to read msDS-KeyVersionNumber from AD (replication or Kerberos cache delay)"
    MSDS_KVNO="Unknown"
else
    log_info "ℹ️ msDS-KeyVersionNumber in AD: $MSDS_KVNO (Kerberos secret synchronized)"
fi

# Clean up temporary Kerberos ticket
kdestroy -q 2>/dev/null || true

# -------------------------------------------------------------------------
# Validate Active Directory trust (Kerberos/SSSD mode)
# -------------------------------------------------------------------------
log_info "🔍 Validating Active Directory trust integrity (Kerberos/SSSD mode)"

# Obtain a valid user TGT for administrative operations.
# NOTE: The password is provided securely via stdin and never exposed in process arguments or shell history.
log_info "ℹ Obtaining Kerberos ticket for synchronization"
echo "$DOMAIN_PASS" | kinit "${DOMAIN_USER}@${REALM}" >/dev/null 2>&1 || \
    log_error "Failed to obtain Kerberos ticket for ${DOMAIN_USER}@${REALM}" 2

# Temporarily relax '-e' and 'pipefail' and neutralize the global ERR trap to make this validation tolerant.
# Failures here must not abort the script.
__old_opts="$(set +o)"    # Save current 'set' options
__old_trap="$(trap -p ERR | sed -E 's/^trap -- //')"
set +e +o pipefail
trap - ERR

# -------------------------------------------------------------------------
# Kerberos keytab validation
# -------------------------------------------------------------------------
TRUST_STATUS="⚠️ Trust check failed"

# Attempt authentication using the local machine account keytab
if kinit -kt /etc/krb5.keytab "$(hostname -s | tr '[:lower:]' '[:upper:]')\$@${REALM}" >/dev/null 2>&1; then
    kdestroy -q
    TRUST_STATUS="✅ Kerberos trust OK"
    log_info "✅ Kerberos machine keytab authentication succeeded"
else
    log_info "⚠️ Kerberos keytab authentication failed - domain trust may be broken"
fi

# -------------------------------------------------------------------------
# Validate and re-enable computer object if disabled in AD
# -------------------------------------------------------------------------
log_info "🔧 Checking if computer object is disabled in AD..."

# Query userAccountControl via GSSAPI (machine trust)
UAC_RAW=$(ldapsearch -Y GSSAPI -LLL -o ldif-wrap=no -H "ldap://${DC_SERVER}" \
    -b "CN=${HOST_SHORT_U},${OU}" userAccountControl \
    2>$($VERBOSE && echo /dev/stderr || echo /dev/null) | \
    awk '/^userAccountControl:/ {print $2}' || true)

# Normalize to decimal if hexadecimal
if [[ "$UAC_RAW" =~ ^0x ]]; then
    UAC=$((UAC_RAW))
else
    UAC=$UAC_RAW
fi

# Check ACCOUNTDISABLE bit (0x2)
if (( (UAC & 2) != 0 )); then
    log_info "♻️ Computer object is disabled (UAC=$UAC). Re-enabling..."

    NEW_UAC=$((UAC & ~2))  # Clear only the disable bit, preserve other flags
    LDAP_OUT="/dev/null"
    $VERBOSE && LDAP_OUT="/dev/stderr"

    ldapmodify -Y GSSAPI -H "ldap://${DC_SERVER}" >"$LDAP_OUT" 2>&1 <<EOF
dn: CN=${HOST_SHORT_U},${OU}
changetype: modify
replace: userAccountControl
userAccountControl: $NEW_UAC
EOF

    log_info "✅ Computer object re-enabled successfully (userAccountControl=$NEW_UAC)"
else
    $VERBOSE && log_info "ℹ️ userAccountControl=$UAC (object is enabled or no action needed)"
fi

# -------------------------------------------------------------------------
# Configure SSSD
# -------------------------------------------------------------------------
SSSD_CONF=/etc/sssd/sssd.conf
if [[ -f $SSSD_CONF ]]; then
    bak=${SSSD_CONF}.bak.$(date +%s)
    log_info "💾 Backing up $SSSD_CONF to $bak"
    cp -p "$SSSD_CONF" "$bak"
fi

log_info "🛠️ Writing SSSD configuration (auto-discovery mode for DNS updates)"

# Detect responders available
AVAILABLE_RESPONDERS=()
for svc in nss pam pac; do
    [ -x "/usr/libexec/sssd/sssd_${svc}" ] && AVAILABLE_RESPONDERS+=("$svc")
done
SERVICES_LINE=$(IFS=,; echo "${AVAILABLE_RESPONDERS[*]}")

cat >"$SSSD_CONF" <<EOF
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
services = $SERVICES_LINE
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
ad_domain = $REALM
ad_hostname = $HOST_FQDN
krb5_realm = $REALM
krb5_keytab = /etc/krb5.keytab
realmd_tags = manages-system joined-with-adcli


# -------------------------------------------------------------------------
# General settings
# -------------------------------------------------------------------------
debug_level = 9
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
dyndns_update = True
dyndns_refresh_interval = 43200
dyndns_ttl = 3600
dyndns_update_ptr = True
EOF

run_cmd "chmod 600 $SSSD_CONF"
run_cmd "chown root:root $SSSD_CONF"

# Optional: flush old caches before restart
if command -v sss_cache >/dev/null 2>&1; then
    log_info "🔁 Flushing old SSSD caches"
    sss_cache -E >/dev/null 2>&1 || log_info "⚠️ Failed to flush SSSD cache (non-critical)"
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

# Configure su file
PAM_SU_FILE="/etc/pam.d/su"
log_info "🔐 Configuring /etc/pam.d/su for unified AD integration"

# Define base PAM configuration content
pam_su_base_content=$(cat <<EOF
auth   [success=1 default=ignore] pam_succeed_if.so quiet uid = 0
auth   [success=done default=ignore] pam_localuser.so
auth   sufficient pam_unix.so try_first_pass nullok
auth   sufficient pam_sss.so use_first_pass
auth   required   pam_deny.so
session required pam_env.so readenv=1
session required pam_env.so readenv=1 envfile=/etc/default/locale
session optional pam_mail.so nopen
session required pam_limits.so
EOF
)

case "$OS_FAMILY" in
  debian)
    pam_su_final_content="$pam_su_base_content
@include common-account
@include common-session"
    ;;
  rhel|suse)
    pam_su_final_content="$pam_su_base_content
account include system-auth
session include system-auth"
    ;;
esac

# Backup and apply
if [[ -f "$PAM_SU_FILE" ]]; then
    cp -p "$PAM_SU_FILE" "${PAM_SU_FILE}.bak.$(date +%s)"
    log_info "💾 Backup saved: ${PAM_SU_FILE}.bak.$(date +%s)"
fi

echo "$pam_su_final_content" > "$PAM_SU_FILE"
chmod 644 "$PAM_SU_FILE"
log_info "✅ PAM su file configured successfully"

log_info "🔄 Restarting SSSD"
run_cmd_logged "systemctl enable sssd"
run_cmd_logged "systemctl restart sssd"

unset DOMAIN_PASS

# configure SSH
log_info "🔒 Configuring SSH"
cfg=/etc/ssh/sshd_config
HOST_L=$(to_lower "$(hostname -s)")
ADM="grp-adm-$HOST_L"
ADM_ALL="grp-adm-all-linux-servers"
RDP="grp-ssh-$HOST_L"
RDP_ALL="grp-ssh-all-linux-servers"

ALLOW_GROUPS="$RDP $RDP_ALL $SSH_G root $GLOBAL_ADMIN_GROUPS"

if grep -q '^AllowGroups' "$cfg"; then
    run_cmd "sed -i \"/^AllowGroups/c\\AllowGroups $ALLOW_GROUPS\" $cfg"
else
    run_cmd "echo \"AllowGroups $ALLOW_GROUPS\" >> $cfg"
fi
log_info "🧩 AllowGroups updated -> AllowGroups $ALLOW_GROUPS"

if grep -q '^PasswordAuthentication' "$cfg"; then
    run_cmd "sed -i '/^PasswordAuthentication/c\\PasswordAuthentication yes' $cfg"
else
    run_cmd "echo 'PasswordAuthentication yes' >> $cfg"
fi

# Detect and restart the appropriate SSH service
if systemctl status ssh.service &>/dev/null; then
    run_cmd "systemctl restart ssh.service"
elif systemctl status sshd.service &>/dev/null; then
    run_cmd "systemctl restart sshd.service"
else
    log_info "⚠️ SSH is active, but no known systemd unit found. Skipping restart."
fi

# -------------------------------------------------------------------------
# Ensure explicit inclusion of AD admin sudoers file (safe and idempotent)
# -------------------------------------------------------------------------
SUDO_F="/etc/sudoers.d/ad-admin-groups"
SUDO_MAIN="/etc/sudoers"

log_info "🛡️ Configuring sudoers file: $SUDO_F"

# 1. Ensure target directory exists
mkdir -p "$(dirname "$SUDO_F")"

# 2. Create or refresh AD admin sudoers definition
cat >"$SUDO_F" <<EOF
%$ADM ALL=(ALL) NOPASSWD: ALL
%$ADM_ALL ALL=(ALL) NOPASSWD: ALL
EOF
chmod 440 "$SUDO_F"

# 3. Check if /etc/sudoers already includes this specific file
if ! grep -Eq "^[[:space:]]*#include[[:space:]]+$SUDO_F" "$SUDO_MAIN"; then
	log_info "⚙️ Adding explicit include for $SUDO_F in $SUDO_MAIN"

	# Backup before modification
	SUDO_BAK="${SUDO_MAIN}.bak.$(date +%Y%m%d%H%M%S)"
	cp -p "$SUDO_MAIN" "$SUDO_BAK"

	# Append safely at the end of file
	echo -e "\n# Include AD-specific sudo policy\n#include $SUDO_F" >> "$SUDO_MAIN"

	# Syntax validation (rollback on error)
	if visudo -c >/dev/null 2>&1; then
		log_info "✅ Sudoers include added successfully"
	else
		log_info "🛑 visudo syntax check failed — restoring previous configuration"
		mv -f "$SUDO_BAK" "$SUDO_MAIN"
	fi
else
	log_info "✅ Explicit include for $SUDO_F already present in $SUDO_MAIN"
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
    if systemctl list-unit-files | grep -q '^sssd\.service'; then
        SSSD_STATUS=$(systemctl is-active sssd 2>/dev/null || echo "inactive")
    else
        pgrep sssd >/dev/null 2>&1 && SSSD_STATUS="active" || SSSD_STATUS="inactive"
    fi
    [[ -z "$SSSD_STATUS" ]] && SSSD_STATUS="inactive"

    # ---------------------------------------------------------------
    # SSH service status (handle ssh vs sshd naming)
    # ---------------------------------------------------------------
    if systemctl list-unit-files | grep -q '^ssh\.service'; then
        SSH_STATUS=$(systemctl is-active ssh 2>/dev/null || echo "inactive")
    elif systemctl list-unit-files | grep -q '^sshd\.service'; then
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
DIVIDER=$(printf '%*s\n' "$(tput cols)" '' | tr ' ' '-')
echo "$DIVIDER"
log_info "🌟 DOMAIN JOIN VALIDATION SUMMARY"
echo "$DIVIDER"
printf "%-25s %s\n" "Realm:"              "$REALM_JOINED"
printf "%-25s %s\n" "DC Server:"          "$DC_SERVER"
printf "%-25s %s\n" "Computer Name:"      "$HOST_SHORT_U"
printf "%-25s %s\n" "Kerberos Principal:" "${KLIST_PRINCIPAL:-⚠️ None active}"
printf "%-25s %s\n" "Key Version (KVNO):" "$MSDS_KVNO"
printf "%-25s %s\n" "Domain Trust:"       "$TRUST_STATUS"
printf "%-25s %s\n" "SSSD Service:"       "${SSSD_STATUS,,}"
printf "%-25s %s\n" "SSH Service:"        "${SSH_STATUS,,}"
echo "$DIVIDER"

# Insert short pause and newline without spawning a subshell
sleep 0.05
echo

# Force sync and restore terminal
sync
stty sane 2>/dev/null || true

exit 0
