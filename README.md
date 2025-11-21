# linux-ad-domain-join

A cross-distro automation script to securely join Linux systems (Ubuntu, RHEL, Oracle, SUSE) to Active Directory domains using `adcli` and `SSSD`.

## Features
- Intelligent DNS and KDC reachability tests
- Automated `krb5.conf` and `sssd.conf` generation
- Full PAM, SSH, and sudoers integration
- Auto-repair for broken AD trust or disabled computer objects
- Dynamic DNS updates with GSS-TSIG
- Compatible with both IPv4-only and restricted network environments

## Supported Platforms
- Ubuntu 18.04–24.04
- RHEL, Rocky, AlmaLinux 7–9
- Oracle Linux 7–9
- SUSE Linux Enterprise 12–15

## Download & Usage
```bash
tmp=$(mktemp); ( command -v curl >/dev/null && curl -fsSL https://raw.githubusercontent.com/soulucasbonfim/linux-ad-domain-join/main/linux-ad-domain-join.sh > $tmp || wget -qO $tmp https://raw.githubusercontent.com/soulucasbonfim/linux-ad-domain-join/main/linux-ad-domain-join.sh ); chmod +x $tmp; sudo $tmp
```
