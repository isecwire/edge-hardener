# Changelog

## [2.2.0] - 2026-04-03
### Added
- SARIF output format for CI/CD security scanning integration (--format sarif)
- systemd service hardening audit (checks ProtectSystem, NoNewPrivileges, CapabilityBoundingSet, etc.)
- SELinux/AppArmor profile validation for running processes
- Network namespace isolation detection
- USB device policy audit (authorized_default, removable media controls)
- Ansible playbook generation from fix recommendations (--ansible FILE)
- Delta scoring — show risk score improvement from baseline
### Changed
- Policy engine v2: supports AND/OR conditions on enforcement rules
- HTML report redesigned with dark/light theme toggle
- JSON output now includes a schema version field for forward compatibility
### Fixed
- False positive on SUID detection for snap packages
- Policy file parser handling of YAML anchors

## [2.1.0] - 2026-03-15
### Added
- Network discovery scan for exposed management interfaces (--scan-network)
- Custom check plugin system (drop .sh scripts into checks.d/)
- Crontab/systemd timer audit for persistence mechanisms
- Package integrity verification (dpkg --verify, rpm -V)
- Risk score trend chart in HTML reports
### Changed
- Faster execution with parallel check execution (backgrounded subshells)
- Improved CIS benchmark ID coverage (now 85% of CIS Level 1)
### Fixed
- Baseline comparison crash when check categories differ

## [2.0.0] - 2026-02-28
### Added
- Container security audit (Docker/Podman)
- Cryptographic health checks (OpenSSL, SSH keys, certificates)
- Supply chain binary provenance (RELRO, PIE, stack canary)
- Bootloader security audit (GRUB2, U-Boot)
- Policy engine with YAML profiles
- Auto-remediation (--fix) and fix script generation
- Baseline comparison and trending
- CIS benchmark ID annotations
- Multiple output formats (text, json, html, csv)
- Check filtering (--checks, --exclude)
### Breaking
- JSON output schema v2 with category and cis_id fields
- CLI arguments expanded

## [1.0.0] - 2026-01-15
### Added
- Stable release
- 10 check categories covering kernel, network, filesystem, SSH, firewall
- JSON and HTML report generation
- Quiet mode for CI/CD pipelines
- Color-coded terminal output
- Exit codes for pass/warn/fail
### Changed
- Consolidated check scripts under checks/ directory
### Fixed
- SSH config parsing with multiple Match blocks

## [0.1.0] - 2025-12-05
### Added
- Initial release
- Kernel hardening checks (KASLR, SMEP, SMAP, stack protector)
- Network exposure audit (open ports, unnecessary services)
- Filesystem permissions audit (SUID, world-writable)
- dm-verity status check
- Debug interface detection
- SSH configuration hardening
- Firewall rule validation
- Kernel module loading restrictions
- Core dump configuration
- Basic JSON output
- HTML report generator
