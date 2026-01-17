# Windows Security Studio

**Comprehensive Windows security hardening using official Microsoft methods.**

This repository hosts the source code and documentation for tools designed to secure Windows personal and enterprise devices against advanced threats without relying on third-party security software.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/OFFSECHQ/windows-security-studio/actions/workflows/CodeQL%20Advanced%20-%20Quality.yml/badge.svg)](https://github.com/OFFSECHQ/windows-security-studio/actions/workflows/CodeQL%20Advanced%20-%20Quality.yml)
[![PSScriptAnalyzer](https://github.com/OFFSECHQ/windows-security-studio/actions/workflows/powershell.yml/badge.svg)](https://github.com/OFFSECHQ/windows-security-studio/actions/workflows/powershell.yml)

---

## Key Components

### 1. System Security Studio

A powerful utility to harden your Windows Operating System. It utilizes built-in Windows security features to fine-tune the system toward a maximum security state.

- **Target Audience**: Personal users, Enterprise admins.
- **Features**: Apply Intune security policies, verify compliance, remove bloatware, and visualize security posture.
- **Documentation**: [System Security Studio Wiki](https://github.com/OFFSECHQ/windows-security-studio/wiki/System-Security-Studio)

### 2. App Control Studio

A modern interface for managing Windows Application Control (formerly WDAC).

- **Target Audience**: Users requiring strict application execution policies (Zero Trust).
- **Features**: Configure and deploy Application Control policies to prevent unauthorized code execution.
- **Documentation**: [App Control Studio Wiki](https://github.com/OFFSECHQ/windows-security-studio/wiki/App-Control-Studio)

---

## Philosophy

- **Official Methods Only**: We rely exclusively on documented, supported Microsoft security features.
- **No Third-Party Bloat**: No external "black box" agents or drivers.
- **Defense in Depth**: Creates multiple layers of security (ASR, Exploit Protection, App Control, etc.).
- **Verifiable**: Open Source and transparent. All packages are built from this repository.

---

## Security Recommendations

For a truly secure environment, we recommend adhering to the following best practices in addition to using our tools:

1.  **Use Official Media**: Always install Windows from official Microsoft sources. Avoid modified ISOs.
2.  **Hardware Security**: Prefer Secured-Core PCs (e.g., Microsoft Surface) with TPM 2.0 and DFCI support.
3.  **Account Security**: Use standard user accounts for daily tasks; use Microsoft Entra ID or Microsoft Accounts with MFA/Passkeys.
4.  **Network**: Use DNS over HTTPS (DoH) and avoid unnecessary VPNs unless required for specific privacy needs.
5.  **Browser**: Use Microsoft Edge for hardware-enforced stack protection and SmartScreen integration.

[View full Security Recommendations in Wiki](https://github.com/OFFSECHQ/windows-security-studio/wiki)

---

## Fork Information

This is a fork of [HotCakeX/Harden-Windows-Security](https://github.com/HotCakeX/Harden-Windows-Security), maintained by **OFFSECHQ**.

This fork is automatically synced with the upstream repository and includes custom branding and build configurations.

---

## Support

- **Wiki**: [Comprehensive Documentation](https://github.com/OFFSECHQ/windows-security-studio/wiki)
- **Issues**: [Report bugs](https://github.com/OFFSECHQ/windows-security-studio/issues)
- **Upstream**: [Original Repository](https://github.com/HotCakeX/Harden-Windows-Security)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Original work © Violet Hansen (HotCakeX)  
Fork modifications © OFFSECHQ
