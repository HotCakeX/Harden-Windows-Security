# TLS Security | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/0180bc6ace1ea086653cc405f142d1aada424150/Pictures/Readme%20Categories/TLS%20Security/TLS%20Security.svg" alt="TLS Security - Harden Windows Security repository GitHub" width="550"></p>

<br>

Changes made by this category only affect things that use [Schannel SSP](https://learn.microsoft.com/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-): that includes IIS web server, built-in inbox Windows apps and some other programs supplied by Microsoft, including Windows network communications, but not 3rd party software that use [portable stacks](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations#Portability_concerns) like Java, nodejs, python or php.

If you want to read more: [Demystifying Schannel](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-schannel/ba-p/259233)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Disables TLS 1 and TLS 1.1 security protocols that only **exist for backward compatibility**. All modern software should and do use `TLS 1.2` and `TLS 1.3`. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cryptography#overrideminimumenabledtlsversionclient) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cryptography#overrideminimumenabledtlsversionserver)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Disables [MD5 Hashing Algorithm](https://security.stackexchange.com/questions/52461/how-weak-is-md5-as-a-password-hashing-function) that is **only available for backward compatibility**

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Disables the following [weak ciphers](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices) that are **only available for backward compatibility**: `"DES 56-bit"`,`"RC2 40-bit"`,`"RC2 56-bit"`,`"RC2 128-bit"`,`"RC4 40-bit"`,`"RC4 56-bit"`,`"RC4 64-bit"`,`"RC4 128-bit"`,`"3DES 168-bit (Triple DES 168)"`

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the [TLS](https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data) to only use the [following](https://developers.cloudflare.com/ssl/reference/cipher-suites/recommendations/) secure [cipher suites](https://learn.microsoft.com/windows/win32/secauthn/tls-cipher-suites-in-windows-11) and in this [exact](https://scanigma.com/knowledge-base) order: <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cryptography#tlsciphersuites)

```
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_256_GCM_SHA384
TLS_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
```

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Use the ***TLS for BattleNet*** sub-category if you have the BattleNet game client installed on your system. This client utilizes the `TLS_RSA_WITH_AES_256_CBC_SHA` cipher suite to establish connections with its servers. Since this cipher suite is less secure, it is excluded from the secure cipher-suites list by default. However, enabling this sub-category will include the required cipher suite, allowing you to use BattleNet without interruptions.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Configures](https://learn.microsoft.com/windows-server/security/tls/manage-tls) TLS ECC Curves to [use the following](https://github.com/HotCakeX/Harden-Windows-Security/commit/5b5be1fcab8f7bf5d364f48459aecfc54c6eff9d#commitcomment-115982586) prioritized Curves order: <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cryptography#configureellipticcurvecryptography)

```
nistP521
curve25519
NistP384
NistP256
```

* By default, [in Windows](https://learn.microsoft.com/windows/win32/secauthn/tls-elliptic-curves-in-windows-10-1607-and-later), the order is this:

```
curve25519
NistP256
NistP384
```

*[Read more in this Wiki post](https://github.com/HotCakeX/Harden-Windows-Security/wiki/About-TLS,-DNS,-Encryption-and-OPSEC-concepts)*

<br>
