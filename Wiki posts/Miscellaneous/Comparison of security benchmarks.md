# [Comparison of security benchmarks](#comparison-of-security-benchmarks-) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/lovelybat.gif" width="50" alt="Comparison of security benchmarks">

I conducted a thorough analysis of some of the prominent security benchmarks/guidelines for my GitHub repository and I discovered some fascinating insights. By analysis, I mean that I examined every single recommendation in them and compared them with my own suggestions and Microsoft Security Baselines.

The majority of the recommendations in the security benchmarks align with the Microsoft Security Baselines, which are a set of best practices for securing various products and services. Only a small fraction of the recommendations deviate from the baselines, and they are either additional enhancements (rarely), redundant suggestions or erroneous advice that undermines security!

For my reviews I used the latest available version of each benchmark.

<br>

## [Some of the Pitfalls of Relying on Third-Party Benchmarks](#some-of-the-pitfalls-of-relying-on-third-party-benchmarks-) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/whyme.gif" width="50" alt="Small Gif image for the section named Some of the Pitfalls of Relying on Third-Party Benchmarks">

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/bandage-bleed.gif" width="30" alt="Small Gif for Clipboard sharing from guest to host section"> [Clipboard sharing from guest to host !](#-clipboard-sharing-from-guest-to-host-)

CIS 18.10.44.5 (L1) recommends allowing clipboard operation from an isolated session to the host, i.e. guest to host redirection, which is a highly insecure and irrational suggestion!

These are their precise official words:

> Rationale:
The primary purpose of Microsoft Defender Application Guard is to present a
"sandboxed container" for visiting untrusted websites. If the host clipboard is made
available to Microsoft Defender Application Guard, a compromised Microsoft Defender
Application Guard session will have access to its content, potentially exposing sensitive
information to a malicious website or application. **However, the risk is reduced if the
Microsoft Defender Application Guard clipboard is made accessible to the host, and
indeed that functionality may often be necessary from an operational standpoint**

<br>

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/bandage-bleed.gif" width="30" alt="Small gif for Renaming built-in administrator and guest accounts section"> [Renaming built-in administrator and guest accounts !](#-renaming-built-in-administrator-and-guest-accounts-)

Both CIS and STIG suggest altering the name of the built-in administrator and guest accounts as a security measure.

This is futile as those built-in accounts can be readily identified by PowerShell, regardless of any modifications to its name or description (which I have done).

For example, the `BUILTIN\Administrator` account always has a relative identifier (RID) of `500`.

```powershell
Get-LocalUser | Where-Object -FilterScript {$_.SID -like 'S-1-5-*-500'}
```

> Thanks [Elliot Huffman](https://github.com/elliot-huffman) for suggesting the shorter command!

<details>

```powershell
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
$userPrincipal = New-Object System.DirectoryServices.AccountManagement.UserPrincipal($principalContext)
$searcher = New-Object System.DirectoryServices.AccountManagement.PrincipalSearcher
$searcher.QueryFilter = $userPrincipal
$searcher.FindAll() | Where-Object { $_.Sid -Like "*-500" } | Select-Object SamAccountName</details>
```

</details>

<br>

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/bandage-bleed.gif" width="30" alt="Small gif for Disabling Windows Hello PIN and using traditional passwords instead section"> [Disabling Windows Hello PIN and using traditional passwords instead !](#-disabling-windows-hello-pin-and-using-traditional-passwords-instead-)

These benchmarks recommend disabling Windows Hello PIN and opting for passwords instead. Stig V-253423 and CIS 18.9.27.4.

They argue that this is for domain accounts

Their rationale, which is very wrong, is

> A PIN is created from a much smaller selection of characters than a password, so in
most cases a PIN will be much less robust than a password.

It is a grave security lapse to propose such a policy and then label the benchmark/guideline as “CIS Microsoft Windows 11 Stand-alone Benchmark”, highlighting that it is intended for stand-alone computers, while simultaneously suggesting to disable PIN for domain-joined devices. This is a glaring inconsistency and a perilous practice.

The guideline/benchmark is fundamentally flawed if it presupposes that the computer is domain-joined, despite the label indicating that it is stand-alone. It also neglects to consider that some users may actually be stand-alone (home users that account for the majority of the users) or use Microsoft Entra ID, and this policy is nonsensical for them.

STIG commits the same error, as it only provides a generic Windows 11 guideline/benchmark and recommends disabling Windows Hello PIN, without taking into account the factors mentioned above.

You can [read this Microsoft document](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-why-pin-is-better-than-password) to find out why a PIN is better than an online password

There are proper policies regarding anti-hammering features that can enhance the security of PINs over passwords. I utilize them in my module and [you can find them here](https://github.com/HotCakeX/Harden-Windows-Security#lock-screen).

The benchmarks/guidelines seem to be uninformed of the fact that Windows allows [multi-factor unlock](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/feature-multifactor-unlock), which can enforce a combination of PIN and biometric factors (plus more), to enforce **PIN + Facial recognition** OR **PIN + Fingerprint** etc.

<br>

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/bandage-bleed.gif" width="30" alt="Small gif for Bad configuration for Early Launch Anti Malware section"> [Bad configuration for Early Launch Anti Malware](#-bad-configuration-for-early-launch-anti-malware)

CIS in 18.9.13.1

> The recommended state for this setting is: Enabled: Good, unknown and bad but
critical

That's not even a recommendation, that's the default value! If you use [Harden Windows Security module](https://github.com/HotCakeX/Harden-Windows-Security#miscellaneous-configurations) it sets it to **Good Only**, which is the correct recommendation for a secure environment.

<br>

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/bandage-bleed.gif" width="30" alt="Disabling Windows Error reporting"> [Disabling Windows Error reporting !](#-disabling-windows-error-reporting-)

Their rationale is:

> ...There is no benefit to the corporation to report these errors directly to Microsoft...

Indeed, the corporation that uses the software benefits from it by reporting the problems. This exact way of thinking that leads to making such a policy is the reason why problems remain unsolved, because they are not reported to Microsoft and the IT staff of the companies are simply unable to resolve the problem themselves, since they are not the ones developing the OS.

<br>

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/bandage-bleed.gif" width="30" alt="Disabling Cloud Protection"> [Disabling Cloud Protection!](#-disabling-cloud-protection)

CIS 18.10.43.5.2 (L2), suggests disabling Cloud Protection of Microsoft Defender. **This is precisely the kind of security measure that Threat Actors and advanced persistent threats (APTs) seek to disable** and then CIS is suggesting to disable it, astonishing.

This is an extremely [important security feature](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/cloud-protection-microsoft-defender-antivirus?view=o365-worldwide) that should never be disabled and there is no rationale that justifies disabling it. This feature also uses the [Intelligent Security Graph (ISG)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph).

<br>

### <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/bandage-bleed.gif" width="30" alt="Not enabling important Attack Surface Reduction rules"> [Not enabling important Attack Surface Reduction rules](#-not-enabling-important-attack-surface-reduction-rules)

CIS in 18.10.43.6.1.2 (L1) intentionally leaves out very important ASR rules

1. [Use advanced protection against ransomware](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#use-advanced-protection-against-ransomware)
2. [Block executable files from running unless they meet a prevalence, age, or trusted list criterion](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-executable-files-from-running-unless-they-meet-a-prevalence-age-or-trusted-list-criterion)
3. [Block process creations originating from PSExec and WMI commands](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-process-creations-originating-from-psexec-and-wmi-commands)

Rule #2 has the potential to prevent zero-days!

<br>

### To be continued...

These benchmarks or guidelines have numerous flaws and I have only examined two of them. There are many other benchmarks, standards, guidelines, etc. that may also contain errors or inconsistencies and are totally **unsafe** to implement them.

<br>

## [Aspects that are lacking](#aspects-that-are-lacking-) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/gothwink.gif" width="50" alt="Aspects that are lacking">

The benchmarks omit many new security features that the [Harden Windows Security module](https://github.com/HotCakeX/Harden-Windows-Security) implements.

Everything in the repository is carefully researched, evaluated and tested. The module ensures that nothing is redundant or incompatible with the latest version of Windows. Older versions of the OS are obsolete and insecure, and should be avoided in any environment that requires protection. Threat actors can exploit vulnerabilities and use PoCs even on the same day that an update is released, this applies to any OS.

The security measures in the Harden Windows Security repository are also perfectly suitable for regular home users.

There are many security measures that are missing from the benchmarks/guidelines, such as the ones I use in:

* [Microsoft Defender category](https://github.com/HotCakeX/Harden-Windows-Security#microsoft-security-baselines)

* [Miscellaneous Category](https://github.com/HotCakeX/Harden-Windows-Security#miscellaneous-configurations)

* [Edge Browser category](https://github.com/HotCakeX/Harden-Windows-Security#edge-browser-configurations)

* [TLS Security category](https://github.com/HotCakeX/Harden-Windows-Security#tls-security)

* [Lock screen category](https://github.com/HotCakeX/Harden-Windows-Security#lock-screen)

* And more

The benchmarks/guidelines suggest using application control or whitelisting, but that's just it, a suggestion, no [comprehensive guide about how to do it](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction).

<br>

<p align="center">
<img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/thankyou.gif" alt="Thank You Gif">
</p>

<br>
