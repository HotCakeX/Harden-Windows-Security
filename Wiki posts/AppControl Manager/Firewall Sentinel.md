# Firewall Sentinel

<div align="center">
  <img src="https://github.com/HotCakeX/.github/blob/cfbf11aecf220660147b9a59a0eca937321d1e08/Pictures/Gifs/AppControlManager_FirewallSentinelProfiles.gif?raw=true" alt="Firewall Sentinel" />

</div>

## Overview

Firewall Sentinel is an advanced feature within the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) that implements an automated, identity-based allowlisting framework for the Windows Firewall.

By design, the Windows Firewall is configured to block all inbound traffic while permitting all outbound traffic on Windows clients and servers. Consequently, any application or service can transmit data externally without restriction, whereas incoming network traffic remains blocked unless explicitly authorized by a specific rule.

In accordance with [official Microsoft best practices](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc947827(v=ws.10)), the optimal security posture requires blocking outbound traffic by default and authorizing only specific applications to transmit data. Firewall Sentinel enforces this exact model. Outbound traffic is prohibited unless explicitly validated by user-defined, identity-based allowlisting rules, while inbound traffic remains blocked by default.

This strict egress filtering model provides several critical security advantages:

*   **Mitigation of Data Exfiltration:** It prevents malware, including ransomware and infostealers, from transmitting sensitive user data, credentials, or intellectual property to remote Command and Control (C2) servers.
*   **Neutralization of Reverse Shells:** A reverse shell is a method used by attackers to gain remote access to a compromised system. Unlike a traditional shell, where the attacker connects to the target, a reverse shell allows the target machine to connect back to the attacker's machine. This technique is particularly useful when the target is behind a firewall or Network Address Translation (NAT), as it can bypass security measures that typically block incoming connections. Blocking unauthorized outbound connections effectively severs this communication channel.
*   **Privacy Preservation:** It curbs the telemetry and data collection practices of legitimate but intrusive applications, ensuring that software only communicates with the Internet when explicitly authorized by the user.
*   **Immediate Indicator of Compromise:** Unauthorized connection attempts generate logs, providing early warning signs of malicious activity or unauthorized software installation that would otherwise go unnoticed in a default-allow configuration.

## Profile Selection

Firewall Sentinel currently offers three distinct identity-based allowlisting profiles:

1. **Default Windows:** Restricts Internet access exclusively to the programs, services, and applications that are native to the Windows operating system. All default Windows processes and signed system components are permitted, whereas third-party software is blocked. This is the most secure profile.

2. **Allow Microsoft:** Expands upon the Default Windows profile to permit network connectivity for any application signed with a valid Microsoft code-signing certificate. This profile authorizes built-in Windows components and Microsoft-signed software, but continues to deny Internet access to unsigned or non-Microsoft third-party applications.

3. **Signed and Reputable:** Further extends the Allow Microsoft profile by authorizing all applications previously permitted, in addition to all reputable, signed applications verified by [the Intelligent Security Graph](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph) cloud verdicts. This profile delivers the most comprehensive firewall coverage and serves as an ideal baseline for users seeking to authorize reputable applications without managing granular rules.

Each profile automatically adjusts system configurations, including Windows Firewall settings, to enforce the selected security posture. These system modifications are fully reversible and include the following actions:

*   **Rule Backup:** All existing firewall rules within the Persistent store (Windows Defender Advanced Firewall Settings) and the Group Policy store are backed up.

*   **Rule Migration:** All existing firewall rules in the Persistent store are migrated to the Group Policy store.

*   **App ID Tagging Authorization:** A new outbound firewall rule is generated in the Group Policy store to facilitate App ID Tagging authorization.

*   **System Process Authorization:** A new outbound firewall rule is created in the Group Policy store specifically for the `System` process to ensure the operating system continues to function correctly. As App ID Tagging operates strictly on User-Mode programs, it cannot authorize the Kernel-Mode `System` process.

*   **Service Host Authorization:** A new outbound firewall rule is established in the Group Policy store for `Svchost.exe` to maintain uninterrupted operating system workflows.

*   **Group Policy Application:** A series of Group Policies are applied to enforce strict security standards:

    *   **Block Rule Merging:** Local rule merging is disabled for all three firewall profiles. This prevents third-party installers from automatically creating effective outbound rules in the Persistent store, thereby preserving the integrity of the Firewall Sentinel workflow.
    *   **Default Outbound Action:** The default behavior for all three firewall profiles is set to `Block` for outbound traffic.
    *   **Security Configuration:** Additional hardening measures are applied, such as ensuring the firewall remains active across all three profiles and verifying that the inbound default action remains set to `Block`.

*   **App Control Policy Deployment:** A new App Control policy is deployed to the system to handle App ID Tagging. This policy tags all authorized User-Mode processes with a specific identifier defined in the previously created outbound firewall rule. This establishes a functional bridge between App Control and the Windows Firewall, forming the core mechanism of the Firewall Sentinel feature.

## Policy Pinning

Upon selecting and applying a profile, the resulting App ID Tagging policy is automatically pinned to the interface. This policy resides within the [Policies Library on the Sidebar](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Sidebar), allowing you to back it up, modify it via [the Policy Editor](https://github.com/HotCakeX/Harden-Windows-Security/wiki/PolicyEditor), or use it within other sections of the AppControl Manager.

Users retain the flexibility to unpin the current policy or switch the pinned status to a different App ID Tagging policy as needed.

## Authorizing Third-Party Applications

Firewall Sentinel provides three streamlined methods for authorizing third-party applications to access the Internet:

1.  **Files and Folders:** You may browse for specific executable files or directories containing executables. These targets are scanned and automatically incorporated into the pinned policy. The scan level is configurable, allowing validation based on file hash, file path, file name (for unsigned files), or File Publisher and WHQL File Publisher (for signed files).

2.  **Certificates:** You may import certificate files (`.cer`) to be scanned and added to the pinned policy. Any software or files signed by the imported certificate will be granted Internet connectivity.

3.  **Pattern-Based Allowlisting:** You may define custom path patterns to authorize all files matching a specific criteria. For example, specifying `D:\EnterpriseApps\MyApp\*` authorizes all files located within the `D:\EnterpriseApps\MyApp\` directory and its subdirectories. The application provides additional examples to assist in creating precise file path patterns tailored to your requirements.

## Monitoring Blocked Connections and Logs

Firewall Sentinel includes comprehensive logging capabilities, allowing you to audit blocked or dropped packets. This includes logs for programs prevented from connecting to the Internet and IP addresses blocked by specific firewall rules.

You can search through these logs to analyze traffic patterns and fine-tune your firewall configurations.

Additionally, the feature supports a real-time stream of blocked connections directly within the Firewall Sentinel interface. This is particularly valuable when validating new allowlisting rules or troubleshooting connectivity. When a program or IP address is blocked, a detailed entry is immediately generated in the application.

To facilitate this, `Packet Drop Auditing` is automatically enabled on the system when viewing real-time logs. This setting is mandatory for capturing blocked packet data. You may also manually toggle this setting via the `Actions` menu.

## Notes and Technical Tips

*   **Process Restart Requirement:** When authorizing a new third-party program in Firewall Sentinel, **if the application is currently running**, you must close and restart it. This ensures its files are re-analyzed and tagged correctly. If a program remains unable to connect to the Internet after authorization, it likely indicates that background processes or files associated with the application were not closed completely. In such instances, a system reboot will ensure all processes are terminated and correctly tagged upon the next startup.

*   **EnforceDLL Behavior:** Setting `EnforceDLL` to `False` for AppIDTags in the App Control policy has no operational effect. When the policy is converted to a CIP binary, this setting is omitted entirely if it is false or null; it is only recognized when set to true.

## Frequently Asked Questions

**Q: Can I create custom firewall rules alongside Firewall Sentinel?**

A: Yes, you can create custom firewall rules in addition to the rules generated by Firewall Sentinel. However, keep in mind that Firewall Sentinel enforces a strict allowlisting model, so any custom rules must be carefully crafted to ensure they do not inadvertently allow unauthorized outbound traffic.

**Q: What happens if I switch between different Firewall Sentinel profiles?**

A: When you switch between profiles, Firewall Sentinel will automatically adjust the firewall rules and App Control policies to align with the new profile's security posture. This includes backing up existing rules, migrating them as necessary, and applying the appropriate configurations for the selected profile.

**Q: Can I use Firewall Sentinel on a server operating system?**

A: Yes, Firewall Sentinel is compatible with both client and server versions of Windows. It can be used to enforce strict outbound traffic controls on servers, which is particularly beneficial for preventing data exfiltration and unauthorized communications in a server environment.

**Q: How Long Does It Take for Unauthorized Connections and Programs to Be Blocked After Applying a Firewall Sentinel Profile?**

A: Unauthorized connections and programs are blocked immediately after applying a Firewall Sentinel profile. The firewall rules are updated in real-time, so any attempt by an unauthorized application to access the Internet will be blocked as soon as the profile is active. For instance, if you are using a VPN program that uses OpenVPN or WireGuard, it will be immediately blocked from connecting to the Internet once the profile is applied, and you will see entries in the logs indicating that the connection attempts were blocked. You will have to authorize the VPN program and restart it to restore Internet connectivity.

**Q: Why Do the App ID Tagging Policies Contain Multiple Wildcard Allow Rules?**

A: App ID Tagging policies generated by AppControl Manager include wildcard path-based allow rules for all non-executable extensions supported by Application Control to improve system performance because App ID Tagging only works for `.exe` files and allowing anything that is not `.exe` short circuits policy evaluation by the OS kernel and reduces Application Controls's affect on performance.

### Got More Questions?

Please feel free to [**open new discussion thread**](https://github.com/HotCakeX/Harden-Windows-Security/discussions) on the GitHub repository. I will be happy to answer any questions you have about Firewall Sentinel or any other features of the AppControl Manager.

### Have Suggestions for Improvement?

Please [**open a new issue**](https://github.com/HotCakeX/Harden-Windows-Security/issues) on the GitHub repository to share your ideas for improving Firewall Sentinel or any other aspect of the AppControl Manager. I am always looking for ways to enhance the functionality and usability of the application, and I welcome your feedback and suggestions.

<br>
