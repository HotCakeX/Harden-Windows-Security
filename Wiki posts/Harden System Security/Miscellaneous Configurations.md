# Miscellaneous Configurations | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/d6960a261913f979526c0fac7901effa4b72d813/Pictures/Readme%20Categories/Miscellaneous%20Configurations/Miscellaneous%20Configurations.svg" alt="Miscellaneous Configurations - Harden Windows Security" width="500"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets [Early launch antimalware](https://learn.microsoft.com/windows-hardware/drivers/install/elam-driver-requirements) engine's status to `8` which is **Good only.** The default value is `3`, which allows good, unknown and 'bad but critical'. that is the default value, because setting it to `8` [can prevent your computer from booting](https://learn.microsoft.com/windows/compatibility/early-launch-antimalware#mitigation) if the driver it relies on is critical but at the same time unknown or bad. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system?WT.mc_id=Portal-fx#bootstartdriverinitialization)

    - By being launched first by the kernel, ELAM is ensured to be launched before any third-party software and is therefore able to detect malware in the boot process and prevent it from initializing. ELAM drivers must be specially signed by Microsoft to ensure they are started by the Windows kernel early in the boot process.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Disables location services (Location, Windows Location Provider, Location Scripting) system-wide. Websites and apps won't be able to use your precise location, however they will still be able to detect your location using your IP address. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-System?WT.mc_id=Portal-fx#allowlocation) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-locationprovideradm#disablewindowslocationprovider_1) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-sensors#disablelocationscripting_2)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables `svchost.exe` mitigations. built-in system services hosted in `svchost.exe` processes will have stricter security policies enabled on them. These stricter security policies include a policy requiring all binaries loaded in these processes to be signed by Microsoft, and a policy disallowing dynamically generated code. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-servicecontrolmanager)

    - Requires Business Windows licenses. e.g., [Windows 11 Pro for Workstations](https://www.microsoft.com/en-us/windows/business/windows-11-pro-workstations), [Enterprise](https://www.microsoft.com/en-us/microsoft-365/windows/windows-11-enterprise) or [Education](https://www.microsoft.com/en-us/education/products/windows).

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Turns on Enhanced mode search for Windows indexer. The default is classic mode. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search#allowfindmyfiles)
    - This causes some UI elements in the search settings in Windows settings to become unavailable for Standard user accounts to view, because it will be a managed feature by an Administrator.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Enforce the Administrator role for adding printer drivers](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/devices-prevent-users-from-installing-printer-drivers) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-LocalPoliciesSecurityOptions?WT.mc_id=Portal-fx#devices_preventusersfrominstallingprinterdriverswhenconnectingtosharedprinters)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [SMB/LDAP Signing](https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-LocalPoliciesSecurityOptions?WT.mc_id=Portal-fx#microsoftnetworkclient_digitallysigncommunicationsalways) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-LocalPoliciesSecurityOptions?WT.mc_id=Portal-fx#microsoftnetworkserver_digitallysigncommunicationsalways)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Enables Edge browser (stable/beta/dev channels) to download and install updates on any network, metered or not; because the updates are important and should not be suppressed.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Creates custom views for [Windows Event Viewer](https://learn.microsoft.com/shows/inside/event-viewer) to help keep tabs on important security events:

    - [Attack Surface Reduction Rules](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide#xml-for-attack-surface-reduction-rule-events)

    - [Controlled Folder Access](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide#xml-for-controlled-folder-access-events)

    - [Exploit Protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide#xml-for-exploit-protection-events)

    - [Network Protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide#xml-for-network-protection-events)

    - [MSI and Scripts for App Control Auditing](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)

    - Sudden Shut down events (due to power outage)

    - [Code Integrity Operational](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)

    - [Restarts (By user or by the System/Apps)](https://learn.microsoft.com/troubleshoot/windows-server/performance/incorrect-shutdown-reason-code-sel)

    - Workstation [Locks](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4800) and [Unlocks](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4801)

    - [Checks to make sure ***Other Logon/Logoff Events*** Audit is active](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-other-logonlogoff-events) <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-Audit?WT.mc_id=Portal-fx#accountlogonlogoff_auditotherlogonlogoffevents)

    - [Failed Login attempts via PIN at lock screen](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776)

        - Error/Status code `0xC0000064` indicates wrong PIN entered at lock screen

    - USB storage Connects & Disconnects (Flash drives, phones etc.)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Enables **WinVerifyTrust Signature Validation**, [a security feature related to WinVerifyTrust function that handles Windows Authenticode signature verification for portable executable (PE) files.](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables [Command line process auditing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing). <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-auditsettings#includecmdline)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Enables a policy that requests claims and compound authentication for Dynamic Access Control and Kerberos armoring. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-kerberos#kerberosclientsupportsclaimscompoundarmor)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Enables [Windows Protected Print](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/a-new-modern-and-secure-print-experience-from-windows/ba-p/4002645). <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-printers#configurewindowsprotectedprint)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/magenta-verification.gif" width="25" alt="Rotating pink checkmark denoting registry or cmdlet"> Configures the [SSH client's configurations](https://learn.microsoft.com/windows-server/administration/OpenSSH/openssh-server-configuration#openssh-configuration-files) to use the following secure MACs (Message Authentication Codes): `MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com`.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Enables support for [long paths](https://learn.microsoft.com/windows/win32/fileio/maximum-file-path-limitation).

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> [Force strong key protection](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/system-cryptography-force-strong-key-protection-for-user-keys-stored-on-the-computer) for user keys stored on the computer. User is prompted when the key is first used.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Reduced Telemetry. This sub-category applies all of the policies mentioned below. They do not have any effect on security.

   * Disable Online Tips. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-settings#allowonlinetips)

   * Disable Find My Device feature. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience#allowfindmydevice)

   * Disable Automatic Update of Speech Data. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-speech#allowspeechmodelupdate)

   * Turn off the advertising ID. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy#disableadvertisingid)

   * Turn off cloud optimized content. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience#disablecloudoptimizedcontent)

   * Do not show Windows tips. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience#allowwindowstips)

   * Do not show feedback notifications. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience#donotshowfeedbacknotifications)

   * Turn off Automatic Download and Update of Map Data. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-maps#enableofflinemapsautoupdate)

   * Disable Message Service Cloud Sync for cellular text messages. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-messaging#allowmessagesync)

   * Disable support for web-to-app linking with app URI handlers. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-applicationdefaults#enableappurihandlers)

   * Disable "Continue experiences on this device" feature. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-grouppolicy#enablecdp)

   * Disable Font Providers. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system#allowfontproviders)

   * Don't search the web or display web results in Search. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search#donotusewebresults)

   * Do not allow web search. [More Info](https://learn.microsoft.com/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#21-cortana-and-search-group-policies)

<br>
