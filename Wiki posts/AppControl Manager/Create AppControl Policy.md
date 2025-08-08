# Create App Control Policy

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Create%20Policy.png" alt="AppControl Manager Application's Create App Control Policy Page">

</div>

<br>

<br>

Use [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create new App Control policies based on the [default templates](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/example-appcontrol-base-policies).

* **Allow Microsoft**: Only allows files signed by Microsoft certificates to run on the system.

* **Default Windows**: Only allows files that come by default with Windows OS to run on the system.

* **Signed And Reputable**: Allows files signed by Microsoft certificates to run, it also utilizes [the Intelligent Security Graph](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph) to allow files that are reputable and safe.

* **Microsoft Recommended Block Rules**: It will download the latest Microsoft Recommended (User-Mode) block rules from [the official source](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol) and create an App Control policy.

* **Microsoft Recommended Driver Block Rules**: It will download the latest Microsoft Recommended (Kernel-Mode) block rules from [the official source](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) and create an App Control policy.

   * **Auto update**: It will create a scheduled task on the system that will check every week for the latest Microsoft Recommended block rules and update the policy automatically. [Please refer to this page for more info.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates)

* **Strict Kernel-mode policy**: It's a special kind of policy that will only enforce Kernel-mode files without blocking user-mode files. Please refer [to this article](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection) for more information.

<br>

Deploying any of them is optional. You can create the policies and then deploying them on remote systems using Intune or other methods.

<br>

## Configuration Details

There are different settings and options you can use to fine tune the policy according to your requirements.

* **Audit**: When a policy has Audit mode turned on for it, it will only log the events and not block any files from running.

* **Log Size**: You can configure the max capacity of the `Code Integrity/Operational` log size. It is recommended to increase it from the default `1MB` capacity if you want to begin auditing for App Control events. When the capacity is reached, the log will overwrite the oldest events.

* **Require EVSigners**: When this setting is enabled, the policy will only allow files signed by Extended Validation (EV) certificates to run on the system.

* **Enable Script Enforcement**: When this setting is enabled, the policy will only allow PowerShell scripts or modules that are signed and their signing certificates are allowed in an App Control policy to run. This greatly reduces the attack surface from the Windows script hosts.

* **Test Mode**: Boot Options Menu, such as Safe mode, is disabled for all App Control policies by default. Using Test Mode will allow access to it. It will also automatically enable the `Audit` mode for the policy in case of a failure in a driver that is critical to system boot. It's only recommended to use this setting in a test environment and not in production due to security reasons.

<br>

## Downloads Defense Measures <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/DownloadsDefenseMeasures.png" alt="Downloads Defense Measures icon" width="35">

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Readme%20Categories/Downloads%20Defense%20Measures/Downloads%20Defense%20Measures.png" alt="Downloads Defense Measures - Harden Windows Security GitHub repository" width="300"></p>

<br>

**T**o combat the threat of more sophisticated malware, a preemptive measure is taken by creating and deploying an [App Control](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction) policy on the system. This policy blocks the execution of executables and [other potentially harmful file types](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/feature-availability) in the Downloads folder.

This policy defends the system from malware that can launch itself automatically after being downloaded from the Internet and has the potential to protect against zero-click exploits. The user must ensure the file's safety and explicitly transfer it to a different folder before running it.

The App Control policy employs a wildcard pattern to prevent any file from running in the Downloads folder. Additionally, it verifies that the system downloads folder in the user directory matches the downloads folder in the Edge browser's settings. If there is a discrepancy, a warning message is displayed on the console.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

Creates a custom [App Control](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction) policy that blocks the execution of the following executables:

* wscript.exe
* mshta.exe
* cscript.exe

They are [insecure](https://textslashplain.com/2024/05/20/attack-techniques-full-trust-script-downloads/), unsandboxed script hosts that pose a security risk.

<br>
