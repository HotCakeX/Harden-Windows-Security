# Create App Control Policy

Use [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create new App Control policies based on the [default templates](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/example-appcontrol-base-policies).

* **Allow Microsoft**: Only allows files signed by Microsoft certificates to run on the system.

* **Default Windows**: Only allows files that come by default with Windows OS to run on the system.

* **Signed And Reputable**: Allows files signed by Microsoft certificates to run, it also utilizes [the Intelligent Security Graph](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph) to allow files that are reputable and safe.

* **Microsoft Recommended Block Rules**: It will download the latest Microsoft Recommended (User-Mode) block rules from [the official source](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol) and create an App Control policy.

* **Microsoft Recommended Driver Block Rules**: It will download the latest Microsoft Recommended (Kernel-Mode) block rules from [the official source](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) and create an App Control policy.

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
