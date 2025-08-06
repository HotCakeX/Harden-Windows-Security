# User Account Control | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/503f187e5e870b776d281808fc5574e49f212955/Pictures/Readme%20Categories/User%20Account%20Control/User%20Account%20Control.svg" alt="User Account Control - Harden Windows Security" width="550"></p>

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> [Prompt for elevation of privilege on secure desktop for all binaries](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode) in [Administrator accounts](https://learn.microsoft.com/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4), which presents the sign-in UI and restricts functionality and access to the system until the sign-in requirements are satisfied. The [secure desktop's](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation#reference) primary difference from the user desktop is that only trusted processes running as SYSTEM are allowed to run here (that is, nothing is running at the user's privilege level). The path to get to the secure desktop from the user desktop must also be trusted through the entire chain. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#useraccountcontrol_behavioroftheelevationpromptforadministrators)

    - **Default Behavior:** Prompt for consent for non-Windows binaries: When an operation for a non-Microsoft application requires elevation of privilege, the user is prompted on the secure desktop to select either Permit or Deny. If the user selects Permit, the operation continues with the user's highest available privilege.

    - **Harden Windows Security Behavior:** When an operation requires elevation of privilege, the user is prompted on the secure desktop to select either Permit or Deny. If the user selects Permit, the operation continues with the user's highest available privilege.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Only elevate executables that are signed and validated [by enforcing cryptographic signatures on any interactive application](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-account-control-only-elevate-executables-that-are-signed-and-validated) that requests elevation of privilege. One of the [Potential impacts](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/user-account-control-only-elevate-executables-that-are-signed-and-validated#potential-impact) of it is that it can prevent certain poorly designed programs from prompting for UAC. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#useraccountcontrol_onlyelevateexecutablefilesthataresignedandvalidated)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/discord-verify-gradient.gif" width="25" alt="Rotating green checkmark denoting Subcategory"> Hides the entry points for [Fast User Switching](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowslogon). <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowslogon#hidefastuserswitching)

    - This policy will prevent you from using "Forgot my PIN" feature in lock screen or logon screen. If you forget your PIN, you won't be able to recover it.

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Sets the behavior of the elevation prompt for Standard users to Prompt for Credentials on the Secure Desktop. <img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/green-verification.gif" width="15" alt="Rotating green checkmark denoting CSP"> [CSP](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#useraccountcontrol_behavioroftheelevationpromptforstandardusers)

<br>

- <img src="https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/images/Gifs/bluemark.gif" width="25" alt="Blue Check mark denoting Group Policy"> Configures the type of [Admin Approval Mode](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/windows-11-version-24h2-security-baseline/ba-p/4252801) to be Admin Approval Mode with enhanced privilege protection.

<br>
