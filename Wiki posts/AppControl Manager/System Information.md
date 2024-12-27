# System Information

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/System%20Information.png" alt="AppControl Manager Application's System Information Page">

</div>

<br>

<br>

Use the System Information page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to view details about the deployed App Control policies on the system. 

* Search through the list of policies

* View the rule options in each policy

* Determine which policy is signed or unsigned (requires Windows 11 24H2 or later/Windows Server 2025 or later, otherwise all policies will appear as `unsigned` regardless of their actual signing status)

* Sort the policies using multiple criteria

* See which policy is Base, Supplemental or System

* View the version of each policy

<br>

> [!TIP]\
> You can view the version of the Microsoft Vulnerable Driver Block List in this page by checking the box for including System policies in the list.

<br>

## View Code Integrity Information

In the ***Code Integrity Information*** section you can view advanced details about the current status of Code Integrity on the system. 

You can also check the status of Application Control for Business, including whether User-Mode or Kernel-Mode policies are deployed and whether they are set to Enforced mode or Audit mode.

<br>

## Policy Removal

This page also allows you to **remove** the deployed non-system App Control policies from the system.

Whenever you select a policy from the list, the app will automatically present to you the best and most appropriate course of action in order to remove it.

<br>

### Removing Unsigned or Supplemental Policies

Unsigned Base or signed/unsigned Supplemental Application Control policies can be removed with a single click/tap of a button. Simply select a policy from the list and then use the **Remove** button to remove it.

Starting with Windows 11 24H2/Windows Server 2025, no reboot is required for unsigned base or supplemental policies.

<br>

### Removing Signed Base Policies

Signed Base policies require additional information during the removal process. Select a signed policy and then press the **Remove** button, you will be presented with a dialog asking for additional information.


<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/System%20Information%20Removing%20Signed%20Base%20Policies%20Dialog.png" alt="AppControl Manager Application Signed Base policy removal dialog">

</div>

<br>

<br>

* **Certificate File**: Provide the path to the certificate `.cer` file. The certificate's details must exist in the XML policy file as signers, so ensure it is the same certificate that you used to sign the policy with. The certificate must exist in the Personal store of the Current User certificate stores with private key.

* **Certificate Common Name**: The Common Name (CN) of the same certificate file you select.

* **SignTool Path**: The path to the `SignTool.exe`. If you don't have it, you can toggle the **Auto Acquire** switch. Auto Acquire will try to first find it on the system by checking for installed Windows SDK, if it cannot find it, it will download it from the official Microsoft server.

* **XML File**: The path to the XML policy file of the same policy you're trying to remove from the system.

Once all four fields are populated, press the **Verify** button. This action validates your inputs and enables the **Submit** button, allowing you to proceed with the removal process. All of the information you submit will be saved in app settings so that the next time they will be automatically populated for you.

Following this step, the policy will be re-signed and redeployed on the system with a new [rule option](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-1-app-control-for-business-policy---policy-rule-options) labeled **Enabled: Unsigned System Integrity Policy**.

> [!IMPORTANT]\
> After completing this process, restart your system. Since signed policies are tamper-resistant, they leverage Secure Boot and reside in the EFI partition. Upon reboot, select the same signed policy and press the Remove **button**. The AppControl Manager will detect the policy as safe for removal and delete it from the system without requiring further input. (**If you do not reboot your system and attempt to remove the signed policy that was just re-signed and re-deployed, it will lead to boot failure.**) 

<br>

> [!NOTE]\
> **About the Automatic Policies filter option**
>
> Enabling this checkbox includes supplemental policies named `AppControlManagerSupplementalPolicy` in the displayed results. Each base policy created and deployed via the AppControl Manager automatically deploys a corresponding supplemental policy with this name. This supplemental policy is essential for the operation of the AppControl Manager application itself.
> In addition, it contains a FilePublisher rule for `SignTool.exe`, allowing signing operations to be performed. If you intentionally remove this policy, you will no longer be able to launch the AppControl Manager or use `SignTool.exe` when certain base policies are active.
> 
> **Note that these supplemental policies are automatically removed when their associated base policy is removed from the system, so no additional action is required on your part.**
>
> You can view the XML source of the `AppControlManagerSupplementalPolicy` supplemental policy [here](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/AppControl%20Manager/Resources/AppControlManagerSupplementalPolicy.xml).

<br>
