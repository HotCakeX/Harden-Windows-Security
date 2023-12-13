# Important Notes and Tips about WDAC policies

* WDAC stands for Windows Defender Application Control
* It's used for Application and File whitelisting in Windows.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Supplemental WDAC Policy Considerations

### Verify Policy type

We have to make sure the WDAC policy that we are going to use as a supplemental policy has `PolicyType="Supplemental Policy"` in the `SiPolicy` element of the XML file. If it doesn't, then [we have to use this command](https://learn.microsoft.com/en-us/powershell/module/configci/set-cipolicyidinfo?view=windowsserver2022-ps#example-3-specify-the-base-policy-id-of-a-supplemental-policy) to change it from base policy to supplemental policy of our base policy.

That will also change/create the `<BasePolicyID>GUID</BasePolicyID>` element in the supplemental policy XML file. The GUID will be the `PolicyID` of the base policy specified in the command.

<br>

### Verify Policy Rule options

We have to make sure that the supplemental policy does not contain any policy rule options that only work with a base policy. [This chart shows which ones can be used in a supplemental policy.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create)

<br>

You can [use this PowerShell code](https://learn.microsoft.com/en-us/powershell/module/configci/set-ruleoption) to automatically make sure non-supplemental policy rule options don't exist in a supplemental policy XML file:

```powershell
$supplementalPolicyPath = ".\Supplemental_Policy.xml"
@(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object {
    Set-RuleOption -FilePath $supplementalPolicyPath -Option $_ -Delete
}
```

<br>

A supplemental policy [can only have these policy rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create):

* 5 Enabled:Inherit Default Policy
* 6 Enabled:Unsigned System Integrity Policy (Default)
* 7 Allowed:Debug Policy Augmented
* 13 Enabled:Managed Installer
* 14 Enabled:Intelligent Security Graph Authorization
* 18 Disabled:Runtime FilePath Rule Protection

<br>

### Deny Rules in Supplemental Policy Are Invalid

Deny rules are ignored in supplemental policies by WDAC engine. Supplemental policies are only meant to expand what the base policy trusts, that's why only allow rules are supported in supplemental policies, and that's also the reason why we don't need to merge Microsoft recommended block rules or driver block rules with a supplemental policy.

**When the base policy has a deny rule for a file and we allow the same file in a supplemental policy, the file will still be blocked, because explicit deny rules have the highest priority.**

**[Rule Precedence](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#file-rule-precedence-order)**

<br>

### Signing a Supplemental Policy

Suppose you have a base policy and this base policy will have supplemental policies later on. To add the details of the code signing certificate to the base policy in order to get it ready for signing, you need to use the `-Supplemental` switch parameter with the [Add-SignerRule](https://learn.microsoft.com/en-us/powershell/module/configci/add-signerrule) cmdlet. If you don't do that, the signed base policy after deployment won't accept any signed **supplemental** policies. The `-Supplemental` parameter can only be used for a base policy.

* **Using `-Supplemental` parameter with `Add-SignerRule` cmdlet on a Supplemental policy will cause boot failure after deploying it, because that parameter should only be used when adding singer rules to a base policy.**

<br>

### Removing Supplemental Policies

Whether the deployed supplemental policy is unsigned or signed, you can remove it just like any unsigned policy using CITool.

<br>

### What if You Deploy Unsigned Supplemental Policy on Signed System?

If you deploy an unsigned supplemental policy on a system where all policies including base and supplemental, are signed, the deployed unsigned supplemental policy will be ignored.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How Deny Rules for Files and Certificates/Signers Are Specified

### Denied File Rules

First, Block/Deny File rules are specified in `<FileRules>` element which is directly under `<SiPolicy>` element in the XML file. Deny rules are created by having `<Deny ID="ID_DENY_"` at the beginning of their lines. For example:

```xml
<Deny ID="ID_DENY_AGENT64_SHA1" FriendlyName=<Textual Description/Name> Hash=<Hash Numbers> />
```

<br>

Second, there are File Reference rules for each Deny rule that only mentions them by ID, and these are exactly the same as Allow rules because only Rule IDs are mentioned and nothing about the nature of the rule itself. These are in:

```xml
<SiPolicy>
    <SigningScenarios>
        <SigningScenario>
            <ProductSigners>
                <FileRulesRef>
                    <FileRuleRef RuleID="<The same ID of the Deny File rule mentioned earlier>" />
                </FileRulesRef>
            </ProductSigners>
        </SigningScenario>
    </SigningScenarios>
</SiPolicy>
 ```

<br>

### Denied Certificates/Singers

Denied certificates/singers are first mentioned in `<SiPolicy` => `<Signers>` with the following syntax:

```xml
<Signer ID="ID_SIGNER_VERISIGN_2010" Name="VeriSign Class 3 Code Signing 2010 CA">
... Other possible attributes ...
</Signer>
```

Unlike file rules, this first part doesn't specify whether the certificate/singer must be allowed or blocked by the WDAC policy.

In order to specify whether a certificate/singer should be denied/allowed, the ID of each signer must be specified in the second part of the XML policy file in `<DeniedSigners>` element:

```xml
<SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_<Some generic String>" FriendlyName="<Name>">
        <ProductSigners>
            <DeniedSigners>
                <DeniedSigner SignerId="<ID of the Signer mentioned above in the <Signers> section>" />
            </DeniedSigners>
        </ProductSigners>
    </SigningScenario>
</SigningScenarios>
```

#### [Guidance on Creating WDAC Deny Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/create-wdac-deny-policy)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Verify the Status of User-Mode and Kernel-Mode WDAC on a System

### Using PowerShell

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | select -Property *codeintegrity* | fl
```

`2` means Enforced, `1` means Audit mode, `0` means Disabled/Not running.

### Using System Information

<image>

* Windows Defender Application Control Policy (Kernel Mode)
* Windows Defender Application Control User Mode Policy (User Mode)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Refreshing WDAC Policies

### [Using the built-in CiTool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/citool-commands)

```powershell
CITool --refresh
```

<br>

### Old Method: using [RefreshPolicy(AMD64).exe](https://www.microsoft.com/en-us/download/details.aspx?id=102925)

Using RefreshPolicy(AMD64).exe only works when you add a new policy to the Windows folder, but when you delete a policy from that folder, running RefreshPolicy(AMD64).exe won't make the apps that were previously allowed to run by the policy we just deleted, to be blocked from running again. so after we remove a policy from Windows folder, a system restart is required.

This makes sense because apps that have been previously allowed to run by a policy that we just deleted might be still running in the background or even foreground, so to properly stop them, just running `RefreshPolicy(AMD64).exe` isn't enough and data loss could've occurred if that was the case.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About `<SigningScenarios>` Node in the WDAC Policy XML

It consists of 2 elements:

This one contains the Certificates/Singers of the Kernel-mode drivers

```xml
<SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS_1" FriendlyName="Driver Signing Scenarios">
```

And this one contains the Certificates/Singers of the User-mode binaries

```xml
<SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode Signing Scenarios">
```

**Only** the `Value` needs to stay the same. So, for Kernel-mode drivers it should always be **131** and for User-mode binaries it should always be **12**, anything else can be customized.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Merging Policies

`Merge-cipolicy` cmdlet [does not include duplicates](https://learn.microsoft.com/en-us/powershell/module/configci/merge-cipolicy?view=windowsserver2022-ps#:~:text=The%20command%20does%20not%20include%20duplicates.%20For%20this%20example%2C%20we%20present%20only%20the%20first%20few%20rules.), neither duplicate rules nor rules with duplicate file hashes.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## WDAC Forces Allow-list Architecture by Nature

WDAC forces Allow-list architecture by nature, not deny-list architecture. An empty deployed policy allows nothing to run and leads to system failure. This is why Microsoft recommended blocklists include 2 Allow All rules with the Deny rules, that changes the WDAC policy's nature from being an Allow-list to being a Deny-list.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About Microsoft Recommended Block Rules

### Microsoft Recommended Block Rules

From [Microsoft recommended block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac) document, copy the WDAC policy XML at the end (you might need to expand that section to view it), use a text editor like [VS Code](https://code.visualstudio.com/) to edit it as recommended:

The blocklist policy includes "Allow all" rules for both kernel and user mode files that make it safe to deploy as a standalone WDAC policy. We can even deploy it side-by-side with AllowMicrosoft policy, by keeping its allow all rules in place. [Refer to this document about how multiple base policies work.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/deploy-multiple-wdac-policies)

"Only applications allowed by both policies (All Base policies) run without generating block events", that means even though the Microsoft recommended block rules have **2 allow all rules**, they don't actually allow everything to run, because the same allow all rules don't exist in the default AllowMicrosoft policy, it only contains explicit allow rules.

On Windows versions 1903 and above, Microsoft recommends converting this policy to multiple policy format using the `Set-CiPolicyIdInfo` cmdlet with the `-ResetPolicyId` switch. Then, you can deploy it as a Base policy side-by-side with any other policies in your environment.

If merging into an existing policy that includes an explicit allowlist, you should first remove the two "Allow all" rules and their corresponding FileRuleRefs:

```xml
<Allow ID="ID_ALLOW_A_1" FriendlyName="Allow Kernel Drivers" FileName="*" />
<Allow ID="ID_ALLOW_A_2" FriendlyName="Allow User mode components" FileName="*" />
```

```xml
<FileRuleRef RuleID="ID_ALLOW_A_1" />
<FileRuleRef RuleID="ID_ALLOW_A_2" />
```

<br>

### Microsoft Recommended Driver Block Rules

* Deploying Microsoft recommended block rules (Driver or user mode) alone, after removing the allow all rules from them, will cause boot failure, for obvious reasons.

* [How to check the version of Microsoft recommended ***driver*** block rules that are being enforced](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/deploy-multiple-wdac-policies)
  - The version is mentioned in [Code Integrity operational event logs](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations) with an event ID of `3099` in the General tab.

* We don't need to use the **Recommended Kernel Block Rules** in WDAC when creating a policy because [it's already being enforced by default](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules#microsoft-vulnerable-driver-blocklist) and if we want to update it more regularly, we can do so [by following this section of the document.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules#steps-to-download-and-apply-the-vulnerable-driver-blocklist-binary) Or by [Fast and Automatic Microsoft Recommended Driver Block Rules updates](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates).

<br>

> [Citation:](https://github.com/MicrosoftDocs/WDAC-Toolkit/discussions/217#discussioncomment-5104749) If you only manage Windows 11 22H2 systems (and above), then you don't need the recommended driver block rules in your WDAC policy. Otherwise, you should have the driver block rules in your policy. In either scenario, you should have the recommended user mode rules.

<br>

> [Citation:](https://github.com/MicrosoftDocs/WDAC-Toolkit/discussions/216#discussioncomment-5104866) ISG does not include the recommended blocklist(s).

<br>

> [Citation:](https://github.com/MicrosoftDocs/windows-itpro-docs/issues/11429) About deploying new Signed WDAC policies ***rebootlessly*** using CITool.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Miscellaneous

* [Set the hypervisor Code Integrity option for the WDAC policy XML file to **Strict**](https://learn.microsoft.com/en-us/powershell/module/configci/set-hvcioptions) only after using `Add-SignerRule` cmdlet, because after running `Add-SignerRule` cmdlet, the `<HvciOptions>` resets to `0`.

* Using [Signtool.exe](https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe) with `-fd certHash` will default to the algorithm used on the signing certificate. For example, if the certificate has `SHA512` hashing algorithm, the file that is being signed will use the same algorithm.

* Sometimes [New-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy) Cmdlet creates 2 file rules for each driver file, such as `.sys` files. One of them is stored in **Driver signing scenarios** section under `<SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS_1" FriendlyName="">` and the other is stored in **User mode signing scenarios** section under `<SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="">`. [More info here](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#why-does-scan-create-eight-hash-rules-for-certain-xml-files)

* [File rule levels](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-2-windows-defender-application-control-policy---file-rule-levels) and Cmdlets like [New-CiPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy) only create rules for files with supported extensions. The [table in this page](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/feature-availability) lists all of the support file extensions.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Blocking Individual Windows components

### Blocking Microsoft Store

```powershell
$Package = Get-AppXPackage -Name "Microsoft.WindowsStore"
$Rules += New-CIPolicyRule -Package $Package -Deny
New-CIPolicy -FilePath ".\store.xml" -Rules $Rules
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## File Rule Levels Security
(For User Mode binaries only)

* Hash (Best for any files, especially unsigned files)

* FilePublisher (Best for Signed files)

* SignedVersion (More permissive than FilePublisher, usable only for signed files)

The rest are less secure and more permissive than the 3 file rule levels mentioned above.

P.S FileName relies on the original filename for each binary, which can be [modified.](https://security.stackexchange.com/questions/210843/is-it-possible-to-change-original-filename-of-an-exe)

Find more information in [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Remove Flight Signing Certificates From Default Example Policies

Removing these shouldn't cause any problem as long as you are using stable OS version

```powershell
# Flight root Certs removal
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_STORE_FLIGHT_ROOT"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_WINDOWS_FLIGHT_ROOT"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_ELAM_FLIGHT"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_HAL_FLIGHT"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_WHQL_FLIGHT_SHA2"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_WINDOWS_FLIGHT_ROOT_USER"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_ELAM_FLIGHT_USER"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_HAL_FLIGHT_USER"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_WHQL_FLIGHT_SHA2_USER"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_RT_FLIGHT"
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Remove WDAC Policy Refresh Tool Certificates From Default Example Policies

Starting with Windows 11 22H2, [CITool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/citool-commands) is available in Windows by default and Refresh tool is no longer needed, so use the commands below to remove the certificates that allow that tool to be executed, **their order of execution is important.**

* [Remove-CIPolicyRule](https://learn.microsoft.com/en-us/powershell/module/configci/remove-cipolicyrule)
* [Note](https://github.com/MicrosoftDocs/windows-powershell-docs/issues/3312)

```powershell
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_MICROSOFT_REFRESH_POLICY"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_FILEATTRIB_REFRESH_POLICY"
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Allowing Questionable Software in a WDAC Policy

Questionable software such as pirated software are **never** recommended to be allowed in the WDAC policy because they are tampered with. Pirated software can have signed files too, but they are modified and as a result there is a mismatch between the file hash and the hash of the file saved in their digital signature. When such a mismatch exists for signed files, [Authenticode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode) reports the mismatch, and the file can't be allowed in a WDAC policy.

If you want to go through many files and see which ones have a mismatch between their file hash and signature hash, you can use the following [PowerShell (core)](https://github.com/PowerShell/PowerShell/releases) command, it searches through a folder and all of its sub-folders quickly using [parallel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/foreach-object?view=powershell-7.3#-parallel) operations:

<br>

```powershell
Get-ChildItem -Recurse -Path "Path\To\a\Folder" -File | ForEach-Object -Parallel {Get-AuthenticodeSignature -FilePath $_.FullName} | Where-Object {$_.Status -eq 'HashMismatch'}
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About the Concurrent Deployed WDAC Policies Limit

The limit as stated in [the official document](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/deploy-multiple-wdac-policies) is 32 active policies on a device at once. That is the total number of Base policies + Supplemental policies + any active system deployed policies.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Performing System Reset While Signed WDAC Policy Is Deployed

If you've deployed a Signed WDAC policy on a system and then decide to reset it, either using local install or cloud download, it will fail during the reset process. You must remove the signed WDAC policy prior to performing the reset.

Unsigned WDAC policies don't have this behavior. Since they are neither cryptographically signed nor tamper-proof, they will be removed during the reset process and after reset the system will not have the WDAC policy.

This behavior is true for [Lightly managed](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Lightly-Managed-Devices), [Allow Microsoft](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-3) and [Default Windows](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-4) WDAC policy types.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Citool No Longer Requires GUID.cip Naming Convention for Deployment

Normally, `.cip` files would have to have the same name as the GUID of the xml file they were converted from, but that's no longer necessary. Using [CiTool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/citool-commands) in Windows 11 build `22621`, they can be deployed with any name, even without a name, and lead to a successful WDAC policy deployment.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Policies with Required:EV Signers rule option

If a base policy has rule option number 8, Required:EV Signers, it will require all kernel-mode drivers to have EV signer certificates. You cannot bypass this requirement with a Supplemental policy, you cannot allowlist non-EV signed files in any way. **Non-EV signed files will be blocked even if the base policy is in Audit mode.** This is true for any type of base policy such as Default Windows, Allow Microsoft, Strict Kernel mode etc.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## The Following Policy Rule Options Only Apply to User Mode Binaries/Drivers

* Enabled:Dynamic Code Security (generation)

* Required:Enforce Store Applications

When we remove the `SigningScenario Value="12"` completely which is responsible for User Mode code integrity in the xml policy and also remove any signers that belong to User mode section, such as those that have `_user` in their ID, the [Merge-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/merge-cipolicy) cmdlet automatically removes EKUs that belong to the policy rule options mentioned above during a merge.

Removing the User mode signers, rules and `Enabled:UMCI` rule option allows us to create a Kernel-only WDAC policy that doesn't touch User mode binaries/drivers.

For a Kernel-mode only WDAC policy, only the following EKUs are necessary

```xml
<EKUs>
    <EKU ID="ID_EKU_WINDOWS" Value="010A2B0601040182370A0306" FriendlyName="" />
    <EKU ID="ID_EKU_ELAM" Value="010A2B0601040182373D0401" FriendlyName="" />
    <EKU ID="ID_EKU_HAL_EXT" Value="010a2b0601040182373d0501" FriendlyName="" />
    <EKU ID="ID_EKU_WHQL" Value="010A2B0601040182370A0305" FriendlyName="" />
</EKUs>
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## You Can Merge the Same Policy XML File With Itself

In order to automatically remove unnecessary things from a policy file, such as the EKUs mentioned earlier, you can run a command like this:

```powershell
Merge-CIPolicy .\Policy.xml -OutputFilePath .\Policy1.xml
```

It essentially merges a policy with itself, adding `_0` to each ID and SingerID of the xml nodes which is easily removable using WDACConfig module, **although it's not necessary to remove them at all, they are perfectly fine.**

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## -Audit Parameter of the ConfigCi Cmdlets

When you use `-Audit` parameter of ConfigCI cmdlets such as [Get-SystemDriver](https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver) and [New-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy), these 2 event logs are scanned

1. AppLocker – MSI and Script event log
2. CodeIntegrity - Operational

[**Explained more in here**](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About Double-Signed Files and Filepublisher Level

Sometimes there are files that are signed by 2 certificates, aka double signed files.

When FilePublisher level is used, WDAC creates rules for both of the intermediate certificates of those files, and each rule will have a singer assigned to it. If the file is either User mode only or Kernel mode only, then 2 Signers will be created for it, one for each certificate.

Depending on Kernel or use mode, 2 Allowed Signers are created for the file in either UMCI or KMCI Signing scenario sections.

However, if the file is a kernel mode driver and user mode driver, then 4 signers are created for it, 2 Allowed Signers in the UMCI Signing Scenario and 2 in the KMCI Signing scenario.

### An example

<br>

In the signer below

```xml
<Signer ID="ID_SIGNER_F_2" Name="Microsoft Windows Third Party Component CA 2014">
    <CertRoot Type="TBS" Value="D8BE9E4D9074088EF818BC6F6FB64955E90378B2754155126FEEBBBD969CF0AE" />
    <CertPublisher Value="Microsoft Windows Hardware Compatibility Publisher" />
    <FileAttribRef RuleID="ID_FILEATTRIB_F_46" />
</Signer>
```

<br>

* `Name="Microsoft Windows Third Party Component CA 2014"` is the Common name of the Intermediate certificate of the file
* `Value="D8BE9E4D9074088EF818BC6F6FB64955E90378B2754155126FEEBBBD969CF0AE"` is the TBS (To Be Signed) values of the same Intermediate certificate
* `Value="Microsoft Windows Hardware Compatibility Publisher"` is the Common name of the Leaf certificate of the file

<br>

### Some Notes

1. If 2 files have the same Leaf certificate CN and also have an Intermediate certificate in common (that has the same TBS and CN) then they should be listed under the same Signer.

2. Any Intermediate certificate in the certificate chain/path of a file can be used to allow a file using FilePublisher.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## What Does HVCI option Set to Strict Mean?

[HVCI](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) stands for [Hypervisor-protected Code Integrity](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/introduction-to-device-guard-virtualization-based-security-and-windows-defender-application-control) and it is a feature that uses virtualization-based security (VBS) to protect the Windows kernel from memory attacks. HVCI can be set to different options in a WDAC policy, such as Enabled, DebugMode, or Strict. Setting [HVCI to Strict](https://learn.microsoft.com/en-us/powershell/module/configci/set-hvcioptions) in a WDAC policy provides the highest level of protection for kernel mode code integrity, as it enforces these additional restrictions:

* It prevents unsigned drivers from loading, even if they are allowed by the WDAC policy.
It prevents drivers that are not compatible with HVCI from loading, even if they are signed and allowed by the WDAC policy.

* It prevents drivers that have been tampered with or modified from loading, even if they are signed and allowed by the WDAC policy.

* Setting HVCI to Strict in a WDAC policy can help prevent malware or attackers from exploiting vulnerabilities in kernel mode drivers or bypassing the WDAC policy enforcement.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About Certificates and Certificate Chains

* A file can have only one root certificate at the end of the chain. The root certificate is always self-signed by the CA itself (meaning its IssuerCN and SubjectCN are the same) and it is the ultimate source of trust for the chain that validates it. Having more than one root certificate would imply that there are multiple chains of trust for the same file, which is not possible.

* A file can have more than 1 intermediate certificate and there is no definitive limit for it, but in practice, it is recommended to keep the certificate chain as short as possible.

* A file can have only one leaf certificate at the beginning of the chain. The leaf certificate is the one that belongs to the file itself and contains its public key and other information. Having more than one leaf certificate would imply that there are multiple files with different identities and keys, which is not possible.

* Leaf, intermediate and root are the only types of certificates a file can have in a certificate chain. There are other types of certificates that are not part of a chain, such as self-signed certificates or wildcard certificates, but they are not relevant to WDAC policies.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img width="65" src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/arrow-pink.gif" alt="Continue Reading about BYOVD using Windows Defender Application Control"> [Continue reading about BYOVD protection with WDAC](#-continue-reading-about-byovd-protection-with-wdac)

#### [WDAC policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection) for BYOVD Kernel mode only protection

<br>
