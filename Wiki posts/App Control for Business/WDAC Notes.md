# Important Notes and Tips about App Control policies

* App Control for Business was formerly known as WDAC (Windows Defender Application Control)
* It's used for Application and File whitelisting in Windows.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Supplemental App Control Policy Considerations

### Verify Policy type

We have to make sure the App Control policy that we are going to use as a supplemental policy has `PolicyType="Supplemental Policy"` in the `SiPolicy` element of the XML file. If it doesn't, then [we have to use this command](https://learn.microsoft.com/en-us/powershell/module/configci/set-cipolicyidinfo?view=windowsserver2022-ps#example-3-specify-the-base-policy-id-of-a-supplemental-policy) to change it from base policy to supplemental policy of our base policy.

That will also change/create the `<BasePolicyID>GUID</BasePolicyID>` element in the supplemental policy XML file. The GUID will be the `PolicyID` of the base policy specified in the command.

<br>

### Verify Policy Rule options

We have to make sure that the supplemental policy does not contain any policy rule options that only work with a base policy. [This chart shows which ones can be used in a supplemental policy.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create)

You can [use this PowerShell code](https://learn.microsoft.com/en-us/powershell/module/configci/set-ruleoption) to automatically make sure non-supplemental policy rule options don't exist in a supplemental policy XML file:

```powershell
[System.String]$SupplementalPolicyPath = "<Path to SupplementalPolicy.xml>"
@(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object -Process {
    Set-RuleOption -FilePath $SupplementalPolicyPath -Option $_ -Delete
}
```

<br>

A supplemental policy [can only have these policy rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create):

* 5 Enabled:Inherit Default Policy
* 6 Enabled:Unsigned System Integrity Policy (Default)
* 7 Allowed:Debug Policy Augmented
* 13 Enabled:Managed Installer
* 14 Enabled:Intelligent Security Graph Authorization
* 18 Disabled:Runtime FilePath Rule Protection

<br>

### Deny Rules in Supplemental Policy Are Invalid

Deny rules are ignored in supplemental policies by the App Control engine. Supplemental policies are only meant to expand what the base policy trusts, that's why only allow rules are supported in supplemental policies, and that's also the reason why we don't need to merge Microsoft recommended block rules or driver block rules with a supplemental policy.

<br>

### Rule Precedence

When the base policy has a deny rule for a file and we allow the same file in a supplemental policy, the file will still be blocked, because explicit deny rules have the highest priority.

[More info](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#file-rule-precedence-order)

<br>

### Signing a Supplemental Policy

Suppose you have a base policy which will subsequently have supplemental policies. To add the details of the code signing certificate to the base policy, ensuring its readiness for signing, you need to use the `-Supplemental` switch parameter with the [Add-SignerRule](https://learn.microsoft.com/en-us/powershell/module/configci/add-signerrule) cmdlet. Failing to do so would render the signed *base* policy, post-deployment, incapable of accepting any signed *supplemental* policies. Note that the `-Supplemental` parameter is exclusively applicable to base policies.

> [!IMPORTANT]\
> Using `-Supplemental` parameter with `Add-SignerRule` cmdlet on a Supplemental policy will cause boot failure after deploying it, because that parameter should only be used when adding signer rules to a base policy.

<br>

### Removing Supplemental Policies

Whether the deployed supplemental policy is unsigned or signed, you can remove it just like any unsigned policy using CITool.

<br>

### What if You Deployed an Unsigned Supplemental Policy for a Signed Base Policy?

If you deploy an unsigned supplemental policy on a system where all policies including base and supplemental, are signed, the deployed unsigned supplemental policy will be ignored.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How Deny Rules for Files and Certificates/Signers Are Specified

### Denied File Rules

First, Block/Deny File rules are specified in the `<FileRules>` node which is directly under the `<SiPolicy>` node in the XML file. Deny rules are created by having `<Deny ID="ID_DENY_"` at the beginning of their lines. For example:

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

### Denied Certificates/Signer

Denied certificates/signers are first mentioned in `<SiPolicy` => `<Signers>` with the following syntax:

```xml
<Signer ID="ID_SIGNER_VERISIGN_2010" Name="VeriSign Class 3 Code Signing 2010 CA">
... Other possible elements ...
</Signer>
```

Unlike file rules, this first part doesn't specify whether the certificate/signer must be allowed or blocked by the App Control policy.

In order to specify whether a certificate/signer should be denied/allowed, the ID of each signer must be specified in the second part of the XML policy file in `<DeniedSigners>` element:

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

#### [Guidance on Creating App Control Deny Policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-deny-policy)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## How to Verify the Status of User-Mode and Kernel-Mode Application Control on the System

### Using PowerShell

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | select -Property *codeintegrity* | fl
```

`2` means Enforced, `1` means Audit mode, `0` means Disabled/Not running.

### Using System Information

* App Control for Business Policy (Kernel Mode)
* App Control for Business User Mode Policy (User Mode)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Refreshing App Control Policies

### [Using the built-in CiTool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands)

```powershell
CITool --refresh
```

*Old Method: using [RefreshPolicy(AMD64).exe](https://www.microsoft.com/en-us/download/details.aspx?id=102925)*


> [!NOTE]\
> When a Supplemental policy is removed from the system and you refresh the policies, that doesn't instantly block the apps that were allowed by the removed policy, simply because those apps might be still running on the system, either in the background or foreground. To properly stop them, a system restart is required.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About `<SigningScenarios>` Node in the App Control Policy XML

It consists of 2 elements:

This one contains the Certificates/Signers of the Kernel-mode drivers

```xml
<SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS_1" FriendlyName="Driver Signing Scenarios">
```

And this one contains the Certificates/Signers of the User-mode binaries

```xml
<SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode Signing Scenarios">
```

**Only** the `Value` needs to stay the same. So, for Kernel-mode drivers it should always be **131** and for User-mode binaries it should always be **12**, anything else can be customized, this is according to the CI policy schema.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Merging Policies

`Merge-cipolicy` cmdlet [does not include duplicates](https://learn.microsoft.com/en-us/powershell/module/configci/merge-cipolicy?view=windowsserver2022-ps#:~:text=The%20command%20does%20not%20include%20duplicates.%20For%20this%20example%2C%20we%20present%20only%20the%20first%20few%20rules.), neither duplicate rules nor rules with duplicate file hashes.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## App Control Forces Allow-list Architecture by Nature

App Control forces Allow-list architecture by nature, not deny-list architecture. An empty deployed policy allows nothing to run and leads to system failure. This is why Microsoft recommended blocklists include 2 Allow All rules with the Deny rules, that changes the App Control policy's nature from being an Allow-list to being a Deny-list.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About Microsoft Recommended Block Rules

### How to Manually Consume the Microsoft Recommended Block Rules

From [Microsoft recommended block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol) document, copy the App Control policy XML at the end (you might need to expand that section to view it), use a text editor like [VS Code](https://code.visualstudio.com/) to edit it as recommended:

The blocklist policy includes "Allow all" rules for both kernel and user mode files that make it safe to deploy as a standalone App Control policy or side-by-side any other policy by keeping its allow all rules in place. [Refer to this document about how multiple base policies work.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/deploy-multiple-appcontrol-policies)

<br>

### How Do the Allow All Rules Work

Only applications allowed by **all Base policies** run without generating block events, that means even though the Microsoft recommended block rules have **2 allow all rules**, they don't actually allow everything to run, because for instance in a realistic scenario, the same allow all rules don't exist in other base policies such as AllowMicrosoft or DefaultWindows base policy, they would only contain explicit allow rules.

The policy must be in multiple policy format, which can be achieved by using the `Set-CiPolicyIdInfo` cmdlet with the `-ResetPolicyId` switch.

<br>

> [!IMPORTANT]\
> If merging into an existing policy that includes an explicit allowlist, you should first remove the two "Allow all" rules and their corresponding FileRuleRefs:

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

* How to check the version of the deployed Microsoft recommended ***driver*** block rules
  - The version is mentioned in [Code Integrity operational event logs](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations) with an event ID of `3099` in the General tab.

* We don't need to merge and use the Microsoft recommended driver block rules in a policy, because [it's already being enforced by default](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#microsoft-vulnerable-driver-blocklist) and if we want to update it more regularly, we can do so [by following this section of the document.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#steps-to-download-and-apply-the-vulnerable-driver-blocklist-binary) Or by [Fast and Automatic Microsoft Recommended Driver Block Rules updates](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Fast-and-Automatic-Microsoft-Recommended-Driver-Block-Rules-updates).

<br>

> [Citation:](https://github.com/MicrosoftDocs/WDAC-Toolkit/discussions/217#discussioncomment-5104749) If you only manage Windows 11 22H2 systems (and above), then you don't need the recommended driver block rules in your App Control policy. Otherwise, you should have the driver block rules in your policy. In either scenario, you should have the recommended user mode rules.

<br>

> [Citation:](https://github.com/MicrosoftDocs/WDAC-Toolkit/discussions/216#discussioncomment-5104866) ISG does not include the recommended blocklist(s).

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Miscellaneous

* [Set the hypervisor Code Integrity option for the App Control policy XML file to **Strict**](https://learn.microsoft.com/en-us/powershell/module/configci/set-hvcioptions) only after using `Add-SignerRule` cmdlet, because after running `Add-SignerRule` cmdlet, the `<HvciOptions>` resets to `0`.

* Using [Signtool.exe](https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe) with `-fd certHash` will default to the algorithm used on the signing certificate. For example, if the certificate has `SHA512` hashing algorithm, the file that is being signed will use the same algorithm.

* Sometimes [New-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy) Cmdlet creates 2 file rules for each driver file, such as `.sys` files. One of them is stored in **Driver signing scenarios** section under SigningScenario with the value `131` and the other one is stored in **User mode signing scenarios** section under SigningScenario with the value `12`. [More info here](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#why-does-scan-create-eight-hash-rules-for-certain-files)

* [File rule levels](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-2-app-control-for-business-policy---file-rule-levels) and Cmdlets like [New-CiPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy) only create rules for files with supported extensions. The [table on this page](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability) lists all of the support file extensions.

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

## How to Remove Flight Signing Certificates From Default Example Policies

Removing these do not cause any problem as long as your Windows build is in the Stable, Release Preview or Beta channel.

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

## How to Remove App Control Policy Refresh Tool Certificates From Default Example Policies

Starting with Windows 11 22H2, [CITool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands) is available in Windows by default and Refresh tool is no longer needed, so use the commands below to remove the certificates that allow that tool to be executed, **their order of execution is important.**

* [Remove-CIPolicyRule](https://learn.microsoft.com/en-us/powershell/module/configci/remove-cipolicyrule)
* [Note](https://github.com/MicrosoftDocs/windows-powershell-docs/issues/3312)

```powershell
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_SIGNER_MICROSOFT_REFRESH_POLICY"
Remove-CIPolicyRule -FilePath "DefaultWindows_Enforced.xml" -Id "ID_FILEATTRIB_REFRESH_POLICY"
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Allowing Questionable Software in an App Control Policy

Questionable software such as pirated software are **never** recommended to be allowed in the App Control policy because they are tampered with. Pirated software can have signed files too, but they are modified and as a result there is a mismatch between the file hash and the hash of the file saved in their digital signature. When such a mismatch exists for signed files, [Authenticode](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode) reports the mismatch, and the file can't be allowed in an App Control policy.

If you want to go through many files and see which ones have a mismatch between their file hash and signature hash, you can use the following [PowerShell](https://github.com/PowerShell/PowerShell/releases) command, it searches through a folder and all of its sub-folders quickly.

<br>

```powershell
Foreach ($File in (Get-ChildItem -Path 'Path\To\a\Folder' -File -Recurse)) {
    $Signature = Get-AuthenticodeSignature -FilePath $File.FullName
    if ($Signature.Status -eq 'HashMismatch') {
        Write-Output -InputObject $File.FullName
    }
}
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Performing System Reset While Signed App Control Policy Is Deployed

If you've deployed a Signed App Control policy on a system and then decide to reset it, either using local install or cloud download, it will fail during the reset process. You must remove the signed App Control policy prior to performing the reset.

Unsigned App Control policies don't have this behavior. Since they are neither cryptographically signed nor tamper-proof, they will be removed during the reset process and after reset the system will not have the App Control policy.

This behavior is true for [Lightly managed](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Lightly-Managed-Devices), [Allow Microsoft](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-3) and [Default Windows](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-Fully-managed-device---Variant-4) App Control policy types.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## The .CIP Binary File Can Have Any Name or No Name at All

Using [CiTool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands) in Windows 11 build `22621` and above, `.CIP` binary files can be deployed with any name, even without a name, and lead to a successful App Control policy deployment.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Policies with Required:EV Signers rule option

If a base policy has rule option number 8, **Required:EV Signers**, it will require all kernel-mode drivers to have EV signer certificates.

* You cannot bypass this requirement with a Supplemental policy.

* You cannot allowlist non-EV signed files in any way.

* **Non-EV signed files will be blocked even if the base policy is in Audit mode.** This is true for any type of base policy such as Default Windows, Allow Microsoft, Strict Kernel mode etc.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## The Following Policy Rule Options Only Apply to User Mode Binaries/Drivers

* Enabled:Dynamic Code Security (generation)

* Required:Enforce Store Applications

When we remove the `SigningScenario Value="12"` completely which is responsible for User Mode code integrity in the xml policy and also remove any signers that belong to User mode section, such as those that have `_user` in their ID, the [Merge-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/merge-cipolicy) cmdlet automatically removes EKUs that belong to the policy rule options mentioned above during a merge.

Removing the User mode signers, rules and `Enabled:UMCI` rule option allows us to create a Kernel-only App Control policy that doesn't touch User mode binaries/drivers.

For a Kernel-mode only App Control policy, only the following EKUs are necessary

```xml
<EKUs>
    <EKU ID="ID_EKU_WINDOWS" Value="010A2B0601040182370A0306" FriendlyName="" />
    <EKU ID="ID_EKU_ELAM" Value="010A2B0601040182373D0401" FriendlyName="" />
    <EKU ID="ID_EKU_HAL_EXT" Value="010a2b0601040182373d0501" FriendlyName="" />
    <EKU ID="ID_EKU_WHQL" Value="010A2B0601040182370A0305" FriendlyName="" />
</EKUs>
```

> [!IMPORTANT]\
> [Refer to this document for complete info about Kernel-Mode policies](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## You Can Merge the Same Policy XML File With Itself

In order to automatically remove unnecessary things from a policy file, such as the EKUs mentioned earlier, you can run a command like this:

```powershell
Merge-CIPolicy .\Policy.xml -OutputFilePath .\Policy1.xml
```

It essentially merges a policy with itself, adding `_0` to each ID and SignerID of the xml nodes.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## -Audit Parameter of the ConfigCi Cmdlets

When you use `-Audit` parameter of ConfigCI cmdlets such as [Get-SystemDriver](https://learn.microsoft.com/en-us/powershell/module/configci/get-systemdriver) and [New-CIPolicy](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy), these 2 event logs are scanned

1. AppLocker – MSI and Script event log
2. CodeIntegrity - Operational

[**Explained more in here**](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About Double-Signed Files and FilePublisher Level

Sometimes there are files that are signed by 2 or more certificates, aka double signed files.

When a level such as FilePublisher is used, ConfigCI cmdlets create signer rules for one of the intermediate certificates of each of the signers of those files.

Depending on Kernel or user mode, 2 Allowed Signers are created for the file in either UMCI or KMCI Signing scenario sections.

However, if the file is a kernel mode driver and user mode driver, then 4 signers are created for it, 2 Allowed Signers in the UMCI Signing Scenario and 2 in the KMCI Signing scenario.

### An example

In the signer below

```xml
<Signer ID="ID_SIGNER_F_2" Name="Microsoft Windows Third Party Component CA 2014">
    <CertRoot Type="TBS" Value="D8BE9E4D9074088EF818BC6F6FB64955E90378B2754155126FEEBBBD969CF0AE" />
    <CertPublisher Value="Microsoft Windows Hardware Compatibility Publisher" />
    <FileAttribRef RuleID="ID_FILEATTRIB_F_46" />
</Signer>
```

<br>

* `Name="Microsoft Windows Third Party Component CA 2014"` is the Common Name of one of the Intermediate certificate of the file.

* `Value="D8BE9E4D9074088EF818BC6F6FB64955E90378B2754155126FEEBBBD969CF0AE"` is the TBS (To Be Signed) values of the same Intermediate certificate.
* `Value="Microsoft Windows Hardware Compatibility Publisher"` is the Common Name of the Leaf certificate of the file.

<br>

### Some Notes

1. If 2 files have the same Leaf certificate CN and also have an Intermediate Certificate in common (that has the same TBS and CN) then they should be listed under the same Signer.

2. Any Intermediate certificate in the certificate chain/path of a file can be used to allow a file using FilePublisher level.

3. In case of a multi-certificate signed file, such as the Office installer which is triple-signed, any of the certificates can be used to allow the file in a Supplemental policy or Deny it in a base policy.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## What Does HVCI option Set to Strict Mean?

[HVCI](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) stands for **Hypervisor-protected Code Integrity** and it is a feature that uses virtualization-based security (VBS) to protect the Windows kernel from memory attacks. HVCI can be set to different options in an App Control policy, such as Enabled, DebugMode, or Strict.

Setting [HVCI to Strict](https://learn.microsoft.com/en-us/powershell/module/configci/set-hvcioptions) in an App Control policy provides the highest level of protection for kernel mode code integrity, as it enforces these additional restrictions:

* It prevents unsigned drivers from loading, even if they are allowed by the App Control policy.
It prevents drivers that are not compatible with HVCI from loading, even if they are signed and allowed by the App Control policy.

* It prevents drivers that have been tampered with or modified from loading, even if they are signed and allowed by the App Control policy.

* Setting HVCI to Strict in an App Control policy can help prevent malware or attackers from exploiting vulnerabilities in kernel mode drivers or bypassing the App Control policy enforcement.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## About Certificates and Certificate Chains

* A file can have only one root certificate at the end of the chain. The root certificate is always self-signed by the CA itself (meaning its IssuerCN and SubjectCN are the same) and it is the ultimate source of trust for the chain that validates it. Having more than one root certificate would imply that there are multiple chains of trust for the same file, which is not possible.

* A file can have more than 1 intermediate certificate and there is no definitive limit for it, but in practice, it is recommended to keep the certificate chain as short as possible.

* A file can have only one leaf certificate at the beginning of the chain. The leaf certificate is the one that belongs to the file itself and contains its public key and other information. Having more than one leaf certificate would imply that there are multiple files with different identities and keys, which is not possible.

* Leaf, intermediate and root are the only types of certificates a file can have in a certificate chain. There are other types of certificates that are not part of a chain, such as self-signed certificates or wildcard certificates, but they are not relevant to App Control policies.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## MSI Files and Their Applicable Rule Levels

MSI files cannot be allowed using FilePublisher rule level because they are not PEs and do not have the necessary attributes (Such as file version, original file name, product name, file description and so on) of the PEs (Portable Executable) in order to create FilePublisher/SignedVersion rules for them, so they need to be allowed by other [levels](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide) such as Publisher or Hash.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## The Length of the IDs in the policy XML file has no effect on the size of the generated CIP file

It doesn't matter how long or short the IDs are in the policy XML file, such as Signer IDs, Allowed Signer IDs, CiSigner IDs and so on, you can even use GUIDs as IDs to make sure they stay unique, the size of the generated CIP file will not change. In fact, even the hash of the generated CIP file stays the same when you change the length of the IDs in the policy XML file.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## The Effect of Disabled:Flight Signing Policy Rule Option on Windows Insider Builds

If you deploy an App Control policy that has the `Disabled:Flight Signing` rule option, the Windows Insider page in Windows Settings will not let you choose insider channels whose builds are signed with flight root certificates. For example, if you are on the Release Preview channel, you won't have the option to switch to any other channel and the channel selection can be unavailable in Windows Insider section. To make it appear again, you can re-deploy the policy with `Disabled:Flight Signing` rule option removed from it and then reboot the system. This is to ensure that the user won't accidentally/intentionally get himself/herself into a boot failure situation.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Assign an ID Setting to Policies So Events Generated By Them Show Full Details

Ensure all of your App Control policies have an ID Setting

```xml
<Setting Provider="PolicyInfo" Key="Information" ValueName="Id">
    <Value>
        <String>123456</String>
    </Value>
</Setting>
```

If a policy lacks that setting, the resulting Code Integrity event logs—for instance, those generated when a file is blocked—will not include specific details, such as the name of the policy responsible for the event.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Unsafe Practices

* Only use Signer or Hash based rule types in signed policies, other levels do not provide the kind of high security protection that matches the signed nature of App Control policies.

* Using Managed Installer or ISG policy rule options can reduce security and lead to over authorization, making them unsuitable for signed policy scenarios.

* If using a FilePath rule level and the file path contains a UNC path, **ensure** [UNC hardening is enabled and secure](https://learn.microsoft.com/en-us/archive/blogs/leesteve/demystifying-the-unc-hardening-dilemma).

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## <img width="65" src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Gifs/arrow-pink.gif" alt="Continue Reading about BYOVD using App Control for Business"> [Continue reading about BYOVD protection with App Control for Business](#-continue-reading-about-byovd-protection-with-wdac)

#### [App Control policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection) for BYOVD Kernel mode only protection

<br>
