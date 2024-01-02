# New-WDACConfig available parameters

## New-WDACConfig -GetBlockRules

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-GetBlockRules.apng)

```powershell
New-WDACConfig [-GetBlockRules] [-Deploy] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

Creates a WDAC policy file called ***Microsoft recommended block rules.xml*** from [the official source](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md) for [Microsoft recommended block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac), with *AllowAll* rules and audit mode rule option removed. The policy sets [HVCI to strict](https://learn.microsoft.com/en-us/powershell/module/configci/set-hvcioptions).

### 1 Optional Parameter

* `-Deploy`: Deploys the [latest Microsoft recommended block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac) (For User Mode binaries). It has the 2 default AllowAll rules so it can be deployed as a standalone base policy. Uses [Strict HVCI](https://learn.microsoft.com/en-us/powershell/module/configci/set-hvcioptions).

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-WDACConfig -GetDriverBlockRules

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-GetDriverBlockRules.apng)

```powershell
New-WDACConfig [-GetDriverBlockRules] [-Deploy] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

Creates a WDAC policy file called ***Microsoft recommended driver block rules.xml*** from [the official source](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md) for [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules), with *AllowAll* rules and audit mode rule option removed. The policy sets [HVCI to strict](https://learn.microsoft.com/en-us/powershell/module/configci/set-hvcioptions). Extra information regarding the version and last updated date of [the GitHub document](https://github.com/MicrosoftDocs/windows-itpro-docs/commits/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md) containing block rules will also be displayed.

### 1 Optional Parameter

* `-Deploy`: With the help of PowerShell, uses [the official method](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules#steps-to-download-and-apply-the-vulnerable-driver-blocklist-binary) to deploy the latest version of [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules).

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-WDACConfig -MakeAllowMSFTWithBlockRules

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-MakeAllowMSFTWithBlockRules.apng)

```powershell
New-WDACConfig [-MakeAllowMSFTWithBlockRules] [-Deploy] [-TestMode] [-RequireEVSigners] [-SkipVersionCheck]
[<CommonParameters>]
```

<br>

Calls the [-GetBlockRules](#new-wdacconfig--getblockrules) parameter to get the Microsoft recommended block rules, and merges them with [*AllowMicrosoft default policy*](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/example-wdac-base-policies). The Policy uses [strict HVCI](https://learn.microsoft.com/en-us/powershell/module/configci/set-hvcioptions) and has the following [rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-1-windows-defender-application-control-policy---policy-rule-options):

<br>

| Rule number | Rule option |
| ------------- | ------------- |
| 0 | Enabled:UMCI |
| 2 | Required:WHQL |
| 5 | Enabled:Inherit Default Policy |
| 6 | Enabled:Unsigned System Integrity Policy |
| 11 | Disabled:Script Enforcement |
| 12 | Required:Enforce Store Applications |
| 16 | Enabled:Update Policy No Reboot |
| 17 | Enabled:Allow Supplemental Policies |
| 19 | Enabled:Dynamic Code Security |
| 20 | Enabled:Revoked Expired As Unsigned |

<br>

### 3 Optional Parameters

* `-Deploy`: Indicates that the module will automatically deploy the ***AllowMicrosoftPlusBlockRules*** policy after creation.

* `-TestMode`: Indicates that the created/deployed policy will have ***Enabled:Boot Audit on Failure*** and ***Enabled:Advanced Boot Options Menu*** [policy rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-1-windows-defender-application-control-policy---policy-rule-options).

* `-RequireEVSigners`: Indicates that the created/deployed policy will have [Require EV Signers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard-create-base-policy#advanced-policy-rules-description) policy rule option.

     - > In addition to being WHQL signed, this rule requires that drivers must have been submitted by a partner that has an Extended Verification (EV) certificate. All Windows 10 and later, or Windows 11 drivers will meet this requirement.

<br>

### The outputs of the parameter are

* **AllowMicrosoftPlusBlockRules.xml** policy file
* **{GUID}.cip** for the policy above

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-WDACConfig -SetAutoUpdateDriverBlockRules

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-SetAutoUpdateDriverBlockRules.apng)

```powershell
New-WDACConfig [-SetAutoUpdateDriverBlockRules] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

Creates a scheduled task that runs every 7 days to automatically perform [the official method](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules#steps-to-download-and-apply-the-vulnerable-driver-blocklist-binary) for updating Microsoft recommended driver block rules.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-WDACConfig -PrepMSFTOnlyAudit

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-PrepMSFTOnlyAudit.apng)

```powershell
New-WDACConfig [-PrepMSFTOnlyAudit] [-Deploy] [-LogSize <Int64>] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

Creates a WDAC policy using the default AllowMicrosoft policy in Audit mode that once deployed, prepares the system for generating Audit event logs [for a fully managed device](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices). No reboot required.

After deployment, audit event logs will start to be created for any file that is run but wouldn't be allowed to if the AllowMicrosoft policy was deployed in enforced mode.

It's recommended to use the optional parameter below to increase the log size of Code Integrity events category so that new events won't overwrite the older ones and everything will be captured.

### 2 Optional Parameters

* `-LogSize <Int64>`: Specifies the log size for ***Microsoft-Windows-CodeIntegrity/Operational*** events. The values must be in the form of `<Digit + Data measurement unit>`. e.g., 2MB, 10MB, 1GB, 1TB. The minimum accepted value is 1MB which is the default.

* `-Deploy`: Deploys the policy instead of just creating it.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-WDACConfig -PrepDefaultWindowsAudit

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-PrepDefaultWindowsAudit.apng)

```powershell
New-WDACConfig [-PrepDefaultWindowsAudit] [-Deploy] [-LogSize <Int64>] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

Creates a WDAC policy that once deployed, prepares the system for Default Windows auditing. It will trigger audit logs to be created for any file that is run but is not part of the Windows; Unlike [-PrepMSFTOnlyAudit](#new-wdacconfig--prepmsftonlyaudit) parameter that triggers audit logs for any file that is not signed by Microsoft's trusted root certificate.

This parameter also scans the WDACConfig module files and PowerShell core files, adds them to the Prep audit mode base policy that it deploys, so that the final Supplemental policy generated from Event viewer audit logs won't include those files.

It's recommended to use the optional parameter below to increase the log size of Code Integrity events category so that new events won't overwrite the older ones, and everything will be captured.

### 2 Optional Parameters

* `-LogSize <Int64>`: Specifies the log size for ***Microsoft-Windows-CodeIntegrity/Operational*** events. The values must be in the form of `<Digit + Data measurement unit>`. e.g., 2MB, 10MB, 1GB, 1TB. The minimum accepted value is 1MB which is the default.

* `-Deploy`: Deploys the policy instead of just creating it.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-WDACConfig -MakePolicyFromAuditLogs

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-MakePolicyFromAuditLogs%20-BasePolicyType%20'Allow%20Microsoft%20Base'.apng)

```powershell
New-WDACConfig [-MakePolicyFromAuditLogs] -BasePolicyType <String> [-Deploy] [-TestMode] [-RequireEVSigners]
[-SpecificFileNameLevel <String>] [-NoDeletedFiles] [-NoUserPEs] [-NoScript] [-Level <String>] [-Fallbacks
<String[]>] [-LogSize <Int64>] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

Creates a WDAC policy using the Audit event logs generated [for a fully managed device](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Fully-Managed-Devices).

### 1 Mandatory Parameter

* `-BasePolicyType <String>`: You need to select between **[Allow Microsoft Base](#new-wdacconfig--makeallowmsftwithblockrules)** and **[Default Windows Base](#new-wdacconfig--makedefaultwindowswithblockrules)**, based on which prep audit mode base policy deployed on the system.

### 11 Optional Parameters

* `-Deploy`: Indicates that the module will automatically remove the WDAC policy deployed using either [-PrepMSFTOnlyAudit](#new-wdacconfig--prepmsftonlyaudit) or [-PrepDefaultWindowsAudit](#new-wdacconfig--prepdefaultwindowsaudit) parameters, then deploys the supplemental policy created from Audit event logs along with the selected base policy type, both in enforced mode.

* `-TestMode`: Indicates that the created/deployed policy will have ***Enabled:Boot Audit on Failure*** and ***Enabled:Advanced Boot Options Menu*** [policy rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-1-windows-defender-application-control-policy---policy-rule-options).

* `-RequireEVSigners`: Indicates that the created/deployed policy will have [Require EV Signers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard-create-base-policy#advanced-policy-rules-description) policy rule option.

     - > In addition to being WHQL signed, this rule requires that drivers must have been submitted by a partner that has an Extended Verification (EV) certificate. All Windows 10 and later, or Windows 11 drivers will meet this requirement.

* `-Debug`: Indicates that the module will output 3 additional files for debugging purposes and also write debug messages on the console:
     - *FileRulesAndFileRefs.txt* - Contains the File Rules and Rule refs for the Hash of the files that no longer exist on the disk.
     - *DeletedFilesHashes.xml* - Policy file that contains File Rules and Rule refs for the files that no longer exist on the disk.
     - *AuditLogsPolicy_NoDeletedFiles.xml* - The policy file generated from Audit Event logs based on the specified Level and Fallback parameters.

* `-LogSize <Int64>`: Specifies the log size for ***Microsoft-Windows-CodeIntegrity/Operational*** events. The values must be in the form of `<Digit + Data measurement unit>`. e.g., 2MB, 10MB, 1GB, 1TB. The minimum accepted value is 1MB which is the default.

* `-Levels <String>`: Offers the same official [Levels](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-level) for scanning of event logs. If no level is specified the default, which is set to ***FilePublisher*** in this module, will be used.

* `-Fallbacks <String[]>`: Offers the same official [Fallbacks](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-fallback) for scanning of event logs. If no fallbacks are specified the default, which is set to ***Hash*** in this module, will be used.

* `-SpecificFileNameLevel`: You can choose one of the following options: "OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath". [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-specificfilenamelevel)

* `-NoDeletedFiles`: Indicates that files that were run during program installations but then were deleted and are no longer on the disk, won't be added to the supplemental policy. This can mean the programs you installed will be allowed to run but installation/reinstallation might not be allowed once the policies are deployed.

* `-NoUserPEs`: By default, the module includes user PEs in the scan. When you use this switch parameter, they won't be included. [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-userpes)

* `-NoScript`: [More info available on Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/configci/new-cipolicy#-noscript)

<br>

### The outputs of the parameter are

All of the outputs are saved in a folder named "WDAC" inside the current working directory.

* ***AllowMicrosoftPlusBlockRules.xml***: base policy created using [-MakeAllowMSFTWithBlockRules](#new-wdacconfig--makeallowmsftwithblockrules) parameter

* ***SupplementalPolicy.xml***: The supplemental policy created using the script.

* ***{GUID}.cip***: Binary file for AllowMicrosoft Policy, ready for deployment.

* ***{GUID}.cip***: Binary file for SupplementalPolicy policy, ready for deployment.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-WDACConfig -MakeLightPolicy

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-MakeLightPolicy.apng)

```powershell
New-WDACConfig [-MakeLightPolicy] [-Deploy] [-TestMode] [-RequireEVSigners] [-SkipVersionCheck]
[<CommonParameters>]
```

<br>

Creates a WDAC policy for a [Lightly managed system](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-for-Lightly-Managed-Devices). The Policy uses has the same specifications as [-MakeAllowMSFTWithBlockRules](#new-wdacconfig--makeallowmsftwithblockrules), with the following additional [rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-1-windows-defender-application-control-policy---policy-rule-options):

<br>

| Rule number | Rule option |
| ------------- | ------------- |
| 14 | Enabled:Intelligent Security Graph Authorization |
| 15 | Enabled:Invalidate EAs on Reboot |

<br>

### 3 Optional Parameters

* `-Deploy`: Indicates that the module will automatically deploy the ***SignedAndReputable.xml*** policy file after creation.

* `-TestMode`: Indicates that the created/deployed policy will have ***Enabled:Boot Audit on Failure*** and ***Enabled:Advanced Boot Options Menu*** [policy rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-1-windows-defender-application-control-policy---policy-rule-options).

* `-RequireEVSigners`: Indicates that the created/deployed policy will have [Require EV Signers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard-create-base-policy#advanced-policy-rules-description) policy rule option.

     - > In addition to being WHQL signed, this rule requires that drivers must have been submitted by a partner that has an Extended Verification (EV) certificate. All Windows 10 and later, or Windows 11 drivers will meet this requirement.

### The outputs of the parameter are

* ***SignedAndReputable.xml***
* ***{GUID}.cip***

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## New-WDACConfig -MakeDefaultWindowsWithBlockRules

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/New-WDACConfig/New-WDACConfig%20-MakeDefaultWindowsWithBlockRules.apng)

```powershell
New-WDACConfig [-MakeDefaultWindowsWithBlockRules] [-Deploy] [-IncludeSignTool] [-SignToolPath <String>]
[-TestMode] [-RequireEVSigners] [-SkipVersionCheck] [<CommonParameters>]
```

<br>

Calls the [-GetBlockRules](#new-wdacconfig--getblockrules) parameter to get the Microsoft recommended block rules, and merges them with [*DefaultWindows_Enforced policy*](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/example-wdac-base-policies). The Policy uses [strict HVCI](https://learn.microsoft.com/en-us/powershell/module/configci/set-hvcioptions) and uses the [same policy rule options as -MakeAllowMSFTWithBlockRules](#new-wdacconfig--makeallowmsftwithblockrules) parameter.

<br>

> Since the module uses PowerShell and not Windows PowerShell that is pre-installed in Windows, this parameter will automatically scan `C:\Program Files\PowerShell` directory and add PowerShell files to the ***DefaultWindowsPlusBlockRules.xml*** policy file so that you will be able to continue using the module after deploying the policy. The scan uses ***FilePublisher*** level and ***Hash*** fallback.

### 5 Optional Parameters

* `-Deploy`: Indicates that the module will automatically deploy the ***DefaultWindowsPlusBlockRules*** policy after creation.

* `-TestMode`: Indicates that the created/deployed policy will have ***Enabled:Boot Audit on Failure*** and ***Enabled:Advanced Boot Options Menu*** [policy rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-1-windows-defender-application-control-policy---policy-rule-options).

* `-RequireEVSigners`: Indicates that the created/deployed policy will have [Require EV Signers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/wdac-wizard-create-base-policy#advanced-policy-rules-description) policy rule option.

     - > In addition to being WHQL signed, this rule requires that drivers must have been submitted by a partner that has an Extended Verification (EV) certificate. All Windows 10 and later, or Windows 11 drivers will meet this requirement.

* `-IncludeSignTool`: Indicates that the Default Windows policy that is being created must include Allow rules for `SignTool.exe`. This parameter must be used when you intend to Sign and Deploy the Default Windows policy.

* `-SignToolPath <String>`: [How to use it](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig#you-can-use-it-in-2-different-ways)

<br>

### The outputs of the parameter are

* ***DefaultWindowsPlusBlockRules.xml*** policy file
* ***{GUID}.cip*** for the policy above

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>
