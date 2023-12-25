# WDAC policy for Fully managed device - Variant 4

<div align="center">

| Base policy type|Method used|Signed | Protection score 1-5 |
| :-------------: | :-------------: | :-------------: | :-------------: |
| Default Windows | [WDACConfig module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) | Yes | 5 |

</div>

<br>

```mermaid
flowchart TD
    A(Deploy Default Windows base policy) -->B(Identify Important apps that need Supplemental policy)
    B --> C(Create and Deploy Supplemental policies for them)
    C --> D[Another App is getting blocked?]
    D --> E[Is it a normal app?]
    E --> F[Create Supplemental policy based on App's directory]
    D --> G[Is it a game Installed using Xbox app?]
    G --> H[Is it an app that installs drivers outside app's directory?]
    H --> I[Use Event viewer logs + game/app's directory scan]
    I --> J[Edit-WDACConfig -AllowNewAppsAuditEvents]
    I --> K[Edit-SignedWDACConfig -AllowNewAppsAuditEvents]
    D --> L[Want to allow an entire folder?]
    L --> M[Use folder path with one or more Wildcards]
    M --> N[New-SupplementalWDACConfig -FilePathWildCards]
    F --> O[Edit-WDACConfig -AllowNewApps]
    F --> P[Edit-SignedWDACConfig -AllowNewApps]
    F --> Q[New-SupplementalWDACConfig -Normal]
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Video Guide

<a href="https://youtu.be/AgqhcPV9aPY?si=l_2QPbEAKKVhb9z6"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/PNG%20and%20JPG/YouTube%20Video%20Thumbnails/With%20YouTube%20play%20button/WDAC%20policy%20for%20Fully%20managed%20device%20Variant%204.png" alt="WDAC policy for Fully managed device - Variant 4 YouTube Guide"></a>

<br>

*Every time I use the word "App", I'm referring to regular Win32 programs as well as Microsoft Store installed apps; Basically, any software that you can run.*

This scenario provides the ultimate protection level. Using the WDACConfig module, it's very easy to deploy, manage and maintain a system with this configuration.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Deploy the Default Windows Base Policy on the System

Start by creating the Default Windows base policy xml file, which allows only files and apps that come pre-installed in Windows to run and anything else is blocked.

```powershell
New-WDACConfig -MakeDefaultWindowsWithBlockRules -IncludeSignTool
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig#new-wdacconfig--makedefaultwindowswithblockrules)

<br>

Now what we have the policy xml file for the Default Windows base policy, we need to sign and deploy it.

```powershell
Deploy-SignedWDACConfig -CertPath "C:\Certificate.cer" -PolicyPaths "C:\DefaultWindowsPlusBlockRules.xml" -CertCN "WDAC Certificate" -Deploy
```

* [Cmdlet info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig)

<br>

Since this is a signed base policy, you need to perform a reboot after deployment so that [the anti-tamper protection of a signed base policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-to-Create-and-Deploy-a-Signed-WDAC-Policy-Windows-Defender-Application-Control#if-someone-forcefully-deletes-the-deployed-wdac-policy-file) will start.

After deploying the base policy, you can create Supplemental policies to allow other apps that don't come by default with Windows to run. To do that, you have multiple options.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Creating Supplemental Policy for Apps Already Installed

If you deployed the Default Windows base policy on a system that already had apps installed, you can create Supplemental policy for them using the following syntaxes. **After creating each Supplemental policy, you need to sign and deploy it [using the same Cmdlet we used above.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig)**

### Based on signer rules, hashes, file names etc.

```powershell
New-SupplementalWDACConfig -Normal -ScanLocation "C:\Program Files\Program" -SuppPolicyName "App's Name" -PolicyPath "C:\DefaultWindowsPlusBlockRules.xml"
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig#new-supplementalwdacconfig--normal)

<br>

### Based on File path with one or more wildcard characters

```powershell
New-SupplementalWDACConfig -FilePathWildCards -WildCardPath "C:\Program Files\Program\*" -SuppPolicyName "App's Name" -PolicyPath
"C:\DefaultWindowsPlusBlockRules.xml"
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig#new-supplementalwdacconfig--filepathwildcards)

<br>

### Based on an installed Windows app's name

```powershell
New-SupplementalWDACConfig -InstalledAppXPackages -PackageName "*App's name*" -SuppPolicyName "App's name" -PolicyPath "C:\DefaultWindowsPlusBlockRules.xml"
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig#new-supplementalwdacconfig--installedappxpackages)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Creating Supplemental Policy for New App Installations or Apps Already Installed

If the app you are trying to allow isn't installed and when you try to install it you see a blocked/error message, you can use the following syntaxes to allow them to run and then automatically create Supplemental policy for them.

These methods also work for apps that were installed prior to deploying the Default Windows base policy and now you want to allow them to run by creating Supplemental policy for them.

You can create a Supplemental policy for more than 1 app at a time by browsing for multiple apps' install directories using the commands below.

### Based on App's install directory and Event viewer logs

```powershell
Edit-SignedWDACConfig -AllowNewAppsAuditEvents -CertPath "C:\Certificate.cer" -SuppPolicyName "App's Name" -PolicyPath "C:\DefaultWindowsPlusBlockRules.xml" -CertCN "WDAC Certificate" -LogSize 20MB
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig#edit-signedwdacconfig--allownewappsauditevents)

<br>

### Based on App's install directory only

```powershell
Edit-SignedWDACConfig -AllowNewApps -CertPath "C:\Certificate.cer" -SuppPolicyName "App's Name" -PolicyPath "C:\DefaultWindowsPlusBlockRules.xml" -CertCN "WDAC Certificate"
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig#edit-signedwdacconfig--allownewapps)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## What to Do if You Have a Lot of Supplemental Policies?

Currently, the limit for the number of policies (Base + Supplemental) that can be deployed on a system at a time is 32. So if you are getting close to that limit, you can merge some or all of your Supplemental policies automatically into 1 using the command below:

```powershell
Edit-SignedWDACConfig -MergeSupplementalPolicies -CertPath "C:\Certificate.cer" -SuppPolicyName "Merge of Multiple Supplementals" -PolicyPath "C:\DefaultWindowsPlusBlockRules.xml" -CertCN "WDAC Certificate" -SuppPolicyPaths "C:\Supplemental policy for App1.xml","C:\Supplemental policy for App 2.xml","C:\Supplemental policy for App 3.xml"
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig#edit-signedwdacconfig--mergesupplementalpolicies)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## What to Do When There Is an Update for an Allowed App?

If you've created a Supplemental policy for an app that is already installed and now there is a newer version of that app available, you have multiple options:

1. If the Supplemental policy that you created to allow that app is based on FilePath with wildcards, then the app can be updated and no change in policy is required.

2. If the Supplemental policy is based on [PFN (Package Family Name)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/manage-packaged-apps-with-wdac) of the app, available only for apps that use [MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) installers, like some of the modern apps installed through Microsoft Store, then you don't need to take any action and the app will be updated without any issues.

3. If the Supplemental policy is only based on the app's digital signature, which is common for well-made apps, then you don't need to take any further action. As long as the new version of the app has the same digital signature / developer identity, then it will be allowed to run.

4. If the Supplemental policy is based on individual File Paths (in contrast to wildcard FilePath rules), or based on [FileName rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/select-types-of-rules-to-create#table-3-windows-defender-application-control-policy---filename-levels), then most likely there is no need for any further action to be taken as long as the new app's version uses the same file names or the same file paths for its components.

5. If the Supplemental policy is based on Hash of the app's files, either partially (mixed with signer rules) or entirely (for apps without any digital identity/signature) then all you have to do is to remove the deployed Supplemental policy and create a new Supplemental policy for the app using live audit mode in the module as explained above. Don't need to reboot immediately, but to finish the removal process of a Supplemental policy, whether it's signed or unsigned, a reboot will be eventually needed.

<br>
