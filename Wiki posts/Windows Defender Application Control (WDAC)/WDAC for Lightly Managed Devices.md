# WDAC policy for Lightly managed device

<div align="center">

| Base policy type|Method used|Signed | Protection score 1-5 |
| :-------------: | :-------------: | :-------------: | :-------------: |
| [SignedAndReputable (ISG)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph#configuring-isg-authorization-for-your-wdac-policy) | [WDACConfig module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) | No / Yes | 3.5 / 4 |

</div>

<br>

```mermaid
flowchart TD
    A(Deploy App Control base policy with ISG) -->B(Start using your apps)
    B --> C(Did your app run without problem?)
    C -->|Yes| D[Awesome]
    C -->|No| E[Create a Supplemental policy for it]
```

> [!NOTE]\
> *Every time I use the word "App", I'm referring to regular Win32 programs as well as Microsoft Store installed apps; Basically any software that you can run.*
>
> This scenario provides a high protection level, ***higher if you cryptographically Sign it***. Using the WDACConfig module, it's very easy to deploy, manage and maintain a system with this configuration.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Deploy the SignedAndReputable Base Policy on the System

Start by deploying the SignedAndReputable base policy on the system, which allows only files and apps that are authorized by the [Intelligent Security Graph Authorization](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph) which have known good state to run and anything else is blocked.

### Unsigned version

```powershell
New-WDACConfig -PolicyType SignedAndReputable -Deploy
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig)

<br>

### Signed version

```powershell
New-WDACConfig -PolicyType SignedAndReputable
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig)

```powershell
Deploy-SignedWDACConfig -CertPath "C:\Certificate.cer" -PolicyPaths "C:\Users\HotCakeX\SignedAndReputable.xml" -CertCN "App Control Certificate" -Deploy
```

* [Cmdlet info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig)

<br>

* The module creates ***SignedAndReputable App Control base Policy*** based on [AllowMicrosoft policy template](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/example-appcontrol-base-policies) with ***ISG*** related [rule options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-1-app-control-for-business-policy---policy-rule-options).

* The module also automatically starts the [Application Identity](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service) (`AppIDSvc`) service required for [ISG Authorization](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph#enable-the-necessary-services-to-allow-wdac-to-use-the-isg-correctly-on-the-client) and sets its startup mode to Automatic. It's a protected service so can't be disabled or modified using Services snap-in.

* ISG Authorization requires active Internet connection to communicate with the global ISG network.

* Recommended to perform a reboot regardless of whether you are deploying signed or unsigned version of the "SignedAndReputable" App Control base policy.

<br>

After finishing deploying the SignedAndReputable base policy, if there is an app that is getting blocked and you want to allow it, you can create Supplemental policies to expand your base policy. To do that, you have multiple options.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Creating Supplemental Policy for Apps Already Installed

The following commands use the `-Deploy` optional switch parameter, meaning after Supplemental policy creation, they are automatically deployed on the system.

If you chose the Signed path, omit it from the commands and instead use the [Deploy-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Deploy-SignedWDACConfig) cmdlet to Sign and Deploy the Supplemental policy xml files.

### Based on Signer Rules, Hashes, File Names Etc.

```powershell
New-SupplementalWDACConfig -Normal -ScanLocation "C:\Program Files\Program" -SuppPolicyName "App's Name" -PolicyPath "C:\SignedAndReputable.xml" -Deploy
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig#new-supplementalwdacconfig--normal)

<br>

### Based on File Path With One or More Wildcard Characters

```powershell
New-SupplementalWDACConfig -FilePathWildCards -WildCardPath "C:\Program Files\Program\*" -SuppPolicyName "App's Name" -PolicyPath
"C:\SignedAndReputable.xml" -Deploy
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig#new-supplementalwdacconfig--filepathwildcards)

<br>

### Based on an Installed Windows App’s Name

```powershell
New-SupplementalWDACConfig -InstalledAppXPackages -PackageName "*App's name*" -SuppPolicyName "App's name" -PolicyPath "C:\SignedAndReputable.xml" -Deploy
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig#new-supplementalwdacconfig--installedappxpackages)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Creating Supplemental Policy for New App Installations or Apps Already Installed

If the app you are trying to allow isn't installed, and when you try to install it you see a blocked/error message, you can use the following syntaxes to allow them to run and then automatically create Supplemental policy for them.

These methods also work for apps that were installed prior to deploying the "SignedAndReputable" base policy and now you want to allow them to run by creating Supplemental policy for them.

You can create a Supplemental policy for more than 1 app at a time by browsing for multiple apps' install directories using the commands below.

<br>

### Based on App’s Install Directory and Other Signals - Unsigned Version

```powershell
Edit-WDACConfig -AllowNewApps -SuppPolicyName "App's Name" -PolicyPath "C:\SignedAndReputable.xml"
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig#edit-wdacconfig--allownewapps)

<br>

### Based on App’s Install Directory and Other Signals - Signed Version

```powershell
Edit-SignedWDACConfig -AllowNewApps -CertPath "C:\Certificate.cer" -SuppPolicyName "App's Name" -PolicyPath "C:\SignedAndReputable.xml" -CertCN "App Control Certificate"
```

* [Parameter info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig#edit-signedwdacconfig--allownewapps)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Security Considerations

One of the differences between using **ISG in an App Control policy** vs using **Smart App Control** (which also use ISG) is that App Control policy + ISG rule option passes along reputation from app installers to the binaries they write to disk, it can over-authorize files in some cases. For example, if the installer launches the app upon completion, any files the app writes during that first run will also be allowed.

Smart App Control however doesn't do this, it will trust the installer file itself if it's trustworthy and subsequently checks the trustworthiness of any binaries the installer tries to use and write to the disk, if any of those binaries or components can't be verified or are malicious, they get blocked.

Explained more in here:

* [Security considerations with the ISG option](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/use-appcontrol-with-intelligent-security-graph#security-considerations-with-the-isg-option)

* [Smart app control has blocked part of this app](https://support.microsoft.com/en-us/topic/smart-app-control-has-blocked-part-of-this-app-0729fff1-48bf-4b25-aa97-632fe55ccca2)

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## What to Do When There Is an Update for an Allowed App?

If you've created a Supplemental policy for an app that is already installed and now there is a newer version of that app available, you have multiple options:

1. If the Supplemental policy that you created to allow that app is based on FilePath with wildcards, then the app can be updated and no change in policy is required.

2. If the Supplemental policy is based on [PFN (Package Family Name)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/manage-packaged-apps-with-appcontrol) of the app, available only for apps that use [MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) installers, like some of the modern apps installed through Microsoft Store, then you don't need to take any action and the app will be updated without any issues.

3. If the Supplemental policy is only based on the app's digital signature, which is common for well-made apps, then you don't need to take any further action. As long as the new version of the app has the same digital signature / developer identity, then it will be allowed to run.

4. If the Supplemental policy is based on individual File Paths (in contrast to wildcard FilePath rules), or based on [FileName rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#table-3--specificfilenamelevel-options), then most likely there is no need for any further action to be taken as long as the new app's version uses the same file names or the same file paths for its components.

5. If the Supplemental policy is based on Hash of the app's files, either partially (mixed with signer rules) or entirely (for apps without any digital identity/signature) then all you have to do is to remove the deployed Supplemental policy and create a new Supplemental policy for the app using live audit mode in the module as explained above. Don't need to reboot immediately, but to finish the removal process of a Supplemental policy, whether it's signed or unsigned, a reboot will be eventually needed.

<br>
