# WDAC policy for Fully Managed device - Variant 1

<div align="center">

| Base policy type|Method used|Signed | Protection score 1-5 |
| :-------------: | :-------------: | :-------------: | :-------------: |
| Allow Microsoft / Default Windows | [WDACConfig module](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) | No | 4 |

</div>

> [!NOTE]\
> This variant helps you create and deploy an App Control policy for fully managed device ***using only Event Viewer audit logs.***
>
> This scenario includes using explicit Allow rules for files and certificates/signers, anything not allowed by the policies we are going to make are automatically denied/blocked.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Prepare a Virtual Machine

Install Hyper-V role from optional Windows features if you haven't already.

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -norestart
```

<br>

Download the latest Windows `.ISO` file [from Microsoft website](https://www.microsoft.com/software-download/), create a new VM with it, install Windows and log in. Fully update Windows and then restart to apply the updates. You can create a Hyper-V checkpoint at this point so that you can return back to this clean state later on if you need to.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Prepare a Base policy

There are 2 types of base policies you can choose from.

1. Allow Microsoft: Allows only files and apps that are signed by Microsoft's trusted root certificates.

2. Default Windows: Allows only files and apps that come pre-installed by Windows.

### Deploy the Allow Microsoft Audit Mode Base Policy

```powershell
New-WDACConfig -PolicyType AllowMicrosoft -Audit -LogSize 20MB
```

### Deploy the Default Windows Audit Mode Base Policy

```powershell
New-WDACConfig -PolicyType DefaultWindows -Audit -LogSize 20MB
```

* [Parameter Info](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig)

<br>

Depending on whichever of the option you choose, it deploys the base policy in audit mode. No reboot required.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Generate Audit Event Logs on the System

Install all of the programs that you want to allow in the App Control policy, on the VM. These are the programs that you want to allow to run and be installed on the target system once you've deployed the App Control policy.

* Installing or running 3rd party non-Microsoft programs, while ***Allow Microsoft*** policy in Audit mode is deployed on the VM, generates event logs for each of the programs and their files.

* Installing or running any program that doesn't come pre-installed by default with Windows, while **Default Windows** policy in Audit mode is deployed on the VM, generates event logs for each of the programs and their files.

These event logs are exactly what we need to identify and create Allow rules for the detected files.

Only files that are executed during audit mode phase generate event logs, so by simply installing a program using its installer, we can't trigger event log generation for each of the components and executables that each program has. So, after installing the programs, run them, use them a bit as you normally would so that all of the programs' components are executed and event logs generated for them.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Generate Supplemental Policy From the Audit Event Logs

Run the following command which will scan the local machine's Code Integrity and AppLocker logs and display them to you in a nice GUI (Graphical User Interface) window so that you can see detailed information of each file and choose which ones you want to include in the supplemental policy.

```powershell
ConvertTo-WDACPolicy -BasePolicyFile <Path To The Base Policy XML File>
```

The cmdlet offers a lot more features, [**you can read about them here**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/ConvertTo-WDACPolicy).

<br>
