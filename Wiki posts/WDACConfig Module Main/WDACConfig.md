# WDACConfig (Windows Defender Application Control) Module

> [!IMPORTANT]\
> This module is being deprecated. Use the new AppControl Manager application -> https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager
>

## Preview of the App

<div align="center">

<a href="https://www.youtube.com/watch?v=SzMs13n7elE"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControlManager.gif" alt="AppControl Manager preview"/> </a>

<br>

<a href="https://www.youtube.com/watch?v=SzMs13n7elE"> <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20video%20Demo%20Thumbnail.png" alt="AppControl Manager YouTube Video demo thumbnail" width="700"> </a>

</div>

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## WDACConfig Module's Table of Content [Deprecated]

|  Cmdlet Guide  |     Usage      | PowerShell Console Help |
|    :---:       |     :---:      |          :---:          |
| [New-SupplementalWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-SupplementalWDACConfig) | To create and deploy Supplemental policies | `Get-Help New-SupplementalWDACConfig` |
| [Edit-SignedWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig) | To edit deployed signed App Control policies | `Get-Help Edit-SignedWDACConfig` |
| [New-DenyWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-DenyWDACConfig) | To create a deny mode App Control policy | `Get-Help New-DenyWDACConfig` |
| [New-KernelModeWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/New%E2%80%90KernelModeWDACConfig)  | To create a Strict Kernel mode App Control policy for [total BYOVD protection](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection) | `Get-Help New-KernelModeWDACConfig` |
| [Test-CiPolicy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Test-CiPolicy) | Tests a Code Integrity (App Control) Policy XML file against the Schema and shows the signers in a signed `.CIP` files | `Get-Help Test-CiPolicy` |
| [ConvertTo-WDACPolicy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/ConvertTo-WDACPolicy) | Multi-Purpose & Powerful functionalities such as converting local and MDE logs to App Control Policies | `Get-Help ConvertTo-WDACPolicy` |

<br>
