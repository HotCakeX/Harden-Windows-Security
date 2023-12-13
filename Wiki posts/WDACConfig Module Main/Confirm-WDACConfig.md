# Confirm-WDACConfig available parameters

## Confirm-WDACConfig -ListActivePolicies

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Confirm-WDACConfig/Confirm-WDACConfig%20-ListActivePolicies.apng)

```powershell
Confirm-WDACConfig [-ListActivePolicies] [-OnlyBasePolicies] [-OnlySupplementalPolicies]
```

<br>

Lists the non-System Base and Supplemental WDAC Policies using [CITool](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/citool-commands) and displays their counts.


### 2 Optional Parameters

* `-OnlyBasePolicies`: Using this will only display Base policies.
* `-OnlySupplementalPolicies`: Using this will only display Supplemental policies.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Confirm-WDACConfig -VerifyWDACStatus

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Confirm-WDACConfig/Confirm-WDACConfig%20-VerifyWDACStatus.apng)

```powershell
Confirm-WDACConfig [-VerifyWDACStatus]
```

<br>

Shows the [status](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Notes#how-to-verify-the-status-of-user-mode-and-kernel-mode-wdac-on-a-system) of User-mode and Kernel-mode application control.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Confirm-WDACConfig -CheckSmartAppControlStatus

![image](https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Wiki%20APNGs/Confirm-WDACConfig/Confirm-WDACConfig%20-CheckSmartAppControlStatus.apng)

```powershell
Confirm-WDACConfig [-CheckSmartAppControlStatus]
```

<br>

Checks the status of Smart App Control and reports the results on the console, including the evaluation mode expiration date.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Notes

* **Mandatory** parameters indicate you always need to provide values for them.

* **Automatic** parameters indicate that if you used [Set-CommonWDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig) cmdlet to set default values for them, the module will automatically use them. This saves time and prevents repetitive tasks. However, if no value exists in User Configurations for an Automatic parameter and you didn't explicitly provide a value for that parameter either, then you will see an error asking you to provide value for it. Explicitly providing a value for an Automatic parameter in the command line overrides its default value in User Configurations, meaning the module will ignore the value of the same parameter in the User Configurations file.

* **Optional** parameters indicate that they are not required and without using them the module will automatically run with the optimal settings.

<br>
