# Get Secure Policy Settings

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Get%20Secure%20Policy%20Settings.png" alt="AppControl Manager Application's Get Secure Policy Settings Page">

</div>

<br>

<br>

In this [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) page, you can verify whether a policy with certain secure settings is deployed on the system or not.

App Control for Business policies expose a Settings section where policy authors can define arbitrary secure settings. Secure Settings provide local admin tamper-free settings for secure boot enabled systems, with policy signing enabled. [Learn more about them in here.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/understanding-appcontrol-policy-settings)

<br>

## Description of the Results

* **Value**: The actual value of the string.
* **ValueType**: The type of setting: `WldpString`, `WldpInteger` or `WldpBoolean`.
* **ValueSize**: the size of the returned value.
* **Status**: True/False depending on whether the setting exists on the system.
* **StatusCode**: 0 if the value exists on the system, non-zero if it doesn't.

<br>

## How To Configure Secure Policy Settings

Use the **Policy Editor** page in the AppControl Manager to add Secure Policy Settings to your policies.

### Notes

* `DWord` value is the same as integer or `WldpInteger`.

<br>
