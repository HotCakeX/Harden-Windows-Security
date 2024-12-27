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

You can use the [set-cipolicysetting](https://learn.microsoft.com/en-us/powershell/module/configci/set-cipolicysetting) PowerShell cmdlet to set a secure setting in an XML policy file.

### Example 1

```powershell
Set-CIPolicySetting -FilePath 'Policy.xml' -Provider 'WDACConfig' -ValueType 'Boolean' -Value '1' -ValueName 'IsUserModePolicy' -Key '{4a981f19-1f7f-4167-b4a6-915765e34fd6}'
```

### Example 2

```powershell
Set-CIPolicySetting -FilePath 'Policy.xml' -Provider 'SomeProvider' -ValueType 'String' -Value 'HotCakeX' -ValueName 'Author' -Key '{495e96a3-f6e0-4e7e-bf48-e8b6085b824a}'
```

### Example 3

```powershell
Set-CIPolicySetting -FilePath 'Policy.xml' -Provider 'Provider2' -ValueType 'DWord' -Value '66' -ValueName 'Role' -Key '{741b1fcf-e1ce-49e4-a274-5c367b46b00c}'
```

### Notes

* `DWord` value is the same as integer or `WldpInteger`.

* In order to set a Boolean value using the `Set-CIPolicySetting` cmdlet, you need to use 1 for True or 0 for False, that will create a valid policy XML file that is compliant with the CI Policy Schema.


<br>
