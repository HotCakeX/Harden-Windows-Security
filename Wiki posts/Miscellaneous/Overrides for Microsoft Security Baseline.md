# Optional overrides for Microsoft Security Baseline

Since Microsoft Security Baselines are geared towards Enterprise level security, some functionalities that home users might require are disabled. Use the following overrides in [the Harden System Security App](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) to bring back those functionalities. **Some of these are necessary when using the app in Azure VMs.**

> [!IMPORTANT]\
> All of the features and functionalities listed below are enabled by default in Windows.

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Windows Game Recording and Broadcasting

This setting enables or disables the Windows Game Recording and Broadcasting features. If you disable this setting, Windows Game Recording will not be allowed.
If the setting is enabled or not configured, then Recording and Broadcasting (streaming) will be allowed.

Policy path:

```
Computer Configuration\Administrative Templates\Windows Components\Windows Game Recording and Broadcasting
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Prohibit use of Internet Connection Sharing on your DNS domain network

Determines whether administrators can enable and configure the Internet Connection Sharing (ICS) feature of an Internet connection and if the ICS service can run on the computer.

ICS lets administrators configure their system as an Internet gateway for a small network and provides network services, such as name resolution and addressing through DHCP, to the local private network.

If you enable this setting, ICS cannot be enabled or configured by administrators, and the ICS service cannot run on the computer. The Advanced tab in the Properties dialog box for a LAN or remote access connection is removed. The Internet Connection Sharing page is removed from the New Connection Wizard. The Network Setup Wizard is disabled.

If you disable this setting or do not configure it and have two or more connections, administrators can enable ICS. The Advanced tab in the properties dialog box for a LAN or remote access connection is available. In addition, the user is presented with the option to enable Internet Connection Sharing in the Network Setup Wizard and Make New Connection Wizard. (The Network Setup Wizard is available only in Windows XP Professional.)

By default, ICS is disabled when you create a remote access connection, but administrators can use the Advanced tab to enable it. When running the New Connection Wizard or Network Setup Wizard, administrators can choose to enable ICS.

Note: Internet Connection Sharing is only available when two or more network connections are present.

Note: When the "Prohibit access to properties of a LAN connection," "Ability to change properties of an all user remote access connection," or "Prohibit changing properties of a private remote access connection" settings are set to deny access to the Connection Properties dialog box, the Advanced tab for the connection is blocked.

Note: Non-administrators are already prohibited from configuring Internet Connection Sharing, regardless of this setting.

Note: Disabling this setting does not prevent Wireless Hosted Networking from using the ICS service for DHCP services. To prevent the ICS service from running, on the Network Permissions tab in the network's policy properties, select the "Don't use hosted networks" check box.

Policy path:

```
Computer Configuration\Administrative Templates\Network\Network Connections\Prohibit use of Internet Connection Sharing on your DNS domain network
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Firewall local rule merging

This can prevent Hyper-V default switch from working properly, please see [this forum post on Microsoft Tech Community](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-with-hyper-v-default-switch/m-p/2622890) for more info.

The Group policies that we change back to default values are located in:

```
Computer Configuration\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\
```

From there you need to select ***properties*** and then in each relevant profile tab, you need to select ***Customize*** and change the 2 settings for ***Rule merging*** to ***Yes (Default)*** and also set ***Display a notification*** to ***Yes***, which is the default value in Windows.

Here is an screenshot of the settings for the Public Profile tab:

<br>

![Firewall](https://user-images.githubusercontent.com/118815227/214886150-0acca5b6-5e38-49c4-b0ef-99b1eb832f4f.png)


<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Deny write access to removable drives not protected by BitLocker

Disabling this policy because it can cause inconvenience and if your flash drive is BitLocker encrypted, it can't be used as a bootable Windows installation USB flash drive.

Policy path:

```
Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Removable Data Drives\Deny write access to removable drives not protected by BitLocker
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Enable Clipboard and Drive redirection when using Remote Desktop connection

It is necessary when using Hyper-V VM Enhanced session mode and you want to copy items between guest and host OS.

Policy path:

```
Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Enable Microsoft Defender exclusion lists to be visible to Local Admins

Disables this [policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/defender-csp#configurationhideexclusionsfromlocaladmins) which is located in the following Group Policy path

```
Computer Configuration\Administrative Templates\Windows Components\Microsoft Defender Antivirus\Control whether or not exclusions are visible to Local Admins
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Disabled "Turn off Microsoft Consumer Experiences"

It disables some important features in Windows Settings -> Bluetooth & Devices -> Mobile Devices

More info in this [PR](https://github.com/HotCakeX/Harden-Windows-Security/pull/207)

```
Computer Configuration\Administrative Templates\Windows Components\Cloud Content
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Disabled "Configure password backup directory"

Microsoft Security Baselines set its value to "Active Directory", but since the Harden System Security app does not apply to computers managed by domain controllers or Entra ID, there is no need for this policy to be active.

```
Computer Configuration\Administrative Templates\System\LAPS
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Enabled "Apply UAC restrictions to local accounts on network logons"

A [Security feature](https://learn.microsoft.com/en-US/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction) that is enabled by default and should stay enabled.

```
Computer Configuration\Administrative Templates\MS Security Guide
```

<br>

<img src="https://github.com/HotCakeX/Harden-Windows-Security/raw/main/images/Gifs/1pxRainbowLine.gif" width= "300000" alt="horizontal super thin rainbow RGB line">

<br>

## Restores the ability of Administrator to enable Sudo

Microsoft Security baselines disable the usage of [Sudo](https://devblogs.microsoft.com/commandline/introducing-sudo-for-windows/) which also makes the Sudo option hidden from Windows settings.

```
Computer Configuration\Administrative Templates\System\Configure the behavior of the sudo command --> Maximum allowed sudo mode
```

<br>
