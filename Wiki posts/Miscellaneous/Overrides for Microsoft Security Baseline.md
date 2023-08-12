# Optional overrides for Microsoft Security Baseline

Here are the overrides that can be **optionally** applied by the script to bring back the functionalities that are disabled as the result of applying Microsoft Security Baseline for Windows 11 22H2

<br>

## 1. Windows Game Recording and Broadcasting

This setting enables or disables the Windows Game Recording and Broadcasting features. If you disable this setting, Windows Game Recording will not be allowed.
If the setting is enabled or not configured, then Recording and Broadcasting (streaming) will be allowed.

Policy path:

```
Computer Configuration\Administrative Templates\Windows Components\Windows Game Recording and Broadcasting
```

<br>

## 2. Prohibit use of Internet Connection Sharing on your DNS domain network

Determines whether administrators can enable and configure the Internet Connection Sharing (ICS) feature of an Internet connection and if the ICS service can run on the computer.

ICS lets administrators configure their system as an Internet gateway for a small network and provides network services, such as name resolution and addressing through DHCP, to the local private network.

If you enable this setting, ICS cannot be enabled or configured by administrators, and the ICS service cannot run on the computer. The Advanced tab in the Properties dialog box for a LAN or remote access connection is removed. The Internet Connection Sharing page is removed from the New Connection Wizard. The Network Setup Wizard is disabled.

If you disable this setting or do not configure it and have two or more connections, administrators can enable ICS. The Advanced tab in the properties dialog box for a LAN or remote access connection is available. In addition, the user is presented with the option to enable Internet Connection Sharing in the Network Setup Wizard and Make New Connection Wizard. (The Network Setup Wizard is available only in Windows XP Professional.)

By default, ICS is disabled when you create a remote access connection, but administrators can use the Advanced tab to enable it. When running the New Connection Wizard or Network Setup Wizard, administrators can choose to enable ICS.

Note: Internet Connection Sharing is only available when two or more network connections are present.

Note: When the "Prohibit access to properties of a LAN connection," "Ability to change properties of an all user remote access connection," or "Prohibit changing properties of a private remote access connection" settings are set to deny access to the Connection Properties dialog box, the Advanced tab for the connection is blocked.

Note: Nonadministrators are already prohibited from configuring Internet Connection Sharing, regardless of this setting.

Note: Disabling this setting does not prevent Wireless Hosted Networking from using the ICS service for DHCP services. To prevent the ICS service from running, on the Network Permissions tab in the network's policy properties, select the "Don't use hosted networks" check box.

Policy path:

```
Computer Configuration\Administrative Templates\Network\Network Connections\Prohibit use of Internet Connection Sharing on your DNS domain network
```

<br>

## 3. Firewall local rule merging

This can prevent Hyper-V default switch from working properly, please see [this forum post on Microsoft Tech Community](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-with-hyper-v-default-switch/m-p/2622890) for more info:

The Group policy that we change back to default values are located in:
Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Windows Firewall Properties -> Public Profile Tab -> Settings (select Customize) -> Rule merging, "Apply local connection security rules:" to "No".

Here is a screenshot:

<br>

![Firewall](https://user-images.githubusercontent.com/118815227/214886150-0acca5b6-5e38-49c4-b0ef-99b1eb832f4f.png)

Policy path:

```
Computer Configuration\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\
```

<br>

## 4. Deny write access to removable drives not protected by Bitlocker

Disabling this policy because it can cause inconvenience and if your flash drive is Bitlocker encrypted, It can't be used as a bootable Windows installation USB flash drive.

Policy path:

```
Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Removable Data Drives\Deny write access to removable drives not protected by BitLocker
```

<br>

## 5. Set the status of these 4 Xbox services back to their default states

`XboxGipSvc`, `XblAuthManager`,`XblGameSave`,`XboxNetApiSvc`

Microsoft Security Baseline sets their status to disabled.

Policy path:

```powershell
Computer Configuration\Windows Settings\
```

<br>

## 6. Enable Clipboard and Drive redirection when using Remote Desktop connection

It is necessary when using Hyper-V VM Enhanced session mode and you want to copy items between guest and host OS.

Policy path:

```
Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Device and Resource Redirection\
```

<br>

## 7. Enable the XblGameSave Standby Task

The scheduled task is disabled as a result of applying the Microsoft Security Baselines. The Harden Windows Security script in the [Optional Overrides category](https://github.com/HotCakeX/Harden-Windows-Security#microsoft-security-baselines) enables it again and sets its status back to the default state. The task syncs Xbox game saves on PC.

<br>
