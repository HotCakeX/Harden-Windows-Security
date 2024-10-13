# AppControl Manager

AppControl Manager is a modern secure app that provides easy to use graphical user interface to mange App Control on your device.

The goal is for AppControl manager to reach feature parity with the [WDACConfig](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig) Powershell module as fast as possible and then to surpass it with additional features and improvements.

<br>

## How To Install or Update The App

Use the following PowerShell [command](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Harden-Windows-Security.ps1) as Admin, it will automatically download the latest MSIX file from this repository's release page and install it for you.

> [!TIP]\
> The same command can be used to update the app whenever there is a new version available. In the future the updating functionality will be incorporated inside of the app.

<br>

```powershell
(irm 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1')+'AppControl'|iex
```

<br>

You can find the MSIX file in the [GitHub releases](https://github.com/HotCakeX/Harden-Windows-Security/releases) section.

<br>

## Preview of the App

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControlManager.gif" alt="AppControl Manager preview"/>

<br>

## Technical Details of The App

* Built using [WinUI3](https://learn.microsoft.com/en-us/windows/apps/winui/winui3/) / [XAML](https://github.com/microsoft/microsoft-ui-xaml) / [C#](https://learn.microsoft.com/en-us/dotnet/csharp/).
* Built using the latest [.NET](https://dotnet.microsoft.com).
* Powered by the [WinAppSDK](https://github.com/microsoft/WindowsAppSDK) (formerly Project Reunion).
* Packaged with the modern [MSIX](https://learn.microsoft.com/en-us/windows/msix/overview) format.
* Incorporates the [Mica](https://learn.microsoft.com/en-us/windows/apps/design/style/mica) material design for backgrounds.
* Adopts the Windows 11 [Fluent design system](https://fluent2.microsoft.design/components/windows).
* Fast execution and startup time.
* 0 required dependency.
* 0 Third-party library or file used.
* 0 Telemetry or data collection.
* 0 Windows Registry changes.
* 100% clean uninstallation.
* 100% open-source and free to use.

<br>

## Features Implemented So Far


* Creating, configuring and deploying AllowMicrosoft policy
* Creating, configuring and deploying SignedAndReputable policy (based on ISG)
* Creating and deploying Microsoft recommended driver block rules
* Creating and deploying Microsoft recommended user-mode block rules
* Checking for secure policy settings on the system
* Getting the Code Integrity hashes of the files (Authenticode hash and Page hash)
* Adding/Changing/Removing User Configurations
* Configure policy rule options
* View deployed policies on the system (with filtering search)
* Remove unsigned policies from the system
* Quick access to App Control resources and documentations right within the app

More features will come very quickly in the near future.

<br>
