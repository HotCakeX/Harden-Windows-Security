# Microsoft 365 Apps Security Baseline | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/main/Pictures/Readme%20Categories/Microsoft%20365%20Apps%20Security%20Baselines/Microsoft%20365%20Apps%20Security%20Baselines.png" alt="Microsoft 365 Apps Security Baselines - Harden Windows Security GitHub repository" width="550"></p>

The security baseline for Microsoft 365 Apps for enterprise is published twice a year, usually in June and December. Use [the Harden System Security App](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) to effortlessly apply them onto your system.

On this page, the Harden System Security app enables you to apply the Microsoft 365 Apps Security Baselines on your system, verify compliance, and remove the applied policies.

You can measure the compliance level of your system using the built-in compliance assessment functionality by simply pressing the **Verify** button on this page. You will receive a detailed report of every security measure inside the Microsoft 365 Apps Security Baseline and you will be able to export this security report to a properly formatted JSON file as well.

Each security measure has the following details:

1. `Friendly Name`: Helps you easily identify the security measure and its purpose.
2. `Source`: Shows you which part of the Microsoft 365 Apps Security Baseline this security measure belongs to.
3. `Status`: Whether the current system applies the security measure or not.
4. `Current Value`: The current value of the security measure on the system.
5. `Expected Value`: The correct and secure value the security measure should be in order to be compliant.

<br>

* You can use the Baseline selector Dropdown button to select an older or newer baseline to be applied, removed or verified on your system.

* Use the `Browse` button to browse for a Microsoft 365 Apps Security Baseline ZIP file that you've already downloaded on your device, this way you can use it on systems that have no Internet connectivity.

<br>

> [!NOTE]
> Either when downloading the Microsoft 365 Apps Security Baseline from Microsoft Servers or when browsing for the zip file manually, the Harden System Security app will process it entirely **in memory**, and apply it without writing any temporary files to disk. The same is true for verification or removal processes.
>
> While this approach increases development complexity, it significantly improves security by preventing malicious interference with temporary files before application.
>
> The app caches the baseline in memory to avoid unnecessary re-downloads and/or re-reads. The cache expires every **2 hours**, after which it is refreshed with the latest data from the Microsoft Server/File path you provided, and this only happens if the app is open. The cache is compressed to minimize memory usage.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/9f8c01aea24dd33804e794ab1fbcb68fb71609dc/Pictures/PNG%20and%20JPG/Harden%20System%20Security%20page%20screenshots/Microsoft%20365%20Apps%20Security%20Baselines.png" alt="Microsoft 365 Apps Security Baseline | Harden System Security">

</div>

<br>

> [!TIP]\
> [More info in Microsoft Learn](https://learn.microsoft.com/deployoffice/security/security-baseline)
>
> [Microsoft Security Baselines Version Matrix](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/get-support-for-security-baselines#version-matrix)

<br>
