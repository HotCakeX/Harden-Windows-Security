# Microsoft Security Baselines | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/d6960a261913f979526c0fac7901effa4b72d813/Pictures/Readme%20Categories/Microsoft%20Security%20Baselines/Microsoft%20Security%20Baselines.svg" alt="Microsoft Security Baselines - Harden Windows Security" width="550"></p>

A security baseline is a group of Microsoft-recommended configuration settings that explains their security implications. These settings are based on feedback from Microsoft security engineering teams, product groups, partners, and customers.

In this page, the Harden System Security app enables you to apply the Microsoft Security Baselines on your system, verify compliance, and remove the applied policies.

You can measure the compliance level of your system using the built-in compliance assessment functionality by simply pressing the **Verify** button on this page. You will receive a detailed report of every security measure inside the Microsoft Security Baseline and you will be able to export this security report to a properly formatted JSON file as well.

Each security measure has the following details:

1. `Friendly Name`: Helps you easily identify the security measure and its purpose.
2. `Source`: Shows you which part of the Microsoft Security Baseline this security measure belongs to.
3. `Status`: Whether the current system applies the security measure or not.
4. `Current Value`: The current value of the security measure on the system.
5. `Expected Value`: The correct and secure value the security measure should be in order to be compliant.

<br>

You can change the download URL of the Microsoft Security Baselines in this page too if you need. This can come handy if you want to apply an older baseline on your system or to just change the URL to point to another address such as an alternative mirror.

<br>

> [!NOTE]  
> When applying the Microsoft Security Baseline, Harden System Security app will **automatically download the latest version directly from Microsoft's servers** or from the URL you provided, process it entirely **in memory**, and apply it without writing any temporary files to disk. The same is true for verification or removal processes.
>  
> While this approach increases development complexity, it significantly improves security by preventing malicious interference with temporary files before application.  
>  
> The app caches the baseline in memory to avoid unnecessary re-downloads. The cache expires every **2 hours**, after which it is refreshed with the latest data from the Microsoft Server/Custom URL you provided, and this only happens if the app is open. The cache is compressed to minimize memory usage.

<br>

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/9f8c01aea24dd33804e794ab1fbcb68fb71609dc/Pictures/PNG%20and%20JPG/Harden%20System%20Security%20page%20screenshots/Microsoft%20Security%20Baseline.png" alt="Microsoft Security Baselines | Harden System Security">

</div>

<br>

> [!TIP]\
> [Official Documentation for the Microsoft Security Baseline](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines#what-are-security-baselines)
>
> [Optional Overrides for Microsoft Security Baselines](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Overrides-for-Microsoft-Security-Baseline)
>
> **Highly recommended** to apply these overrides. Use Optional Overrides when applying the hardening measures on Azure VMs.
>

<br>
