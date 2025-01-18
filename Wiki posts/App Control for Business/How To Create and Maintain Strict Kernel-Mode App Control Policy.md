# How To Create and Maintain Strict Kernel-Mode App Control Policy

A [**Strict Kernel-mode**](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection) App Control policy is a special kind of policy that only enforces Kernel-mode drivers without affecting user-mode files. [The AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) fully supports this unique policy and allows you to create and maintain it effortlessly.

<br>

## Creating the Base Policy

Navigate to the [Create App Control policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-App-Control-Policy) page and scroll down to the `Create Strict Kernel-Mode Policy` section.

<img src="https://raw.githubusercontent.com/HotCakeX/.github/1df694f5fc413e27f9cf4621777d85cba60ef0d2/Pictures/PNG%20and%20JPG/How%20To%20Create%20and%20Maintain%20Strict%20Kernel-Mode%20App%20Control%20Policy/Creating%20the%20base%20policy.png" alt="creating new base strict kernel mode policy">

<br>

<br>

* Toggle the `Audit` switch. We need to deploy the base policy in Audit mode first in order to generate audit logs that we will use later.

* Toggle the `No flight root certificates` switch if you don't plan to use this policy on the insider builds of Windows on (Dev or Canary channels). Those builds are signed with a different certificate. Release Preview and Beta builds are signed with production certificates and they will work either way.

* Toggle the `Deploy` button and finally press the `Create` button. In few seconds, the policy will be created and deployed in Audit mode on the system.

> [!IMPORTANT]\
> Restart your computer after deploying the policy. The reason we deploy it in Audit mode is that we need audit logs to be generated for kernel-mode drivers that belong to your hardware devices so we can create a supplemental policy for them to allow them to run.

<br>

## Creating the Supplemental Policy

After restarting the system and relaunching the AppControl Manager, navigate to the [System Information](https://github.com/HotCakeX/Harden-Windows-Security/wiki/System-Information) page. Press the `Retrieve Policies` button, locate the Strict kernel-mode base policy, and remove it from the system.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/8a4f06e919efc7ddd5b833203445ac9ea64b184c/Pictures/PNG%20and%20JPG/How%20To%20Create%20and%20Maintain%20Strict%20Kernel-Mode%20App%20Control%20Policy/Remove%20base%20policy.png" alt="Removing app control policy using AppControl Manager">

<br>

<br>

Once removed, redeploy the same base policy using the [Create App Control policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-App-Control-Policy) page, but this time ensure that Audit Mode is disabled.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/d14d7437685416117edda8a56496180a2047984f/Pictures/PNG%20and%20JPG/How%20To%20Create%20and%20Maintain%20Strict%20Kernel-Mode%20App%20Control%20Policy/redeploy%20base%20policy%20in%20enforced%20mode.png" alt="redeploy strict kernel mode base policy in enforced mode">

<br>

<br>

Now navigate to the [Create Supplemental Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Supplemental-App-Control-Policy#create-kernel-mode-supplemental-policy) page. Scroll down to the `Kernel-mode policy` section.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/6a635612aef4c1dbb00533689d568eaf7d52c98e/Pictures/PNG%20and%20JPG/How%20To%20Create%20and%20Maintain%20Strict%20Kernel-Mode%20App%20Control%20Policy/Creating%20supplemental%20policy.png" alt="Creating strict kernel mode supplemental policy">

<br>

<br>

Press the `Scan for Kernel-mode Logs Since Last Reboot` button. It will begin fetching all kernel-mode Code Integrity logs that were generated since the last reboot that belong to signed files and will display the results in a data grid that is accessible by clicking/tapping on the `View detected kernel-mode files` section.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/733d7bafe220df3a484ad0d32172756364a57333/Pictures/PNG%20and%20JPG/How%20To%20Create%20and%20Maintain%20Strict%20Kernel-Mode%20App%20Control%20Policy/scanning%20for%20logs.png" alt="Scan for drivers since last reboot">

<br>

<br>

While reviewing the detected kernel-mode drivers, you can right-click or tap + hold on a row to open a context menu that allows you to remove the driver from the list and it will be excluded from the supplemental policy.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/733d7bafe220df3a484ad0d32172756364a57333/Pictures/PNG%20and%20JPG/How%20To%20Create%20and%20Maintain%20Strict%20Kernel-Mode%20App%20Control%20Policy/Kernel%20Mode%20Drivers%20Results.png" alt="kernel mode drivers results review">

<br>

<br>

After reviewing and confirming the results, return to the Supplemental Policy creation page. Locate the strict kernel-mode base policy XML file you created earlier by using the file browser. Enable the `Deploy After Creation` toggle, then click/tap the `Create Supplemental Policy` button. This will generate the Supplemental Policy and automatically deploy it to the system.

In the future, you can follow the same steps to allow additional kernel-mode files in your base policy by creating separate Supplemental Policies as needed. Additionally, you can explore other powerful features of AppControl Manager, such as scanning the system for logs or authorizing new applications and drivers for streamlined policy management.

<br>
