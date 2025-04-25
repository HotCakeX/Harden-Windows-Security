# Allow New Apps

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Allow%20New%20Apps.png" alt="AppControl Manager Application's Allow New Apps Page">

</div>

<br>

<br>

## Description

Use this page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) on a system where Application Control policies are already deployed.

When you need to install a new application, this page provides an intuitive way to temporarily enable Audit mode in your existing deployed base policy. This allows the installation of the app while ensuring the base policy automatically reverts to Enforced mode immediately afterward.

During Audit mode, AppControl Manager captures all relevant Code Integrity and AppLocker events, analyzes them, and presents detailed insights in an organized view. You can also navigate to the specific folder path(s) where the application was installed, enabling the app to scan and display the contents on a separate page.

The compiled data, scanned files and recorded events, are presented to you for review, filter, sort, and manage. Once you're satisfied, you can seamlessly convert these into a single Supplemental policy ready for deployment.

While much of the process is automated, you remain in full control. With just a few clicks, you can fine-tune and manage your App Control policy efficiently.

Rest assured, no unauthorized software or malware can make its way into your Supplemental policy. Every file and event is accompanied by highly detailed information, eliminating any guesswork and ensuring only trusted elements are included.

If something like a power outage occurs during the audit mode phase, on the next reboot, the enforced mode base policy will be automatically deployed using a scheduled task that acts as a "snapback guarantee".

> [!NOTE]\
> This feature can also detect and create supplemental policy for Kernel protected files, such as the executables of games installed using Xbox app. Make sure you run the game while the base policy is deployed in Audit mode so that it can capture those executables.

> [!TIP]\
> You can use both Signed and Unsigned App Control policies. The app will automatically detect the signing status of the XML policy file that you select and prompt for any additional information required.

<br>

## Other Use Cases

You can also use this page to create supplemental policies for every program you wish to deploy to your endpoints. For example, if your company needs to allow the employees to use 20 programs such as Photoshop, AutoDesk, Visual Studio etc., you can follow these steps:

1. Prepare a clean VM (Virtual Machine such as Hyper-V) by installing the latest OS version on it and updating it. After update and restart of the guest OS in the VM, Install the **AppControl Manager** on it and shut it down. Now create a Hyper-V checkpoint. You will use this checkpoint to return back to this clean state.

2. Use AppControl Manager to [deploy a base policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-App-Control-Policy) such as `Allow Microsoft`.

3. Use the `Allow New Apps` feature to browse for the base policy and enter the name of the program you wish to create a supplemental policy for.

4. In `Step 2`, the Audit mode is enabled, so start installing your program. After installation is completed, run the program, use it a bit and close it.

5. Browse for the installation directories of the installed program and go to `Step 3`.

6. The AppControl Manager will begin redeploying the base policy in enforced mode and starts scanning the directories you selected and any audit events that were generated.

7. The detected and captured data will be presented to you in 2 different pages. Review them, search through them and remove any of them that you don't want to be included in the supplemental policy.

8. Once you're done reviewing, create the supplemental policy and deploy it on the system. Use the FilePublisher level which will create maintainable supplemental policies and will use signature(s) of the signed files and hashes of the unsigned files.

9. After the policy is deployed, try starting your program again and make sure it 100% works and all of its features are usable.

10. If one of the files of the program still gets blocked, that means you didn't browse for the directory where that file is located or you didn't use the program's feature that would trigger audit logs to be generated for its files. AppControl Manager offers multiple features that you can use to generate supplemental policies and then [merge them all](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Merge-App-Control-Policies) into one. For example, you can [create a supplemental policy just from the event logs](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Policy-From-Event-Logs).

<br>

## Configuration Details

* **Supplemental Policy Name**: Enter the name for the Supplemental policy that will be created. Preferably use the name of the app you're trying to install so that you will be able to recognize the policy in System Information page easily.

* **Browse for a Policy XML file**: Use this button to browse for the path to the base policy file.

* **Log Size**: Use this number box to increase or decrease the maximum capacity of the `Code Integrity/Operational` logs. The bigger the number, the more events will be captured without being overwritten.

* **Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

* **Browse for folders**: Use this button in Step 2 to browse for the installation directories of the app(s) you installed. This will help improve the accuracy of the supplemental policy that will be created. If for some reason you cannot locate the installation directory of the app you installed, ensure you start the app after installation, use it as you normally would so that audit logs will be generated for all of its files and components. These audit logs will then be displayed to you in the `Review the Event Logs` tab.

* **Deploy After Creation**: If toggled, only the supplemental policy XML file will be available in the [User Configuration directory](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager#where-is-the-user-configurations-directory) at the end of the operation. If it's not toggled, the CIP file will also be made available. Both files will have the same name as the policy name that you choose.

<br>
