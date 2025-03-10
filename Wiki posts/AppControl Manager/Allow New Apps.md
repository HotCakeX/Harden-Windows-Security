# Allow New Apps

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Allow%20New%20Apps.png" alt="AppControl Manager Application's Allow New Apps Page">

</div>

<br>

<br>

This page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) is designed as a practical hub for managing App Control on your system. Consider it your centralized solution for effortlessly overseeing your app-related policies and allowing new apps.

When you need to install a new application, this page provides an intuitive way to temporarily enable Audit mode in your existing base policy. This allows the installation of the app while ensuring the base policy automatically reverts to Enforced mode immediately afterward.

During Audit mode, AppControl Manager captures all relevant Code Integrity and AppLocker events, analyzes them, and presents detailed insights in an organized view. You can also navigate to the specific folder paths where the application was installed, enabling the tool to scan and display the contents on a separate page.

The compiled data, scanned files and recorded events, are presented for you to review, filter, sort, and manage. Once you're satisfied, you can seamlessly convert these into a single Supplemental policy ready for deployment.

While much of the process is automated, you remain in full control. With just a few clicks, you can fine-tune and manage your App Control policy efficiently.

Rest assured, no unauthorized software or malware can make its way into your Supplemental policy. Every file and event is accompanied by highly detailed information, eliminating any guesswork and ensuring only trusted elements are included.

If something like a power outage occurs during the audit mode phase, on the next reboot, the enforced mode base policy will be automatically deployed using a scheduled task that acts as a "snapback guarantee".

> [!NOTE]\
> This feature can also detect and create supplemental policy for Kernel protected files, such as the executables of games installed using Xbox app. Make sure you run the game while the base policy is deployed in Audit mode so that it can capture those executables.

> [!TIP]\
> You can use both Signed and Unsigned App Control policies. The app will automatically detect the signing status of the XML policy file that you select and prompt for any additional information required.

<br>

## Configuration Details

* **Supplemental Policy Name**: Enter the name for the Supplemental policy that will be created. Preferably use the name of the app you're trying to install so that you will be able to recognize the policy in System Information page easily.

* **Browse for a Policy XML file**: Use this button to browse for the path to the base policy file.

* **Log Size**: Use this number box to increase or decrease the maximum capacity of the `Code Integrity/Operational` logs. The bigger the number, the more events will be captured without being overwritten.

* **Scan Level**: You can choose from different scan levels. [Refer to this page for all the information about them.](https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Rule-Levels-Comparison-and-Guide)

* **Browse for folders**: Use this button in Step 2 to browse for the installation directories of the app(s) you installed. This will help improve the accuracy of the supplemental policy that will be created. If for some reason you cannot locate the installation directory of the app you installed, ensure you start the app after installation, use it as you normally would so that audit logs will be generated for all of its files and components. These audit logs will then be displayed to you in the `Review the Event Logs` tab.

* **Deploy After Creation**: If toggled, only the supplemental policy XML file will be available in the [User Configuration directory](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager#where-is-the-user-configurations-directory) at the end of the operation. If it's not toggled, the CIP file will also be made available. Both files will have the same name as the policy name that you choose.

<br>
