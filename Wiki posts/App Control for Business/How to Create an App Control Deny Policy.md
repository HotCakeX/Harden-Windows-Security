# How to Create an App Control Deny Policy

Application Control is based on whitelisting strategy, that means everything that is not allowed in the policy is automatically denied. However, there are times when you might need to only prevent a certain app or file from running, while allowing everything else. This is where the App Control Deny Policy comes in.

Use the [Create Deny Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Deny-App-Control-Policy) page in the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create a new App Control Deny Policy based on different criteria.

<br>

## Create an App Control Deny Policy by Scanning Files and Folders

In the [Create Deny Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Deny-App-Control-Policy) page, select the **Files and Folders** section to expand it.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/ea0139c82415aa735341490086ff22af03d93a87/Pictures/PNG%20and%20JPG/How%20to%20Create%20an%20App%20Control%20Deny%20Policy/Files%20and%20Folders%20section.png" alt="Deny policy Files and Folders section">

<br>

<br>

* Browse for files and/or folders that you want to be scanned and included in the Deny policy.

* Select an appropriate name for the Deny policy that will help you recognize it after deployment.

* The scalability is set to ***2*** by default but you can increase it if the number of files/folders are too many. The higher this number, the faster the scan will be completed and the more system resources will be consumed during the scan phase.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/c89b6fd8edeaea7062fb7b73a00b593f13b16c62/Pictures/PNG%20and%20JPG/How%20to%20Create%20an%20App%20Control%20Deny%20Policy/Files%20and%20Folders%20details%20filled.png" alt="Files and Folders deny policy section">

<br>

<br>

Having selected all of the required details, you can now press the **Create Deny Policy button** and wait for the scan to finish.

All of the files and folders that you selected will be recursively scanned and any App Control compatible files that are found in them will be added to **View detected file details** page at the bottom of the section to show you the exact files that will be included in the deny policy.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/c89b6fd8edeaea7062fb7b73a00b593f13b16c62/Pictures/PNG%20and%20JPG/How%20to%20Create%20an%20App%20Control%20Deny%20Policy/Files%20and%20Folders%20Scan%20Results.png" alt="Files and Folders deny policy section scan results">

<br>

<br>

If you toggle the **Deploy after Creation** button the Deny policy will also be deployed on the system after creation.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/b716692bc5eac4158f07fb2f1a3f94fa2ecdf609/Pictures/PNG%20and%20JPG/How%20to%20Create%20an%20App%20Control%20Deny%20Policy/Files%20and%20Folders%20Deploy%20button.png" alt="Files and folders section Deploy button focus">

<br>

<br>

## Create a Deny Policy for Packaged Apps

Packaged apps are modern, they use MSIX packages and are easy to manage and block/deny in App Control policies because all of the files in a packaged app share the same signing certificate and Package Family Name.

Use the [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to create deny policies for packaged apps. The policy that you create will not need any changes when the apps are updated since the denial is based on the `PackageFamilyName` aka `PFN`.

In order to create this type of deny policy, navigate to the [Create Deny Policy](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Create-Deny-App-Control-Policy) page in the AppControl Manager and expand the **Package Family Name** section.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/29c774a6339adf75bea5f019ad32a3f214fe764e/Pictures/PNG%20and%20JPG/How%20to%20Create%20an%20App%20Control%20Deny%20Policy/Deny%20policy%20PFN%20app%20selection.png" alt="PFN section selecting apps after search">

<br>

<br>

The apps list will be automatically preloaded for you upon expanding the section. You can use the search bar to search for one or more app(s) and then select them.

Next, enter a suitable name for the Deny policy and finally press the **Create Deny Policy** button.

The deny policy will be created and if you toggled the **Deploy after Creation** button, it will also be deployed on the system.

In the screenshots above, we searched for the Photos app, selected it and after deploying that policy, the Photos app will no longer be able to run on the system when we try to launch it.

<br>

<img src="https://raw.githubusercontent.com/HotCakeX/.github/ce3c1c2553573fcb16036ebee76989ab7dd8a403/Pictures/PNG%20and%20JPG/How%20to%20Create%20an%20App%20Control%20Deny%20Policy/example%20of%20blocked%20photos%20app%20for%20PFN%20section.png" alt="PFN blocked Photos app notice in Windows">

<br>

<br>
