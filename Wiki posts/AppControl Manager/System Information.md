# System Information

Use the System Information page in [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) to view details about the deployed App Control policies on the system. 

* Search through the list of policies

* View the rule options in each policy

* Determine which policy is signed or unsigned

* Sort the policies using multiple criteria

* See which policy is Base, Supplemental or System

* View the version of each policy

<br>

> [!TIP]\
> You can view the version of the Microsoft Vulnerable Driver Block List in this page by checking the box for including System policies in the list.

<br>

This page also allows you to **remove** the deployed App Control policies from the system with a single click/tap.

In the ***Code Integrity Information*** section you can view advanced details about the current status of Code Integrity on the system.

> [!NOTE]\
> **About the Automatic Policies filter option**
>
> Enabling this checkbox includes supplemental policies named `AppControlManagerSupplementalPolicy` in the displayed results. Each base policy created and deployed via the AppControl Manager automatically deploys a corresponding supplemental policy with this name. This supplemental policy is essential for the operation of the AppControl Manager application itself.
> In addition, it contains a FilePublisher rule for `SignTool.exe`, allowing signing operations to be performed. If you intentionally remove this policy, you will no longer be able to launch the AppControl Manager or use `SignTool.exe` when certain base policies are active.
> 
> **Note that these supplemental policies are automatically removed when their associated base policy is removed from the system, so no additional action is required on your part.**
>
> You can view the XML source of the `AppControlManagerSupplementalPolicy` supplemental policy [here](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/AppControl%20Manager/Resources/AppControlManagerSupplementalPolicy.xml).

<br>
