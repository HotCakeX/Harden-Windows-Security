# Sidebar

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/PNG%20and%20JPG/AppControl%20Manager%20page%20screenshots/Sidebar.png" alt="AppControl Manager Application's Sidebar">

</div>

<br>

<br>

The [AppControl Manager](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager) features a versatile Sidebar designed to streamline user interactions and enhance productivity.

## Policies Library

A place where you can import as many App Control policies as you want and use them in different parts of the app. Policies in the library exist in the app's memory at runtime. You can import XML, CIP and P7B files to the library. The Sidebar button on the app's top bar displays the total count of the App Control policies in the library.

Any new policy that you create in the app will be automatically added to the library and when it happens a unique animation is displayed to make it clear where the new policy has been transferred to. You have the option to save the policies in the library as XML or CIP files.

* The library offers quick actions for every policy in it when you click or tap on it, such as:

    * Saving as XML (prompts for file picker so you can pick a location to save)
    * Saving as CIP (prompts for file picker so you can pick a location to save)
    * Opening in Policy Editor (The changes will be saved back to the same exact policy in the library)
    * Configuring Rule Options (The changes will be saved back to the same exact policy in the library)
    * Removing from the list (If persistence is enabled, this means it will be removed from the cache on the disk as well.)
    * Deploying on the system (only available when running the app as Admin)

* Some of the quick actions described above are also available when swiping right or left on each policy in the list. (only available on devices with touch capability)

* You can right-click or top + hold on each policy in the library to access the following features

    * Copy BasePolicyID
    * Copy policyID

### Persistence Feature

You can enable persistence for the Policies Library so that the policies in the library will remain intact even after you close the app or restart your system. This option is on by default. You can turn it off and on via a toggle switch on the Sidebar.

Persistent Library feature does not prevent the policies to remain intact when you uninstall the AppControl Manager, so if you ever plan to uninstall the app, make sure to use the `Backup All` option under the `Actions` menu to create a backup first.

When the library contains any policy, persistence is off and you attempt to close the app, you will encounter a notice reminding you that there are unsaved policies. You can configure this behavior in the app's settings page. At this point you can either enable persistence, save policies manually to files, or simply ignore the warning and confirm app closing dialog.

The Policies Library with all of its capabilities and persistence offers a seamless experience that **just works** out of the box, without adding any additional burden or responsibility to the user.

### Assigning Policies From the Library to Different Section of the App

Pages within the AppControl Manager that require a policy automatically recognize when there is any policy in the library. As you navigate to these pages, subtle indicators appear <img src="https://raw.githubusercontent.com/HotCakeX/.github/refs/heads/main/Pictures/Gifs/AppControl%20Manager%20Menu/AugmentationIndicator.gif" width="25">, prompting you to open the Sidebar and quickly assign a policy to these sections.

<br>

### Configuration Details

* **Sidebar Guide**: Use this button to open this page in the browser.

* **Open User Config Directory**: Use this button to open the [User Configuration directory](https://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager#where-is-the-user-configurations-directory) in File Explorer.

* Use the **Optimize Memory** button to optimize memory usage of the app and try to reduce it. AppControl Manager is already highly optimized but this gives users more control over its memory usage. The app will generate a detailed report in the Logs page that you can check out, showing the type and amount of memory changes.

<br>
